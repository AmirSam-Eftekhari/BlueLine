"""
Scan orchestrator.

Runs the full pipeline: discover -> plan -> execute analyzers -> execute
dynamic/fuzzing -> correlate -> risk-score -> compute coverage. One
analyzer raising an exception is CAUGHT and recorded as a failed stage —
it does not take down the rest of the scan. This is verified by
tests/test_orchestrator.py with a deliberately broken analyzer.
"""

from __future__ import annotations

import threading
import traceback
from datetime import datetime, timezone
from typing import Callable, Optional

from app.analyzers.base import AnalyzerRegistry, default_registry
from app.core.coverage import CoverageEngine
from app.core.correlation import FindingCorrelator
from app.core.logging_setup import log_structured
from app.core.models import (
    Finding, ScanConfig, ScanResult, StageResult, TargetProfile, utc_now,
)
from app.core.risk import RiskEngine
from app.fuzzing.engine import FuzzingEngine
from app.runtime.dynamic import DynamicRunner
from app.targets.discovery import TargetDiscovery

ProgressCallback = Callable[[str, str, dict], None]  # (stage_name, status, detail)


class CancellationToken:
    def __init__(self):
        self._cancelled = threading.Event()

    def cancel(self):
        self._cancelled.set()

    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()


class ScanOrchestrator:
    def __init__(self, registry: Optional[AnalyzerRegistry] = None):
        self.registry = registry or default_registry()
        self.risk_engine = RiskEngine()
        self.coverage_engine = CoverageEngine()
        self.correlator = FindingCorrelator()

    def run_scan(self, scan_id: str, target_path: str, config: ScanConfig,
                 progress: Optional[ProgressCallback] = None,
                 cancel_token: Optional[CancellationToken] = None) -> ScanResult:
        cancel_token = cancel_token or CancellationToken()
        progress = progress or (lambda *a, **k: None)

        def emit(stage, status, detail=None):
            detail = detail or {}
            progress(stage, status, detail)
            log_structured("scanner", f"{stage}: {status}", scan_id=scan_id, stage=stage, status=status)
            if status == "failed":
                log_structured("analyzer", f"Analyzer stage failed: {stage}", scan_id=scan_id,
                                stage=stage, error=detail.get("error", ""))

        log_structured("scanner", "Scan started", scan_id=scan_id, target=target_path, profile=config.profile)

        # -- Stage: Target Discovery -----------------------------------
        emit("Target Discovery", "running")
        discovery = TargetDiscovery(exclude_globs=config.exclude_globs)
        profile = discovery.discover(target_path)
        emit("Target Discovery", "completed", {"languages": profile.languages})

        result = ScanResult(scan_id=scan_id, target_profile=profile, config=config)
        stage_results: list[StageResult] = []

        if cancel_token.is_cancelled():
            result.status = "cancelled"
            result.cancelled = True
            return result

        # -- Stage: Environment Profiling (capability plan) --------------
        emit("Environment Profiling", "running")
        applicable = self.registry.applicable(profile)
        emit("Environment Profiling", "completed",
             {"applicable_analyzers": [a.name for a in applicable]})

        # -- Stage: run each applicable static/dependency/config analyzer --
        for analyzer in applicable:
            if cancel_token.is_cancelled():
                break
            stage_name = analyzer.display_name
            started = utc_now()
            emit(stage_name, "running")
            try:
                findings = analyzer.run(profile, config)
                stage_results.append(StageResult(
                    stage_name=stage_name, status="completed", started_at=started,
                    finished_at=utc_now(), findings_count=len(findings),
                ))
                result.findings.extend(findings)
                emit(stage_name, "completed", {"findings": len(findings)})
            except Exception as e:  # noqa: BLE001 - deliberate: one bad analyzer must not kill the scan
                stage_results.append(StageResult(
                    stage_name=stage_name, status="failed", started_at=started,
                    finished_at=utc_now(), error=f"{e.__class__.__name__}: {e}",
                    coverage_impact=15.0,
                ))
                emit(stage_name, "failed", {"error": str(e), "trace": traceback.format_exc(limit=3)})

        # -- Stage: Dynamic Analysis --------------------------------------
        if config.enable_dynamic and "CLI" in profile.interfaces and not cancel_token.is_cancelled():
            stage_name = "Dynamic Analysis"
            started = utc_now()
            emit(stage_name, "running")
            try:
                dyn_findings, dyn_detail = self._run_dynamic(profile, config)
                stage_results.append(StageResult(
                    stage_name=stage_name, status="completed", started_at=started,
                    finished_at=utc_now(), findings_count=len(dyn_findings), detail=dyn_detail,
                ))
                result.findings.extend(dyn_findings)
                emit(stage_name, "completed", dyn_detail)
            except Exception as e:
                stage_results.append(StageResult(
                    stage_name=stage_name, status="failed", started_at=started,
                    finished_at=utc_now(), error=str(e), coverage_impact=20.0,
                ))
                emit(stage_name, "failed", {"error": str(e)})
        else:
            stage_results.append(StageResult(
                stage_name="Dynamic Analysis", status="skipped", started_at=utc_now(),
                finished_at=utc_now(),
                detail={"reason": "disabled by scan profile or no runnable CLI entry point detected"},
            ))

        # -- Stage: Fuzzing -------------------------------------------------
        if config.enable_fuzzing and "CLI" in profile.interfaces and not cancel_token.is_cancelled():
            stage_name = "Fuzzing"
            started = utc_now()
            emit(stage_name, "running")
            try:
                fuzz_findings, fuzz_detail = self._run_fuzzing(profile, config)
                stage_results.append(StageResult(
                    stage_name=stage_name, status="completed", started_at=started,
                    finished_at=utc_now(), findings_count=len(fuzz_findings), detail=fuzz_detail,
                ))
                result.findings.extend(fuzz_findings)
                emit(stage_name, "completed", fuzz_detail)
            except Exception as e:
                stage_results.append(StageResult(
                    stage_name=stage_name, status="failed", started_at=started,
                    finished_at=utc_now(), error=str(e), coverage_impact=20.0,
                ))
                emit(stage_name, "failed", {"error": str(e)})
        else:
            stage_results.append(StageResult(
                stage_name="Fuzzing", status="skipped", started_at=utc_now(), finished_at=utc_now(),
                detail={"reason": "disabled by scan profile or no runnable CLI entry point detected"},
            ))

        # -- Stage: Correlation ---------------------------------------------
        emit("Finding Correlation", "running")
        result.findings = self.correlator.correlate(result.findings)
        emit("Finding Correlation", "completed", {"findings_after_merge": len(result.findings)})

        # -- Stage: Risk Assessment ------------------------------------------
        emit("Risk Assessment", "running")
        for f in result.findings:
            self.risk_engine.apply(f)
        emit("Risk Assessment", "completed")

        # HIGH/CRITICAL findings get their own security-log trail — metadata
        # only (id, category, location), never evidence/snippets, which can
        # contain target source code or extracted secret strings.
        for f in result.findings:
            if f.severity.value in ("HIGH", "CRITICAL"):
                log_structured("security", f"{f.severity.value} finding: {f.title}",
                                scan_id=scan_id, finding_id=f.id, category=f.category,
                                subcategory=f.subcategory, severity=f.severity.value,
                                confidence=f.confidence, validation_status=f.validation_status.value,
                                location=f.location, risk_score=f.risk_score)

        # -- Stage: Coverage --------------------------------------------------
        emit("Coverage Calculation", "running")
        result.stage_results = stage_results
        result.coverage = self.coverage_engine.compute(profile, stage_results)
        emit("Coverage Calculation", "completed", result.coverage)

        result.status = "cancelled" if cancel_token.is_cancelled() else "completed"
        result.cancelled = cancel_token.is_cancelled()
        result.finished_at = utc_now()
        emit("Report Generation", "completed")
        log_structured("scanner", "Scan finished", scan_id=scan_id, status=result.status,
                        findings_count=len(result.findings),
                        severity_counts=result.severity_counts())
        return result

    # ---------------------------------------------------------------------
    def _run_dynamic(self, profile: TargetProfile, config: ScanConfig):
        from app.analyzers.dependency import Finding as _F  # noqa: reuse Finding type
        runner = DynamicRunner(timeout_seconds=config.dynamic_timeout_seconds)
        findings: list[Finding] = []
        runs = 0
        crash_count = 0
        network_observed: set[str] = set()
        entry = self._pick_entry_command(profile)
        if entry is None:
            return findings, {"reason": "no invocable entry point"}

        mutator_inputs = ["", "0", "-1", "A" * 5000, "\x00\x00\x00", "%s%s%s", "'; --", "../../etc/passwd"]
        for data in mutator_inputs[: config.dynamic_max_runs]:
            if runs >= config.dynamic_max_runs:
                break
            obs = runner.run(entry, input_data=data.encode(), monitor_activity=True)
            runs += 1
            network_observed.update(obs.network_activity)
            if obs.classification in ("crash", "timeout"):
                crash_count += 1
                findings.append(self._finding_from_observation(profile, entry, obs))
                log_structured("runtime", f"Dynamic run {obs.classification}", target=profile.target_path,
                                classification=obs.classification, exit_code=obs.exit_code,
                                duration_seconds=obs.duration_seconds)

        if network_observed:
            findings.append(self._network_activity_finding(profile, entry, network_observed))

        return findings, {"runs": runs, "crashes_or_timeouts": crash_count,
                           "network_endpoints_observed": len(network_observed)}

    def _run_fuzzing(self, profile: TargetProfile, config: ScanConfig):
        engine = FuzzingEngine(runner=DynamicRunner(timeout_seconds=min(config.dynamic_timeout_seconds, 3)))
        entry = self._pick_entry_command(profile)
        findings: list[Finding] = []
        if entry is None:
            return findings, {"reason": "no invocable entry point"}

        campaign = engine.run_campaign(entry, seeds=["seed", "0", "test"],
                                        max_cases=config.fuzz_max_cases,
                                        time_budget_seconds=config.fuzz_time_budget_seconds)
        for anomaly in campaign.anomalies:
            findings.append(self._finding_from_observation(
                profile, entry, anomaly.observation, occurrence_count=anomaly.occurrence_count,
                repro_input=anomaly.representative_input,
            ))
            log_structured("runtime", f"Fuzzing anomaly: {anomaly.classification}",
                            target=profile.target_path, classification=anomaly.classification,
                            occurrence_count=anomaly.occurrence_count)
        log_structured("runtime", "Fuzzing campaign complete", target=profile.target_path,
                        total_cases_run=campaign.total_cases_run, distinct_anomalies=len(campaign.anomalies))
        return findings, {
            "total_cases_run": campaign.total_cases_run,
            "cases_per_second": campaign.cases_per_second,
            "distinct_anomalies": len(campaign.anomalies),
        }

    @staticmethod
    def _pick_entry_command(profile: TargetProfile) -> Optional[list[str]]:
        import sys as _sys
        for ep in profile.entry_points:
            full = f"{profile.target_path.rstrip('/')}/{ep}"
            if ep.endswith(".py"):
                return [_sys.executable, full]
        for ex in profile.executables:
            full = f"{profile.target_path.rstrip('/')}/{ex}" if not ex.startswith("/") else ex
            return [full]
        return None

    def _network_activity_finding(self, profile, entry, endpoints: set[str]) -> Finding:
        from app.core.models import (
            DetectionMethod, Evidence, RiskFactors, Severity, ValidationStatus, new_finding_id,
        )
        return Finding(
            id=new_finding_id(prefix="BL-DYN"),
            title="Target attempted network access during offline analysis",
            category="Reliability", subcategory="Unexpected Network Activity",
            severity=Severity.MEDIUM, confidence=85, validation_status=ValidationStatus.CONFIRMED,
            affected_target=profile.target_path, affected_component=" ".join(entry),
            location=None, detection_method=DetectionMethod.DYNAMIC_ANALYSIS,
            evidence=[Evidence(description=f"Observed {len(endpoints)} distinct outbound connection(s) "
                                            f"during sandboxed execution: {sorted(endpoints)[:10]}")],
            observed_behavior=f"Connected to: {sorted(endpoints)}",
            expected_behavior="An offline analysis target making outbound network connections is "
                              "unexpected and worth reviewing, whether or not it's malicious.",
            impact="Unexpected network activity from an analyzed binary/script could indicate "
                   "telemetry, an update check, exfiltration, or command-and-control behavior — "
                   "this finding does not distinguish between those; manual review of the "
                   "destination is needed.",
            reproduction=f"Re-run {' '.join(entry)} in a sandboxed/monitored environment and observe "
                         f"outbound connections directly.",
            remediation="Review why the target is making these connections; block network access "
                        "for this target's execution context if it should be fully offline.",
            risk_factors=RiskFactors(impact=6, exploitability=2, exposure=5, confidence=85, reproducibility=7),
            detector_sources=["dynamic_runner_activity_monitor"],
        )

    def _finding_from_observation(self, profile, entry, obs, occurrence_count=1, repro_input=None) -> Finding:
        from app.core.models import (
            DetectionMethod, Evidence, RiskFactors, Severity, ValidationStatus, new_finding_id,
        )
        is_fuzz = repro_input is not None
        sev = Severity.HIGH if obs.classification == "crash" else Severity.MEDIUM
        repro_bytes = repro_input if repro_input is not None else b""
        return Finding(
            id=new_finding_id(prefix="BL-DYN" if not is_fuzz else "BL-FUZZ"),
            title=f"Target {obs.classification} on {'fuzzed' if is_fuzz else 'crafted'} input",
            category="Reliability" if obs.classification != "crash" else "Robustness",
            subcategory=obs.classification.upper(),
            severity=sev,
            confidence=92 if obs.classification == "crash" else 70,
            validation_status=ValidationStatus.CONFIRMED,  # this was literally reproduced, right now
            affected_target=profile.target_path,
            affected_component=" ".join(entry),
            location=None,
            detection_method=DetectionMethod.FUZZING if is_fuzz else DetectionMethod.DYNAMIC_ANALYSIS,
            evidence=[Evidence(
                description=f"Process {obs.classification} (exit_code={obs.exit_code}, "
                            f"timed_out={obs.timed_out}) after {occurrence_count} occurrence(s)",
                raw_output=(obs.stderr or obs.stdout)[:2000],
            )],
            observed_behavior=f"exit_code={obs.exit_code}, duration={obs.duration_seconds}s, "
                              f"stderr_head={obs.stderr[:200]!r}",
            expected_behavior="Process should handle the input without crashing, hanging, or "
                              "raising an unhandled exception.",
            impact="A reproducible crash or hang triggered by external input is a reliability issue, "
                   "and may be a security issue (denial of service, or worse if the crash is "
                   "memory-corruption-related) depending on how the input reaches this code path.",
            reproduction=f"Re-run: {' '.join(entry)}  with stdin = {repro_bytes[:200]!r}"
                         if is_fuzz else f"Re-run: {' '.join(entry)} with the crafted input from evidence",
            remediation="Add explicit input validation before this code path; investigate the crash "
                        "with a debugger to determine root cause and security relevance before dismissing "
                        "it as a normal bug.",
            risk_factors=RiskFactors(
                impact=8 if obs.classification == "crash" else 5,
                exploitability=5, exposure=4, confidence=92 if obs.classification == "crash" else 70,
                reproducibility=10,  # we just reproduced it
            ),
            detector_sources=["fuzzing_engine" if is_fuzz else "dynamic_runner"],
        )
