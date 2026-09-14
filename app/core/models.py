"""
BlueLine core data models.

This module defines the unified schema used across every analyzer, the
orchestrator, the risk engine, and the reporting layer. Every analyzer in
BlueLine — regardless of language or technique — must produce Finding
objects that conform to this schema. This is what makes correlation,
risk scoring, and reporting possible without per-analyzer special-casing.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Severity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {
            Severity.INFORMATIONAL: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class ValidationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"        # Reproduced with concrete evidence (e.g. dynamic/fuzz crash)
    PROBABLE = "PROBABLE"          # Strong static evidence, pattern well-established
    SUSPECTED = "SUSPECTED"        # Static heuristic match, plausible but unconfirmed
    UNVERIFIED = "UNVERIFIED"      # Informational / could not be validated (e.g. no live vuln DB)
    FALSE_POSITIVE = "FALSE_POSITIVE"  # Explicitly marked by a human reviewer or later analysis


class DetectionMethod(str, Enum):
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    DEPENDENCY_ANALYSIS = "DEPENDENCY_ANALYSIS"
    CONFIGURATION_ANALYSIS = "CONFIGURATION_ANALYSIS"
    DYNAMIC_ANALYSIS = "DYNAMIC_ANALYSIS"
    FUZZING = "FUZZING"
    CORRELATED = "CORRELATED"  # produced by merging >=2 findings from other methods


class CapabilityLevel(str, Enum):
    FULL_SUPPORT = "FULL_SUPPORT"
    PARTIAL_SUPPORT = "PARTIAL_SUPPORT"
    STATIC_ONLY = "STATIC_ONLY"
    DYNAMIC_ONLY = "DYNAMIC_ONLY"
    EXPERIMENTAL = "EXPERIMENTAL"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass
class RiskFactors:
    """Transparent inputs to the risk score. See core/risk.py for the formula."""
    impact: float            # 0-10: how bad if realized
    exploitability: float    # 0-10: how easy to trigger/exploit
    exposure: float          # 0-10: how reachable (e.g. exposed endpoint vs internal helper)
    confidence: float        # 0-100: analyzer's confidence this finding is real
    reproducibility: float   # 0-10: 10 = deterministically reproduced, 0 = one-off/unclear

    def as_dict(self) -> dict:
        return {
            "impact": self.impact,
            "exploitability": self.exploitability,
            "exposure": self.exposure,
            "confidence": self.confidence,
            "reproducibility": self.reproducibility,
        }


@dataclass
class Evidence:
    description: str
    snippet: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    raw_output: Optional[str] = None  # e.g. captured stdout/stderr/stack trace

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class Finding:
    id: str
    title: str
    category: str
    subcategory: str
    severity: Severity
    confidence: float                  # 0-100
    validation_status: ValidationStatus
    affected_target: str                # target name/root
    affected_component: str             # file / endpoint / binary region
    location: Optional[str]             # e.g. "src/app.py:184"
    detection_method: DetectionMethod
    evidence: list[Evidence] = field(default_factory=list)
    observed_behavior: str = ""
    expected_behavior: str = ""
    impact: str = ""
    reproduction: Optional[str] = None
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    risk_factors: Optional[RiskFactors] = None
    risk_score: Optional[float] = None  # filled in by RiskEngine
    first_seen: str = field(default_factory=utc_now)
    last_seen: str = field(default_factory=utc_now)
    detector_sources: list[str] = field(default_factory=list)  # which analyzer(s) reported this
    fingerprint: str = ""  # stable hash for dedup/correlation across scans

    def compute_fingerprint(self) -> str:
        basis = f"{self.category}|{self.subcategory}|{self.affected_component}|{self.location}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def as_dict(self) -> dict:
        d = {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "subcategory": self.subcategory,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "validation_status": self.validation_status.value,
            "affected_target": self.affected_target,
            "affected_component": self.affected_component,
            "location": self.location,
            "detection_method": self.detection_method.value,
            "evidence": [e.as_dict() for e in self.evidence],
            "observed_behavior": self.observed_behavior,
            "expected_behavior": self.expected_behavior,
            "impact": self.impact,
            "reproduction": self.reproduction,
            "remediation": self.remediation,
            "references": self.references,
            "risk_factors": self.risk_factors.as_dict() if self.risk_factors else None,
            "risk_score": self.risk_score,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "detector_sources": self.detector_sources,
            "fingerprint": self.fingerprint,
        }
        return d


def new_finding_id(prefix: str = "BL-SEC") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


@dataclass
class AnalyzerCapability:
    name: str
    level: CapabilityLevel
    notes: str = ""


@dataclass
class TargetProfile:
    target_path: str
    target_type: str                    # e.g. "Source Repository", "Executable", "Web/API"
    languages: list[str] = field(default_factory=list)
    build_systems: list[str] = field(default_factory=list)
    package_managers: list[str] = field(default_factory=list)
    dependencies_count: int = 0
    entry_points: list[str] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)   # e.g. "CLI", "HTTP API"
    executables: list[str] = field(default_factory=list)
    test_suites_detected: list[str] = field(default_factory=list)
    container_definitions: list[str] = field(default_factory=list)
    file_count: int = 0
    total_size_bytes: int = 0
    capabilities: list[AnalyzerCapability] = field(default_factory=list)
    discovery_warnings: list[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=utc_now)

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["capabilities"] = [c.__dict__ | {"level": c.level.value} for c in self.capabilities]
        return d


@dataclass
class ScanConfig:
    profile: str = "standard"  # quick | standard | deep | maximum | custom
    enable_static: bool = True
    enable_dependency: bool = True
    enable_configuration: bool = True
    enable_dynamic: bool = False
    enable_fuzzing: bool = False
    fuzz_max_cases: int = 200
    fuzz_time_budget_seconds: int = 30
    dynamic_timeout_seconds: int = 5
    dynamic_max_runs: int = 20
    max_file_size_bytes: int = 5_000_000
    exclude_globs: list[str] = field(default_factory=lambda: [
        "**/node_modules/**", "**/.git/**", "**/venv/**", "**/.venv/**",
        "**/__pycache__/**", "**/dist/**", "**/build/**",
    ])

    @staticmethod
    def for_profile(profile: str) -> "ScanConfig":
        profile = profile.lower()
        if profile == "quick":
            return ScanConfig(profile="quick", enable_dynamic=False, enable_fuzzing=False)
        if profile == "standard":
            return ScanConfig(profile="standard", enable_dynamic=True, enable_fuzzing=False,
                               dynamic_max_runs=10)
        if profile == "deep":
            return ScanConfig(profile="deep", enable_dynamic=True, enable_fuzzing=True,
                               fuzz_max_cases=500, fuzz_time_budget_seconds=60, dynamic_max_runs=30)
        if profile == "maximum":
            return ScanConfig(profile="maximum", enable_dynamic=True, enable_fuzzing=True,
                               fuzz_max_cases=2000, fuzz_time_budget_seconds=180, dynamic_max_runs=100)
        return ScanConfig(profile="custom")


@dataclass
class StageResult:
    stage_name: str
    status: str  # "completed" | "failed" | "skipped" | "partial"
    started_at: str
    finished_at: Optional[str] = None
    error: Optional[str] = None
    coverage_impact: float = 0.0
    findings_count: int = 0
    detail: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    scan_id: str
    target_profile: TargetProfile
    config: ScanConfig
    findings: list[Finding] = field(default_factory=list)
    stage_results: list[StageResult] = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    started_at: str = field(default_factory=utc_now)
    finished_at: Optional[str] = None
    status: str = "running"  # running | completed | cancelled | failed
    cancelled: bool = False

    def as_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target_profile": self.target_profile.as_dict(),
            "config": self.config.__dict__,
            "findings": [f.as_dict() for f in self.findings],
            "stage_results": [s.__dict__ for s in self.stage_results],
            "coverage": self.coverage,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
        }

    def severity_counts(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
