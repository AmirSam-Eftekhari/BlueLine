"""
Configuration analyzer — Dockerfiles, .env files, generic YAML/config files.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from app.analyzers.base import Analyzer
from app.core.models import (
    AnalyzerCapability, CapabilityLevel, DetectionMethod, Evidence, Finding,
    RiskFactors, ScanConfig, Severity, TargetProfile, ValidationStatus, new_finding_id,
)

ENV_SECRET_RE = re.compile(r"(?i)^\s*([A-Z0-9_]*(SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*=\s*(\S+)")
DOCKER_LATEST_RE = re.compile(r"^\s*FROM\s+[\w./-]+(:latest)?\s*$", re.IGNORECASE)
DOCKER_ROOT_RE = re.compile(r"^\s*USER\s+root\s*$", re.IGNORECASE)
DOCKER_ADD_URL_RE = re.compile(r"^\s*ADD\s+https?://", re.IGNORECASE)


class ConfigurationAnalyzer(Analyzer):
    name = "config_analyzer"
    display_name = "Configuration Analyzer"
    detection_method = "CONFIGURATION_ANALYSIS"

    def applies_to(self, profile: TargetProfile) -> bool:
        return bool(profile.config_files) or bool(profile.container_definitions)

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.FULL_SUPPORT)

    def run(self, profile: TargetProfile, config: ScanConfig) -> list[Finding]:
        root = Path(profile.target_path)
        findings: list[Finding] = []
        if not root.is_dir():
            return findings

        for rel in profile.config_files:
            fpath = root / rel
            name = fpath.name.lower()
            if name.startswith(".env") or name == "env":
                findings += self._scan_env_file(fpath, rel, str(root))

        for rel in profile.container_definitions:
            fpath = root / rel
            if fpath.name.lower().startswith("dockerfile"):
                findings += self._scan_dockerfile(fpath, rel, str(root))

        return findings

    def _scan_env_file(self, fpath: Path, rel: str, target: str) -> list[Finding]:
        out = []
        try:
            lines = fpath.read_text(errors="ignore").splitlines()
        except OSError:
            return out
        for i, line in enumerate(lines, start=1):
            m = ENV_SECRET_RE.match(line)
            if m and len(m.group(3)) > 2 and not m.group(3).startswith("${"):
                out.append(Finding(
                    id=new_finding_id(prefix="BL-CFG"),
                    title=f"Secret-shaped value committed in {fpath.name}",
                    category="Credential Management", subcategory="Committed Secret",
                    severity=Severity.HIGH, confidence=65,
                    validation_status=ValidationStatus.SUSPECTED,
                    affected_target=target, affected_component=rel, location=f"{rel}:{i}",
                    detection_method=DetectionMethod.CONFIGURATION_ANALYSIS,
                    evidence=[Evidence(description=f"Variable '{m.group(1)}' has a literal value in a "
                                                    f"tracked config file", file_path=rel, line_start=i)],
                    impact="If this file is committed to version control, the credential is exposed to "
                           "anyone with repository access and should be treated as compromised.",
                    remediation="Remove the literal value, add the file to .gitignore if not already, "
                                "and rotate the credential.",
                    risk_factors=RiskFactors(impact=8, exploitability=2, exposure=3, confidence=65, reproducibility=9),
                    detector_sources=[self.name],
                ))
        return out

    def _scan_dockerfile(self, fpath: Path, rel: str, target: str) -> list[Finding]:
        out = []
        try:
            lines = fpath.read_text(errors="ignore").splitlines()
        except OSError:
            return out
        for i, line in enumerate(lines, start=1):
            if DOCKER_LATEST_RE.match(line) or re.match(r"^\s*FROM\s+\S+:latest\s*$", line, re.IGNORECASE):
                out.append(self._dockerfinding(target, rel, i, line,
                    "Base image uses ':latest' or an unpinned tag", "Reproducibility",
                    Severity.LOW, 60,
                    "Unpinned base images can silently change between builds, breaking reproducibility "
                    "and potentially introducing new vulnerabilities.",
                    "Pin the base image to a specific digest or version tag."))
            if DOCKER_ROOT_RE.match(line):
                out.append(self._dockerfinding(target, rel, i, line,
                    "Container explicitly runs as root", "Access Control",
                    Severity.MEDIUM, 70,
                    "Running as root inside the container increases the impact of any container escape.",
                    "Create and switch to a non-root user for the runtime stage."))
            if DOCKER_ADD_URL_RE.match(line):
                out.append(self._dockerfinding(target, rel, i, line,
                    "ADD used to fetch a remote URL", "Supply Chain",
                    Severity.MEDIUM, 55,
                    "ADD with a URL fetches and extracts remote content with no integrity verification shown.",
                    "Use curl/wget with checksum verification in a RUN step instead of ADD <url>."))
        return out

    def _dockerfinding(self, target, rel, lineno, line, title, category, sev, conf, impact, remediation) -> Finding:
        return Finding(
            id=new_finding_id(prefix="BL-CFG"), title=title, category=category, subcategory="Dockerfile",
            severity=sev, confidence=conf, validation_status=ValidationStatus.PROBABLE,
            affected_target=target, affected_component=rel, location=f"{rel}:{lineno}",
            detection_method=DetectionMethod.CONFIGURATION_ANALYSIS,
            evidence=[Evidence(description=title, snippet=line.strip(), file_path=rel, line_start=lineno)],
            impact=impact, remediation=remediation,
            risk_factors=RiskFactors(impact=5, exploitability=3, exposure=4, confidence=conf, reproducibility=8),
            detector_sources=[self.name],
        )
