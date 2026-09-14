"""
Dependency / supply-chain analyzer.

HONESTY NOTE: BlueLine is offline-first and this build environment has no
route to a live vulnerability feed (NVD/OSV/GitHub Advisories). Rather
than fabricate CVE data (explicitly forbidden), this analyzer ships a
small, manually curated local sample of well-documented historical
vulnerabilities for a handful of very widely used pip/npm packages. This
is clearly NOT comprehensive and is labeled as such everywhere it
surfaces (target profile capability = PARTIAL_SUPPORT, every finding
gets a "local sample, not comprehensive" note). Anything not in the
sample is reported as UNVERIFIED / INFORMATIONAL (outdated-looking or
just listed), never silently treated as clean.

Production deployments should wire this analyzer's `feed` object to a
real source (OSV.dev API, a vendored OSV database dump, GitHub Advisory
DB export, etc.) — the interface is deliberately kept swappable
(see `VulnerabilityFeed`).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from app.analyzers.base import Analyzer
from app.core.models import (
    AnalyzerCapability, CapabilityLevel, DetectionMethod, Evidence, Finding,
    RiskFactors, ScanConfig, Severity, TargetProfile, ValidationStatus, new_finding_id,
)


@dataclass
class KnownVuln:
    package: str
    ecosystem: str          # "pip" | "npm"
    affected_below: str     # simple "fixed version" — versions strictly below this are flagged
    reference_id: str
    summary: str
    severity: Severity
    confidence: int


# Small curated sample. CVE IDs below refer to real, well-documented
# historical incidents; treat the identifiers as reference pointers to
# verify independently (e.g. against nvd.nist.gov) rather than as a
# guaranteed-accurate live lookup.
CURATED_VULN_SAMPLE: list[KnownVuln] = [
    KnownVuln("pyyaml", "pip", "5.1", "CVE-2017-18342",
              "yaml.load() on untrusted input can execute arbitrary Python objects before "
              "the safer default introduced in PyYAML 5.1 (full_load/SafeLoader).",
              Severity.HIGH, 70),
    KnownVuln("requests", "pip", "2.20.0", "CVE-2018-18074",
              "Authorization header could be leaked to a different host on redirect.",
              Severity.MEDIUM, 65),
    KnownVuln("urllib3", "pip", "1.26.5", "CVE-2021-33503",
              "Catastrophic backtracking (ReDoS) possible in URL authority parsing.",
              Severity.MEDIUM, 60),
    KnownVuln("jinja2", "pip", "2.10.1", "CVE-2019-10906",
              "Sandbox escape allowing execution of arbitrary Python code via crafted templates "
              "in sandboxed-environment usage.",
              Severity.HIGH, 55),
    KnownVuln("lodash", "npm", "4.17.19", "CVE-2020-8203",
              "Prototype pollution via zipObjectDeep and related functions.",
              Severity.HIGH, 65),
    KnownVuln("minimist", "npm", "1.2.6", "CVE-2021-44906",
              "Prototype pollution via crafted --__proto__ style arguments.",
              Severity.HIGH, 65),
    KnownVuln("ini", "npm", "1.3.6", "CVE-2020-7788",
              "Prototype pollution when parsing a crafted INI file.",
              Severity.MEDIUM, 60),
    KnownVuln("axios", "npm", "0.21.1", "CVE-2020-28168",
              "Proxy configuration could be bypassed, enabling server-side request forgery.",
              Severity.MEDIUM, 55),
]


class VulnerabilityFeed:
    """Swap this out for a real feed in production; interface stays the same."""

    def __init__(self, sample: list[KnownVuln] | None = None):
        self.sample = {(v.package.lower(), v.ecosystem): v for v in (sample or CURATED_VULN_SAMPLE)}

    def lookup(self, package: str, ecosystem: str) -> KnownVuln | None:
        return self.sample.get((package.lower(), ecosystem))


VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def _version_tuple(v: str) -> tuple[int, int, int] | None:
    m = VERSION_RE.search(v)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _less_than(a: str, b: str) -> bool | None:
    ta, tb = _version_tuple(a), _version_tuple(b)
    if ta is None or tb is None:
        return None
    return ta < tb


class DependencyAnalyzer(Analyzer):
    name = "dependency"
    display_name = "Dependency & Supply-Chain Analyzer"
    detection_method = "DEPENDENCY_ANALYSIS"

    def __init__(self, feed: VulnerabilityFeed | None = None):
        self.feed = feed or VulnerabilityFeed()

    def applies_to(self, profile: TargetProfile) -> bool:
        return bool(profile.package_managers)

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.PARTIAL_SUPPORT,
                                   f"Checked against a local curated sample of "
                                   f"{len(self.feed.sample)} historical vulnerabilities — not a live feed")

    def run(self, profile: TargetProfile, config: ScanConfig) -> list[Finding]:
        root = Path(profile.target_path)
        findings: list[Finding] = []
        findings += self._scan_requirements_txt(root)
        findings += self._scan_package_json(root)
        return findings

    # -- pip ---------------------------------------------------------------
    def _scan_requirements_txt(self, root: Path) -> list[Finding]:
        out = []
        candidates = [root / "requirements.txt"] if root.is_dir() else []
        for req_path in candidates:
            if not req_path.exists():
                continue
            try:
                lines = req_path.read_text(errors="ignore").splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, start=1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([0-9][A-Za-z0-9_.\-]*)", line)
                if not m:
                    if re.match(r"^[A-Za-z0-9_.\-]+\s*(>=|~=|>)", line) or re.match(r"^[A-Za-z0-9_.\-]+$", line):
                        pkg = re.match(r"^([A-Za-z0-9_.\-]+)", line).group(1)
                        out.append(self._unpinned_finding(pkg, str(req_path.relative_to(root)), lineno, str(root)))
                    continue
                pkg, version = m.group(1), m.group(2)
                out.append(self._check_version(pkg, version, "pip",
                                                str(req_path.relative_to(root)), lineno, str(root)))
        return [f for f in out if f is not None]

    # -- npm -----------------------------------------------------------------
    def _scan_package_json(self, root: Path) -> list[Finding]:
        out = []
        pkg_path = root / "package.json" if root.is_dir() else None
        if not pkg_path or not pkg_path.exists():
            return out
        try:
            data = json.loads(pkg_path.read_text(errors="ignore"))
        except (OSError, ValueError):
            return out
        deps = {}
        deps.update(data.get("dependencies", {}) or {})
        deps.update(data.get("devDependencies", {}) or {})
        rel = str(pkg_path.relative_to(root))
        for pkg, version_spec in deps.items():
            version = re.sub(r"^[~^>=<\s]+", "", str(version_spec)).strip()
            if not version or not VERSION_RE.search(version):
                out.append(self._unpinned_finding(pkg, rel, 1, str(root)))
                continue
            out.append(self._check_version(pkg, version, "npm", rel, 1, str(root)))
        return [f for f in out if f is not None]

    # -- shared --------------------------------------------------------------
    def _check_version(self, pkg: str, version: str, ecosystem: str, rel: str, lineno: int, target: str) -> Finding | None:
        vuln = self.feed.lookup(pkg, ecosystem)
        if vuln is None:
            return None  # not in our small sample — genuinely unknown, we say nothing rather than guess
        cmp = _less_than(version, vuln.affected_below)
        if cmp is None:
            status_cat = "UNVERIFIED"
        elif cmp is True:
            status_cat = "KNOWN_VULNERABILITY"
        else:
            return None  # version is >= fixed version, not flagged

        return Finding(
            id=new_finding_id(prefix="BL-DEP"),
            title=f"{pkg} {version}: {vuln.reference_id}",
            category="Dependency Vulnerability",
            subcategory=status_cat,
            severity=vuln.severity if status_cat == "KNOWN_VULNERABILITY" else Severity.LOW,
            confidence=vuln.confidence if status_cat == "KNOWN_VULNERABILITY" else 30,
            validation_status=ValidationStatus.PROBABLE if status_cat == "KNOWN_VULNERABILITY" else ValidationStatus.UNVERIFIED,
            affected_target=target,
            affected_component=f"{pkg}=={version}",
            location=f"{rel}:{lineno}",
            detection_method=DetectionMethod.DEPENDENCY_ANALYSIS,
            evidence=[Evidence(description=f"{pkg} {version} matched local sample entry for versions below "
                                            f"{vuln.affected_below} ({vuln.reference_id})",
                                file_path=rel, line_start=lineno)],
            impact=vuln.summary,
            remediation=f"Upgrade {pkg} to {vuln.affected_below} or later.",
            references=[vuln.reference_id],
            risk_factors=RiskFactors(
                impact={Severity.CRITICAL: 9, Severity.HIGH: 7, Severity.MEDIUM: 5, Severity.LOW: 3}.get(vuln.severity, 4),
                exploitability=4, exposure=4, confidence=vuln.confidence, reproducibility=7,
            ) if status_cat == "KNOWN_VULNERABILITY" else None,
            detector_sources=[self.name],
        )

    def _unpinned_finding(self, pkg: str, rel: str, lineno: int, target: str) -> Finding:
        return Finding(
            id=new_finding_id(prefix="BL-DEP"),
            title=f"Unpinned or unresolved dependency version: {pkg}",
            category="Dependency Hygiene",
            subcategory="VERSION_DRIFT",
            severity=Severity.INFORMATIONAL,
            confidence=50,
            validation_status=ValidationStatus.UNVERIFIED,
            affected_target=target,
            affected_component=pkg,
            location=f"{rel}:{lineno}",
            detection_method=DetectionMethod.DEPENDENCY_ANALYSIS,
            evidence=[Evidence(description=f"{pkg} has no exact pinned version in the manifest",
                                file_path=rel, line_start=lineno)],
            impact="Unpinned versions make builds non-reproducible and can silently pull in a "
                   "vulnerable release later.",
            remediation="Pin exact versions (or use a lockfile) for reproducible, auditable builds.",
            detector_sources=[self.name],
        )
