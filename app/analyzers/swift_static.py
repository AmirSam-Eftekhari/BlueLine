"""
Swift static analyzer. Same honesty stance as the others: line/regex
matching, not a real parser (no SwiftSyntax tooling available in this
sandbox). Declared PARTIAL_SUPPORT.
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

RULES = [
    dict(id="SWIFT-PROCESS-EXEC", pattern=re.compile(r"\bProcess\s*\(\s*\)|\bNSTask\s*\("),
         title="Process()/NSTask usage", category="Injection", subcategory="Command Injection",
         severity=Severity.MEDIUM, confidence=50,
         impact="Spawns an external process; injection risk if the executable path or arguments "
                "incorporate external input.",
         remediation="Validate/allow-list the executable path and arguments; avoid building them "
                     "from unvalidated external input.",
         risk=RiskFactors(impact=7, exploitability=5, exposure=5, confidence=50, reproducibility=6)),
    dict(id="SWIFT-WEAK-HASH", pattern=re.compile(r"\bCC_MD5\s*\(|\bInsecure\.MD5\b|\bCC_SHA1\s*\("),
         title="Weak cryptographic hash (MD5/SHA-1)", category="Cryptography", subcategory="Weak Hash",
         severity=Severity.LOW, confidence=70,
         impact="MD5/SHA-1 are broken for collision resistance; unsuitable for passwords or "
                "integrity-critical use.",
         remediation="Use SHA256 (CryptoKit) for integrity, and a dedicated password hash for credentials.",
         risk=RiskFactors(impact=4, exploitability=3, exposure=3, confidence=70, reproducibility=8)),
    dict(id="SWIFT-SQL-INTERP",
         pattern=re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\b.{0,120}\\\(', re.IGNORECASE),
         title="SQL query built with string interpolation", category="Injection", subcategory="SQL Injection",
         severity=Severity.HIGH, confidence=58,
         impact="Interpolating values directly into SQL via Swift string interpolation (\\()) is "
                "vulnerable to SQL injection.",
         remediation="Use parameterized queries (SQLite bind parameters, Core Data predicates) "
                     "instead of string interpolation.",
         risk=RiskFactors(impact=9, exploitability=6, exposure=6, confidence=58, reproducibility=5)),
    dict(id="SWIFT-HARDCODED-SECRET",
         pattern=re.compile(r'(?i)(let|var)\s+\w*(password|secret|api[_-]?key|token)\w*\s*[:=].{0,20}"[A-Za-z0-9_\-/+=]{6,}"'),
         title="Hardcoded credential-shaped string literal", category="Credential Management",
         subcategory="Hardcoded Secret", severity=Severity.HIGH, confidence=55,
         impact="Secrets embedded in source are exposed to anyone with source/IPA access.",
         remediation="Move to the Keychain or a secrets manager, not a source-code literal; "
                     "rotate the exposed credential.",
         risk=RiskFactors(impact=8, exploitability=3, exposure=3, confidence=55, reproducibility=9)),
    dict(id="SWIFT-USERDEFAULTS-SECRET",
         pattern=re.compile(r"UserDefaults\.standard\.set\([^)]*\b(password|token|secret)\b", re.IGNORECASE),
         title="Credential-shaped value stored in UserDefaults", category="Credential Management",
         subcategory="Insecure Local Storage", severity=Severity.MEDIUM, confidence=55,
         impact="UserDefaults is plist-backed and unencrypted; not an appropriate place for "
                "passwords, tokens, or other secrets.",
         remediation="Store credentials in the Keychain, not UserDefaults.",
         risk=RiskFactors(impact=6, exploitability=3, exposure=4, confidence=55, reproducibility=8)),
    dict(id="SWIFT-FORCE-UNWRAP-EXTERNAL",
         pattern=re.compile(r"(readLine\(\)|try\?\s+\w+\([^)]*\))\s*!"),
         title="Force-unwrap used directly on external/fallible input", category="Error Handling",
         subcategory="Panic-based DoS", severity=Severity.LOW, confidence=35,
         impact="A forced unwrap (!) crashes the process immediately if the value is nil — if the "
                "source is external (stdin, network, try?), a crafted/missing input can crash the app.",
         remediation="Handle the nil case explicitly (if let, guard let, or a default value) "
                     "instead of ! on anything derived from external input.",
         risk=RiskFactors(impact=4, exploitability=4, exposure=4, confidence=35, reproducibility=7)),
]

COMMENT_LINE = re.compile(r"^\s*(//|\*|/\*)")


class SwiftStaticAnalyzer(Analyzer):
    name = "swift_static"
    display_name = "Swift Static Analyzer"
    detection_method = "STATIC_ANALYSIS"

    def applies_to(self, profile: TargetProfile) -> bool:
        return "Swift" in profile.languages

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.PARTIAL_SUPPORT,
                                   "Heuristic/regex-based — no real parser (no SwiftSyntax tooling "
                                   "available in this build environment)")

    def run(self, profile: TargetProfile, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        root = Path(profile.target_path)
        for fpath in self._collect_files(root, config):
            try:
                text = fpath.read_text(errors="ignore")
                if len(text.encode("utf-8", "ignore")) > config.max_file_size_bytes:
                    continue
            except OSError:
                continue
            rel = str(fpath.relative_to(root)) if root.is_dir() else fpath.name

            for i, line in enumerate(text.splitlines(), start=1):
                if COMMENT_LINE.match(line):
                    continue
                for rule in RULES:
                    if rule["pattern"].search(line):
                        findings.append(Finding(
                            id=new_finding_id(),
                            title=rule["title"], category=rule["category"], subcategory=rule["subcategory"],
                            severity=rule["severity"], confidence=rule["confidence"],
                            validation_status=ValidationStatus.SUSPECTED,
                            affected_target=str(root), affected_component=rel, location=f"{rel}:{i}",
                            detection_method=DetectionMethod.STATIC_ANALYSIS,
                            evidence=[Evidence(description=f"Pattern {rule['id']} matched",
                                                snippet=line.strip(), file_path=rel, line_start=i)],
                            impact=rule["impact"], remediation=rule["remediation"],
                            risk_factors=rule["risk"], detector_sources=[self.name],
                        ))
        return findings

    @staticmethod
    def _collect_files(root: Path, config: ScanConfig) -> list[Path]:
        import fnmatch
        if root.is_file():
            return [root] if root.suffix == ".swift" else []
        out = []
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            if any(fnmatch.fnmatch(dirpath, pat) or fnmatch.fnmatch(rel_dir, pat) for pat in config.exclude_globs):
                dirnames[:] = []
                continue
            for fn in filenames:
                if fn.endswith(".swift"):
                    out.append(Path(dirpath) / fn)
        return out
