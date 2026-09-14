"""
Go static analyzer.

Same honesty stance as JS/Java: pattern-based, not a real parser (no
network route to install go/ast tooling or gosec in this sandbox).
Declared PARTIAL_SUPPORT.
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
    dict(id="GO-EXEC-COMMAND-SHELL", pattern=re.compile(r'exec\.Command\s*\(\s*"(sh|bash|cmd|cmd\.exe)"'),
         title="exec.Command invoking a shell directly", category="Injection", subcategory="Command Injection",
         severity=Severity.HIGH, confidence=68,
         impact="Explicitly invoking a shell reintroduces shell-metacharacter injection risk if any "
                "argument includes external input.",
         remediation="Invoke the target binary directly with an argument list instead of going through a shell.",
         risk=RiskFactors(impact=8, exploitability=6, exposure=5, confidence=68, reproducibility=6)),
    dict(id="GO-EXEC-COMMAND-CONCAT", pattern=re.compile(r'exec\.Command\s*\([^)]*\+'),
         title="exec.Command() built with string concatenation", category="Injection",
         subcategory="Command Injection", severity=Severity.MEDIUM, confidence=55,
         impact="Building a command or its arguments via concatenation raises injection risk if the "
                "concatenated value includes external input.",
         remediation="Pass arguments as separate exec.Command(name, arg1, arg2, ...) elements, never "
                     "concatenated into one string.",
         risk=RiskFactors(impact=7, exploitability=5, exposure=5, confidence=55, reproducibility=5)),
    dict(id="GO-INSECURE-SKIP-VERIFY", pattern=re.compile(r"InsecureSkipVerify\s*:\s*true"),
         title="TLS certificate validation disabled (InsecureSkipVerify)", category="Cryptography",
         subcategory="TLS Misconfiguration", severity=Severity.HIGH, confidence=90,
         impact="InsecureSkipVerify: true disables TLS certificate validation entirely, allowing "
                "man-in-the-middle attacks.",
         remediation="Remove InsecureSkipVerify; fix the underlying certificate/trust issue instead.",
         risk=RiskFactors(impact=8, exploitability=5, exposure=5, confidence=90, reproducibility=9)),
    dict(id="GO-WEAK-HASH", pattern=re.compile(r'crypto/(md5|sha1)"'),
         title="Weak cryptographic hash package imported (md5/sha1)", category="Cryptography",
         subcategory="Weak Hash", severity=Severity.LOW, confidence=45,
         impact="MD5/SHA-1 are broken for collision resistance; unsuitable for passwords or "
                "integrity-critical use. (Import alone doesn't confirm security-relevant usage.)",
         remediation="Use crypto/sha256 or stronger for integrity; use bcrypt/scrypt/Argon2 for "
                     "password hashing.",
         risk=RiskFactors(impact=4, exploitability=2, exposure=3, confidence=45, reproducibility=8)),
    dict(id="GO-INSECURE-RANDOM", pattern=re.compile(r'"math/rand"'),
         title='"math/rand" imported (not cryptographically secure)', category="Cryptography",
         subcategory="Weak Randomness", severity=Severity.LOW, confidence=35,
         impact="math/rand is predictable and unsuitable for tokens, session IDs, or password resets. "
                "(Import alone doesn't confirm security-relevant usage.)",
         remediation="Use crypto/rand for anything security-relevant.",
         risk=RiskFactors(impact=5, exploitability=3, exposure=3, confidence=35, reproducibility=8)),
    dict(id="GO-SQL-CONCAT",
         pattern=re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\b.{0,120}"\s*\+|"\s*\+.{0,60}(SELECT|INSERT|UPDATE|DELETE)\b',
                             re.IGNORECASE),
         title="String-concatenated SQL query", category="Injection", subcategory="SQL Injection",
         severity=Severity.HIGH, confidence=55,
         impact="SQL built via string concatenation is vulnerable to SQL injection if any part "
                "includes external input.",
         remediation="Use database/sql with parameterized queries ($1/?  placeholders) instead of "
                     "string concatenation.",
         risk=RiskFactors(impact=9, exploitability=6, exposure=6, confidence=55, reproducibility=5)),
    dict(id="GO-HARDCODED-SECRET",
         pattern=re.compile(r'(?i)(password|secret|api[_-]?key|token)\s*:?=\s*"[A-Za-z0-9_\-/+=]{6,}"'),
         title="Hardcoded credential-shaped string literal", category="Credential Management",
         subcategory="Hardcoded Secret", severity=Severity.HIGH, confidence=55,
         impact="Secrets embedded in source are exposed to anyone with source access.",
         remediation="Move to environment variables or a secrets manager; rotate the exposed credential.",
         risk=RiskFactors(impact=8, exploitability=3, exposure=3, confidence=55, reproducibility=9)),
    dict(id="GO-UNHANDLED-ERROR", pattern=re.compile(r"^\s*_\s*=\s*\w+\.(Close|Write|Remove)\s*\("),
         title="Error from a security-relevant call explicitly discarded", category="Error Handling",
         subcategory="Silent Failure", severity=Severity.LOW, confidence=30,
         impact="Discarding errors from file/resource operations can silently mask failures relevant "
                "to security or data integrity.",
         remediation="Check and handle (or explicitly log) the error instead of discarding it with `_ =`.",
         risk=RiskFactors(impact=3, exploitability=1, exposure=2, confidence=30, reproducibility=9)),
]

COMMENT_LINE = re.compile(r"^\s*//")


class GoStaticAnalyzer(Analyzer):
    name = "go_static"
    display_name = "Go Static Analyzer"
    detection_method = "STATIC_ANALYSIS"

    def applies_to(self, profile: TargetProfile) -> bool:
        return "Go" in profile.languages

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.PARTIAL_SUPPORT,
                                   "Heuristic/regex-based — no real parser (no go/ast or gosec available "
                                   "in this build environment)")

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
            return [root] if root.suffix == ".go" else []
        out = []
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            if any(fnmatch.fnmatch(dirpath, pat) or fnmatch.fnmatch(rel_dir, pat) for pat in config.exclude_globs):
                dirnames[:] = []
                continue
            for fn in filenames:
                if fn.endswith(".go"):
                    out.append(Path(dirpath) / fn)
        return out
