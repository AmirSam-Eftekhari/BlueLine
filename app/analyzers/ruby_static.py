"""
Ruby static analyzer. Same honesty stance as JS/Java/Go: pattern-based,
not a real parser (no Ripper/parser gem available — no network route to
RubyGems in this sandbox). Declared PARTIAL_SUPPORT.
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
    dict(id="RB-EVAL", pattern=re.compile(r"\beval\s*\("), title="Use of eval()",
         category="Injection", subcategory="Code Injection", severity=Severity.HIGH, confidence=75,
         impact="eval() executes arbitrary strings as Ruby code; dangerous if any input reaches it.",
         remediation="Avoid eval(). Use an explicit parser/dispatch table for data-driven behavior.",
         risk=RiskFactors(impact=8, exploitability=6, exposure=5, confidence=75, reproducibility=6)),
    dict(id="RB-SYSTEM-EXEC",
         pattern=re.compile(r"\bsystem\s*\(|`[^`]*#\{|%x\{|Kernel\.exec\s*\(|IO\.popen\s*\("),
         title="Shell command execution with possible interpolation", category="Injection",
         subcategory="Command Injection", severity=Severity.HIGH, confidence=60,
         impact="system()/backticks/IO.popen invoke a shell; injection risk if any interpolated "
                "value includes external input.",
         remediation="Use Process.spawn / IO.popen with an argument array (not a single interpolated "
                     "string) to avoid shell interpretation.",
         risk=RiskFactors(impact=8, exploitability=6, exposure=5, confidence=60, reproducibility=6)),
    dict(id="RB-MARSHAL-LOAD", pattern=re.compile(r"Marshal\.load\s*\("),
         title="Unsafe deserialization via Marshal.load", category="Insecure Deserialization",
         subcategory="Marshal", severity=Severity.HIGH, confidence=80,
         impact="Marshal.load on untrusted data can instantiate arbitrary objects and lead to "
                "remote code execution via gadget chains.",
         remediation="Never Marshal.load data from an untrusted source; use JSON with a schema instead.",
         risk=RiskFactors(impact=9, exploitability=5, exposure=4, confidence=80, reproducibility=5)),
    dict(id="RB-YAML-UNSAFE", pattern=re.compile(r"YAML\.load\s*\((?!.*safe)"),
         title="YAML.load() without safe_load", category="Insecure Deserialization", subcategory="YAML",
         severity=Severity.MEDIUM, confidence=65,
         impact="YAML.load on untrusted input can instantiate arbitrary Ruby objects.",
         remediation="Use YAML.safe_load instead of YAML.load for untrusted input.",
         risk=RiskFactors(impact=7, exploitability=4, exposure=4, confidence=65, reproducibility=5)),
    dict(id="RB-WEAK-HASH", pattern=re.compile(r"Digest::(MD5|SHA1)\b"),
         title="Weak cryptographic hash (MD5/SHA1)", category="Cryptography", subcategory="Weak Hash",
         severity=Severity.LOW, confidence=65,
         impact="MD5/SHA1 are broken for collision resistance; unsuitable for passwords or "
                "integrity-critical use.",
         remediation="Use Digest::SHA256+ for integrity; use bcrypt for password hashing.",
         risk=RiskFactors(impact=4, exploitability=3, exposure=3, confidence=65, reproducibility=8)),
    dict(id="RB-SQL-INTERP",
         pattern=re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\b.{0,120}#\{', re.IGNORECASE),
         title="SQL query built with string interpolation", category="Injection", subcategory="SQL Injection",
         severity=Severity.HIGH, confidence=60,
         impact="Interpolating values directly into SQL is vulnerable to SQL injection.",
         remediation="Use parameterized queries (ActiveRecord where(\"col = ?\", val) or bound "
                     "placeholders) instead of string interpolation.",
         risk=RiskFactors(impact=9, exploitability=6, exposure=6, confidence=60, reproducibility=5)),
    dict(id="RB-HARDCODED-SECRET",
         pattern=re.compile(r'(?i)(password|secret|api[_-]?key|token)\s*=\s*["\'][A-Za-z0-9_\-/+=]{6,}["\']'),
         title="Hardcoded credential-shaped string literal", category="Credential Management",
         subcategory="Hardcoded Secret", severity=Severity.HIGH, confidence=55,
         impact="Secrets embedded in source are exposed to anyone with source access.",
         remediation="Move to environment variables or Rails encrypted credentials; rotate the secret.",
         risk=RiskFactors(impact=8, exploitability=3, exposure=3, confidence=55, reproducibility=9)),
    dict(id="RB-DYNAMIC-SEND", pattern=re.compile(r"\.send\s*\(\s*params"),
         title="Dynamic method dispatch driven by request params", category="Injection",
         subcategory="Insecure Metaprogramming", severity=Severity.HIGH, confidence=55,
         impact="Calling .send with a method name derived from user input can invoke unintended "
                "methods (mass-assignment/metaprogramming injection).",
         remediation="Allow-list the specific methods that may be called instead of dispatching "
                     "directly from request parameters.",
         risk=RiskFactors(impact=7, exploitability=5, exposure=5, confidence=55, reproducibility=5)),
    dict(id="RB-INSECURE-RANDOM", pattern=re.compile(r"\bRandom\.rand\s*\(|\brand\s*\("),
         title="rand()/Random used (not cryptographically secure)", category="Cryptography",
         subcategory="Weak Randomness", severity=Severity.LOW, confidence=30,
         impact="Ruby's rand() is not suitable for tokens, session IDs, or password resets.",
         remediation="Use SecureRandom (e.g. SecureRandom.hex) for anything security-relevant.",
         risk=RiskFactors(impact=5, exploitability=3, exposure=3, confidence=30, reproducibility=7)),
]

COMMENT_LINE = re.compile(r"^\s*#")


class RubyStaticAnalyzer(Analyzer):
    name = "ruby_static"
    display_name = "Ruby Static Analyzer"
    detection_method = "STATIC_ANALYSIS"

    def applies_to(self, profile: TargetProfile) -> bool:
        return "Ruby" in profile.languages

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.PARTIAL_SUPPORT,
                                   "Heuristic/regex-based — no real parser (no Ripper/parser gem "
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
            return [root] if root.suffix == ".rb" else []
        out = []
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            if any(fnmatch.fnmatch(dirpath, pat) or fnmatch.fnmatch(rel_dir, pat) for pat in config.exclude_globs):
                dirnames[:] = []
                continue
            for fn in filenames:
                if fn.endswith(".rb"):
                    out.append(Path(dirpath) / fn)
        return out
