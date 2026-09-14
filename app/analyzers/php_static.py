"""
PHP static analyzer. Same honesty stance as the others: pattern-based,
not a real parser (no php-parser/nikic AST tooling available in this
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
    dict(id="PHP-EVAL", pattern=re.compile(r"\beval\s*\("), title="Use of eval()",
         category="Injection", subcategory="Code Injection", severity=Severity.HIGH, confidence=75,
         impact="eval() executes arbitrary strings as PHP code; dangerous if any input reaches it.",
         remediation="Avoid eval(). Use an explicit parser/dispatch table for data-driven behavior.",
         risk=RiskFactors(impact=8, exploitability=6, exposure=5, confidence=75, reproducibility=6)),
    dict(id="PHP-SHELL-EXEC",
         pattern=re.compile(r"\b(exec|shell_exec|system|passthru|popen|proc_open)\s*\("),
         title="Shell command execution function used", category="Injection", subcategory="Command Injection",
         severity=Severity.HIGH, confidence=60,
         impact="These functions invoke a shell; injection risk if any argument includes external input.",
         remediation="Avoid shell functions for untrusted input; if unavoidable, use escapeshellarg() "
                     "on every argument.",
         risk=RiskFactors(impact=8, exploitability=6, exposure=5, confidence=60, reproducibility=6)),
    dict(id="PHP-UNSERIALIZE", pattern=re.compile(r"\bunserialize\s*\("),
         title="Unsafe deserialization via unserialize()", category="Insecure Deserialization",
         subcategory="PHP Object Injection", severity=Severity.HIGH, confidence=75,
         impact="unserialize() on untrusted data is a well-known PHP Object Injection vector, "
                "potentially leading to remote code execution via gadget chains (magic methods).",
         remediation="Use json_decode() instead of unserialize() for untrusted data; if PHP "
                     "serialization is required, pass allowed_classes => false.",
         risk=RiskFactors(impact=9, exploitability=6, exposure=5, confidence=75, reproducibility=5)),
    dict(id="PHP-LFI-INCLUDE",
         pattern=re.compile(r"\b(include|include_once|require|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"),
         title="File inclusion driven directly by request input", category="Path Traversal",
         subcategory="Local/Remote File Inclusion", severity=Severity.CRITICAL, confidence=88,
         impact="Including a file path taken directly from request input allows local/remote file "
                "inclusion, often leading to remote code execution.",
         remediation="Never pass request input directly to include/require; map to an allow-listed "
                     "set of files instead.",
         risk=RiskFactors(impact=10, exploitability=8, exposure=7, confidence=88, reproducibility=8)),
    dict(id="PHP-EXTRACT-REQUEST", pattern=re.compile(r"\bextract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"),
         title="extract() called on request superglobal", category="Injection",
         subcategory="Variable Injection", severity=Severity.HIGH, confidence=80,
         impact="extract() on request data lets an attacker define or overwrite arbitrary local "
                "variables, potentially bypassing security checks elsewhere in the function.",
         remediation="Never extract() request superglobals directly; access needed keys explicitly.",
         risk=RiskFactors(impact=8, exploitability=6, exposure=6, confidence=80, reproducibility=7)),
    dict(id="PHP-SQL-CONCAT",
         pattern=re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\b.{0,120}\$_(GET|POST|REQUEST|COOKIE)', re.IGNORECASE),
         title="SQL query built directly from request input", category="Injection", subcategory="SQL Injection",
         severity=Severity.CRITICAL, confidence=75,
         impact="Building SQL directly from $_GET/$_POST/etc. is a classic, highly exploitable "
                "SQL injection vector.",
         remediation="Use prepared statements (PDO/mysqli) with bound parameters instead of "
                     "concatenating request input into SQL.",
         risk=RiskFactors(impact=10, exploitability=8, exposure=7, confidence=75, reproducibility=6)),
    dict(id="PHP-WEAK-HASH", pattern=re.compile(r"\b(md5|sha1)\s*\(\s*\$_(GET|POST|REQUEST)|password.{0,20}(md5|sha1)\s*\(", re.IGNORECASE),
         title="Weak hash used for password-shaped value", category="Cryptography", subcategory="Weak Hash",
         severity=Severity.MEDIUM, confidence=45,
         impact="MD5/SHA1 are unsuitable for password hashing (fast to brute-force, no built-in salt).",
         remediation="Use password_hash() (bcrypt/Argon2) and password_verify() instead.",
         risk=RiskFactors(impact=6, exploitability=4, exposure=4, confidence=45, reproducibility=7)),
    dict(id="PHP-HARDCODED-SECRET",
         pattern=re.compile(r'(?i)(password|secret|api[_-]?key|token)\s*=\s*["\'][A-Za-z0-9_\-/+=]{6,}["\']'),
         title="Hardcoded credential-shaped string literal", category="Credential Management",
         subcategory="Hardcoded Secret", severity=Severity.HIGH, confidence=55,
         impact="Secrets embedded in source are exposed to anyone with source access.",
         remediation="Move to environment variables (getenv()) or a secrets manager; rotate the secret.",
         risk=RiskFactors(impact=8, exploitability=3, exposure=3, confidence=55, reproducibility=9)),
    dict(id="PHP-INSECURE-RANDOM", pattern=re.compile(r"\b(mt_rand|rand)\s*\("),
         title="mt_rand()/rand() used (not cryptographically secure)", category="Cryptography",
         subcategory="Weak Randomness", severity=Severity.LOW, confidence=30,
         impact="mt_rand()/rand() are not suitable for tokens, session IDs, or password resets.",
         remediation="Use random_bytes()/random_int() for anything security-relevant.",
         risk=RiskFactors(impact=5, exploitability=3, exposure=3, confidence=30, reproducibility=7)),
]

COMMENT_LINE = re.compile(r"^\s*(//|#|\*)")


class PhpStaticAnalyzer(Analyzer):
    name = "php_static"
    display_name = "PHP Static Analyzer"
    detection_method = "STATIC_ANALYSIS"

    def applies_to(self, profile: TargetProfile) -> bool:
        return "PHP" in profile.languages

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.PARTIAL_SUPPORT,
                                   "Heuristic/regex-based — no real parser (no php-parser/AST tooling "
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
            return [root] if root.suffix == ".php" else []
        out = []
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            if any(fnmatch.fnmatch(dirpath, pat) or fnmatch.fnmatch(rel_dir, pat) for pat in config.exclude_globs):
                dirnames[:] = []
                continue
            for fn in filenames:
                if fn.endswith(".php"):
                    out.append(Path(dirpath) / fn)
        return out
