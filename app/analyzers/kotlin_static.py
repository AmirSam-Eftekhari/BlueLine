"""
Kotlin static analyzer. Same honesty stance as the other pattern-based
analyzers: line/regex matching, not a real parser (no kotlinc/PSI
tooling available in this sandbox). Declared PARTIAL_SUPPORT.

Kotlin runs on the JVM and shares several risk classes with Java
(ObjectInputStream deserialization, MessageDigest/Cipher weak crypto,
Runtime.exec), plus a few idioms of its own (string templates for SQL,
!! force-unwrap as a panic-based DoS vector analogous to Rust's
unwrap()/PHP's issues).
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
    dict(id="KT-RUNTIME-EXEC", pattern=re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\("),
         title="Runtime.exec()/ProcessBuilder usage", category="Injection", subcategory="Command Injection",
         severity=Severity.HIGH, confidence=65,
         impact="Invokes an external process; injection risk if any argument incorporates "
                "external input, and a single-string exec() form is shell-interpreted on some platforms.",
         remediation="Use ProcessBuilder with an explicit argument list, and validate/allow-list inputs.",
         risk=RiskFactors(impact=8, exploitability=6, exposure=5, confidence=65, reproducibility=6)),
    dict(id="KT-OBJ-DESERIALIZE", pattern=re.compile(r"new\s+ObjectInputStream\s*\(|ObjectInputStream\s*\("),
         title="Java native deserialization (ObjectInputStream)", category="Insecure Deserialization",
         subcategory="Java Deserialization", severity=Severity.HIGH, confidence=68,
         impact="Deserializing untrusted data with ObjectInputStream is a well-known JVM RCE vector "
                "via gadget chains in classpath libraries.",
         remediation="Avoid native Java/Kotlin deserialization for untrusted data; use JSON with a "
                     "schema (kotlinx.serialization) instead.",
         risk=RiskFactors(impact=9, exploitability=5, exposure=4, confidence=68, reproducibility=5)),
    dict(id="KT-WEAK-HASH", pattern=re.compile(r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1)"', re.IGNORECASE),
         title="Weak cryptographic hash (MD5/SHA-1)", category="Cryptography", subcategory="Weak Hash",
         severity=Severity.LOW, confidence=70,
         impact="MD5/SHA-1 are broken for collision resistance; unsuitable for passwords or "
                "integrity-critical use.",
         remediation="Use SHA-256+ for integrity, and a dedicated password hash (bcrypt/Argon2) "
                     "for credentials.",
         risk=RiskFactors(impact=4, exploitability=3, exposure=3, confidence=70, reproducibility=8)),
    dict(id="KT-WEAK-CIPHER", pattern=re.compile(r'Cipher\.getInstance\s*\(\s*"(DES|RC4|AES/ECB)'),
         title="Weak or insecure cipher configuration", category="Cryptography", subcategory="Weak Cipher",
         severity=Severity.HIGH, confidence=72,
         impact="DES/RC4 are broken, and AES in ECB mode leaks structural patterns in the plaintext.",
         remediation="Use AES-256/GCM (authenticated encryption) instead.",
         risk=RiskFactors(impact=7, exploitability=4, exposure=4, confidence=72, reproducibility=8)),
    dict(id="KT-SQL-TEMPLATE",
         pattern=re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\b.{0,120}\$\{?\w', re.IGNORECASE),
         title="SQL query built with string template interpolation", category="Injection",
         subcategory="SQL Injection", severity=Severity.HIGH, confidence=55,
         impact="Interpolating values directly into SQL via Kotlin string templates is vulnerable "
                "to SQL injection.",
         remediation="Use parameterized queries (PreparedStatement, Exposed, or Room bound "
                     "parameters) instead of string templates.",
         risk=RiskFactors(impact=9, exploitability=6, exposure=6, confidence=55, reproducibility=5)),
    dict(id="KT-HARDCODED-SECRET",
         pattern=re.compile(r'(?i)(val|var)\s+\w*(password|secret|api[_-]?key|token)\w*\s*[:=].{0,20}"[A-Za-z0-9_\-/+=]{6,}"'),
         title="Hardcoded credential-shaped string literal", category="Credential Management",
         subcategory="Hardcoded Secret", severity=Severity.HIGH, confidence=55,
         impact="Secrets embedded in source are exposed to anyone with source/APK access.",
         remediation="Move to environment variables, a secrets manager, or Android's EncryptedSharedPreferences; "
                     "rotate the exposed credential.",
         risk=RiskFactors(impact=8, exploitability=3, exposure=3, confidence=55, reproducibility=9)),
    dict(id="KT-FORCE-UNWRAP-EXTERNAL",
         pattern=re.compile(r"(readLine\(\)|intent\.getStringExtra\([^)]*\)|args\[\d+\])\s*!!"),
         title="!! force-unwrap used directly on external input", category="Error Handling",
         subcategory="Panic-based DoS", severity=Severity.LOW, confidence=40,
         impact="!! throws a KotlinNullPointerException immediately if the value is null — if the "
                "source is external (stdin, Intent extras, CLI args), a crafted/missing input can "
                "crash the app.",
         remediation="Handle the null case explicitly (?:, requireNotNull with a message, or an "
                     "early return) instead of !! on anything derived from external input.",
         risk=RiskFactors(impact=4, exploitability=4, exposure=4, confidence=40, reproducibility=7)),
    dict(id="KT-INSECURE-RANDOM", pattern=re.compile(r"\bjava\.util\.Random\s*\(|\bRandom\s*\(\s*\)"),
         title="java.util.Random used (not cryptographically secure)", category="Cryptography",
         subcategory="Weak Randomness", severity=Severity.LOW, confidence=40,
         impact="java.util.Random/kotlin.random.Random default instances are predictable and "
                "unsuitable for tokens, session IDs, or password resets.",
         remediation="Use java.security.SecureRandom for anything security-relevant.",
         risk=RiskFactors(impact=5, exploitability=3, exposure=3, confidence=40, reproducibility=7)),
]

COMMENT_LINE = re.compile(r"^\s*(//|\*|/\*)")


class KotlinStaticAnalyzer(Analyzer):
    name = "kotlin_static"
    display_name = "Kotlin Static Analyzer"
    detection_method = "STATIC_ANALYSIS"

    def applies_to(self, profile: TargetProfile) -> bool:
        return "Kotlin" in profile.languages

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.PARTIAL_SUPPORT,
                                   "Heuristic/regex-based — no real parser (no kotlinc/PSI tooling "
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
        exts = (".kt", ".kts")
        if root.is_file():
            return [root] if root.suffix in exts else []
        out = []
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            if any(fnmatch.fnmatch(dirpath, pat) or fnmatch.fnmatch(rel_dir, pat) for pat in config.exclude_globs):
                dirnames[:] = []
                continue
            for fn in filenames:
                if fn.endswith(exts):
                    out.append(Path(dirpath) / fn)
        return out
