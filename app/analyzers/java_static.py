"""
Java static analyzer.

Same honesty stance as the JS analyzer: this is pattern/line-based, not a
real parser (javalang/JavaParser were not installable in this sandbox —
no network route to Maven Central or a Java toolchain). Declared
PARTIAL_SUPPORT everywhere. Genuinely catches a real, common set of
Java-specific security anti-patterns.
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
    dict(id="JAVA-RUNTIME-EXEC", pattern=re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\("),
         title="Runtime.exec() usage", category="Injection", subcategory="Command Injection",
         severity=Severity.HIGH, confidence=70,
         impact="Runtime.exec() invokes an external process; injection risk if any argument "
                "incorporates external input, and a single-string form is shell-interpreted on some platforms.",
         remediation="Use ProcessBuilder with an explicit argument list, and validate/allow-list inputs.",
         risk=RiskFactors(impact=8, exploitability=6, exposure=5, confidence=70, reproducibility=6)),
    dict(id="JAVA-PROCESSBUILDER-SHELL", pattern=re.compile(r'ProcessBuilder\s*\(\s*"(/bin/sh|sh|cmd\.exe|cmd)"'),
         title="ProcessBuilder invoking a shell directly", category="Injection", subcategory="Command Injection",
         severity=Severity.HIGH, confidence=65,
         impact="Explicitly invoking a shell reintroduces shell-metacharacter injection risk.",
         remediation="Invoke the target binary directly with an argument list instead of going through a shell.",
         risk=RiskFactors(impact=8, exploitability=6, exposure=5, confidence=65, reproducibility=6)),
    dict(id="JAVA-OBJ-DESERIALIZE", pattern=re.compile(r"new\s+ObjectInputStream\s*\("),
         title="Java native deserialization (ObjectInputStream)", category="Insecure Deserialization",
         subcategory="Java Deserialization", severity=Severity.HIGH, confidence=68,
         impact="Deserializing untrusted data with ObjectInputStream is a well-known Java RCE vector "
                "via gadget chains in classpath libraries.",
         remediation="Avoid native Java deserialization for untrusted data; use JSON with a schema, "
                     "or a look-ahead deserialization filter (ObjectInputFilter) if it must be used.",
         risk=RiskFactors(impact=9, exploitability=5, exposure=4, confidence=68, reproducibility=5)),
    dict(id="JAVA-XXE", pattern=re.compile(r"DocumentBuilderFactory\.newInstance\s*\(\s*\)"),
         title="XML parser created without disabling external entities", category="XML External Entity",
         subcategory="XXE", severity=Severity.MEDIUM, confidence=45,
         impact="DocumentBuilderFactory is vulnerable to XXE by default unless external entity "
                "processing is explicitly disabled.",
         remediation="Call setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) "
                     "(or the equivalent) before parsing untrusted XML.",
         risk=RiskFactors(impact=6, exploitability=4, exposure=4, confidence=45, reproducibility=6)),
    dict(id="JAVA-WEAK-HASH", pattern=re.compile(r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1)"', re.IGNORECASE),
         title="Weak cryptographic hash (MD5/SHA-1)", category="Cryptography", subcategory="Weak Hash",
         severity=Severity.LOW, confidence=70,
         impact="MD5/SHA-1 are broken for collision resistance; unsuitable for passwords or "
                "integrity-critical use.",
         remediation="Use SHA-256+ for integrity, and a dedicated password hash (bcrypt/scrypt/Argon2) "
                     "for credentials.",
         risk=RiskFactors(impact=4, exploitability=3, exposure=3, confidence=70, reproducibility=8)),
    dict(id="JAVA-WEAK-CIPHER", pattern=re.compile(r'Cipher\.getInstance\s*\(\s*"(DES|RC4|AES/ECB)'),
         title="Weak or insecure cipher configuration", category="Cryptography", subcategory="Weak Cipher",
         severity=Severity.HIGH, confidence=72,
         impact="DES/RC4 are broken, and AES in ECB mode leaks structural patterns in the plaintext.",
         remediation="Use AES-256/GCM (authenticated encryption) instead.",
         risk=RiskFactors(impact=7, exploitability=4, exposure=4, confidence=72, reproducibility=8)),
    dict(id="JAVA-CUSTOM-TRUST-MANAGER", pattern=re.compile(r"\bcheckServerTrusted\s*\("),
         title="Custom TrustManager overrides checkServerTrusted", category="Cryptography",
         subcategory="TLS Misconfiguration", severity=Severity.MEDIUM, confidence=35,
         impact="Custom TrustManager implementations are a common place to accidentally (or "
                "deliberately, for testing) disable certificate validation entirely. This alone "
                "doesn't confirm that — verify the method body actually validates the chain.",
         remediation="Ensure checkServerTrusted performs real chain/hostname validation, or use the "
                     "platform default TrustManager instead of a custom one.",
         risk=RiskFactors(impact=7, exploitability=4, exposure=4, confidence=35, reproducibility=6)),
    dict(id="JAVA-SQL-CONCAT",
         pattern=re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\b.{0,120}"\s*\+|"\s*\+.{0,60}(SELECT|INSERT|UPDATE|DELETE)\b',
                             re.IGNORECASE),
         title="String-concatenated SQL query", category="Injection", subcategory="SQL Injection",
         severity=Severity.HIGH, confidence=55,
         impact="SQL built via string concatenation is vulnerable to SQL injection if any part "
                "includes external input.",
         remediation="Use PreparedStatement with bound parameters instead of Statement + string concatenation.",
         risk=RiskFactors(impact=9, exploitability=6, exposure=6, confidence=55, reproducibility=5)),
    dict(id="JAVA-HARDCODED-SECRET",
         pattern=re.compile(r'(?i)(password|secret|api[_-]?key|token)\s*=\s*"[A-Za-z0-9_\-/+=]{6,}"'),
         title="Hardcoded credential-shaped string literal", category="Credential Management",
         subcategory="Hardcoded Secret", severity=Severity.HIGH, confidence=55,
         impact="Secrets embedded in source are exposed to anyone with source access.",
         remediation="Move to environment variables or a secrets manager; rotate the exposed credential.",
         risk=RiskFactors(impact=8, exploitability=3, exposure=3, confidence=55, reproducibility=9)),
    dict(id="JAVA-INSECURE-RANDOM", pattern=re.compile(r"new\s+java\.util\.Random\s*\(|new\s+Random\s*\("),
         title="java.util.Random used (not cryptographically secure)", category="Cryptography",
         subcategory="Weak Randomness", severity=Severity.LOW, confidence=40,
         impact="java.util.Random is predictable and unsuitable for tokens, session IDs, or password resets.",
         remediation="Use java.security.SecureRandom for anything security-relevant.",
         risk=RiskFactors(impact=5, exploitability=3, exposure=3, confidence=40, reproducibility=7)),
]

COMMENT_LINE = re.compile(r"^\s*(//|\*|/\*)")


class JavaStaticAnalyzer(Analyzer):
    name = "java_static"
    display_name = "Java Static Analyzer"
    detection_method = "STATIC_ANALYSIS"

    def applies_to(self, profile: TargetProfile) -> bool:
        return "Java" in profile.languages

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.PARTIAL_SUPPORT,
                                   "Heuristic/regex-based — no real parser (javalang/JavaParser were not "
                                   "installable in this build environment)")

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
            lines = text.splitlines()

            for i, line in enumerate(lines, start=1):
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
            return [root] if root.suffix == ".java" else []
        out = []
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            if any(fnmatch.fnmatch(dirpath, pat) or fnmatch.fnmatch(rel_dir, pat) for pat in config.exclude_globs):
                dirnames[:] = []
                continue
            for fn in filenames:
                if fn.endswith(".java"):
                    out.append(Path(dirpath) / fn)
        return out
