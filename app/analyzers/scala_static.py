"""
Scala static analyzer. Same honesty stance as the others: line/regex
matching, not a real parser (no scalameta tooling available in this
sandbox). Declared PARTIAL_SUPPORT. Scala runs on the JVM and shares
several risk classes with Java/Kotlin (ObjectInputStream, MessageDigest/
Cipher weak crypto, Runtime.exec).
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
    dict(id="SCALA-PROCESS-EXEC",
         pattern=re.compile(r"scala\.sys\.process\.|Runtime\.getRuntime\(\)\.exec\s*\(|\.!!\s*$|Process\s*\("),
         title="External process execution", category="Injection", subcategory="Command Injection",
         severity=Severity.MEDIUM, confidence=45,
         impact="Invokes an external process; injection risk if any argument incorporates "
                "external input.",
         remediation="Validate/allow-list inputs; avoid building commands from unvalidated "
                     "external input, especially via string interpolation into sys.process.",
         risk=RiskFactors(impact=7, exploitability=5, exposure=5, confidence=45, reproducibility=6)),
    dict(id="SCALA-OBJ-DESERIALIZE", pattern=re.compile(r"new\s+ObjectInputStream\s*\("),
         title="Java native deserialization (ObjectInputStream)", category="Insecure Deserialization",
         subcategory="Java Deserialization", severity=Severity.HIGH, confidence=68,
         impact="Deserializing untrusted data with ObjectInputStream is a well-known JVM RCE vector "
                "via gadget chains in classpath libraries.",
         remediation="Avoid native Java/Scala deserialization for untrusted data; use a JSON codec "
                     "(circe, play-json) with a schema instead.",
         risk=RiskFactors(impact=9, exploitability=5, exposure=4, confidence=68, reproducibility=5)),
    dict(id="SCALA-WEAK-HASH", pattern=re.compile(r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1)"', re.IGNORECASE),
         title="Weak cryptographic hash (MD5/SHA-1)", category="Cryptography", subcategory="Weak Hash",
         severity=Severity.LOW, confidence=70,
         impact="MD5/SHA-1 are broken for collision resistance; unsuitable for passwords or "
                "integrity-critical use.",
         remediation="Use SHA-256+ for integrity, and a dedicated password hash (bcrypt/Argon2) "
                     "for credentials.",
         risk=RiskFactors(impact=4, exploitability=3, exposure=3, confidence=70, reproducibility=8)),
    dict(id="SCALA-SQL-INTERP",
         pattern=re.compile(r's"[^"]*(SELECT|INSERT|UPDATE|DELETE)\b[^"]*\$', re.IGNORECASE),
         title="SQL query built with string interpolation", category="Injection", subcategory="SQL Injection",
         severity=Severity.HIGH, confidence=58,
         impact="Interpolating values directly into SQL via Scala string interpolators (s\"...\") "
                "is vulnerable to SQL injection.",
         remediation="Use parameterized queries (PreparedStatement, Slick/Doobie bound parameters) "
                     "instead of string interpolation.",
         risk=RiskFactors(impact=9, exploitability=6, exposure=6, confidence=58, reproducibility=5)),
    dict(id="SCALA-HARDCODED-SECRET",
         pattern=re.compile(r'(?i)(val|var)\s+\w*(password|secret|api[_-]?key|token)\w*\s*[:=].{0,20}"[A-Za-z0-9_\-/+=]{6,}"'),
         title="Hardcoded credential-shaped string literal", category="Credential Management",
         subcategory="Hardcoded Secret", severity=Severity.HIGH, confidence=55,
         impact="Secrets embedded in source are exposed to anyone with source access.",
         remediation="Move to environment variables or a secrets manager; rotate the exposed credential.",
         risk=RiskFactors(impact=8, exploitability=3, exposure=3, confidence=55, reproducibility=9)),
    dict(id="SCALA-INSECURE-RANDOM", pattern=re.compile(r"scala\.util\.Random\s*\(\s*\)|new\s+java\.util\.Random\s*\("),
         title="Random used (not cryptographically secure)", category="Cryptography",
         subcategory="Weak Randomness", severity=Severity.LOW, confidence=40,
         impact="scala.util.Random/java.util.Random are predictable and unsuitable for tokens, "
                "session IDs, or password resets.",
         remediation="Use java.security.SecureRandom for anything security-relevant.",
         risk=RiskFactors(impact=5, exploitability=3, exposure=3, confidence=40, reproducibility=7)),
    dict(id="SCALA-UNSAFE-GET",
         pattern=re.compile(r"(readLine\(\)|args\(\d+\))\s*\.get\b"),
         title=".get used directly on external/fallible input", category="Error Handling",
         subcategory="Panic-based DoS", severity=Severity.LOW, confidence=35,
         impact=".get throws immediately on a None/Failure — if the source is external "
                "(stdin, CLI args), a crafted/missing input can crash the process.",
         remediation="Handle the empty case explicitly (getOrElse, pattern matching, or Try) "
                     "instead of .get on anything derived from external input.",
         risk=RiskFactors(impact=4, exploitability=4, exposure=4, confidence=35, reproducibility=7)),
]

COMMENT_LINE = re.compile(r"^\s*(//|\*|/\*)")


class ScalaStaticAnalyzer(Analyzer):
    name = "scala_static"
    display_name = "Scala Static Analyzer"
    detection_method = "STATIC_ANALYSIS"

    def applies_to(self, profile: TargetProfile) -> bool:
        return "Scala" in profile.languages

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.PARTIAL_SUPPORT,
                                   "Heuristic/regex-based — no real parser (no scalameta tooling "
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
            return [root] if root.suffix == ".scala" else []
        out = []
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            if any(fnmatch.fnmatch(dirpath, pat) or fnmatch.fnmatch(rel_dir, pat) for pat in config.exclude_globs):
                dirnames[:] = []
                continue
            for fn in filenames:
                if fn.endswith(".scala"):
                    out.append(Path(dirpath) / fn)
        return out
