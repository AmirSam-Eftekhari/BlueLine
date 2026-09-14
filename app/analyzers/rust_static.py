"""
Rust static analyzer. Same honesty stance as the other pattern-based
analyzers: line/regex matching, not a real parser (no syn/rustc tooling
available in this sandbox). Declared PARTIAL_SUPPORT.

Rust already prevents most memory-safety bugs at compile time, so the
rules here focus on what Rust's type system does NOT protect against:
explicit `unsafe` escapes, shelling out, weak crypto, hardcoded
secrets, SQL built by string formatting, and unwrap()/expect() on
external input (a panic-based denial-of-service vector, not a memory
safety issue, but a real reliability concern in Rust specifically since
panics are the idiomatic Rust failure mode for "this should never
happen" that often turns out to happen when the input is attacker-controlled).
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
    dict(id="RUST-UNSAFE-BLOCK", pattern=re.compile(r"\bunsafe\s*\{"),
         title="unsafe block", category="Memory Safety", subcategory="Unsafe Escape",
         severity=Severity.LOW, confidence=50,
         impact="unsafe blocks opt out of Rust's compile-time memory-safety guarantees; the code "
                "inside needs the same scrutiny as C/C++ would.",
         remediation="Minimize unsafe blocks, document the invariant that makes each one sound, "
                     "and prefer a safe abstraction (or a well-audited crate) where possible.",
         risk=RiskFactors(impact=5, exploitability=3, exposure=3, confidence=50, reproducibility=9)),
    dict(id="RUST-TRANSMUTE", pattern=re.compile(r"\bstd::mem::transmute\s*\(|\btransmute\s*\("),
         title="mem::transmute() usage", category="Memory Safety", subcategory="Type Punning",
         severity=Severity.MEDIUM, confidence=65,
         impact="transmute reinterprets raw bytes as an arbitrary type with no validation — a "
                "classic source of undefined behavior if the types aren't truly compatible.",
         remediation="Use a safe conversion (TryFrom, from_le_bytes, etc.) instead of transmute "
                     "wherever one exists.",
         risk=RiskFactors(impact=6, exploitability=3, exposure=3, confidence=65, reproducibility=8)),
    dict(id="RUST-COMMAND-SHELL", pattern=re.compile(r'Command::new\s*\(\s*"(sh|bash|cmd|cmd\.exe)"'),
         title="Command::new invoking a shell directly", category="Injection", subcategory="Command Injection",
         severity=Severity.HIGH, confidence=68,
         impact="Explicitly invoking a shell reintroduces shell-metacharacter injection risk if "
                "any argument includes external input.",
         remediation="Invoke the target binary directly with .arg()-supplied arguments instead of "
                     "going through a shell.",
         risk=RiskFactors(impact=8, exploitability=6, exposure=5, confidence=68, reproducibility=6)),
    dict(id="RUST-WEAK-HASH", pattern=re.compile(r"\bmd5::|Md5::new|\bsha1::|Sha1::new"),
         title="Weak cryptographic hash (MD5/SHA1)", category="Cryptography", subcategory="Weak Hash",
         severity=Severity.LOW, confidence=55,
         impact="MD5/SHA1 are broken for collision resistance; unsuitable for passwords or "
                "integrity-critical use.",
         remediation="Use sha2/sha3 for integrity; use a dedicated password hash (argon2 crate) "
                     "for credentials.",
         risk=RiskFactors(impact=4, exploitability=3, exposure=3, confidence=55, reproducibility=8)),
    dict(id="RUST-SQL-FORMAT",
         pattern=re.compile(r'format!\s*\(\s*"[^"]*(SELECT|INSERT|UPDATE|DELETE)\b', re.IGNORECASE),
         title="SQL query built with format!()", category="Injection", subcategory="SQL Injection",
         severity=Severity.HIGH, confidence=60,
         impact="SQL built with format! string interpolation is vulnerable to SQL injection if any "
                "interpolated value includes external input.",
         remediation="Use a parameterized query (sqlx's query! macros, or bound parameters with "
                     "rusqlite/postgres) instead of format!().",
         risk=RiskFactors(impact=9, exploitability=6, exposure=6, confidence=60, reproducibility=5)),
    dict(id="RUST-HARDCODED-SECRET",
         pattern=re.compile(r'(?i)(password|secret|api[_-]?key|token)\s*(:\s*&?\w+\s*)?=\s*"[A-Za-z0-9_\-/+=]{6,}"'),
         title="Hardcoded credential-shaped string literal", category="Credential Management",
         subcategory="Hardcoded Secret", severity=Severity.HIGH, confidence=55,
         impact="Secrets embedded in source are exposed to anyone with source access.",
         remediation="Move to environment variables or a secrets manager; rotate the exposed credential.",
         risk=RiskFactors(impact=8, exploitability=3, exposure=3, confidence=55, reproducibility=9)),
    dict(id="RUST-UNWRAP-EXTERNAL",
         pattern=re.compile(r"(env::args|read_line|from_str|env::var)\([^)]*\)[^;]*\.unwrap\(\)"),
         title="unwrap() apparently used directly on external input", category="Error Handling",
         subcategory="Panic-based DoS", severity=Severity.LOW, confidence=40,
         impact="unwrap() panics the whole process on unexpected input — if the input source is "
                "external (args, stdin, env vars), a crafted input can crash the service.",
         remediation="Handle the Result/Option explicitly (match, ?, or .unwrap_or_default()) "
                     "instead of unwrap() on anything derived from external input.",
         risk=RiskFactors(impact=4, exploitability=4, exposure=4, confidence=40, reproducibility=7)),
]

COMMENT_LINE = re.compile(r"^\s*//")


class RustStaticAnalyzer(Analyzer):
    name = "rust_static"
    display_name = "Rust Static Analyzer"
    detection_method = "STATIC_ANALYSIS"

    def applies_to(self, profile: TargetProfile) -> bool:
        return "Rust" in profile.languages

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.PARTIAL_SUPPORT,
                                   "Heuristic/regex-based — no real parser (no syn/rustc tooling "
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
            return [root] if root.suffix == ".rs" else []
        out = []
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            if any(fnmatch.fnmatch(dirpath, pat) or fnmatch.fnmatch(rel_dir, pat) for pat in config.exclude_globs):
                dirnames[:] = []
                continue
            for fn in filenames:
                if fn.endswith(".rs"):
                    out.append(Path(dirpath) / fn)
        return out
