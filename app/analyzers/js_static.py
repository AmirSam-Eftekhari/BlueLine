"""
JavaScript/TypeScript static analyzer.

IMPORTANT HONESTY NOTE: this is regex/line-based, not a real AST parser.
JS/TS require a proper parser (acorn/babel/typescript-eslint) to do this
right, and this build environment had no network access to npm to install
one. Rather than claim full support with a fake parser, this analyzer is
explicitly declared PARTIAL_SUPPORT everywhere in the product (target
profile, reports, UI). It still finds real issues — string-pattern
matching genuinely catches some categories of bug — but it will miss
things a real parser would catch, and can false-positive on patterns
inside strings/comments. Treat findings from this analyzer as SUSPECTED
unless stated otherwise.
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
    dict(id="JS-EVAL", pattern=re.compile(r"\beval\s*\("), title="Use of eval()",
         category="Injection", subcategory="Code Injection", severity=Severity.HIGH, confidence=75,
         impact="eval() executes arbitrary strings as code; dangerous if any input reaches it.",
         remediation="Avoid eval(). Use JSON.parse for data, or an explicit dispatch/parsing approach.",
         risk=RiskFactors(impact=8, exploitability=6, exposure=5, confidence=75, reproducibility=6)),
    dict(id="JS-NEWFUNC", pattern=re.compile(r"new\s+Function\s*\("), title="Dynamic code via Function() constructor",
         category="Injection", subcategory="Code Injection", severity=Severity.HIGH, confidence=70,
         impact="Function() constructor compiles a string into executable code, similar risk to eval().",
         remediation="Avoid constructing functions from dynamic strings.",
         risk=RiskFactors(impact=8, exploitability=6, exposure=5, confidence=70, reproducibility=6)),
    dict(id="JS-CHILDPROC-EXEC", pattern=re.compile(r"child_process\.exec\s*\("), title="child_process.exec() usage",
         category="Injection", subcategory="Command Injection", severity=Severity.HIGH, confidence=68,
         impact="exec() runs a shell string; injection risk if any part comes from external input. "
                "(execFile/spawn with an argument array is safer.)",
         remediation="Prefer execFile()/spawn() with an argument array instead of a shell string.",
         risk=RiskFactors(impact=8, exploitability=6, exposure=5, confidence=68, reproducibility=6)),
    dict(id="JS-INNERHTML", pattern=re.compile(r"\.innerHTML\s*="), title="Direct innerHTML assignment",
         category="Cross-Site Scripting", subcategory="DOM XSS", severity=Severity.MEDIUM, confidence=55,
         impact="Assigning unsanitized content to innerHTML can lead to DOM-based XSS.",
         remediation="Use textContent for plain text, or a sanitizer (DOMPurify) before setting HTML.",
         risk=RiskFactors(impact=6, exploitability=5, exposure=6, confidence=55, reproducibility=5)),
    dict(id="JS-DOCWRITE", pattern=re.compile(r"document\.write\s*\("), title="Use of document.write()",
         category="Cross-Site Scripting", subcategory="DOM XSS", severity=Severity.LOW, confidence=50,
         impact="document.write with dynamic content is a common XSS vector and blocks async rendering.",
         remediation="Use safe DOM manipulation APIs instead.",
         risk=RiskFactors(impact=5, exploitability=4, exposure=5, confidence=50, reproducibility=5)),
    dict(id="JS-HARDCODED-SECRET",
         pattern=re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{6,}['\"]"),
         title="Hardcoded credential-shaped string literal", category="Credential Management",
         subcategory="Hardcoded Secret", severity=Severity.HIGH, confidence=55,
         impact="Secrets embedded in source are exposed to anyone with source access.",
         remediation="Move to environment variables or a secrets manager; rotate the exposed credential.",
         risk=RiskFactors(impact=8, exploitability=3, exposure=3, confidence=55, reproducibility=9)),
    dict(id="JS-NOSNIFF-DISABLED", pattern=re.compile(r"rejectUnauthorized\s*:\s*false"),
         title="TLS certificate validation disabled", category="Cryptography", subcategory="TLS Misconfiguration",
         severity=Severity.HIGH, confidence=85,
         impact="Disabling certificate validation allows man-in-the-middle attacks.",
         remediation="Remove rejectUnauthorized: false; fix the underlying certificate issue instead.",
         risk=RiskFactors(impact=8, exploitability=5, exposure=5, confidence=85, reproducibility=8)),
    dict(id="JS-SQL-CONCAT", pattern=re.compile(r"(SELECT|INSERT|UPDATE|DELETE)[^`'\"]{0,80}['\"]\s*\+"),
         title="Dynamically concatenated SQL query", category="Injection", subcategory="SQL Injection",
         severity=Severity.HIGH, confidence=60,
         impact="String-concatenated SQL is vulnerable to SQL injection.",
         remediation="Use parameterized queries via your DB driver's placeholder syntax.",
         risk=RiskFactors(impact=9, exploitability=6, exposure=6, confidence=60, reproducibility=5)),
    dict(id="JS-JWT-NONE", pattern=re.compile(r"algorithms?\s*:\s*\[\s*['\"]none['\"]"),
         title="JWT verification allows 'none' algorithm", category="Authentication",
         subcategory="JWT Misconfiguration", severity=Severity.CRITICAL, confidence=90,
         impact="Accepting the 'none' algorithm lets an attacker forge unsigned tokens that pass verification.",
         remediation="Explicitly allow-list a strong signing algorithm (e.g. RS256/HS256) and reject 'none'.",
         risk=RiskFactors(impact=10, exploitability=8, exposure=7, confidence=90, reproducibility=9)),
    dict(id="JS-INSECURE-RANDOM", pattern=re.compile(r"Math\.random\(\)"),
         title="Math.random() used (not cryptographically secure)", category="Cryptography",
         subcategory="Weak Randomness", severity=Severity.LOW, confidence=40,
         impact="Math.random() is not suitable for security tokens, password resets, or session IDs.",
         remediation="Use crypto.randomBytes() / crypto.getRandomValues() for anything security-relevant.",
         risk=RiskFactors(impact=5, exploitability=3, exposure=3, confidence=40, reproducibility=7)),
]

COMMENT_LINE = re.compile(r"^\s*(//|\*|/\*)")


class JavaScriptStaticAnalyzer(Analyzer):
    name = "js_static"
    display_name = "JavaScript/TypeScript Static Analyzer"
    detection_method = "STATIC_ANALYSIS"

    def applies_to(self, profile: TargetProfile) -> bool:
        return "JavaScript" in profile.languages or "TypeScript" in profile.languages

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.PARTIAL_SUPPORT,
                                   "Heuristic/regex-based — no AST/type-flow analysis in this build")

    def run(self, profile: TargetProfile, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        root = Path(profile.target_path)
        files = self._collect_files(root, config)

        for fpath in files:
            try:
                text = fpath.read_text(errors="ignore")
                if len(text.encode("utf-8", "ignore")) > config.max_file_size_bytes:
                    continue
            except OSError:
                continue

            lines = text.splitlines()
            rel = str(fpath.relative_to(root)) if root.is_dir() else fpath.name

            for i, line in enumerate(lines, start=1):
                if COMMENT_LINE.match(line):
                    continue
                for rule in RULES:
                    if rule["pattern"].search(line):
                        loc = f"{rel}:{i}"
                        findings.append(Finding(
                            id=new_finding_id(),
                            title=rule["title"],
                            category=rule["category"],
                            subcategory=rule["subcategory"],
                            severity=rule["severity"],
                            confidence=rule["confidence"],
                            validation_status=ValidationStatus.SUSPECTED,
                            affected_target=str(root),
                            affected_component=rel,
                            location=loc,
                            detection_method=DetectionMethod.STATIC_ANALYSIS,
                            evidence=[Evidence(description=f"Pattern {rule['id']} matched",
                                                snippet=line.strip(), file_path=rel, line_start=i)],
                            impact=rule["impact"],
                            remediation=rule["remediation"],
                            risk_factors=rule["risk"],
                            detector_sources=[self.name],
                        ))
        return findings

    @staticmethod
    def _collect_files(root: Path, config: ScanConfig) -> list[Path]:
        import fnmatch
        exts = (".js", ".jsx", ".mjs", ".ts", ".tsx")
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
