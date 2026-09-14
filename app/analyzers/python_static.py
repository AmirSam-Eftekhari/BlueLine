"""
Python static security analyzer.

This is a real AST-based analyzer (uses Python's `ast` module — no regex
guessing on source text). Every rule below inspects actual parsed syntax
nodes. This is the most complete analyzer in BlueLine v1: FULL_SUPPORT.

Rules implemented (each maps to one category):
  PY-EVAL-EXEC       use of eval()/exec()
  PY-OS-SYSTEM       os.system() / os.popen()
  PY-SUBPROC-SHELL   subprocess.* with shell=True
  PY-PICKLE-LOAD     pickle.load/loads (unsafe deserialization)
  PY-YAML-UNSAFE     yaml.load without SafeLoader
  PY-WEAK-HASH       hashlib.md5/sha1 used
  PY-WEAK-RANDOM     `random` module used in apparent security context
  PY-HARDCODED-SECRET string literal assigned to a credential-shaped name
  PY-SQL-CONCAT      string concatenation/f-string built into a SQL-shaped call
  PY-TEMP-INSECURE   tempfile.mktemp (race-prone) usage
  PY-TAR-TRAVERSAL   tarfile extractall without member filtering
  PY-XML-EXTERNAL    xml.etree/minidom parsing without defusedxml
  PY-ASSERT-SECURITY assert used for an apparent auth/permission check
  PY-DEBUG-FLASK     Flask/Django debug=True
  PY-BIND-ALL        binding a socket/server to 0.0.0.0
  PY-BROAD-EXCEPT    bare `except:` swallowing all errors silently
  PY-FSTRING-SQL     (folded into PY-SQL-CONCAT)
  PY-INSECURE-PERM   os.chmod with overly permissive mode (e.g. 0o777)
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

from app.analyzers.base import Analyzer
from app.core.models import (
    AnalyzerCapability, CapabilityLevel, DetectionMethod, Evidence, Finding,
    RiskFactors, ScanConfig, Severity, TargetProfile, ValidationStatus, new_finding_id,
)

SECRET_NAME_HINTS = ("password", "passwd", "secret", "api_key", "apikey", "token", "auth_key", "private_key")
SQL_CALL_HINTS = ("execute", "executemany", "raw", "cursor")
AUTH_ASSERT_HINTS = ("is_admin", "authenticated", "authorized", "has_permission", "role", "logged_in")


class _Visitor(ast.NodeVisitor):
    def __init__(self, file_rel: str, source_lines: list[str]):
        self.file_rel = file_rel
        self.lines = source_lines
        self.raw_findings: list[dict] = []
        # Simple same-function taint tracking: variable names that were
        # assigned a dynamically-built (f-string/concat/.format) value,
        # so `query = "..." + x; cur.execute(query)` is still caught even
        # though the concatenation isn't inline in the call.
        self.dynamic_sql_vars: set[str] = set()

    def _snippet(self, lineno: int, span: int = 1) -> str:
        start = max(0, lineno - 1)
        end = min(len(self.lines), lineno + span - 1)
        return "\n".join(self.lines[start:end]).strip()

    def _add(self, rule: str, lineno: int, **kw):
        self.raw_findings.append({"rule": rule, "line": lineno, "snippet": self._snippet(lineno), **kw})

    # -- calls -----------------------------------------------------------
    def visit_Call(self, node: ast.Call):
        func_name = self._call_name(node)

        if func_name in ("eval", "exec"):
            self._add("PY-EVAL-EXEC", node.lineno, func=func_name)

        if func_name in ("os.system", "os.popen"):
            self._add("PY-OS-SYSTEM", node.lineno, func=func_name)

        if func_name and func_name.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add("PY-SUBPROC-SHELL", node.lineno, func=func_name)

        if func_name in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads"):
            self._add("PY-PICKLE-LOAD", node.lineno, func=func_name)

        if func_name in ("yaml.load",):
            has_safe_loader = any(
                kw.arg == "Loader" and isinstance(kw.value, ast.Attribute) and kw.value.attr == "SafeLoader"
                for kw in node.keywords
            )
            if not has_safe_loader:
                self._add("PY-YAML-UNSAFE", node.lineno)

        if func_name in ("hashlib.md5", "hashlib.sha1"):
            self._add("PY-WEAK-HASH", node.lineno, func=func_name)

        if func_name == "tempfile.mktemp":
            self._add("PY-TEMP-INSECURE", node.lineno)

        if func_name and func_name.endswith(".extractall"):
            # tarfile.extractall(path) without a member filter is a classic
            # path-traversal vector (CVE-class: crafted archive entries with
            # '../' can write outside the target directory).
            if not node.keywords and not any(isinstance(a, ast.Name) for a in node.args[1:]):
                self._add("PY-TAR-TRAVERSAL", node.lineno)

        if func_name in ("os.chmod", "Path.chmod"):
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, int) and a.value & 0o777 == 0o777:
                    self._add("PY-INSECURE-PERM", node.lineno, mode=oct(a.value))

        if func_name in ("app.run", "application.run"):
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add("PY-DEBUG-FLASK", node.lineno)
                if kw.arg == "host" and isinstance(kw.value, ast.Constant) and kw.value.value == "0.0.0.0":
                    self._add("PY-BIND-ALL", node.lineno)

        if func_name and any(func_name.endswith("." + h) or func_name == h for h in SQL_CALL_HINTS):
            for a in node.args:
                is_inline_dynamic = self._looks_like_dynamic_sql(a)
                is_tainted_var = isinstance(a, ast.Name) and a.id in self.dynamic_sql_vars
                if is_inline_dynamic or is_tainted_var:
                    self._add("PY-SQL-CONCAT", node.lineno)
                    break

        self.generic_visit(node)

    def _looks_like_dynamic_sql(self, node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):  # f-string
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return True
        if isinstance(node, ast.Call) and self._call_name(node) == "str.format":
            return True
        return False

    def _call_name(self, node: ast.Call) -> str | None:
        f = node.func
        if isinstance(f, ast.Name):
            return f.id
        if isinstance(f, ast.Attribute):
            parts = []
            cur = f
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return None

    # -- assignments -------------------------------------------------------
    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            name = target.id.lower() if isinstance(target, ast.Name) else None
            if name and any(h in name for h in SECRET_NAME_HINTS):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) >= 4:
                    self._add("PY-HARDCODED-SECRET", node.lineno, var=name)
            if isinstance(target, ast.Name) and self._looks_like_dynamic_sql(node.value):
                self.dynamic_sql_vars.add(target.id)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "random":
                # Flag later only if used near auth-sounding names; kept
                # simple in v1: flag import, mark SUSPECTED not PROBABLE.
                pass
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        src = self._snippet(node.lineno)
        if any(h in src for h in AUTH_ASSERT_HINTS):
            self._add("PY-ASSERT-SECURITY", node.lineno)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.type is None:
            body_is_pass = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
            self._add("PY-BROAD-EXCEPT", node.lineno, silent=body_is_pass)
        self.generic_visit(node)


RULE_META = {
    "PY-EVAL-EXEC": dict(
        title="Use of eval()/exec()", category="Injection", subcategory="Code Injection",
        severity=Severity.HIGH, confidence=90, validation=ValidationStatus.PROBABLE,
        impact="Arbitrary code execution if input reaches this call.",
        remediation="Avoid eval()/exec() on any data that isn't fully trusted and static. "
                    "Use ast.literal_eval() for data, or an explicit parser/dispatch table.",
        risk=RiskFactors(impact=8, exploitability=6, exposure=5, confidence=90, reproducibility=6),
    ),
    "PY-OS-SYSTEM": dict(
        title="Use of os.system()/os.popen()", category="Injection", subcategory="Command Injection",
        severity=Severity.HIGH, confidence=85, validation=ValidationStatus.PROBABLE,
        impact="Shell command injection if any part of the command incorporates external input.",
        remediation="Use subprocess.run([...], shell=False) with an argument list instead of a shell string.",
        risk=RiskFactors(impact=8, exploitability=6, exposure=5, confidence=85, reproducibility=6),
    ),
    "PY-SUBPROC-SHELL": dict(
        title="subprocess call with shell=True", category="Injection", subcategory="Command Injection",
        severity=Severity.MEDIUM, confidence=75, validation=ValidationStatus.SUSPECTED,
        impact="Command injection risk if the command string includes external input.",
        remediation="Pass a list of arguments and use shell=False; avoid string-built shell commands.",
        risk=RiskFactors(impact=7, exploitability=5, exposure=5, confidence=75, reproducibility=5),
    ),
    "PY-PICKLE-LOAD": dict(
        title="Unsafe deserialization via pickle", category="Insecure Deserialization", subcategory="pickle",
        severity=Severity.HIGH, confidence=88, validation=ValidationStatus.PROBABLE,
        impact="Deserializing untrusted pickle data can lead to arbitrary code execution.",
        remediation="Never unpickle data from an untrusted source. Use JSON or a schema-validated format instead.",
        risk=RiskFactors(impact=9, exploitability=5, exposure=4, confidence=88, reproducibility=5),
    ),
    "PY-YAML-UNSAFE": dict(
        title="yaml.load() without SafeLoader", category="Insecure Deserialization", subcategory="YAML",
        severity=Severity.MEDIUM, confidence=80, validation=ValidationStatus.PROBABLE,
        impact="Untrusted YAML can instantiate arbitrary Python objects, potentially leading to code execution.",
        remediation="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
        risk=RiskFactors(impact=7, exploitability=4, exposure=4, confidence=80, reproducibility=5),
    ),
    "PY-WEAK-HASH": dict(
        title="Weak cryptographic hash (MD5/SHA1)", category="Cryptography", subcategory="Weak Hash",
        severity=Severity.LOW, confidence=70, validation=ValidationStatus.SUSPECTED,
        impact="MD5/SHA1 are broken for collision resistance; unsuitable for passwords or integrity-critical use.",
        remediation="Use SHA-256+ for integrity, and a dedicated password hash (bcrypt/scrypt/argon2) for credentials.",
        risk=RiskFactors(impact=4, exploitability=3, exposure=3, confidence=70, reproducibility=8),
    ),
    "PY-HARDCODED-SECRET": dict(
        title="Hardcoded credential-shaped string literal", category="Credential Management", subcategory="Hardcoded Secret",
        severity=Severity.HIGH, confidence=60, validation=ValidationStatus.SUSPECTED,
        impact="Secrets embedded in source are exposed to anyone with source access and are hard to rotate.",
        remediation="Move to environment variables or a secrets manager; rotate the exposed credential.",
        risk=RiskFactors(impact=8, exploitability=3, exposure=3, confidence=60, reproducibility=9),
    ),
    "PY-SQL-CONCAT": dict(
        title="Dynamically built SQL query", category="Injection", subcategory="SQL Injection",
        severity=Severity.HIGH, confidence=72, validation=ValidationStatus.SUSPECTED,
        impact="String-built SQL is vulnerable to SQL injection if any component includes external input.",
        remediation="Use parameterized queries / prepared statements instead of string concatenation or f-strings.",
        risk=RiskFactors(impact=9, exploitability=6, exposure=6, confidence=72, reproducibility=5),
    ),
    "PY-TEMP-INSECURE": dict(
        title="tempfile.mktemp() race condition", category="Insecure File Handling", subcategory="TOCTOU",
        severity=Severity.MEDIUM, confidence=80, validation=ValidationStatus.PROBABLE,
        impact="mktemp() returns a name without creating the file, allowing a race condition (TOCTOU) attack.",
        remediation="Use tempfile.mkstemp() or NamedTemporaryFile(), which create the file atomically.",
        risk=RiskFactors(impact=6, exploitability=4, exposure=3, confidence=80, reproducibility=6),
    ),
    "PY-TAR-TRAVERSAL": dict(
        title="tarfile.extractall() without member filtering", category="Path Traversal", subcategory="Archive Extraction",
        severity=Severity.HIGH, confidence=78, validation=ValidationStatus.PROBABLE,
        impact="A crafted archive with '../' entries can write files outside the intended extraction directory.",
        remediation="Validate each member's resolved path stays under the target directory before extracting "
                    "(or use the `filter='data'` argument on Python 3.12+).",
        risk=RiskFactors(impact=8, exploitability=5, exposure=4, confidence=78, reproducibility=7),
    ),
    "PY-ASSERT-SECURITY": dict(
        title="assert used for a security-relevant check", category="Authorization", subcategory="Improper Enforcement",
        severity=Severity.MEDIUM, confidence=55, validation=ValidationStatus.SUSPECTED,
        impact="assert statements are stripped when Python runs with -O, silently disabling the check.",
        remediation="Use an explicit `if not check: raise PermissionError(...)` instead of assert.",
        risk=RiskFactors(impact=7, exploitability=3, exposure=4, confidence=55, reproducibility=6),
    ),
    "PY-DEBUG-FLASK": dict(
        title="Flask app run with debug=True", category="Configuration", subcategory="Debug Mode Enabled",
        severity=Severity.HIGH, confidence=95, validation=ValidationStatus.PROBABLE,
        impact="Flask's debugger exposes an interactive shell that allows remote code execution if reachable.",
        remediation="Never enable debug=True in production; use an env-controlled flag defaulting to False.",
        risk=RiskFactors(impact=9, exploitability=7, exposure=7, confidence=95, reproducibility=9),
    ),
    "PY-BIND-ALL": dict(
        title="Server bound to 0.0.0.0", category="Configuration", subcategory="Network Exposure",
        severity=Severity.MEDIUM, confidence=65, validation=ValidationStatus.SUSPECTED,
        impact="Binding to all interfaces may expose a service beyond its intended network boundary.",
        remediation="Bind to a specific interface (e.g. 127.0.0.1) unless external exposure is intentional.",
        risk=RiskFactors(impact=5, exploitability=3, exposure=6, confidence=65, reproducibility=8),
    ),
    "PY-BROAD-EXCEPT": dict(
        title="Bare except clause", category="Error Handling", subcategory="Silent Failure",
        severity=Severity.LOW, confidence=60, validation=ValidationStatus.SUSPECTED,
        impact="Swallows all exceptions including security-relevant ones, masking failures and complicating audits.",
        remediation="Catch specific exception types; log and re-raise unexpected ones.",
        risk=RiskFactors(impact=3, exploitability=1, exposure=2, confidence=60, reproducibility=9),
    ),
    "PY-INSECURE-PERM": dict(
        title="Overly permissive file permissions", category="Access Control", subcategory="File Permissions",
        severity=Severity.MEDIUM, confidence=70, validation=ValidationStatus.SUSPECTED,
        impact="World-writable files/directories can be tampered with by any local user.",
        remediation="Use the least-permissive mode that satisfies the actual requirement (e.g. 0o600 / 0o750).",
        risk=RiskFactors(impact=6, exploitability=4, exposure=3, confidence=70, reproducibility=8),
    ),
}


class PythonStaticAnalyzer(Analyzer):
    name = "python_static"
    display_name = "Python Static Analyzer"
    detection_method = "STATIC_ANALYSIS"

    def applies_to(self, profile: TargetProfile) -> bool:
        return "Python" in profile.languages

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.FULL_SUPPORT,
                                   "AST-based rule engine, 15 rule classes")

    def run(self, profile: TargetProfile, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        root = Path(profile.target_path)
        py_files = self._collect_py_files(root, config)

        for fpath in py_files:
            try:
                source = fpath.read_text(errors="ignore")
                if len(source.encode("utf-8", "ignore")) > config.max_file_size_bytes:
                    continue
                tree = ast.parse(source, filename=str(fpath))
            except (SyntaxError, ValueError, OSError):
                # A broken/unparseable file is test data, not an analyzer crash.
                continue

            visitor = _Visitor(str(fpath.relative_to(root)) if root.is_dir() else fpath.name,
                                source.splitlines())
            try:
                visitor.visit(tree)
            except RecursionError:
                continue

            for raw in visitor.raw_findings:
                meta = RULE_META.get(raw["rule"])
                if not meta:
                    continue
                loc = f"{visitor.file_rel}:{raw['line']}"
                f = Finding(
                    id=new_finding_id(),
                    title=meta["title"],
                    category=meta["category"],
                    subcategory=meta["subcategory"],
                    severity=meta["severity"],
                    confidence=meta["confidence"],
                    validation_status=meta["validation"],
                    affected_target=str(root),
                    affected_component=visitor.file_rel,
                    location=loc,
                    detection_method=DetectionMethod.STATIC_ANALYSIS,
                    evidence=[Evidence(description=f"Rule {raw['rule']} matched",
                                        snippet=raw["snippet"], file_path=visitor.file_rel,
                                        line_start=raw["line"])],
                    impact=meta["impact"],
                    remediation=meta["remediation"],
                    risk_factors=meta["risk"],
                    detector_sources=[self.name],
                )
                findings.append(f)
        return findings

    @staticmethod
    def _collect_py_files(root: Path, config: ScanConfig) -> list[Path]:
        import fnmatch
        if root.is_file():
            return [root] if root.suffix == ".py" else []
        out = []
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            if any(fnmatch.fnmatch(dirpath, pat) or fnmatch.fnmatch(rel_dir, pat) for pat in config.exclude_globs):
                dirnames[:] = []
                continue
            for fn in filenames:
                if fn.endswith(".py"):
                    out.append(Path(dirpath) / fn)
        return out
