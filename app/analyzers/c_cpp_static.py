"""
C/C++ static analyzer — EXPERIMENTAL.

Honesty note: this is the weakest analyzer in BlueLine v1. Real C/C++
analysis needs a real parser with preprocessor handling (clang's AST via
libclang, or a tool like cppcheck) — none of which could be installed in
this build environment (apt/mingw/network to package mirrors were
blocked). What's here is line-pattern matching for a handful of
classically dangerous libc calls. It WILL miss most real bugs and can
false-positive heavily (e.g. a safely-bounded strcpy). It is registered
and shown in the UI as EXPERIMENTAL with that caveat — never as
FULL_SUPPORT — per the "no fake universality" requirement.
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

DANGEROUS_FUNCS = {
    "strcpy": ("Use of strcpy()", "Buffer Overflow", Severity.HIGH,
               "strcpy() does not bound-check; a longer source string overflows the destination buffer.",
               "Use strncpy()/strlcpy() with an explicit bound, or std::string in C++."),
    "strcat": ("Use of strcat()", "Buffer Overflow", Severity.HIGH,
               "strcat() does not bound-check the destination buffer.",
               "Use strncat() with an explicit bound, or std::string in C++."),
    "gets": ("Use of gets()", "Buffer Overflow", Severity.CRITICAL,
             "gets() has no way to bound input length and is a classic stack-smashing vector; removed from C11.",
             "Use fgets() with an explicit buffer size."),
    "sprintf": ("Use of sprintf()", "Buffer Overflow", Severity.MEDIUM,
                "sprintf() does not bound-check the output buffer.",
                "Use snprintf() with an explicit buffer size."),
    "system": ("Use of system()", "Command Injection", Severity.HIGH,
               "system() invokes a shell; injection risk if any part of the command includes external input.",
               "Use exec-family functions with an explicit argument array instead of a shell string."),
    "strtok": ("Use of strtok()", "Thread Safety", Severity.LOW,
               "strtok() uses hidden static state and is not thread-safe/reentrant.",
               "Use strtok_r() (POSIX) or an explicit tokenizer."),
}

CALL_RE = {name: re.compile(r"\b" + re.escape(name) + r"\s*\(") for name in DANGEROUS_FUNCS}
COMMENT_RE = re.compile(r"^\s*(//|\*|/\*)")


class CCppStaticAnalyzer(Analyzer):
    name = "c_cpp_static"
    display_name = "C/C++ Static Analyzer"
    detection_method = "STATIC_ANALYSIS"

    def applies_to(self, profile: TargetProfile) -> bool:
        return "C" in profile.languages or "C++" in profile.languages

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.EXPERIMENTAL,
                                   "Pattern-matching on ~6 dangerous libc calls only; no real parser, "
                                   "no memory-safety data-flow analysis, expect false positives/negatives")

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
            rel = str(fpath.relative_to(root)) if root.is_dir() else fpath.name

            for i, line in enumerate(text.splitlines(), start=1):
                if COMMENT_RE.match(line):
                    continue
                for func, pattern in CALL_RE.items():
                    if pattern.search(line):
                        title, category, sev, impact, remediation = DANGEROUS_FUNCS[func]
                        findings.append(Finding(
                            id=new_finding_id(),
                            title=title,
                            category=category,
                            subcategory="Unsafe libc Call",
                            severity=sev,
                            confidence=45,  # deliberately low — this analyzer is EXPERIMENTAL
                            validation_status=ValidationStatus.SUSPECTED,
                            affected_target=str(root),
                            affected_component=rel,
                            location=f"{rel}:{i}",
                            detection_method=DetectionMethod.STATIC_ANALYSIS,
                            evidence=[Evidence(description=f"Call to {func}() matched by pattern",
                                                snippet=line.strip(), file_path=rel, line_start=i)],
                            impact=impact,
                            remediation=remediation,
                            risk_factors=RiskFactors(impact=7, exploitability=4, exposure=4,
                                                      confidence=45, reproducibility=6),
                            detector_sources=[self.name],
                        ))
        return findings

    @staticmethod
    def _collect_files(root: Path, config: ScanConfig) -> list[Path]:
        import fnmatch
        exts = (".c", ".h", ".cpp", ".cc", ".cxx", ".hpp")
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
