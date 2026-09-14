"""
Binary/executable analyzer.

Honesty split, consistent with the rest of BlueLine:
  - ELF (Linux/Unix executables): FULL analysis for the properties this
    build actually parses (architecture, PIE, stripped, linked
    libraries) — validated against real compiled binaries, see
    tests/test_elf_parser.py and docs/ARCHITECTURE.md.
  - PE (Windows executables): header metadata only (machine type,
    subsystem, section count, build timestamp) — validated against a
    synthetic, spec-conformant PE64 fixture (tests/test_pe_parser.py),
    since no real Windows binary was available in this build
    environment. The import table (which DLLs/functions it links
    against) is NOT parsed — that needs RVA-to-file-offset translation
    through the section table, which was judged not worth shipping
    without a real binary to validate the result against.
  - Mach-O (macOS): detected by magic bytes only, no header parsing.
  - String extraction (secrets, private key material, debug paths)
    applies to any executable format, since it doesn't depend on
    understanding the container format at all.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.analyzers.base import Analyzer
from app.analyzers.elf_parser import extract_strings, parse_elf, parse_pe
from app.core.models import (
    AnalyzerCapability, CapabilityLevel, DetectionMethod, Evidence, Finding,
    RiskFactors, ScanConfig, Severity, TargetProfile, ValidationStatus, new_finding_id,
)

STRING_RULES = [
    dict(id="BIN-PRIVATE-KEY",
         pattern=re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
         title="Private key material embedded in binary", category="Credential Management",
         subcategory="Embedded Private Key", severity=Severity.CRITICAL, confidence=95,
         impact="A private key compiled or embedded into a binary is exposed to anyone who can "
                "read the file — effectively the same as publishing the key.",
         remediation="Remove the embedded key immediately, rotate it, and load secrets at runtime "
                     "from a secrets manager or environment variable instead.",
         risk=RiskFactors(impact=10, exploitability=8, exposure=6, confidence=95, reproducibility=10)),
    dict(id="BIN-HARDCODED-SECRET",
         pattern=re.compile(r'(?i)(api[_-]?key|secret|password|token)["\']?\s*[:=]\s*["\']?[A-Za-z0-9_\-/+=]{8,}'),
         title="Credential-shaped string embedded in binary", category="Credential Management",
         subcategory="Hardcoded Secret", severity=Severity.MEDIUM, confidence=40,
         impact="A string matching common credential patterns was found in the binary. Binary "
                "strings lack the surrounding context source code has, so this has a higher "
                "false-positive rate than the equivalent source-code check — verify manually.",
         remediation="If this is a real credential, remove it and rotate it. If it's a false "
                     "positive (e.g. a format string or variable name), no action needed.",
         risk=RiskFactors(impact=7, exploitability=3, exposure=3, confidence=40, reproducibility=8)),
    dict(id="BIN-DEBUG-PATH",
         pattern=re.compile(r"(/home/[A-Za-z0-9_.\-]+/|/Users/[A-Za-z0-9_.\-]+/|C:\\Users\\[A-Za-z0-9_.\-]+\\)"),
         title="Developer file path embedded in binary", category="Information Disclosure",
         subcategory="Build Path Disclosure", severity=Severity.LOW, confidence=50,
         impact="Embedded build-machine paths can reveal developer usernames or internal project "
                "structure — minor information disclosure, not itself exploitable.",
         remediation="Build with path-independent settings (e.g. compiler flags that strip build "
                     "paths) if this information shouldn't be public.",
         risk=RiskFactors(impact=2, exploitability=1, exposure=3, confidence=50, reproducibility=9)),
]

EXECUTABLE_MAGIC_PREFIXES = {
    b"MZ": "PE (Windows)",
    b"\xcf\xfa\xed\xfe": "Mach-O (macOS)",
    b"\xca\xfe\xba\xbe": "Mach-O universal / Java class",
}


class BinaryAnalyzer(Analyzer):
    name = "binary_analysis"
    display_name = "Binary/Executable Analyzer"
    detection_method = "STATIC_ANALYSIS"

    def applies_to(self, profile: TargetProfile) -> bool:
        return bool(profile.executables)

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.PARTIAL_SUPPORT,
                                   "ELF metadata/linked-library parsing validated against real "
                                   "compiled binaries; PE header metadata validated against a "
                                   "synthetic fixture (no import table parsing); Mach-O detected "
                                   "by magic bytes only")

    def run(self, profile: TargetProfile, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        root = Path(profile.target_path)

        for rel in profile.executables:
            full_path = str(root) if root.is_file() else str(root / rel)
            findings.extend(self._analyze_one(full_path, rel, str(root)))
        return findings

    def _analyze_one(self, full_path: str, rel: str, target: str) -> list[Finding]:
        out: list[Finding] = []

        elf_info = parse_elf(full_path)
        if elf_info.is_elf:
            out.extend(self._elf_findings(elf_info, rel, target))
        else:
            pe_info = parse_pe(full_path)
            if pe_info.is_pe:
                out.extend(self._pe_findings(pe_info, rel, target))
            else:
                try:
                    with open(full_path, "rb") as fh:
                        head = fh.read(4)
                except OSError:
                    head = b""
                fmt = next((label for magic, label in EXECUTABLE_MAGIC_PREFIXES.items()
                            if head.startswith(magic)), None)
                if fmt:
                    out.append(Finding(
                        id=new_finding_id(prefix="BL-BIN"),
                        title=f"{fmt} executable detected — internals not parsed in this build",
                        category="Coverage Limitation", subcategory="Unparsed Binary Format",
                        severity=Severity.INFORMATIONAL, confidence=100,
                        validation_status=ValidationStatus.CONFIRMED,
                        affected_target=target, affected_component=rel, location=rel,
                        detection_method=DetectionMethod.STATIC_ANALYSIS,
                        evidence=[Evidence(description=f"File header matches {fmt} magic bytes")],
                        impact="Import table, linked libraries, and other structural details for this "
                               "format are not extracted in this build — only string-based checks apply.",
                        remediation="No action needed; this is a capability note, not a finding about "
                                    "the target itself.",
                        detector_sources=[self.name],
                    ))

        # String-based checks apply regardless of container format.
        strings = extract_strings(full_path)
        out.extend(self._string_findings(strings, rel, target))
        return out

    def _pe_findings(self, info, rel: str, target: str) -> list[Finding]:
        return [Finding(
            id=new_finding_id(prefix="BL-BIN"),
            title=f"PE binary profile: {info.machine}, {info.subsystem}, "
                  f"{info.number_of_sections} section(s)",
            category="Target Metadata", subcategory="Binary Profile",
            severity=Severity.INFORMATIONAL, confidence=100, validation_status=ValidationStatus.CONFIRMED,
            affected_target=target, affected_component=rel, location=rel,
            detection_method=DetectionMethod.STATIC_ANALYSIS,
            evidence=[Evidence(description=f"Parsed PE/COFF header: bitness={info.bitness}, "
                                            f"timestamp={info.timestamp}. Note: the import table "
                                            f"(linked DLLs) is not parsed in this build — see "
                                            f"docs/SUPPORTED_TARGETS.md.")],
            impact="Informational — not itself a vulnerability.",
            remediation="No action needed.",
            detector_sources=[self.name],
        )]

    def _elf_findings(self, info, rel: str, target: str) -> list[Finding]:
        out = []
        out.append(Finding(
            id=new_finding_id(prefix="BL-BIN"),
            title=f"ELF binary profile: {info.machine}, {info.elf_type}"
                  f"{', dynamically linked' if not info.statically_linked else ', statically linked'}",
            category="Target Metadata", subcategory="Binary Profile",
            severity=Severity.INFORMATIONAL, confidence=100, validation_status=ValidationStatus.CONFIRMED,
            affected_target=target, affected_component=rel, location=rel,
            detection_method=DetectionMethod.STATIC_ANALYSIS,
            evidence=[Evidence(description=f"Parsed ELF header: bitness={info.bitness}, "
                                            f"entry=0x{info.entry_point:x}, "
                                            f"needed={info.needed_libraries}")],
            impact="Informational — not itself a vulnerability.",
            remediation="No action needed.",
            detector_sources=[self.name],
        ))

        if info.elf_type_raw == 2:  # ET_EXEC, no PIE
            out.append(Finding(
                id=new_finding_id(prefix="BL-BIN"),
                title="Binary compiled without position-independent code (no PIE)",
                category="Exploit Mitigation", subcategory="Missing PIE",
                severity=Severity.LOW, confidence=90, validation_status=ValidationStatus.CONFIRMED,
                affected_target=target, affected_component=rel, location=rel,
                detection_method=DetectionMethod.STATIC_ANALYSIS,
                evidence=[Evidence(description="ELF e_type is ET_EXEC, not ET_DYN")],
                impact="Without PIE, the binary loads at a fixed address, making ASLR "
                       "considerably less effective against memory-corruption exploits.",
                remediation="Recompile with -pie (GCC/Clang) or the equivalent for your toolchain.",
                risk_factors=RiskFactors(impact=2, exploitability=2, exposure=2, confidence=90, reproducibility=10),
                detector_sources=[self.name],
            ))

        if not info.stripped:
            out.append(Finding(
                id=new_finding_id(prefix="BL-BIN"),
                title="Binary retains its symbol table (not stripped)",
                category="Information Disclosure", subcategory="Unstripped Binary",
                severity=Severity.INFORMATIONAL, confidence=95, validation_status=ValidationStatus.CONFIRMED,
                affected_target=target, affected_component=rel, location=rel,
                detection_method=DetectionMethod.STATIC_ANALYSIS,
                evidence=[Evidence(description="No .symtab section was stripped from the binary")],
                impact="Symbol names make reverse engineering meaningfully easier — not a "
                       "vulnerability by itself, but worth an intentional decision for release builds.",
                remediation="Strip release builds (`strip <binary>`) if symbol names aren't needed "
                            "for crash reporting/debugging in production.",
                detector_sources=[self.name],
            ))
        return out

    def _string_findings(self, strings: list[str], rel: str, target: str) -> list[Finding]:
        out = []
        seen_rules = set()
        for s in strings:
            for rule in STRING_RULES:
                if rule["id"] in seen_rules:
                    continue  # one finding per rule per binary, not one per matching string
                if rule["pattern"].search(s):
                    seen_rules.add(rule["id"])
                    out.append(Finding(
                        id=new_finding_id(prefix="BL-BIN"),
                        title=rule["title"], category=rule["category"], subcategory=rule["subcategory"],
                        severity=rule["severity"], confidence=rule["confidence"],
                        validation_status=ValidationStatus.SUSPECTED,
                        affected_target=target, affected_component=rel, location=rel,
                        detection_method=DetectionMethod.STATIC_ANALYSIS,
                        evidence=[Evidence(description=f"Pattern {rule['id']} matched an extracted string",
                                            snippet=s[:120])],
                        impact=rule["impact"], remediation=rule["remediation"],
                        risk_factors=rule["risk"], detector_sources=[self.name],
                    ))
        return out
