import unittest
from pathlib import Path

from app.analyzers.binary_analysis import BinaryAnalyzer
from app.core.models import ScanConfig
from app.targets.discovery import TargetDiscovery

FIXTURES = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-binaries")


class TestBinaryAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = TargetDiscovery().discover(FIXTURES)
        cls.findings = BinaryAnalyzer().run(cls.profile, ScanConfig.for_profile("standard"))

    def test_applies_to_target_with_executables(self):
        analyzer = BinaryAnalyzer()
        self.assertTrue(analyzer.applies_to(self.profile))

    def test_does_not_apply_to_source_only_target(self):
        py_profile = TargetDiscovery().discover(
            str(Path(FIXTURES).parent / "vulnerable-python"))
        self.assertFalse(BinaryAnalyzer().applies_to(py_profile))

    def test_declared_capability_is_partial_not_full(self):
        cap = BinaryAnalyzer().capability_for(self.profile)
        self.assertEqual(cap.level.value, "PARTIAL_SUPPORT")

    def test_detects_private_key_in_binary(self):
        key_findings = [f for f in self.findings if f.subcategory == "Embedded Private Key"]
        self.assertTrue(key_findings, "Failed to detect the planted private key string")
        self.assertEqual(key_findings[0].severity.value, "CRITICAL")
        self.assertEqual(key_findings[0].affected_component, "secrets_binary")

    def test_declared_severity_survives_risk_engine_scoring(self):
        # Regression: risk_factors authored for a rule must actually
        # produce the severity band the analyzer intends. This caught a
        # real bug where BIN-PRIVATE-KEY's own risk_factors scored into
        # the HIGH band instead of CRITICAL, and Missing-PIE scored into
        # MEDIUM instead of LOW — the analyzer's declared `severity=`
        # field is cosmetic once risk_factors are present; the formula
        # in RiskEngine is what actually wins (see docs/FINDINGS_AND_RISK.md).
        from app.core.risk import RiskEngine
        engine = RiskEngine()
        key_findings = [f for f in self.findings if f.subcategory == "Embedded Private Key"]
        pie_findings = [f for f in self.findings if f.subcategory == "Missing PIE"]
        self.assertTrue(key_findings and pie_findings)
        # These findings came straight from the analyzer (not through the
        # orchestrator's Risk Assessment stage), so apply the same engine
        # the orchestrator would, to check what severity it WOULD assign.
        engine.apply(key_findings[0])
        engine.apply(pie_findings[0])
        self.assertEqual(key_findings[0].severity.value, "CRITICAL")
        self.assertEqual(pie_findings[0].severity.value, "LOW")

    def test_detects_hardcoded_secret_in_binary(self):
        secret_findings = [f for f in self.findings if f.subcategory == "Hardcoded Secret"
                            and f.affected_component == "secrets_binary"]
        self.assertTrue(secret_findings, "Failed to detect the planted api_key string")

    def test_flags_missing_pie_on_nopie_binary_only(self):
        nopie_flags = [f for f in self.findings if f.subcategory == "Missing PIE"
                        and f.affected_component == "normal_nopie"]
        pie_flags = [f for f in self.findings if f.subcategory == "Missing PIE"
                     and f.affected_component == "normal_pie"]
        self.assertTrue(nopie_flags)
        self.assertFalse(pie_flags, "A PIE binary must not be flagged as missing PIE")

    def test_flags_unstripped_but_not_stripped_binary(self):
        unstripped = [f for f in self.findings if f.subcategory == "Unstripped Binary"
                      and f.affected_component == "normal_dynamic"]
        stripped_flagged = [f for f in self.findings if f.subcategory == "Unstripped Binary"
                             and f.affected_component == "normal_stripped"]
        self.assertTrue(unstripped)
        self.assertFalse(stripped_flagged, "A stripped binary must not be flagged as unstripped")

    def test_static_binary_gets_metadata_finding(self):
        static_findings = [f for f in self.findings if f.affected_component == "normal_static"]
        self.assertTrue(any("statically linked" in f.title for f in static_findings))

    def test_one_finding_per_string_rule_not_per_match(self):
        # secrets_binary embeds one private-key string and one secret
        # string — must produce ONE finding per rule, not a flood.
        key_findings = [f for f in self.findings if f.subcategory == "Embedded Private Key"
                         and f.affected_component == "secrets_binary"]
        self.assertEqual(len(key_findings), 1)

    def test_full_scan_via_orchestrator_includes_binary_findings(self):
        from app.core.orchestrator import ScanOrchestrator
        orch = ScanOrchestrator()
        result = orch.run_scan("binary_integration_test", FIXTURES, ScanConfig.for_profile("quick"))
        self.assertEqual(result.status, "completed")
        self.assertTrue(any(f.category == "Credential Management" for f in result.findings))

    def test_pe_file_gets_real_metadata_not_just_a_placeholder(self):
        import tempfile
        from tests.test_pe_parser import build_minimal_pe64

        with tempfile.TemporaryDirectory() as tmp:
            pe_path = Path(tmp) / "app.exe"
            pe_path.write_bytes(build_minimal_pe64(machine=0x8664, subsystem=3))
            profile = TargetDiscovery().discover(tmp)
            findings = BinaryAnalyzer().run(profile, ScanConfig.for_profile("standard"))
            profile_findings = [f for f in findings if f.subcategory == "Binary Profile"]
            self.assertTrue(profile_findings)
            self.assertIn("x86-64", profile_findings[0].title)
            self.assertIn("Windows Console", profile_findings[0].title)
            # Must NOT fall back to the generic "internals not parsed" placeholder.
            self.assertFalse(any(f.subcategory == "Unparsed Binary Format" for f in findings))


if __name__ == "__main__":
    unittest.main()
