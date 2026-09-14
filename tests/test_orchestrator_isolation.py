import unittest
from pathlib import Path

from app.analyzers.base import Analyzer, AnalyzerRegistry
from app.core.models import AnalyzerCapability, CapabilityLevel, ScanConfig, TargetProfile
from app.core.orchestrator import ScanOrchestrator

FIXTURE = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-python")


class DeliberatelyBrokenAnalyzer(Analyzer):
    name = "broken_analyzer"
    display_name = "Deliberately Broken Analyzer"

    def applies_to(self, profile: TargetProfile) -> bool:
        return True

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.EXPERIMENTAL)

    def run(self, profile, config):
        raise RuntimeError("intentional analyzer failure for isolation testing")


class WorkingAnalyzer(Analyzer):
    name = "working_analyzer"
    display_name = "Working Analyzer"

    def applies_to(self, profile: TargetProfile) -> bool:
        return True

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.FULL_SUPPORT)

    def run(self, profile, config):
        from app.core.models import Finding, DetectionMethod, Severity, ValidationStatus, new_finding_id
        return [Finding(
            id=new_finding_id(), title="Test finding", category="Test", subcategory="Test",
            severity=Severity.LOW, confidence=50, validation_status=ValidationStatus.SUSPECTED,
            affected_target=profile.target_path, affected_component="test", location=None,
            detection_method=DetectionMethod.STATIC_ANALYSIS, detector_sources=[self.name],
        )]


class TestOrchestratorIsolation(unittest.TestCase):
    def test_one_broken_analyzer_does_not_kill_the_scan(self):
        registry = AnalyzerRegistry()
        registry.register(DeliberatelyBrokenAnalyzer())
        registry.register(WorkingAnalyzer())

        orchestrator = ScanOrchestrator(registry=registry)
        config = ScanConfig.for_profile("quick")
        result = orchestrator.run_scan("isolation_test", FIXTURE, config)

        self.assertEqual(result.status, "completed",
                          "A single broken analyzer crashed the entire scan — isolation failed")

        stage_names = {s.stage_name: s for s in result.stage_results}
        self.assertIn("Deliberately Broken Analyzer", stage_names)
        self.assertEqual(stage_names["Deliberately Broken Analyzer"].status, "failed")
        self.assertIn("intentional analyzer failure", stage_names["Deliberately Broken Analyzer"].error)

        self.assertIn("Working Analyzer", stage_names)
        self.assertEqual(stage_names["Working Analyzer"].status, "completed")

        # The working analyzer's finding must still have made it through.
        self.assertTrue(any(f.title == "Test finding" for f in result.findings))

    def test_coverage_reflects_the_failed_stage(self):
        registry = AnalyzerRegistry()
        registry.register(DeliberatelyBrokenAnalyzer())
        orchestrator = ScanOrchestrator(registry=registry)
        result = orchestrator.run_scan("isolation_test_2", FIXTURE, ScanConfig.for_profile("quick"))
        by_stage = result.coverage["by_stage"]
        self.assertEqual(by_stage["Deliberately Broken Analyzer"], 0.0)


if __name__ == "__main__":
    unittest.main()
