import unittest

from app.core.correlation import FindingCorrelator
from app.core.coverage import CoverageEngine
from app.core.models import (
    AnalyzerCapability, CapabilityLevel, DetectionMethod, Finding, RiskFactors, Severity,
    StageResult, TargetProfile, ValidationStatus, new_finding_id,
)
from app.core.risk import RiskEngine


class TestRiskEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RiskEngine()

    def test_max_factors_yield_max_score(self):
        factors = RiskFactors(impact=10, exploitability=10, exposure=10, confidence=100, reproducibility=10)
        self.assertEqual(self.engine.score(factors), 100.0)

    def test_min_factors_yield_zero_score(self):
        factors = RiskFactors(impact=0, exploitability=0, exposure=0, confidence=0, reproducibility=0)
        self.assertEqual(self.engine.score(factors), 0.0)

    def test_severity_bands_are_monotonic_with_score(self):
        prev_rank = -1
        for score in [0, 10, 20, 40, 50, 65, 80, 90, 100]:
            sev = self.engine.severity_from_score(score)
            self.assertGreaterEqual(sev.rank, prev_rank)
            prev_rank = sev.rank if sev.rank >= prev_rank else prev_rank

    def test_explain_contributions_sum_to_score(self):
        factors = RiskFactors(impact=7, exploitability=5, exposure=6, confidence=80, reproducibility=9)
        score = self.engine.score(factors)
        explanation = self.engine.explain(factors)
        self.assertAlmostEqual(explanation["total"], score, delta=0.2)

    def test_severity_and_confidence_are_independent(self):
        # A finding can be high-severity but low-confidence — the engine
        # must not silently conflate the two into one number.
        factors = RiskFactors(impact=10, exploitability=9, exposure=8, confidence=20, reproducibility=3)
        f = Finding(id=new_finding_id(), title="t", category="c", subcategory="s",
                    severity=Severity.LOW, confidence=20, validation_status=ValidationStatus.SUSPECTED,
                    affected_target="t", affected_component="c", location=None,
                    detection_method=DetectionMethod.STATIC_ANALYSIS, risk_factors=factors)
        self.engine.apply(f)
        self.assertEqual(f.confidence, 20)  # confidence untouched by risk scoring
        self.assertNotEqual(f.risk_score, f.confidence)


class TestCoverageEngine(unittest.TestCase):
    def test_never_reports_100_percent_when_a_stage_failed(self):
        stages = [
            StageResult(stage_name="A", status="completed", started_at="t", coverage_impact=0),
            StageResult(stage_name="B", status="failed", started_at="t", coverage_impact=100),
        ]
        profile = TargetProfile(target_path="/x", target_type="t")
        result = CoverageEngine().compute(profile, stages)
        self.assertEqual(result["by_stage"]["B"], 0.0)
        self.assertLess(result["overall_assessment_coverage"], 100.0)

    def test_skipped_stage_is_not_counted_as_zero_or_full(self):
        stages = [StageResult(stage_name="A", status="skipped", started_at="t")]
        result = CoverageEngine().compute(TargetProfile(target_path="/x", target_type="t"), stages)
        self.assertIsNone(result["by_stage"]["A"])


class TestFindingCorrelator(unittest.TestCase):
    def _finding(self, validation, source, location="f.py:1"):
        return Finding(
            id=new_finding_id(), title="Same bug", category="Injection", subcategory="SQLi",
            severity=Severity.MEDIUM, confidence=60, validation_status=validation,
            affected_target="t", affected_component="f.py", location=location,
            detection_method=DetectionMethod.STATIC_ANALYSIS, detector_sources=[source],
        )

    def test_duplicate_findings_from_different_analyzers_are_merged(self):
        a = self._finding(ValidationStatus.SUSPECTED, "static_analyzer")
        b = self._finding(ValidationStatus.CONFIRMED, "fuzzer")
        merged = FindingCorrelator().correlate([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].validation_status, ValidationStatus.CONFIRMED)
        self.assertIn("static_analyzer", merged[0].detector_sources)
        self.assertIn("fuzzer", merged[0].detector_sources)

    def test_distinct_locations_are_not_merged(self):
        a = self._finding(ValidationStatus.SUSPECTED, "static_analyzer", location="f.py:1")
        b = self._finding(ValidationStatus.SUSPECTED, "static_analyzer", location="f.py:99")
        merged = FindingCorrelator().correlate([a, b])
        self.assertEqual(len(merged), 2)


if __name__ == "__main__":
    unittest.main()
