import unittest
from pathlib import Path

from app.analyzers.dependency import DependencyAnalyzer
from app.core.models import ScanConfig
from app.targets.discovery import TargetDiscovery

PY_FIXTURE = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-python")
JS_FIXTURE = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-javascript")


class TestDependencyAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = DependencyAnalyzer()
        self.config = ScanConfig.for_profile("standard")

    def test_flags_known_vulnerable_pip_package(self):
        profile = TargetDiscovery().discover(PY_FIXTURE)
        findings = self.analyzer.run(profile, self.config)
        pkgs_flagged = {f.affected_component.split("==")[0] for f in findings
                        if f.subcategory == "KNOWN_VULNERABILITY"}
        self.assertIn("pyyaml", pkgs_flagged)
        self.assertIn("requests", pkgs_flagged)

    def test_flags_known_vulnerable_npm_package(self):
        profile = TargetDiscovery().discover(JS_FIXTURE)
        findings = self.analyzer.run(profile, self.config)
        pkgs_flagged = {f.affected_component.split("==")[0] for f in findings
                        if f.subcategory == "KNOWN_VULNERABILITY"}
        self.assertIn("lodash", pkgs_flagged)
        self.assertIn("minimist", pkgs_flagged)

    def test_never_invents_a_cve_for_unknown_package(self):
        profile = TargetDiscovery().discover(PY_FIXTURE)
        findings = self.analyzer.run(profile, self.config)
        # 'click' is in requirements.txt but NOT in our curated sample —
        # the analyzer must say nothing about it rather than guess.
        click_findings = [f for f in findings if f.affected_component.startswith("click")]
        for f in click_findings:
            self.assertNotEqual(f.subcategory, "KNOWN_VULNERABILITY")

    def test_patched_version_is_not_flagged(self):
        from app.analyzers.dependency import DependencyAnalyzer, KnownVuln, VulnerabilityFeed
        feed = VulnerabilityFeed([KnownVuln("demo-pkg", "pip", "2.0.0", "CVE-0000-0000",
                                             "test", __import__("app.core.models", fromlist=["Severity"]).Severity.HIGH, 80)])
        analyzer = DependencyAnalyzer(feed=feed)
        f = analyzer._check_version("demo-pkg", "2.0.0", "pip", "requirements.txt", 1, "/tmp")
        self.assertIsNone(f, "A version equal to the fixed version must not be flagged as vulnerable")


if __name__ == "__main__":
    unittest.main()
