import json
import unittest
from pathlib import Path
from unittest import mock

from app.core import logging_setup, paths


class TestLoggingSetup(unittest.TestCase):
    def setUp(self):
        # Reset the module-level logger cache and any handlers between
        # tests so each test gets a fresh logger pointed at its own tmp dir.
        for logger in logging_setup._LOGGERS.values():
            for h in list(logger.handlers):
                logger.removeHandler(h)
                h.close()
        logging_setup._LOGGERS.clear()

    def test_creates_separate_log_files_per_stream(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(paths, "user_data_dir", return_value=Path(tmp)):
                for name in logging_setup.LOG_NAMES:
                    logging_setup.log_structured(name, f"test message for {name}")
                log_dir = Path(tmp) / "logs"
                for name in logging_setup.LOG_NAMES:
                    self.assertTrue((log_dir / f"{name}.log").exists(), f"{name}.log was not created")

    def test_log_entries_are_valid_json_lines(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(paths, "user_data_dir", return_value=Path(tmp)):
                logging_setup.log_structured("scanner", "stage completed", stage="Python Static Analyzer",
                                              status="completed", findings=5)
                log_file = Path(tmp) / "logs" / "scanner.log"
                lines = log_file.read_text().strip().splitlines()
                self.assertEqual(len(lines), 1)
                entry = json.loads(lines[0])  # must not raise
                self.assertEqual(entry["level"], "INFO")
                self.assertEqual(entry["logger"], "blueline.scanner")
                self.assertEqual(entry["data"]["stage"], "Python Static Analyzer")
                self.assertEqual(entry["data"]["findings"], 5)

    def test_a_real_scan_produces_scanner_and_security_log_entries(self):
        import tempfile
        from app.core.orchestrator import ScanOrchestrator
        from app.core.models import ScanConfig

        fixture = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-python")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(paths, "user_data_dir", return_value=Path(tmp)):
                orch = ScanOrchestrator()
                orch.run_scan("log_test_scan", fixture, ScanConfig.for_profile("quick"))

                scanner_log = (Path(tmp) / "logs" / "scanner.log").read_text()
                self.assertIn("Scan started", scanner_log)
                self.assertIn("Scan finished", scanner_log)
                self.assertIn("log_test_scan", scanner_log)

                security_log = (Path(tmp) / "logs" / "security.log").read_text()
                self.assertTrue(security_log.strip(), "Expected at least one HIGH/CRITICAL finding logged")

    def test_security_log_never_contains_finding_evidence_or_snippets(self):
        # Privacy guarantee: the security log carries metadata (id,
        # category, location) about a finding, never the actual evidence
        # snippet — which could be a real secret string or source code
        # extracted from the target.
        import tempfile
        from app.core.orchestrator import ScanOrchestrator
        from app.core.models import ScanConfig

        fixture = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-python")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(paths, "user_data_dir", return_value=Path(tmp)):
                orch = ScanOrchestrator()
                result = orch.run_scan("log_privacy_test", fixture, ScanConfig.for_profile("quick"))

                # The fixture contains a literal hardcoded API key string —
                # confirm it exists in a finding's evidence, then confirm
                # that exact string never appears in the security log.
                secret_findings = [f for f in result.findings if f.subcategory == "Hardcoded Secret"]
                self.assertTrue(secret_findings)
                snippet = secret_findings[0].evidence[0].snippet if secret_findings[0].evidence else None

                security_log = (Path(tmp) / "logs" / "security.log").read_text()
                for line in security_log.strip().splitlines():
                    entry = json.loads(line)
                    self.assertNotIn("evidence", entry.get("data", {}))
                    self.assertNotIn("snippet", entry.get("data", {}))
                if snippet:
                    self.assertNotIn(snippet, security_log)

    def test_analyzer_log_records_a_stage_failure(self):
        import tempfile
        from app.analyzers.base import Analyzer, AnalyzerRegistry
        from app.core.models import AnalyzerCapability, CapabilityLevel, ScanConfig
        from app.core.orchestrator import ScanOrchestrator

        class BrokenAnalyzer(Analyzer):
            name = "broken"
            display_name = "Broken For Logging Test"

            def applies_to(self, profile):
                return True

            def capability_for(self, profile):
                return AnalyzerCapability(self.display_name, CapabilityLevel.EXPERIMENTAL)

            def run(self, profile, config):
                raise RuntimeError("boom for logging test")

        fixture = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-python")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(paths, "user_data_dir", return_value=Path(tmp)):
                registry = AnalyzerRegistry()
                registry.register(BrokenAnalyzer())
                orch = ScanOrchestrator(registry=registry)
                orch.run_scan("log_failure_test", fixture, ScanConfig.for_profile("quick"))

                analyzer_log = (Path(tmp) / "logs" / "analyzer.log").read_text()
                self.assertIn("Broken For Logging Test", analyzer_log)
                self.assertIn("boom for logging test", analyzer_log)


if __name__ == "__main__":
    unittest.main()
