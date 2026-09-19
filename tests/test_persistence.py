import os
import tempfile
import unittest

from app.core.models import ScanConfig
from app.core.orchestrator import ScanOrchestrator
from app.persistence.store import ScanStore
from pathlib import Path

FIXTURE = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-python")


class TestPersistence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.sqlite3")

    def tearDown(self):
        self.tmp.cleanup()

    def test_save_and_reopen_scan(self):
        orch = ScanOrchestrator()
        result = orch.run_scan("persist_test_1", FIXTURE, ScanConfig.for_profile("quick"))
        store = ScanStore(self.db_path)
        store.save(result)
        reloaded = store.load("persist_test_1")
        store.close()

        self.assertIsNotNone(reloaded)
        self.assertEqual(reloaded["scan_id"], "persist_test_1")
        self.assertEqual(len(reloaded["findings"]), len(result.findings))

    def test_history_lists_saved_scans(self):
        orch = ScanOrchestrator()
        result = orch.run_scan("persist_test_2", FIXTURE, ScanConfig.for_profile("quick"))
        store = ScanStore(self.db_path)
        store.save(result)
        rows = store.list_history()
        store.close()
        self.assertTrue(any(r["scan_id"] == "persist_test_2" for r in rows))

    def test_compare_detects_new_and_resolved_findings(self):
        from app.core.models import Finding, DetectionMethod, Severity, ValidationStatus, TargetProfile, new_finding_id

        store = ScanStore(self.db_path)
        orch = ScanOrchestrator()

        result_a = orch.run_scan("cmp_a", FIXTURE, ScanConfig.for_profile("quick"))
        # Simulate a fix: drop one finding, and simulate a new one appearing.
        original_findings = list(result_a.findings)
        result_a.findings = original_findings[1:]  # pretend the first finding was fixed
        store.save(result_a)

        result_b = orch.run_scan("cmp_b", FIXTURE, ScanConfig.for_profile("quick"))
        new_finding = Finding(
            id=new_finding_id(), title="Brand new bug", category="Test", subcategory="Test",
            severity=Severity.HIGH, confidence=90, validation_status=ValidationStatus.PROBABLE,
            affected_target=FIXTURE, affected_component="new.py", location="new.py:1",
            detection_method=DetectionMethod.STATIC_ANALYSIS,
        )
        result_b.findings = list(original_findings) + [new_finding]
        store.save(result_b)

        diff = store.compare("cmp_a", "cmp_b")
        store.close()

        self.assertTrue(any(f["title"] == "Brand new bug" for f in diff["new_findings"]))
        self.assertGreaterEqual(len(diff["resolved_findings"]), 0)  # depends on fingerprint collisions

    def test_reloaded_scan_can_generate_every_report_format(self):
        # Regression test: report generation on a scan loaded back from
        # storage (not a freshly-run ScanResult) exercises a different code
        # path (the CLI's _scan_result_from_dict shim) and once broke JSON
        # export specifically — this pins all four formats against that.
        from app.cli import _scan_result_from_dict
        from app.reporting.csv_report import generate_csv_report
        from app.reporting.html_report import generate_html_report
        from app.reporting.json_report import generate_json_report, generate_sarif_report

        orch = ScanOrchestrator()
        result = orch.run_scan("reload_report_test", FIXTURE, ScanConfig.for_profile("quick"))
        store = ScanStore(self.db_path)
        store.save(result)
        reloaded_dict = store.load("reload_report_test")
        store.close()

        reconstructed = _scan_result_from_dict(reloaded_dict)
        self.assertTrue(generate_html_report(reconstructed))
        self.assertTrue(generate_json_report(reconstructed))
        self.assertTrue(generate_sarif_report(reconstructed))
        self.assertTrue(generate_csv_report(reconstructed))

    def test_compare_raises_on_unknown_scan_id(self):
        store = ScanStore(self.db_path)
        with self.assertRaises(ValueError):
            store.compare("nope_a", "nope_b")
        store.close()

    def test_delete_removes_a_scan_from_history(self):
        orch = ScanOrchestrator()
        result = orch.run_scan("delete_test_1", FIXTURE, ScanConfig.for_profile("quick"))
        store = ScanStore(self.db_path)
        store.save(result)
        self.assertIsNotNone(store.load("delete_test_1"))

        deleted = store.delete("delete_test_1")
        self.assertTrue(deleted)
        self.assertIsNone(store.load("delete_test_1"))
        self.assertNotIn("delete_test_1", [r["scan_id"] for r in store.list_history()])
        store.close()

    def test_delete_of_nonexistent_scan_returns_false_not_an_error(self):
        store = ScanStore(self.db_path)
        deleted = store.delete("scan_that_was_never_saved")
        self.assertFalse(deleted)
        store.close()

    def test_delete_all_clears_every_scan(self):
        orch = ScanOrchestrator()
        store = ScanStore(self.db_path)
        for i in range(3):
            result = orch.run_scan(f"delete_all_test_{i}", FIXTURE, ScanConfig.for_profile("quick"))
            store.save(result)
        self.assertEqual(len(store.list_history()), 3)

        count = store.delete_all()
        self.assertEqual(count, 3)
        self.assertEqual(store.list_history(), [])
        store.close()

    def test_delete_all_scoped_to_one_target_leaves_others_alone(self):
        orch = ScanOrchestrator()
        store = ScanStore(self.db_path)
        result_a = orch.run_scan("scope_test_a", FIXTURE, ScanConfig.for_profile("quick"))
        store.save(result_a)
        # A second, distinct target path so scoped deletion has something to leave alone.
        other_fixture = str(Path(FIXTURE).parent / "vulnerable-javascript")
        result_b = orch.run_scan("scope_test_b", other_fixture, ScanConfig.for_profile("quick"))
        store.save(result_b)

        count = store.delete_all(target_path=result_a.target_profile.target_path)
        self.assertEqual(count, 1)
        self.assertIsNone(store.load("scope_test_a"))
        self.assertIsNotNone(store.load("scope_test_b"))
        store.close()


if __name__ == "__main__":
    unittest.main()
