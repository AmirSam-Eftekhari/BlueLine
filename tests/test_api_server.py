import tempfile
import unittest
from pathlib import Path

import app.api_server as api_server_module
from app.persistence.store import ScanStore

FIXTURE = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-python")


class TestApiServerDeleteEndpoints(unittest.TestCase):
    """Uses Flask's test client (in-process, no real network/subprocess)
    against the real api_server Flask app — but with its module-level
    `_store` swapped for an isolated temp-file store for the duration of
    these tests, so this never touches the real user's scan history."""

    @classmethod
    def setUpClass(cls):
        cls._original_store = api_server_module._store
        cls._tmp = tempfile.TemporaryDirectory()
        api_server_module._store = ScanStore(str(Path(cls._tmp.name) / "test.sqlite3"))
        cls.client = api_server_module.app.test_client()

    @classmethod
    def tearDownClass(cls):
        api_server_module._store.close()
        api_server_module._store = cls._original_store
        cls._tmp.cleanup()

    def _run_a_real_scan_via_api(self, target=FIXTURE):
        resp = self.client.post("/api/scan/start", json={"target_path": target, "profile": "quick"})
        scan_id = resp.get_json()["scan_id"]
        # Poll the real status endpoint until the real background scan finishes.
        import time
        deadline = time.time() + 15
        while time.time() < deadline:
            status = self.client.get(f"/api/scan/{scan_id}/status").get_json()
            if status["status"] in ("completed", "failed", "cancelled"):
                break
            time.sleep(0.1)
        return scan_id

    def test_delete_single_scan_via_api(self):
        scan_id = self._run_a_real_scan_via_api()
        history_before = [r["scan_id"] for r in self.client.get("/api/history").get_json()]
        self.assertIn(scan_id, history_before)

        resp = self.client.delete(f"/api/scan/{scan_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["deleted"])

        history_after = [r["scan_id"] for r in self.client.get("/api/history").get_json()]
        self.assertNotIn(scan_id, history_after)

    def test_delete_nonexistent_scan_returns_404(self):
        resp = self.client.delete("/api/scan/scan_definitely_not_real")
        self.assertEqual(resp.status_code, 404)
        self.assertIn("error", resp.get_json())

    def test_delete_all_history_via_api(self):
        self._run_a_real_scan_via_api()
        self._run_a_real_scan_via_api()
        self.assertGreaterEqual(len(self.client.get("/api/history").get_json()), 2)

        resp = self.client.delete("/api/history")
        self.assertEqual(resp.status_code, 200)
        self.assertGreaterEqual(resp.get_json()["deleted_count"], 2)
        self.assertEqual(self.client.get("/api/history").get_json(), [])

    def test_deleting_a_scan_still_findable_afterward_returns_404_not_stale_data(self):
        scan_id = self._run_a_real_scan_via_api()
        self.client.delete(f"/api/scan/{scan_id}")
        # Findings/report endpoints for a deleted scan must not silently
        # return stale cached data.
        findings_resp = self.client.get(f"/api/scan/{scan_id}/findings")
        self.assertEqual(findings_resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
