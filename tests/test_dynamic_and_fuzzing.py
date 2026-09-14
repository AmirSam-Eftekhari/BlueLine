import sys
import tempfile
import unittest
from pathlib import Path

from app.fuzzing.engine import FuzzingEngine
from app.runtime.dynamic import DynamicRunner


class TestDynamicRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.script = Path(self.tmp.name) / "target.py"

    def tearDown(self):
        self.tmp.cleanup()

    def test_classifies_normal_exit(self):
        self.script.write_text("print('ok')")
        runner = DynamicRunner(timeout_seconds=3)
        obs = runner.run([sys.executable, str(self.script)])
        self.assertEqual(obs.classification, "normal")
        self.assertEqual(obs.exit_code, 0)

    def test_classifies_unhandled_exception_as_crash(self):
        self.script.write_text("raise RuntimeError('boom')")
        runner = DynamicRunner(timeout_seconds=3)
        obs = runner.run([sys.executable, str(self.script)])
        self.assertEqual(obs.classification, "crash")
        self.assertIn("RuntimeError", obs.stderr)

    def test_classifies_timeout(self):
        self.script.write_text("import time\ntime.sleep(30)")
        runner = DynamicRunner(timeout_seconds=1)
        obs = runner.run([sys.executable, str(self.script)])
        self.assertTrue(obs.timed_out)
        self.assertEqual(obs.classification, "timeout")

    def test_classifies_clean_nonzero_exit_separately_from_crash(self):
        self.script.write_text("import sys; sys.exit(3)")
        runner = DynamicRunner(timeout_seconds=3)
        obs = runner.run([sys.executable, str(self.script)])
        self.assertEqual(obs.classification, "nonzero_exit")
        self.assertEqual(obs.exit_code, 3)

    def test_spawn_error_on_nonexistent_binary(self):
        runner = DynamicRunner(timeout_seconds=3)
        obs = runner.run(["/definitely/does/not/exist/binary"])
        self.assertEqual(obs.classification, "spawn_error")
        self.assertIsNotNone(obs.error)

    def test_broken_target_does_not_raise_out_of_runner(self):
        # Malformed target = test data, not a BlueLine failure.
        self.script.write_bytes(b"\xff\xfe\x00garbage-not-a-real-script")
        runner = DynamicRunner(timeout_seconds=3)
        try:
            runner.run([sys.executable, str(self.script)])
        except Exception as e:  # pragma: no cover
            self.fail(f"DynamicRunner raised instead of reporting an observation: {e}")


class TestFuzzingEngine(unittest.TestCase):
    def test_finds_planted_crash_via_black_box_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "target.py"
            script.write_text(
                "import sys\n"
                "data = sys.stdin.buffer.read()\n"
                "text = data.decode('utf-8', errors='replace')\n"
                "if '\\x00' in text:\n"
                "    raise ValueError('null byte crash')\n"
                "print(len(text))\n"
            )
            engine = FuzzingEngine(runner=DynamicRunner(timeout_seconds=2))
            campaign = engine.run_campaign([sys.executable, str(script)], seeds=["seed"],
                                            max_cases=200, time_budget_seconds=20)
            self.assertGreater(campaign.total_cases_run, 0)
            self.assertGreaterEqual(len(campaign.anomalies), 1,
                                     "Fuzzer failed to find a bug that's directly in its candidate corpus")
            self.assertTrue(any(a.classification == "crash" for a in campaign.anomalies))

    def test_anomalies_are_deduplicated_not_one_per_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "target.py"
            script.write_text("raise RuntimeError('always crashes')\n")
            engine = FuzzingEngine(runner=DynamicRunner(timeout_seconds=2))
            campaign = engine.run_campaign([sys.executable, str(script)], seeds=["seed"],
                                            max_cases=50, time_budget_seconds=15)
            # Every single case crashes identically -> must collapse to ONE anomaly, not 50.
            self.assertEqual(len(campaign.anomalies), 1)
            self.assertGreaterEqual(campaign.anomalies[0].occurrence_count, 2)


if __name__ == "__main__":
    unittest.main()
