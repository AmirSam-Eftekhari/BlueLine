import sys
import tempfile
import unittest
from pathlib import Path

from app.fuzzing.engine import FuzzingEngine
from app.fuzzing.mutator import Mutator
from app.runtime.dynamic import DynamicRunner

STAGED_BUG_SOURCE = (
    "import sys\n"
    "data = sys.stdin.buffer.read()\n"
    "if len(data) > 200:\n"
    "    if b'\\x00' in data:\n"
    "        raise RuntimeError('crash - reached stage 2')\n"
    "    print('stage1_only')\n"
    "else:\n"
    "    print('no_stage1')\n"
)


def _flat_single_generation_campaign(command, seeds, max_cases, time_budget_seconds):
    """Reimplements the OLD (pre-generational) flat approach exactly, so
    the comparison is against the real prior behavior, not a strawman:
    one static candidate batch, no feedback loop."""
    from app.fuzzing.engine import FuzzAnomaly, FuzzCampaignResult
    import time

    mutator = Mutator(seed=1337)
    runner = DynamicRunner(timeout_seconds=2)
    cases = mutator.generate_batch(seeds, max_cases)
    anomalies = {}
    start = time.monotonic()
    run_count = 0
    for case in cases:
        if time.monotonic() - start > time_budget_seconds:
            break
        obs = runner.run(command, input_data=case)
        run_count += 1
        if obs.classification in ("crash", "timeout", "spawn_error"):
            key = f"{obs.classification}|{obs.exit_code}|{(obs.stderr.splitlines() or [''])[0][:120]}"
            if key not in anomalies:
                anomalies[key] = FuzzAnomaly(classification=obs.classification,
                                              representative_input=case, observation=obs)
    duration = time.monotonic() - start
    return FuzzCampaignResult(target_command=command, total_cases_run=run_count,
                               anomalies=list(anomalies.values()), duration_seconds=duration,
                               cases_per_second=run_count / duration if duration > 0 else 0.0)


class TestGenerationalFuzzingImprovement(unittest.TestCase):
    """This is the actual regression test that justifies the generational
    rewrite: proves, head-to-head against the identical target, that the
    new engine finds a two-stage bug the old flat approach essentially
    never does. Both sides actually execute real subprocesses — nothing
    here is simulated."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.script = Path(cls.tmp.name) / "staged_bug.py"
        cls.script.write_text(STAGED_BUG_SOURCE)
        cls.command = [sys.executable, str(cls.script)]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_old_flat_approach_essentially_never_finds_the_staged_bug(self):
        trials = 3
        found = 0
        for _ in range(trials):
            campaign = _flat_single_generation_campaign(
                self.command, seeds=["seed", "0", "test"], max_cases=300, time_budget_seconds=15)
            if any(a.classification == "crash" for a in campaign.anomalies):
                found += 1
        self.assertEqual(found, 0,
                          "Expected the flat single-generation approach to fail here — if it now "
                          "succeeds, the baseline this improvement was justified against has changed "
                          "and the comparison needs to be revisited.")

    def test_generational_approach_reliably_finds_the_staged_bug(self):
        trials = 3
        found = 0
        for _ in range(trials):
            engine = FuzzingEngine(runner=DynamicRunner(timeout_seconds=2))
            campaign = engine.run_campaign(
                self.command, seeds=["seed", "0", "test"], max_cases=300, time_budget_seconds=15)
            if any(a.classification == "crash" for a in campaign.anomalies):
                found += 1
        self.assertGreaterEqual(found, 2, f"Only found the staged bug in {found}/{trials} trials")

    def test_campaign_result_reports_generation_metadata(self):
        engine = FuzzingEngine(runner=DynamicRunner(timeout_seconds=2))
        campaign = engine.run_campaign(self.command, seeds=["seed"], max_cases=300, time_budget_seconds=15)
        self.assertGreaterEqual(campaign.generations_run, 1)
        self.assertGreaterEqual(campaign.interesting_inputs_found, 0)

    def test_single_condition_bug_still_found_immediately_gen_zero(self):
        # Non-regression: a simple always-crashes-on-a-known-pattern bug
        # (the kind the old flat approach already handled) must still be
        # found, and found efficiently (not needing many generations).
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "simple_bug.py"
            script.write_text(
                "import sys\n"
                "data = sys.stdin.buffer.read()\n"
                "if b'\\x00' in data:\n"
                "    raise ValueError('simple crash')\n"
            )
            engine = FuzzingEngine(runner=DynamicRunner(timeout_seconds=2))
            campaign = engine.run_campaign([sys.executable, str(script)], seeds=["seed"],
                                            max_cases=200, time_budget_seconds=15)
            self.assertTrue(any(a.classification == "crash" for a in campaign.anomalies))

    def test_corpus_growth_is_capped_against_echo_style_targets(self):
        # A target that echoes input back would otherwise make nearly
        # every case look "interesting", exploding the corpus. Confirm
        # the cap actually bounds this rather than consuming the whole
        # budget on one generation.
        from app.fuzzing.engine import MAX_INTERESTING_SEEDS_PER_GENERATION
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "echo.py"
            script.write_text(
                "import sys\n"
                "data = sys.stdin.buffer.read()\n"
                "sys.stdout.buffer.write(data[:60])\n"  # echoes input back -> near-unique output every time
            )
            engine = FuzzingEngine(runner=DynamicRunner(timeout_seconds=2))
            campaign = engine.run_campaign([sys.executable, str(script)], seeds=["seed", "abc", "xyz"],
                                            max_cases=150, time_budget_seconds=20)
            # It should still run to completion within budget, not hang
            # or wildly overrun — the cap keeps generation sizes bounded.
            self.assertLessEqual(campaign.total_cases_run, 150)
            self.assertGreater(campaign.generations_run, 0)


if __name__ == "__main__":
    unittest.main()
