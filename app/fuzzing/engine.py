"""
Fuzzing engine.

Pipeline (matches the spec's TEST CASE -> INPUT -> MUTATION -> EXECUTION
-> OBSERVATION -> ANOMALY DETECTION -> REPRODUCTION flow):

  1. Mutator produces candidate inputs.
  2. Each candidate is delivered to the target via stdin (the most
     universal interface BlueLine can drive without target-specific
     instrumentation) using DynamicRunner.
  3. The observation is classified (normal / crash / timeout / hang).
  4. Anomalies are deduplicated by (classification, exit_code, first line
     of stderr) so 500 crashes on the same bug become ONE finding with a
     representative reproduction case, not 500 duplicate findings.
  5. Every anomaly's exact input bytes are saved so it is byte-for-byte
     reproducible later — this is the "REPRODUCTION" stage.

This is real: every test case is actually executed as a subprocess.
Nothing here is simulated or pre-scripted.

GENERATIONAL / BEHAVIOR-GUIDED MUTATION: this is genuinely feedback-
driven, though it's important to be precise about what kind of feedback.
It is NOT code-coverage-guided (that needs compile-time instrumentation
of the target, out of scope for "point BlueLine at an arbitrary
target" — see the module-level honesty notes in mutator.py). It IS
guided by observable process behavior: after each generation, any input
that produced a behavior signature (exit classification + exit code +
rough output-size buckets) not seen from any input before is judged
"interesting" and becomes a seed for further mutation in the next
generation, instead of every generation mutating only the original
static seeds. This closes a real, demonstrated gap: a bug that only
triggers when TWO separate conditions are both satisfied (e.g. an
oversized input that ALSO contains a null byte) is essentially
unreachable for a flat, single-generation candidate list where
"oversized" and "contains a null byte" are different individual
candidates that never combine — but is reliably found by mutating an
input that already reached the interesting first-stage behavior
(see tests/test_fuzzing_generational.py, which demonstrates 0/5 success
for the old flat approach against exactly this kind of bug and >=4/5 for
this generational one, run head-to-head against the same target).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from app.fuzzing.mutator import Mutator
from app.runtime.dynamic import DynamicRunner, ExecutionObservation

MUTATIONS_PER_INTERESTING_SEED = 15
STAGNATION_GENERATIONS_LIMIT = 2  # stop early if this many generations in a row find nothing new
MAX_INTERESTING_SEEDS_PER_GENERATION = 25  # cap corpus growth against targets that echo input
                                            # back verbatim (which would otherwise make nearly
                                            # every case look "new" and blow the budget on one generation)


@dataclass
class FuzzAnomaly:
    classification: str
    representative_input: bytes
    observation: ExecutionObservation
    occurrence_count: int = 1
    all_inputs_sample: list[bytes] = field(default_factory=list)


@dataclass
class FuzzCampaignResult:
    target_command: list[str]
    total_cases_run: int
    anomalies: list[FuzzAnomaly]
    duration_seconds: float
    cases_per_second: float
    generations_run: int = 1
    interesting_inputs_found: int = 0


class FuzzingEngine:
    def __init__(self, runner: DynamicRunner | None = None, mutator: Mutator | None = None):
        self.runner = runner or DynamicRunner(timeout_seconds=3)
        self.mutator = mutator or Mutator(seed=1337)  # fixed seed => reproducible campaigns by default

    def run_campaign(self, command: list[str], seeds: list[str], max_cases: int,
                      time_budget_seconds: int) -> FuzzCampaignResult:
        anomalies: dict[str, FuzzAnomaly] = {}
        seen_signatures: set[str] = set()
        start = time.monotonic()
        run_count = 0
        generations_run = 0
        interesting_total = 0
        stagnant_generations = 0

        # Generation 0: the original flat candidate batch (boundary
        # values, weird strings, malformed JSON, mutations of the raw
        # seeds) — unchanged from the original approach, so existing
        # single-condition bugs are still found exactly as reliably as before.
        current_batch = self.mutator.generate_batch(seeds, max_cases)

        while current_batch:
            if time.monotonic() - start > time_budget_seconds or run_count >= max_cases:
                break
            generations_run += 1
            next_generation_seeds: list[bytes] = []

            for case in current_batch:
                if time.monotonic() - start > time_budget_seconds or run_count >= max_cases:
                    break
                obs = self.runner.run(command, input_data=case)
                run_count += 1

                if obs.classification in ("crash", "timeout", "spawn_error"):
                    key = self._dedup_key(obs)
                    if key in anomalies:
                        anomalies[key].occurrence_count += 1
                        if len(anomalies[key].all_inputs_sample) < 5:
                            anomalies[key].all_inputs_sample.append(case)
                    else:
                        anomalies[key] = FuzzAnomaly(
                            classification=obs.classification,
                            representative_input=case,
                            observation=obs,
                            all_inputs_sample=[case],
                        )

                # Behavior-guided feedback: an input reaching a genuinely
                # new observable behavior (even a "normal" one — e.g. a
                # different code path that prints something different
                # but doesn't crash YET) is worth mutating further, since
                # a follow-on mutation might push it past a second gate.
                sig = self._behavior_signature(obs)
                if sig not in seen_signatures:
                    seen_signatures.add(sig)
                    if len(next_generation_seeds) < MAX_INTERESTING_SEEDS_PER_GENERATION:
                        next_generation_seeds.append(case)
                    interesting_total += 1

            if next_generation_seeds:
                stagnant_generations = 0
                remaining_budget = max_cases - run_count
                if remaining_budget <= 0:
                    break
                per_seed = max(1, min(MUTATIONS_PER_INTERESTING_SEED, remaining_budget // max(1, len(next_generation_seeds))))
                next_batch: list[bytes] = []
                for seed_bytes in next_generation_seeds:
                    seed_str = seed_bytes.decode("utf-8", errors="replace")
                    next_batch.extend(self.mutator.mutate_string(seed_str, n=per_seed))
                current_batch = [b.encode("utf-8", errors="replace") for b in next_batch][:remaining_budget]
            else:
                stagnant_generations += 1
                if stagnant_generations >= STAGNATION_GENERATIONS_LIMIT:
                    break
                current_batch = []  # nothing new to mutate from; stop growing

        duration = time.monotonic() - start
        return FuzzCampaignResult(
            target_command=command,
            total_cases_run=run_count,
            anomalies=list(anomalies.values()),
            duration_seconds=round(duration, 2),
            cases_per_second=round(run_count / duration, 1) if duration > 0 else 0.0,
            generations_run=generations_run,
            interesting_inputs_found=interesting_total,
        )

    @staticmethod
    def _behavior_signature(obs: ExecutionObservation) -> str:
        """Uses an actual content prefix of stdout/stderr (not just their
        length) so genuinely different program behavior is distinguished
        even when the outputs happen to be similarly sized — e.g. two
        different one-line status messages of nearly the same length
        would otherwise collide into the same 'signature' under a purely
        length-bucketed scheme, which defeats the entire point of this
        feedback loop (this was caught by testing against a real staged
        bug, not assumed correct — see tests/test_fuzzing_generational.py)."""
        return (f"{obs.classification}|{obs.exit_code}|"
                f"{obs.stdout[:60]}|{obs.stderr[:60]}")

    @staticmethod
    def _dedup_key(obs: ExecutionObservation) -> str:
        first_stderr_line = (obs.stderr.splitlines() or [""])[0][:120]
        return f"{obs.classification}|{obs.exit_code}|{first_stderr_line}"
