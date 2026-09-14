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
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from app.fuzzing.mutator import Mutator
from app.runtime.dynamic import DynamicRunner, ExecutionObservation


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


class FuzzingEngine:
    def __init__(self, runner: DynamicRunner | None = None, mutator: Mutator | None = None):
        self.runner = runner or DynamicRunner(timeout_seconds=3)
        self.mutator = mutator or Mutator(seed=1337)  # fixed seed => reproducible campaigns by default

    def run_campaign(self, command: list[str], seeds: list[str], max_cases: int,
                      time_budget_seconds: int) -> FuzzCampaignResult:
        cases = self.mutator.generate_batch(seeds, max_cases)
        anomalies: dict[str, FuzzAnomaly] = {}
        start = time.monotonic()
        run_count = 0

        for case in cases:
            if time.monotonic() - start > time_budget_seconds:
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

        duration = time.monotonic() - start
        return FuzzCampaignResult(
            target_command=command,
            total_cases_run=run_count,
            anomalies=list(anomalies.values()),
            duration_seconds=round(duration, 2),
            cases_per_second=round(run_count / duration, 1) if duration > 0 else 0.0,
        )

    @staticmethod
    def _dedup_key(obs: ExecutionObservation) -> str:
        first_stderr_line = (obs.stderr.splitlines() or [""])[0][:120]
        return f"{obs.classification}|{obs.exit_code}|{first_stderr_line}"
