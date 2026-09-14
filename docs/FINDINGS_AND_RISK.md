# Understanding BlueLine Findings

Every finding BlueLine reports carries several independent fields. They
are independent on purpose — collapsing them into one number would hide
information you need to triage correctly.

## Severity vs. Confidence vs. Validation Status — three different axes

| Field | Question it answers | Values |
|---|---|---|
| **Severity** | *If this is real, how bad is it?* | INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL |
| **Confidence** | *How sure is the detector that this is real?* | 0-100% |
| **Validation Status** | *Has this actually been confirmed?* | CONFIRMED, PROBABLE, SUSPECTED, UNVERIFIED, FALSE_POSITIVE |

A finding can legitimately be **CRITICAL severity at 35% confidence** —
that combination means "if this pattern is really exploitable the way
it looks, it's very bad, but we're not very sure it actually is." Don't
read severity alone as a priority order; check confidence and
validation status too.

**Validation Status specifically:**
- `CONFIRMED` — actually reproduced with concrete evidence. In this
  codebase, that's earned two ways: a dynamic/fuzz run that actually
  crashed the target (see `app/core/orchestrator.py::_finding_from_observation`,
  which always sets `CONFIRMED` because the crash just happened, live),
  or a live HTTP response BlueLine directly observed (the Web/API
  analyzer's header/cookie/CORS findings — it saw the actual response).
- `PROBABLE` — strong static evidence for a well-established bad
  pattern (e.g. Python's `PY-DEBUG-FLASK` rule at 95% confidence) but
  not dynamically reproduced.
- `SUSPECTED` — a heuristic pattern match, plausible but unconfirmed.
  This is the default for every regex/pattern-based analyzer (JS, Java,
  Go, Ruby, PHP, C/C++) — see each analyzer's module docstring for why.
- `UNVERIFIED` — informational, or couldn't be checked against real
  data (e.g. a dependency not in BlueLine's small curated vulnerability
  sample).
- `FALSE_POSITIVE` — for manual triage workflows; nothing in the current
  engine sets this automatically.

## The Risk Score formula (fully documented, not a black box)

From `app/core/risk.py`:

```
risk_score = (
    0.35 * impact +
    0.25 * exploitability +
    0.15 * exposure +
    0.15 * confidence +
    0.10 * reproducibility
) * 100
```

Each factor (except confidence, already 0-100) is authored on a 0-10
scale and normalized before weighting. Severity is then derived from
the score using fixed, inspectable bands:

| Score | Severity |
|---|---|
| ≥ 85 | CRITICAL |
| ≥ 65 | HIGH |
| ≥ 40 | MEDIUM |
| ≥ 15 | LOW |
| < 15 | INFORMATIONAL |

Calling `RiskEngine.explain(factors)` returns the exact per-factor
contribution to the final score — this is what a "why did this get
scored this way" UI panel would show, and it's exercised in
`tests/test_risk_coverage_correlation.py`.

## Coverage: what was actually tested, not assumed

`app/core/coverage.py` computes coverage **per stage**, from real
`StageResult` outcomes:
- A stage that completed successfully: up to 100%, reduced by any
  partial `coverage_impact` it reported.
- A stage that failed (an analyzer threw an exception): **0%**, always
  — a crashed analyzer contributes nothing, and that's visible.
- A stage that was skipped (e.g. Dynamic Analysis with no runnable
  entry point): reported as `null`/"N/A (skipped)", deliberately
  distinct from both 0% and 100% — skipped is not the same claim as
  "ran and found a clean surface."

`Overall Assessment Coverage` is the average of the *measured* stages
only (skipped stages don't count against or for it). The accompanying
note field is included in every report and is worth repeating here
verbatim, since it's the single most important sentence in the whole
product:

> Coverage reflects what was actually executed and validated, not an
> assumption of completeness. A high coverage percentage means the
> applicable analyzers ran successfully across the applicable surface —
> it does not mean no vulnerabilities remain outside that surface.

## Finding Correlation: why you won't see the same bug five times

`app/core/correlation.py` groups findings sharing a fingerprint
(category + subcategory + affected component + location) into one
merged finding. If the static analyzer flags something as `SUSPECTED`
and the fuzzer later independently crashes that exact code path
(`CONFIRMED`), the merged finding takes the **higher** validation
status and **highest** confidence of the group, and lists every
detector that contributed. This is proven, not assumed — see
`tests/test_web_api_analyzer.py` and the dynamic/fuzzing test suite for
a case where two independent engines find the same real bug and get
merged into a single `CONFIRMED` finding.

## Capability Levels: what "supported" actually means here

Every analyzer declares one of these for the specific target it's
looking at (`app/core/models.py::CapabilityLevel`):

| Level | Meaning in this codebase |
|---|---|
| `FULL_SUPPORT` | Python only — real AST parser, broad rule coverage |
| `PARTIAL_SUPPORT` | JS/TS, Java, Go, Ruby, PHP, dependencies, Web/API — real detection, but pattern-based or narrow-scope, not a complete parser/live-traffic scanner |
| `EXPERIMENTAL` | C/C++ — pattern-matching on a handful of calls, deliberately low confidence |
| `UNSUPPORTED` | Any other detected language (Rust, etc.) — detected, but no analyzer runs |

This is shown in the Target Setup screen, the Settings screen, and
every generated report — the same source of truth
(`TargetDiscovery._capabilities_for`) feeds all three, so they can't
drift out of sync with each other.
