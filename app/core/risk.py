"""
RiskEngine — transparent, documented risk scoring.

FORMULA (documented, not hidden):

    risk_score = (
        0.35 * impact_norm +
        0.25 * exploitability_norm +
        0.15 * exposure_norm +
        0.15 * confidence_norm +
        0.10 * reproducibility_norm
    ) * 100

Where each *_norm is the raw factor normalized to a 0-1 scale
(impact/exploitability/exposure/reproducibility are authored on a 0-10
scale; confidence is already 0-100).

Severity is then derived from risk_score using fixed bands. Severity and
risk_score are DIFFERENT things: severity is a coarse bucket for triage,
risk_score is the underlying continuous number, and confidence is a
separate axis entirely (how sure we are the finding is real). A finding
can be CRITICAL severity with only 40% confidence — that combination is
valid and must be shown to the user, not hidden by picking one number.
"""

from __future__ import annotations

from app.core.models import Finding, RiskFactors, Severity

WEIGHTS = {
    "impact": 0.35,
    "exploitability": 0.25,
    "exposure": 0.15,
    "confidence": 0.15,
    "reproducibility": 0.10,
}

SEVERITY_BANDS = [
    (85, Severity.CRITICAL),
    (65, Severity.HIGH),
    (40, Severity.MEDIUM),
    (15, Severity.LOW),
    (0, Severity.INFORMATIONAL),
]


class RiskEngine:
    """Computes a transparent 0-100 risk score from RiskFactors."""

    def score(self, factors: RiskFactors) -> float:
        impact_norm = _clamp01(factors.impact / 10.0)
        exploit_norm = _clamp01(factors.exploitability / 10.0)
        exposure_norm = _clamp01(factors.exposure / 10.0)
        confidence_norm = _clamp01(factors.confidence / 100.0)
        repro_norm = _clamp01(factors.reproducibility / 10.0)

        score = (
            WEIGHTS["impact"] * impact_norm
            + WEIGHTS["exploitability"] * exploit_norm
            + WEIGHTS["exposure"] * exposure_norm
            + WEIGHTS["confidence"] * confidence_norm
            + WEIGHTS["reproducibility"] * repro_norm
        ) * 100
        return round(score, 1)

    def severity_from_score(self, score: float) -> Severity:
        for threshold, severity in SEVERITY_BANDS:
            if score >= threshold:
                return severity
        return Severity.INFORMATIONAL

    def apply(self, finding: Finding) -> Finding:
        """Mutates finding in place: sets risk_score and (if not already
        pinned by the analyzer) recomputes severity from the score so
        severity is always consistent with the transparent formula."""
        if finding.risk_factors is None:
            # No factors supplied (e.g. purely informational finding) — leave as-is.
            return finding
        finding.risk_score = self.score(finding.risk_factors)
        finding.severity = self.severity_from_score(finding.risk_score)
        return finding

    def explain(self, factors: RiskFactors) -> dict:
        """Returns the score plus a per-factor breakdown, for UI display."""
        contributions = {
            "impact": round(WEIGHTS["impact"] * _clamp01(factors.impact / 10.0) * 100, 1),
            "exploitability": round(WEIGHTS["exploitability"] * _clamp01(factors.exploitability / 10.0) * 100, 1),
            "exposure": round(WEIGHTS["exposure"] * _clamp01(factors.exposure / 10.0) * 100, 1),
            "confidence": round(WEIGHTS["confidence"] * _clamp01(factors.confidence / 100.0) * 100, 1),
            "reproducibility": round(WEIGHTS["reproducibility"] * _clamp01(factors.reproducibility / 10.0) * 100, 1),
        }
        total = round(sum(contributions.values()), 1)
        return {"total": total, "contributions": contributions, "weights": WEIGHTS}


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))
