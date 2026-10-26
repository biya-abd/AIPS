"""
Risk scoring for AIPS.

The formula is intentionally simple and fully documented so a score is
always reproducible from the evidence stored with a detection. No ML,
no hidden weights, no randomness.

    risk_score = min(100, BASE[rule] + FREQUENCY_BONUS + OFFENDER_BONUS)

Where:
  BASE[rule]        -- a fixed starting point per rule (see RULE_BASE_SCORE)
  FREQUENCY_BONUS    = min(10, occurrence_count - 1) * 3
                        (repeated triggers of the SAME grouped detection
                        raise its score, capped at +30, so dashboards do not
                        see unbounded score inflation from one noisy source)
  OFFENDER_BONUS     = 20 if the source IP has triggered >= REPEAT_OFFENDER_RULE_COUNT
                        *distinct* rules within REPEAT_OFFENDER_WINDOW_SECONDS, else 0

Severity bands (fixed thresholds on the final 0-100 score):
  0-29   -> low
  30-59  -> medium
  60-84  -> high
  85-100 -> critical

This is deliberately conservative/explainable rather than "smart" --
the AI integration (see app/ai/openrouter_client.py) is layered on top
for narrative explanation and investigative suggestions, but never
changes the numeric score or severity band.
"""
from __future__ import annotations

RULE_BASE_SCORE = {
    "BRUTE_FORCE": 40,
    "EXCESS_RATE": 30,
    "REPEAT_404": 25,
    "PATH_TRAVERSAL": 50,
    "SUSPICIOUS_PATH": 35,
    "MALFORMED_REQUEST": 30,
}

FREQUENCY_BONUS_PER_OCCURRENCE = 3
FREQUENCY_BONUS_CAP = 30
OFFENDER_BONUS = 20


def compute_risk_score(rule_name: str, occurrence_count: int, is_repeat_offender: bool) -> int:
    base = RULE_BASE_SCORE.get(rule_name, 20)
    freq_bonus = min(FREQUENCY_BONUS_CAP, max(0, occurrence_count - 1) * FREQUENCY_BONUS_PER_OCCURRENCE)
    offender_bonus = OFFENDER_BONUS if is_repeat_offender else 0
    return min(100, base + freq_bonus + offender_bonus)


def severity_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"
