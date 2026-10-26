import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.detection.risk import compute_risk_score, severity_from_score, RULE_BASE_SCORE


def test_base_score_no_repeat_no_offender():
    score = compute_risk_score("BRUTE_FORCE", occurrence_count=1, is_repeat_offender=False)
    assert score == RULE_BASE_SCORE["BRUTE_FORCE"]


def test_frequency_bonus_increases_with_occurrences():
    s1 = compute_risk_score("REPEAT_404", occurrence_count=1, is_repeat_offender=False)
    s2 = compute_risk_score("REPEAT_404", occurrence_count=3, is_repeat_offender=False)
    s3 = compute_risk_score("REPEAT_404", occurrence_count=50, is_repeat_offender=False)
    assert s2 > s1
    assert s3 >= s2
    # frequency bonus is capped at 30
    assert s3 - RULE_BASE_SCORE["REPEAT_404"] <= 30


def test_offender_bonus_applied_once():
    base = compute_risk_score("EXCESS_RATE", occurrence_count=1, is_repeat_offender=False)
    with_offender = compute_risk_score("EXCESS_RATE", occurrence_count=1, is_repeat_offender=True)
    assert with_offender == base + 20


def test_score_never_exceeds_100():
    score = compute_risk_score("PATH_TRAVERSAL", occurrence_count=1000, is_repeat_offender=True)
    assert score == 100


def test_score_is_reproducible():
    a = compute_risk_score("SUSPICIOUS_PATH", occurrence_count=4, is_repeat_offender=True)
    b = compute_risk_score("SUSPICIOUS_PATH", occurrence_count=4, is_repeat_offender=True)
    assert a == b


def test_severity_bands():
    assert severity_from_score(0) == "low"
    assert severity_from_score(29) == "low"
    assert severity_from_score(30) == "medium"
    assert severity_from_score(59) == "medium"
    assert severity_from_score(60) == "high"
    assert severity_from_score(84) == "high"
    assert severity_from_score(85) == "critical"
    assert severity_from_score(100) == "critical"


def test_unknown_rule_gets_conservative_default():
    score = compute_risk_score("SOME_FUTURE_RULE", occurrence_count=1, is_repeat_offender=False)
    assert score == 20
