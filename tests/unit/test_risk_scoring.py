"""Tests unitaires du score de risque et des niveaux d'alerte."""

from __future__ import annotations

import pytest

from ueba.scoring.risk import (
    DEFAULT_CRITICALITY,
    RiskAssessment,
    RiskLevel,
    RiskScorer,
    mitre_context,
    recommended_action,
)


def test_score_unanimous_with_default_context() -> None:
    """3/3 votes + contexte 0.5 (défaut) -> 0.6*100 + 0.4*50 = 80 = CRITIQUE limite."""
    assert RiskScorer().score(vote_count=3) == 80.0


def test_score_majority_with_default_context() -> None:
    """2/3 votes + contexte 0.5 -> 0.6*66.67 + 0.4*50 = 60.0."""
    assert RiskScorer().score(vote_count=2) == 60.0


def test_score_unanimous_critical_technique_reaches_critique() -> None:
    """3/3 votes sur T1110.003 (contexte 0.85) -> 94 = CRITIQUE."""
    s = RiskScorer().score(vote_count=3, context_score=mitre_context("T1110.003"))
    assert s == 94.0
    assert RiskScorer().classify(s) == RiskLevel.CRITIQUE


def test_score_none_vote_count_is_max_consensus() -> None:
    assert RiskScorer().score(vote_count=None, context_score=0.5) == 80.0


def test_score_clamps_context() -> None:
    scorer = RiskScorer()
    assert scorer.score(vote_count=3, context_score=5.0) == 100.0
    assert scorer.score(vote_count=3, context_score=-2.0) == 60.0  # contexte=0 -> 0.6*100


def test_score_clamps_vote_count() -> None:
    scorer = RiskScorer()
    assert scorer.score(vote_count=99, context_score=0.0) == 60.0
    assert scorer.score(vote_count=-1, context_score=0.0) == 0.0


def test_score_is_reproducible_independent_of_batch() -> None:
    """Le score ne dépend que de (vote_count, context) — aucune normalisation externe."""
    scorer = RiskScorer()
    assert scorer.score(2, 0.85) == scorer.score(2, 0.85)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (95.0, RiskLevel.CRITIQUE),
        (80.0, RiskLevel.CRITIQUE),
        (79.9, RiskLevel.ELEVE),
        (60.0, RiskLevel.ELEVE),
        (59.9, RiskLevel.MOYEN),
        (40.0, RiskLevel.MOYEN),
        (39.9, RiskLevel.FAIBLE),
        (0.0, RiskLevel.FAIBLE),
    ],
)
def test_classify_thresholds(score: float, expected: RiskLevel) -> None:
    assert RiskScorer().classify(score) == expected


def test_assess_returns_score_and_level() -> None:
    result = RiskScorer().assess(vote_count=3, context_score=0.85)
    assert result == RiskAssessment(risk_score=94.0, risk_level=RiskLevel.CRITIQUE)


def test_mitre_context_lookup() -> None:
    assert mitre_context("T1110.003") == 0.85
    assert mitre_context("T9999") == DEFAULT_CRITICALITY
    assert mitre_context(None) == DEFAULT_CRITICALITY


def test_recommended_action_covers_all_levels() -> None:
    for level in RiskLevel:
        assert recommended_action(level)  # chaîne non vide


def test_custom_weights() -> None:
    scorer = RiskScorer(consensus_weight=0.5, context_weight=0.5)
    assert scorer.score(vote_count=3, context_score=1.0) == 100.0
    assert scorer.score(vote_count=3, context_score=0.0) == 50.0


def test_risk_level_string_value() -> None:
    assert RiskLevel.CRITIQUE.value == "CRITIQUE"
    assert RiskLevel.ELEVE.value == "ÉLEVÉ"


def test_invalid_n_models_raises() -> None:
    with pytest.raises(ValueError, match="n_models"):
        RiskScorer(n_models=0)


def test_invalid_weights_sum_raises() -> None:
    with pytest.raises(ValueError, match="valoir 1.0"):
        RiskScorer(consensus_weight=0.7, context_weight=0.7)


def test_negative_weights_raise() -> None:
    with pytest.raises(ValueError, match="positifs"):
        RiskScorer(consensus_weight=-0.5, context_weight=1.5)
