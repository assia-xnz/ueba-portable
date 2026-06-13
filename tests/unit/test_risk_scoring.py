"""Tests unitaires du score de risque et des niveaux d'alerte."""

from __future__ import annotations

import pytest

from ueba.scoring.risk import RiskAssessment, RiskLevel, RiskScorer


def test_score_unanimous_consensus_is_max_without_intensity() -> None:
    """3/3 votes, intensité nulle -> 70 (poids consensus par défaut)."""
    scorer = RiskScorer()
    assert scorer.score(vote_count=3) == 70.0


def test_score_majority_consensus() -> None:
    """2/3 votes, intensité nulle -> 100 * 0.7 * 2/3 ≈ 46.7."""
    assert RiskScorer().score(vote_count=2) == 46.7


def test_score_combines_consensus_and_intensity() -> None:
    """3/3 votes + intensité max -> 100 (70 + 30)."""
    assert RiskScorer().score(vote_count=3, intensity=1.0) == 100.0


def test_score_none_vote_count_treated_as_max_consensus() -> None:
    """vote_count=None (utilisateur inconnu, default-deny) -> consensus maximal."""
    assert RiskScorer().score(vote_count=None) == 70.0


def test_score_clamps_intensity() -> None:
    """L'intensité est écrêtée sur [0, 1]."""
    scorer = RiskScorer()
    assert scorer.score(vote_count=3, intensity=5.0) == 100.0
    assert scorer.score(vote_count=3, intensity=-2.0) == 70.0


def test_score_clamps_vote_count() -> None:
    """vote_count hors bornes est écrêté sur [0, n_models]."""
    scorer = RiskScorer()
    assert scorer.score(vote_count=99) == 70.0
    assert scorer.score(vote_count=-1) == 0.0


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
    """Les seuils de classification respectent les bornes inférieures incluses."""
    assert RiskScorer().classify(score) == expected


def test_assess_returns_score_and_level() -> None:
    """assess() combine score et niveau dans un RiskAssessment."""
    result = RiskScorer().assess(vote_count=3, intensity=1.0)
    assert result == RiskAssessment(risk_score=100.0, risk_level=RiskLevel.CRITIQUE)


def test_custom_weights() -> None:
    """Des poids personnalisés modifient la pondération du score."""
    scorer = RiskScorer(consensus_weight=0.5, intensity_weight=0.5)
    assert scorer.score(vote_count=3, intensity=1.0) == 100.0
    assert scorer.score(vote_count=3, intensity=0.0) == 50.0


def test_risk_level_string_value() -> None:
    """RiskLevel est sérialisable en chaîne lisible (pour ES/Kibana)."""
    assert RiskLevel.CRITIQUE.value == "CRITIQUE"
    assert RiskLevel.ELEVE.value == "ÉLEVÉ"


def test_invalid_n_models_raises() -> None:
    with pytest.raises(ValueError, match="n_models"):
        RiskScorer(n_models=0)


def test_invalid_weights_sum_raises() -> None:
    with pytest.raises(ValueError, match="valoir 1.0"):
        RiskScorer(consensus_weight=0.7, intensity_weight=0.7)


def test_negative_weights_raise() -> None:
    with pytest.raises(ValueError, match="positifs"):
        RiskScorer(consensus_weight=-0.5, intensity_weight=1.5)
