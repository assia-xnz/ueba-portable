"""Tests unitaires du calcul du MTTD (Mean Time To Detect)."""

from __future__ import annotations

from datetime import datetime, timedelta

from ueba.domain.features import FEATURE_NAMES, FeatureVector
from ueba.domain.per_user_ensemble import PerUserVerdict
from ueba.metrics.mttd import MTTDCalculator, MTTDReport

_WINDOW = timedelta(hours=1)


def _vector(user: str, window_start: datetime) -> FeatureVector:
    """Construit un FeatureVector neutre (features à zéro) pour les tests MTTD."""
    values = {name: 0.0 for name in FEATURE_NAMES}
    return FeatureVector(
        user=user,
        window_start=window_start,
        window_end=window_start + _WINDOW,
        **values,
    )


def _verdict(user: str, *, is_anomaly: bool = True, vote_count: int | None = 3) -> PerUserVerdict:
    return PerUserVerdict(
        is_anomaly=is_anomaly,
        user=user,
        used_model=user,
        was_in_training=True,
        vote_count=vote_count,
    )


def test_mttd_single_user_simple() -> None:
    """Détection dans la fenêtre couvrant l'attaque -> MTTD = window_end - attack_start."""
    attack = {"a.amrani": datetime(2026, 5, 13, 11, 0)}
    vectors = [_vector("a.amrani", datetime(2026, 5, 13, 11, 0))]
    detections = [_verdict("a.amrani")]

    report = MTTDCalculator().calculate(attack, detections, vectors)

    assert report.per_user_mttd["a.amrani"] == timedelta(hours=1)
    assert report.first_detection_times["a.amrani"] == datetime(2026, 5, 13, 12, 0)
    assert report.detected_users == ["a.amrani"]
    assert report.missed_users == []
    assert report.global_mttd == timedelta(hours=1)


def test_mttd_picks_earliest_qualifying_window() -> None:
    """Parmi plusieurs fenêtres anormales, la plus précoce (>= attaque) est retenue."""
    attack = {"l.mus": datetime(2026, 5, 13, 11, 0)}
    vectors = [
        _vector("l.mus", datetime(2026, 5, 13, 12, 0)),  # plus tardive
        _vector("l.mus", datetime(2026, 5, 13, 11, 0)),  # plus précoce -> retenue
        _vector("l.mus", datetime(2026, 5, 13, 13, 0)),
    ]
    detections = [_verdict("l.mus"), _verdict("l.mus"), _verdict("l.mus")]

    report = MTTDCalculator().calculate(attack, detections, vectors)

    assert report.first_detection_times["l.mus"] == datetime(2026, 5, 13, 12, 0)
    assert report.per_user_mttd["l.mus"] == timedelta(hours=1)


def test_mttd_ignores_windows_before_attack() -> None:
    """Une fenêtre se terminant avant le début de l'attaque ne compte pas."""
    attack = {"y.ben": datetime(2026, 5, 13, 11, 0)}
    vectors = [
        _vector("y.ben", datetime(2026, 5, 13, 8, 0)),  # window_end 09:00 < attaque
        _vector("y.ben", datetime(2026, 5, 13, 11, 30)),  # qualifiante
    ]
    detections = [_verdict("y.ben"), _verdict("y.ben")]

    report = MTTDCalculator().calculate(attack, detections, vectors)

    assert report.first_detection_times["y.ben"] == datetime(2026, 5, 13, 12, 30)
    assert report.per_user_mttd["y.ben"] == timedelta(minutes=90)


def test_mttd_ignores_non_anomalous_verdicts() -> None:
    """Un verdict is_anomaly=False n'est jamais une détection."""
    attack = {"n.alam": datetime(2026, 5, 13, 11, 0)}
    vectors = [_vector("n.alam", datetime(2026, 5, 13, 11, 0))]
    detections = [_verdict("n.alam", is_anomaly=False)]

    report = MTTDCalculator().calculate(attack, detections, vectors)

    assert report.detected_users == []
    assert report.missed_users == ["n.alam"]
    assert report.global_mttd == timedelta(0)


def test_mttd_missed_user_when_no_detection() -> None:
    """Un utilisateur ciblé sans aucune fenêtre anormale est compté comme manqué."""
    attack = {
        "a.amrani": datetime(2026, 5, 13, 11, 0),
        "k.alaa": datetime(2026, 5, 13, 11, 0),
    }
    vectors = [_vector("a.amrani", datetime(2026, 5, 13, 11, 0))]
    detections = [_verdict("a.amrani")]

    report = MTTDCalculator().calculate(attack, detections, vectors)

    assert report.detected_users == ["a.amrani"]
    assert report.missed_users == ["k.alaa"]
    assert report.detection_rate == 0.5


def test_mttd_global_is_mean_over_detected() -> None:
    """Le MTTD global est la moyenne des MTTD individuels des détectés."""
    attack = {
        "u1": datetime(2026, 5, 13, 11, 0),
        "u2": datetime(2026, 5, 13, 11, 0),
    }
    vectors = [
        _vector("u1", datetime(2026, 5, 13, 11, 0)),  # MTTD 60 min
        _vector("u2", datetime(2026, 5, 13, 12, 0)),  # MTTD 120 min
    ]
    detections = [_verdict("u1"), _verdict("u2")]

    report = MTTDCalculator().calculate(attack, detections, vectors)

    assert report.global_mttd == timedelta(minutes=90)
    assert report.global_mttd_minutes == 90.0


def test_mttd_ignores_users_outside_attack_set() -> None:
    """Les utilisateurs non ciblés (hors attack_start_times) sont ignorés."""
    attack = {"a.amrani": datetime(2026, 5, 13, 11, 0)}
    vectors = [
        _vector("soc-admin", datetime(2026, 5, 13, 11, 0)),
        _vector("a.amrani", datetime(2026, 5, 13, 11, 0)),
    ]
    detections = [_verdict("soc-admin"), _verdict("a.amrani")]

    report = MTTDCalculator().calculate(attack, detections, vectors)

    assert report.detected_users == ["a.amrani"]
    assert "soc-admin" not in report.per_user_mttd


def test_mttd_length_mismatch_raises() -> None:
    """detections et vectors de longueurs différentes -> ValueError."""
    calc = MTTDCalculator()
    try:
        calc.calculate({}, [_verdict("u1")], [])
    except ValueError as exc:
        assert "longueur" in str(exc)
    else:  # pragma: no cover - le test doit lever
        raise AssertionError("ValueError attendue")


def test_mttd_empty_inputs() -> None:
    """Aucune entrée -> rapport vide cohérent."""
    report = MTTDCalculator().calculate({}, [], [])
    assert report == MTTDReport()
    assert report.detection_rate == 0.0
    assert report.global_mttd_minutes == 0.0
