"""Tests unitaires du filtre de persistance (réduction des faux positifs)."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from ueba.domain.persistence import PersistenceFilter
from ueba.pipeline import AnomalyRecord

_STEP = timedelta(minutes=30)
_ORIGIN = datetime(2026, 5, 13, 8, 0, 0)


def _rec(user: str, k: int, *, is_anomaly: bool) -> AnomalyRecord:
    start = _ORIGIN + k * _STEP
    return AnomalyRecord(
        user=user,
        window_start=start,
        window_end=start + timedelta(hours=1),
        is_anomaly=is_anomaly,
        mode="per-user",
        used_model=user,
        vote_count=3 if is_anomaly else 0,
        votes={
            "isolation_forest": is_anomaly,
            "one_class_svm": is_anomaly,
            "autoencoder": is_anomaly,
        },
    )


def _flags(records: list[AnomalyRecord]) -> list[bool]:
    return [r.is_anomaly for r in records]


def test_isolated_anomaly_is_suppressed() -> None:
    records = [_rec("u", 0, is_anomaly=True)]
    out = PersistenceFilter(min_consecutive=2).apply(records)
    assert _flags(out) == [False]


def test_consecutive_run_is_kept() -> None:
    records = [_rec("u", 0, is_anomaly=True), _rec("u", 1, is_anomaly=True)]
    out = PersistenceFilter(min_consecutive=2).apply(records)
    assert _flags(out) == [True, True]


def test_run_shorter_than_min_suppressed() -> None:
    records = [_rec("u", k, is_anomaly=True) for k in range(2)]
    out = PersistenceFilter(min_consecutive=3).apply(records)
    assert _flags(out) == [False, False]


def test_gap_breaks_the_run() -> None:
    # deux anomalies espacées de 3h (> max_gap 60 min) -> deux séries isolées
    records = [_rec("u", 0, is_anomaly=True), _rec("u", 6, is_anomaly=True)]
    out = PersistenceFilter(min_consecutive=2, max_gap=timedelta(minutes=60)).apply(records)
    assert _flags(out) == [False, False]


def test_per_user_isolation() -> None:
    # u1 a une série (gardée), u2 a un isolé (supprimé), entrelacés
    records = [
        _rec("u1", 0, is_anomaly=True),
        _rec("u2", 0, is_anomaly=True),
        _rec("u1", 1, is_anomaly=True),
    ]
    out = PersistenceFilter(min_consecutive=2).apply(records)
    flags = {(r.user, r.window_start): r.is_anomaly for r in out}
    assert flags[("u1", _ORIGIN)] is True
    assert flags[("u1", _ORIGIN + _STEP)] is True
    assert flags[("u2", _ORIGIN)] is False


def test_non_anomalous_untouched() -> None:
    records = [_rec("u", 0, is_anomaly=False), _rec("u", 1, is_anomaly=False)]
    out = PersistenceFilter(min_consecutive=2).apply(records)
    assert _flags(out) == [False, False]


def test_min_consecutive_one_is_noop() -> None:
    records = [_rec("u", 0, is_anomaly=True)]
    out = PersistenceFilter(min_consecutive=1).apply(records)
    assert _flags(out) == [True]


def test_order_preserved() -> None:
    records = [
        _rec("u", 2, is_anomaly=True),
        _rec("u", 0, is_anomaly=True),
        _rec("u", 1, is_anomaly=True),
    ]
    out = PersistenceFilter(min_consecutive=2).apply(records)
    # ordre d'entrée conservé, tous gardés (série de 3 fenêtres rapprochées)
    assert [r.window_start for r in out] == [r.window_start for r in records]
    assert _flags(out) == [True, True, True]


def test_invalid_min_consecutive() -> None:
    with pytest.raises(ValueError, match="min_consecutive"):
        PersistenceFilter(min_consecutive=0)
