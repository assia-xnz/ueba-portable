"""Tests unitaires de l'agrégation par entité (utilisateur × jour)."""

from __future__ import annotations

from datetime import datetime, timedelta

from ueba.pipeline import AnomalyRecord
from ueba.scoring.entity_risk import EntityAlert, aggregate_entities

_H = timedelta(hours=1)


def _rec(user: str, start: datetime, *, is_anomaly: bool = True, votes: int = 3) -> AnomalyRecord:
    return AnomalyRecord(
        user=user,
        window_start=start,
        window_end=start + _H,
        is_anomaly=is_anomaly,
        mode="per-user",
        used_model=user,
        vote_count=votes,
        votes=None,
    )


def test_groups_by_user_and_day() -> None:
    recs = [
        _rec("a", datetime(2026, 5, 13, 11, 0)),
        _rec("a", datetime(2026, 5, 13, 12, 0)),
        _rec("a", datetime(2026, 5, 14, 9, 0)),
        _rec("b", datetime(2026, 5, 13, 11, 0)),
    ]
    alerts = aggregate_entities(recs)
    keys = {(a.user, a.day) for a in alerts}
    assert keys == {("a", "2026-05-13"), ("a", "2026-05-14"), ("b", "2026-05-13")}


def test_counts_and_strong_votes() -> None:
    recs = [
        _rec("a", datetime(2026, 5, 13, 11, 0), votes=3),
        _rec("a", datetime(2026, 5, 13, 12, 0), votes=2),
        _rec("a", datetime(2026, 5, 13, 13, 0), votes=3),
    ]
    alert = aggregate_entities(recs)[0]
    assert alert.anomaly_count == 3
    assert alert.strong_count == 2  # deux fenêtres à vote >= 3
    assert alert.peak_votes == 3
    assert alert.first_detection == datetime(2026, 5, 13, 11, 0)
    assert alert.last_detection == datetime(2026, 5, 13, 14, 0)


def test_non_anomalous_ignored() -> None:
    recs = [
        _rec("a", datetime(2026, 5, 13, 11, 0), is_anomaly=False),
        _rec("a", datetime(2026, 5, 13, 12, 0), is_anomaly=True, votes=2),
    ]
    alerts = aggregate_entities(recs)
    assert len(alerts) == 1
    assert alerts[0].anomaly_count == 1


def test_sorted_by_risk_descending() -> None:
    # entité bruyante mais faible consensus vs entité à votes forts
    recs = [
        _rec("noise", datetime(2026, 5, 10, 8, 0), votes=2),
        _rec("noise", datetime(2026, 5, 10, 9, 0), votes=2),
        _rec("attack", datetime(2026, 5, 13, 11, 0), votes=3),
        _rec("attack", datetime(2026, 5, 13, 12, 0), votes=3),
    ]
    alerts = aggregate_entities(recs)
    # 'attack' (2 votes forts) doit passer devant 'noise' (0 vote fort)
    assert alerts[0].user == "attack"
    assert alerts[0].strong_count == 2
    assert alerts[1].user == "noise"
    assert alerts[1].strong_count == 0


def test_empty_input() -> None:
    assert aggregate_entities([]) == []


def test_strong_vote_threshold_configurable() -> None:
    recs = [_rec("a", datetime(2026, 5, 13, 11, 0), votes=2)]
    assert aggregate_entities(recs, strong_vote=2)[0].strong_count == 1
    assert aggregate_entities(recs, strong_vote=3)[0].strong_count == 0


def test_entity_alert_priority_key() -> None:
    alert = EntityAlert(
        "a",
        "2026-05-13",
        anomaly_count=4,
        strong_count=2,
        peak_votes=3,
        first_detection=datetime(2026, 5, 13, 11, 0),
        last_detection=datetime(2026, 5, 13, 15, 0),
    )
    assert alert.priority == (2, 4, 3)
