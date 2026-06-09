"""Tests unitaires du moteur de baseline glissante (RollingBaselineEngine)."""

from datetime import datetime, timedelta

import pytest

from ueba.domain.schema import NormalizedEvent
from ueba.scoring.rolling_baseline import RollingBaselineEngine

WINDOW_SIZE = timedelta(hours=1)
WINDOW_STEP = timedelta(minutes=30)


def _event(
    event_id: str,
    *,
    day: int,
    hour: int,
    minute: int = 0,
    user: str = "a.amrani",
    host: str = "soc-dc01",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=datetime(2026, 5, day, hour, minute, 0),
        user=user,
        host=host,
        event_id=event_id,
    )


@pytest.fixture
def engine() -> RollingBaselineEngine:
    return RollingBaselineEngine(
        window_size=WINDOW_SIZE,
        window_step=WINDOW_STEP,
        lookback_days=7,
        min_observations=2,
    )


class TestRollingBaselineEngineInit:
    def test_default_lookback_days_is_seven(self) -> None:
        eng = RollingBaselineEngine(window_size=WINDOW_SIZE, window_step=WINDOW_STEP)
        assert eng.lookback_days == 7

    def test_invalid_lookback_days_raises(self) -> None:
        with pytest.raises(ValueError):
            RollingBaselineEngine(window_size=WINDOW_SIZE, window_step=WINDOW_STEP, lookback_days=0)
        with pytest.raises(ValueError):
            RollingBaselineEngine(window_size=WINDOW_SIZE, window_step=WINDOW_STEP, lookback_days=-1)


class TestRollingBaselineEngineExtract:
    def test_returns_empty_list_for_no_events(self, engine: RollingBaselineEngine) -> None:
        assert engine.extract([]) == []

    def test_produces_feature_vectors_for_each_window(self, engine: RollingBaselineEngine) -> None:
        events = [
            _event("4624", day=13, hour=9, minute=0),
            _event("4624", day=13, hour=10, minute=0),
        ]
        vectors = engine.extract(events)
        assert len(vectors) >= 1
        assert all(v.user == "a.amrani" for v in vectors)

    def test_vectors_have_sixteen_features(self, engine: RollingBaselineEngine) -> None:
        events = [_event("4624", day=13, hour=9, minute=m) for m in range(0, 50, 10)]
        vectors = engine.extract(events)
        assert len(vectors) >= 1
        assert len(vectors[0].to_vector()) == 16

    def test_z_scores_are_zero_when_lookback_is_empty(self, engine: RollingBaselineEngine) -> None:
        # Un seul événement sans historique antérieur → lookback vide → z = 0.0
        events = [_event("4624", day=13, hour=9, minute=0)]
        vectors = engine.extract(events)
        assert all(v.z_login_count == 0.0 for v in vectors)
        assert all(v.z_process_count == 0.0 for v in vectors)

    def test_z_scores_are_nonzero_with_sufficient_lookback(self) -> None:
        # Activité normale pendant 7 jours (lookback), puis pic anormal le jour 8
        engine = RollingBaselineEngine(
            window_size=WINDOW_SIZE,
            window_step=WINDOW_STEP,
            lookback_days=7,
            min_observations=2,
        )
        # Lookback : jours 6 et 7 — 1 login par heure
        lookback = [_event("4624", day=d, hour=h) for d in (6, 7) for h in range(8, 18)]
        # Jour 13 (hors lookback) : pic de 10 logins en 1 heure
        scoring = [_event("4624", day=13, hour=9, minute=m) for m in range(0, 60, 6)]
        events = lookback + scoring

        vectors = engine.extract(events)
        scoring_vectors = [v for v in vectors if v.window_start.day == 13]
        # Le z-score doit être positif (pic par rapport à la baseline)
        assert any(v.z_login_count > 0.0 for v in scoring_vectors)

    def test_baseline_is_per_user(self) -> None:
        engine = RollingBaselineEngine(
            window_size=WINDOW_SIZE,
            window_step=WINDOW_STEP,
            lookback_days=7,
            min_observations=2,
        )
        # user_a : actif tous les jours (baseline stable)
        # user_b : aucune activité dans le lookback
        lookback = [_event("4624", day=d, hour=9, user="user_a") for d in range(6, 8)]
        scoring = [
            _event("4624", day=13, hour=9, user="user_a"),
            _event("4624", day=13, hour=9, user="user_b"),
        ]
        vectors = engine.extract(lookback + scoring)
        scoring_day = [v for v in vectors if v.window_start.day == 13]

        user_a_vec = next((v for v in scoring_day if v.user == "user_a"), None)
        user_b_vec = next((v for v in scoring_day if v.user == "user_b"), None)

        # user_a a un historique → z_login_count peut être non nul
        # user_b n'a pas d'historique → z = 0.0 (comportement prudent)
        if user_b_vec is not None:
            assert user_b_vec.z_login_count == 0.0

    def test_events_sorted_per_user_across_multiple_users(self, engine: RollingBaselineEngine) -> None:
        events = [
            _event("4624", day=13, hour=9, minute=0, user="alice"),
            _event("4624", day=13, hour=9, minute=0, user="bob"),
            _event("4625", day=13, hour=9, minute=10, user="alice"),
        ]
        vectors = engine.extract(events)
        users = {v.user for v in vectors}
        assert users == {"alice", "bob"}


class TestRollingBaselineWindowGeneration:
    def test_window_start_aligns_with_first_event_timestamp(self) -> None:
        engine = RollingBaselineEngine(
            window_size=timedelta(hours=1),
            window_step=timedelta(hours=1),
            lookback_days=1,
        )
        t0 = datetime(2026, 5, 13, 9, 0)
        events = [
            NormalizedEvent(timestamp=t0, user="u", host="h", event_id="4624"),
        ]
        vectors = engine.extract(events)
        assert len(vectors) >= 1
        assert vectors[0].window_start == t0

    def test_rolling_baseline_uses_only_past_events(self) -> None:
        engine = RollingBaselineEngine(
            window_size=timedelta(hours=1),
            window_step=timedelta(hours=1),
            lookback_days=1,
            min_observations=1,
        )
        # Jour 12 : 5 logins (lookback pour le jour 13)
        # Jour 13 : 1 login (scoring)
        # Jour 14 : 20 logins (ne doit PAS influencer la baseline du jour 13)
        past = [_event("4624", day=12, hour=9, minute=m) for m in range(0, 50, 10)]
        scoring = [_event("4624", day=13, hour=9, minute=0)]
        future = [_event("4624", day=14, hour=9, minute=m) for m in range(0, 60, 3)]

        vectors_with_future = engine.extract(past + scoring + future)
        vectors_without_future = engine.extract(past + scoring)

        day13_with = [v for v in vectors_with_future if v.window_start.day == 13]
        day13_without = [v for v in vectors_without_future if v.window_start.day == 13]

        # La baseline du jour 13 ne doit pas changer selon les données du jour 14
        if day13_with and day13_without:
            assert day13_with[0].z_login_count == pytest.approx(
                day13_without[0].z_login_count, abs=1e-9
            )
