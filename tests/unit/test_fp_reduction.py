"""Tests des leviers de réduction des faux positifs (default-deny + persistance)."""

from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np

from ueba.domain.features import FEATURE_NAMES, FeatureVector
from ueba.domain.per_user_ensemble import UNKNOWN_MODEL_LABEL, PerUserAnomalyEnsemble

_WINDOW = timedelta(hours=1)
_ORIGIN = datetime(2026, 5, 1, 8, 0, 0)


def _vec(user: str, k: int, *, seed: int = 0) -> FeatureVector:
    rng = np.random.default_rng(seed + k)
    values = {name: float(5.0 + rng.normal(0, 0.3)) for name in FEATURE_NAMES}
    start = _ORIGIN + k * _WINDOW
    return FeatureVector(user=user, window_start=start, window_end=start + _WINDOW, **values)


def _train(default_deny: bool) -> PerUserAnomalyEnsemble:
    ens = PerUserAnomalyEnsemble(min_windows_per_user=10, default_deny=default_deny)
    vectors = [_vec("known", k) for k in range(40)]
    ens.fit(vectors)
    return ens


def test_default_deny_true_flags_unknown_user() -> None:
    ens = _train(default_deny=True)
    verdict = ens.predict([_vec("brand.new", 0)])[0]
    assert verdict.is_anomaly is True
    assert verdict.used_model == UNKNOWN_MODEL_LABEL


def test_default_deny_false_does_not_flag_unknown_user() -> None:
    """Levier anti-FP : un utilisateur sans modèle n'est plus auto-alerté."""
    ens = _train(default_deny=False)
    verdict = ens.predict([_vec("brand.new", 0)])[0]
    assert verdict.is_anomaly is False
    assert verdict.used_model == UNKNOWN_MODEL_LABEL
    assert verdict.was_in_training is False


def test_default_deny_round_trips_through_save_load(tmp_path) -> None:  # type: ignore[no-untyped-def]
    ens = _train(default_deny=False)
    path = tmp_path / "m.joblib"
    ens.save(str(path))
    restored = PerUserAnomalyEnsemble.load(str(path))
    verdict = restored.predict([_vec("brand.new", 0)])[0]
    assert verdict.is_anomaly is False  # le réglage a survécu à la sérialisation
