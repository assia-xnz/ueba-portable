"""Tests unitaires de l'ensemble d'anomalies personnalisé (un modèle par utilisateur)."""

from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np
import pytest

from ueba.domain.features import FEATURE_NAMES, FeatureVector
from ueba.domain.per_user_ensemble import (
    UNKNOWN_MODEL_LABEL,
    PerUserAnomalyEnsemble,
    PerUserVerdict,
)

_WINDOW = timedelta(hours=1)
_ORIGIN = datetime(2026, 5, 1, 8, 0, 0)


def _make_vector(
    user: str,
    window_start: datetime,
    *,
    base: float = 5.0,
    scale: float = 0.5,
    seed: int = 0,
    **overrides: float,
) -> FeatureVector:
    """Construit un :class:`FeatureVector` aux 16 features tirées autour de `base`."""
    rng = np.random.default_rng(seed)
    values = {name: float(base + rng.normal(0.0, scale)) for name in FEATURE_NAMES}
    values.update(overrides)
    return FeatureVector(
        user=user,
        window_start=window_start,
        window_end=window_start + _WINDOW,
        **values,
    )


def _make_user_windows(
    user: str,
    n: int,
    *,
    start: datetime = _ORIGIN,
    step: timedelta = _WINDOW,
    base: float = 5.0,
    scale: float = 0.5,
    seed: int = 0,
    **overrides: float,
) -> list[FeatureVector]:
    """Construit `n` fenêtres horaires consécutives pour un même utilisateur."""
    return [
        _make_vector(
            user,
            start + i * step,
            base=base,
            scale=scale,
            seed=seed + i,
            **overrides,
        )
        for i in range(n)
    ]


class TestFitMultipleUsers:
    """Apprentissage d'un modèle distinct par utilisateur."""

    def test_fit_on_multiple_users(self) -> None:
        vectors = (
            _make_user_windows("alice", 10, base=5.0, seed=0)
            + _make_user_windows("bob", 10, base=20.0, seed=100)
            + _make_user_windows("carol", 10, base=50.0, seed=200)
        )
        ensemble = PerUserAnomalyEnsemble(min_windows_per_user=5, n_estimators=50)
        ensemble.fit(vectors)

        assert ensemble.is_fitted is True
        assert ensemble.trained_users == ["alice", "bob", "carol"]


class TestPredictRouting:
    """Routage de chaque observation vers le bon modèle utilisateur."""

    @pytest.fixture(scope="class")
    def fitted(self) -> PerUserAnomalyEnsemble:
        vectors = _make_user_windows("alice", 12, base=5.0, seed=0) + _make_user_windows(
            "bob", 12, base=30.0, seed=100
        )
        ensemble = PerUserAnomalyEnsemble(min_windows_per_user=5, n_estimators=50)
        ensemble.fit(vectors)
        return ensemble

    def test_predict_known_user_uses_correct_model(self, fitted: PerUserAnomalyEnsemble) -> None:
        probe = _make_vector("alice", _ORIGIN, base=5.0, seed=0)
        (verdict,) = fitted.predict([probe])

        assert isinstance(verdict, PerUserVerdict)
        assert verdict.user == "alice"
        assert verdict.used_model == "alice"
        assert verdict.was_in_training is True
        assert verdict.vote_count is not None
        assert verdict.score_iforest is not None

    def test_predict_unknown_user_returns_anomaly_default_deny(
        self, fitted: PerUserAnomalyEnsemble
    ) -> None:
        probe = _make_vector("ghost", _ORIGIN, base=5.0, seed=0)
        (verdict,) = fitted.predict([probe])

        assert verdict.is_anomaly is True
        assert verdict.used_model == UNKNOWN_MODEL_LABEL
        assert verdict.was_in_training is False
        assert verdict.score_iforest is None
        assert verdict.score_ocsvm is None
        assert verdict.score_autoencoder is None
        assert verdict.vote_count is None


class TestFiltering:
    """Exclusion des comptes machine et des utilisateurs trop peu observés."""

    def test_fit_filters_machine_accounts(self) -> None:
        vectors = (
            _make_user_windows("alice", 10, base=5.0, seed=0)
            + _make_user_windows("WS01$", 10, base=5.0, seed=50)
            + _make_user_windows("SYSTEM", 10, base=5.0, seed=80)
            + _make_user_windows("ANONYMOUS LOGON", 10, base=5.0, seed=90)
        )
        ensemble = PerUserAnomalyEnsemble(min_windows_per_user=5, n_estimators=50)
        ensemble.fit(vectors)

        assert ensemble.trained_users == ["alice"]

    def test_fit_keeps_machine_accounts_when_filter_disabled(self) -> None:
        vectors = _make_user_windows("alice", 10, seed=0) + _make_user_windows("WS01$", 10, seed=50)
        ensemble = PerUserAnomalyEnsemble(
            min_windows_per_user=5, exclude_machine_accounts=False, n_estimators=50
        )
        ensemble.fit(vectors)

        assert "WS01$" in ensemble.trained_users

    def test_fit_filters_users_with_too_few_windows(self) -> None:
        vectors = _make_user_windows("alice", 12, base=5.0, seed=0) + _make_user_windows(
            "rare", 4, base=5.0, seed=300
        )
        ensemble = PerUserAnomalyEnsemble(min_windows_per_user=10, n_estimators=50)
        ensemble.fit(vectors)

        assert "alice" in ensemble.trained_users
        assert "rare" not in ensemble.trained_users

    def test_fit_filters_empty_and_dash_users(self) -> None:
        vectors = (
            _make_user_windows("alice", 10, seed=0)
            + _make_user_windows("", 10, seed=10)
            + _make_user_windows("-", 10, seed=20)
        )
        ensemble = PerUserAnomalyEnsemble(min_windows_per_user=5, n_estimators=50)
        ensemble.fit(vectors)

        assert ensemble.trained_users == ["alice"]

    def test_fit_skips_user_with_empty_training_subset(self) -> None:
        # Un seul vecteur valide → int(1 × 0.8) = 0 → sous-ensemble train vide → ignoré.
        vectors = _make_user_windows("solo", 1, seed=0)
        ensemble = PerUserAnomalyEnsemble(min_windows_per_user=1, train_ratio=0.8, n_estimators=50)
        ensemble.fit(vectors)

        assert ensemble.is_fitted is True
        assert "solo" not in ensemble.trained_users


class TestChronologicalOrdering:
    """Le split d'apprentissage respecte la flèche du temps, quel que soit l'ordre d'entrée."""

    def test_fit_chronological_ordering(self) -> None:
        # Fenêtres anciennes normales, fenêtres récentes extrêmes.
        early = _make_user_windows("u", 8, start=_ORIGIN, base=5.0, seed=0)
        late = [
            _make_vector(
                "u",
                _ORIGIN + timedelta(hours=8 + i),
                base=5.0,
                seed=i,
                failed_login_count=400.0,
                login_velocity=90.0,
            )
            for i in range(2)
        ]
        # Entrée volontairement désordonnée : récentes d'abord, anciennes ensuite.
        shuffled = late + list(reversed(early))

        ensemble = PerUserAnomalyEnsemble(min_windows_per_user=5, train_ratio=0.8, n_estimators=80)
        ensemble.fit(shuffled)

        # train_ratio=0.8 sur 10 fenêtres triées → apprentissage sur les 8 anciennes
        # (normales). Les fenêtres récentes extrêmes doivent ressortir comme anomalies.
        verdicts = ensemble.predict(late)
        assert all(v.is_anomaly for v in verdicts)


class TestPersistence:
    """Sauvegarde/rechargement complets de l'état entraîné."""

    def test_save_and_load_preserves_complete_state(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        vectors = _make_user_windows("alice", 10, base=5.0, seed=0) + _make_user_windows(
            "bob", 10, base=25.0, seed=100
        )
        ensemble = PerUserAnomalyEnsemble(min_windows_per_user=5, n_estimators=50)
        ensemble.fit(vectors)

        path = tmp_path / "per_user.joblib"
        ensemble.save(str(path))
        restored = PerUserAnomalyEnsemble.load(str(path))

        assert restored.is_fitted is True
        assert restored.trained_users == ensemble.trained_users

    def test_predict_consistency_after_load(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        vectors = _make_user_windows("alice", 10, base=5.0, seed=0) + _make_user_windows(
            "bob", 10, base=25.0, seed=100
        )
        probes = [
            _make_vector("alice", _ORIGIN, base=5.0, seed=0),
            _make_vector("alice", _ORIGIN, base=200.0, seed=7),
            _make_vector("bob", _ORIGIN, base=25.0, seed=100),
            _make_vector("ghost", _ORIGIN, base=5.0, seed=0),
        ]
        ensemble = PerUserAnomalyEnsemble(min_windows_per_user=5, n_estimators=50)
        ensemble.fit(vectors)
        before = ensemble.predict(probes)

        path = tmp_path / "per_user.joblib"
        ensemble.save(str(path))
        after = PerUserAnomalyEnsemble.load(str(path)).predict(probes)

        assert [v.is_anomaly for v in before] == [v.is_anomaly for v in after]
        assert [v.vote_count for v in before] == [v.vote_count for v in after]
        assert [v.used_model for v in before] == [v.used_model for v in after]


class TestApiContract:
    """Compatibilité du contrat public avec :class:`AnomalyEnsemble`."""

    def test_api_contract_compatible_with_anomaly_ensemble(self) -> None:
        for method in ("fit", "predict", "save", "load"):
            assert callable(getattr(PerUserAnomalyEnsemble, method))

    def test_predict_before_fit_raises_runtime_error(self) -> None:
        ensemble = PerUserAnomalyEnsemble(min_windows_per_user=5, n_estimators=50)
        with pytest.raises(RuntimeError):
            ensemble.predict([_make_vector("alice", _ORIGIN)])

    def test_invalid_min_windows_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            PerUserAnomalyEnsemble(min_windows_per_user=0)

    def test_invalid_train_ratio_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            PerUserAnomalyEnsemble(train_ratio=0.0)
        with pytest.raises(ValueError):
            PerUserAnomalyEnsemble(train_ratio=1.5)
