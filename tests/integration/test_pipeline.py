"""Tests d'intégration du pipeline UEBA (orchestration extract → fit → predict).

Couvre les deux modes d'apprentissage (``global`` et ``per-user``), le flux
complet :meth:`UEBAPipeline.run` sur la fixture Wazuh synthétique, et le
cycle sauvegarde/rechargement du modèle.
"""

from __future__ import annotations

import csv
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pytest

from ueba.domain.features import FEATURE_NAMES, FeatureVector
from ueba.pipeline import GLOBAL_MODEL_LABEL, AnomalyRecord, UEBAPipeline

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_logs.csv"

_WINDOW = timedelta(hours=1)
_ORIGIN = datetime(2026, 5, 1, 8, 0, 0)


def _make_user_windows(
    user: str, n: int, *, base: float = 5.0, seed: int = 0
) -> list[FeatureVector]:
    """Construit `n` fenêtres horaires consécutives pour un utilisateur."""
    rng = np.random.default_rng(seed)
    vectors: list[FeatureVector] = []
    for i in range(n):
        values = {name: float(base + rng.normal(0.0, 0.5)) for name in FEATURE_NAMES}
        start = _ORIGIN + i * _WINDOW
        vectors.append(
            FeatureVector(user=user, window_start=start, window_end=start + _WINDOW, **values)
        )
    return vectors


@pytest.fixture(scope="module")
def fixture_events():  # type: ignore[no-untyped-def]
    """Charge et normalise les événements de la fixture Wazuh synthétique."""
    from ueba.adapters.wazuh import WazuhAdapter

    with FIXTURE_PATH.open(newline="", encoding="utf-8") as f:
        records = list(csv.DictReader(f))
    return WazuhAdapter().normalize(records)


@pytest.fixture(scope="module")
def training_vectors() -> list[FeatureVector]:
    """Deux utilisateurs au volume suffisant pour entraîner un modèle dédié."""
    return _make_user_windows("alice", 15, base=5.0, seed=0) + _make_user_windows(
        "bob", 15, base=25.0, seed=100
    )


class TestPipelineConstruction:
    """Validation des paramètres de construction."""

    def test_invalid_mode_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            UEBAPipeline(window_size=_WINDOW, window_step=_WINDOW, ensemble_mode="hybride")  # type: ignore[arg-type]

    def test_default_mode_is_per_user(self) -> None:
        pipeline = UEBAPipeline(window_size=_WINDOW, window_step=_WINDOW)
        assert pipeline.mode == "per-user"


class TestPipelineLifecycle:
    """Cycle de vie fit/predict et gestion des erreurs."""

    def test_predict_before_fit_raises(self, training_vectors: list[FeatureVector]) -> None:
        pipeline = UEBAPipeline(window_size=_WINDOW, window_step=_WINDOW)
        with pytest.raises(RuntimeError):
            pipeline.predict(training_vectors)

    def test_fit_empty_vectors_raises(self) -> None:
        pipeline = UEBAPipeline(window_size=_WINDOW, window_step=_WINDOW)
        with pytest.raises(ValueError):
            pipeline.fit([])

    def test_save_before_fit_raises(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        pipeline = UEBAPipeline(window_size=_WINDOW, window_step=_WINDOW)
        with pytest.raises(RuntimeError):
            pipeline.save_model(str(tmp_path / "m.joblib"))


class TestPerUserMode:
    """Mode per-user : un modèle dédié par utilisateur."""

    def test_fit_predict_routes_per_user(self, training_vectors: list[FeatureVector]) -> None:
        pipeline = UEBAPipeline(
            window_size=_WINDOW,
            window_step=_WINDOW,
            ensemble_mode="per-user",
            min_windows_per_user=10,
            n_estimators=50,
        )
        pipeline.fit(training_vectors)
        records = pipeline.predict(training_vectors)

        assert len(records) == len(training_vectors)
        assert all(isinstance(r, AnomalyRecord) for r in records)
        assert all(r.mode == "per-user" for r in records)
        assert {r.used_model for r in records} == {"alice", "bob"}
        assert all(r.votes is not None and r.vote_count is not None for r in records)

    def test_unknown_user_is_default_deny(self, training_vectors: list[FeatureVector]) -> None:
        pipeline = UEBAPipeline(
            window_size=_WINDOW,
            window_step=_WINDOW,
            ensemble_mode="per-user",
            min_windows_per_user=10,
            n_estimators=50,
        )
        pipeline.fit(training_vectors)
        (record,) = pipeline.predict(_make_user_windows("ghost", 1, seed=7))

        assert record.is_anomaly is True
        assert record.used_model == "unknown"
        assert record.votes is None
        assert record.vote_count is None

    def test_train_ratio_is_forwarded_to_per_user(self) -> None:
        # Le pipeline propage train_ratio : 1.0 entraîne l'utilisateur,
        # une valeur trop faible le laisse non entraîné (→ default-deny).
        vectors = _make_user_windows("u", 2, base=5.0, seed=0)

        full = UEBAPipeline(
            window_size=_WINDOW,
            window_step=_WINDOW,
            ensemble_mode="per-user",
            min_windows_per_user=2,
            train_ratio=1.0,
            n_estimators=50,
        )
        full.fit(vectors)
        assert all(r.used_model == "u" for r in full.predict(vectors))

        tiny = UEBAPipeline(
            window_size=_WINDOW,
            window_step=_WINDOW,
            ensemble_mode="per-user",
            min_windows_per_user=2,
            train_ratio=0.4,
            n_estimators=50,
        )
        tiny.fit(vectors)
        assert all(r.used_model == "unknown" for r in tiny.predict(vectors))


class TestGlobalMode:
    """Mode global : un unique modèle pour toute la population."""

    def test_fit_predict_uses_single_model(self, training_vectors: list[FeatureVector]) -> None:
        pipeline = UEBAPipeline(
            window_size=_WINDOW,
            window_step=_WINDOW,
            ensemble_mode="global",
            n_estimators=50,
        )
        pipeline.fit(training_vectors)
        records = pipeline.predict(training_vectors)

        assert len(records) == len(training_vectors)
        assert all(r.mode == "global" for r in records)
        assert all(r.used_model == GLOBAL_MODEL_LABEL for r in records)
        assert all(r.votes is not None and r.vote_count is not None for r in records)

    def test_predict_empty_returns_empty(self, training_vectors: list[FeatureVector]) -> None:
        pipeline = UEBAPipeline(
            window_size=_WINDOW, window_step=_WINDOW, ensemble_mode="global", n_estimators=50
        )
        pipeline.fit(training_vectors)
        assert pipeline.predict([]) == []


class TestRunEndToEnd:
    """Flux complet extract → fit → predict sur la fixture Wazuh."""

    def test_run_global_on_fixture(self, fixture_events) -> None:  # type: ignore[no-untyped-def]
        pipeline = UEBAPipeline(
            window_size=_WINDOW,
            window_step=timedelta(minutes=30),
            ensemble_mode="global",
            n_estimators=50,
        )
        records = pipeline.run(fixture_events)

        assert len(records) > 0
        assert all(isinstance(r, AnomalyRecord) for r in records)
        assert all(r.mode == "global" for r in records)

    def test_run_per_user_on_fixture(self, fixture_events) -> None:  # type: ignore[no-untyped-def]
        pipeline = UEBAPipeline(
            window_size=_WINDOW,
            window_step=timedelta(minutes=30),
            ensemble_mode="per-user",
            min_windows_per_user=5,
            n_estimators=50,
        )
        records = pipeline.run(fixture_events)
        assert len(records) > 0
        assert all(r.mode == "per-user" for r in records)


class TestModelPersistence:
    """Sauvegarde et rechargement du pipeline entraîné."""

    def test_per_user_round_trip(
        self, training_vectors: list[FeatureVector], tmp_path
    ) -> None:  # type: ignore[no-untyped-def]
        pipeline = UEBAPipeline(
            window_size=_WINDOW,
            window_step=_WINDOW,
            ensemble_mode="per-user",
            min_windows_per_user=10,
            n_estimators=50,
        )
        pipeline.fit(training_vectors)
        before = pipeline.predict(training_vectors)

        path = tmp_path / "pipeline.joblib"
        pipeline.save_model(str(path))
        restored = UEBAPipeline.load_model(str(path))
        after = restored.predict(training_vectors)

        assert restored.mode == "per-user"
        assert [r.is_anomaly for r in before] == [r.is_anomaly for r in after]
        assert [r.used_model for r in before] == [r.used_model for r in after]

    def test_global_round_trip_preserves_fitted_state(
        self, training_vectors: list[FeatureVector], tmp_path
    ) -> None:  # type: ignore[no-untyped-def]
        pipeline = UEBAPipeline(
            window_size=_WINDOW, window_step=_WINDOW, ensemble_mode="global", n_estimators=50
        )
        pipeline.fit(training_vectors)
        before = pipeline.predict(training_vectors)

        path = tmp_path / "global.joblib"
        pipeline.save_model(str(path))
        restored = UEBAPipeline.load_model(str(path))
        # Doit prédire immédiatement (le bug _is_fitted de AnomalyEnsemble.load est contourné).
        after = restored.predict(training_vectors)

        assert restored.mode == "global"
        assert [r.is_anomaly for r in before] == [r.is_anomaly for r in after]

    def test_load_model_accepts_per_user_ensemble_payload(
        self, training_vectors: list[FeatureVector], tmp_path
    ) -> None:  # type: ignore[no-untyped-def]
        # Un modèle sauvegardé directement par PerUserAnomalyEnsemble (cas du
        # notebook Colab) doit être chargeable par le pipeline (rétrocompat).
        from ueba.domain.per_user_ensemble import PerUserAnomalyEnsemble

        ensemble = PerUserAnomalyEnsemble(min_windows_per_user=10, n_estimators=50)
        ensemble.fit(training_vectors)

        path = tmp_path / "notebook_model.joblib"
        ensemble.save(str(path))

        pipeline = UEBAPipeline.load_model(str(path))
        records = pipeline.predict(training_vectors)

        assert pipeline.mode == "per-user"
        assert len(records) == len(training_vectors)
        assert {r.used_model for r in records} == {"alice", "bob"}
