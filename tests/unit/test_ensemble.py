"""Tests unitaires de l'ensemble de détection d'anomalies par vote majoritaire."""

import numpy as np
import pytest

from ueba.domain.ensemble import ENSEMBLE_SIZE, AnomalyEnsemble, EnsembleVerdict


def _make_normal_population(n: int = 120, n_features: int = 16, seed: int = 42) -> np.ndarray:
    """Génère une population « normale » resserrée autour d'un comportement stable."""
    rng = np.random.default_rng(seed)
    return rng.normal(loc=5.0, scale=0.5, size=(n, n_features))


def _make_extreme_outliers(n: int = 5, n_features: int = 16) -> np.ndarray:
    """Génère des observations extrêmes, très éloignées de la population normale."""
    return np.full((n, n_features), fill_value=500.0)


class TestEnsembleVerdict:
    """Vérifie les propriétés dérivées du verdict."""

    def test_vote_count_reflects_number_of_anomaly_votes(self) -> None:
        verdict = EnsembleVerdict(
            is_anomaly=True,
            votes={"isolation_forest": True, "one_class_svm": True, "autoencoder": False},
            anomaly_score=2 / 3,
        )
        assert verdict.vote_count == 2

    def test_vote_count_is_zero_when_no_model_flags_anomaly(self) -> None:
        verdict = EnsembleVerdict(
            is_anomaly=False,
            votes={"isolation_forest": False, "one_class_svm": False, "autoencoder": False},
            anomaly_score=0.0,
        )
        assert verdict.vote_count == 0


class TestAnomalyEnsembleLifecycle:
    """Vérifie le cycle de vie fit/predict et la gestion des erreurs."""

    def test_predict_before_fit_raises_runtime_error(self) -> None:
        ensemble = AnomalyEnsemble()
        with pytest.raises(RuntimeError):
            ensemble.predict(_make_normal_population(n=5))

    def test_fit_rejects_empty_feature_matrix(self) -> None:
        ensemble = AnomalyEnsemble()
        with pytest.raises(ValueError):
            ensemble.fit(np.empty((0, 16)))

    def test_predict_returns_empty_list_for_empty_matrix(self) -> None:
        ensemble = AnomalyEnsemble(n_estimators=50)
        ensemble.fit(_make_normal_population(n=60))
        assert ensemble.predict(np.empty((0, 16))) == []

    def test_invalid_majority_threshold_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            AnomalyEnsemble(majority_threshold=0)
        with pytest.raises(ValueError):
            AnomalyEnsemble(majority_threshold=ENSEMBLE_SIZE + 1)


class TestAnomalyEnsembleDetection:
    """Vérifie la détection d'anomalies et le mécanisme de vote majoritaire."""

    @pytest.fixture(scope="class")
    def fitted_ensemble(self) -> AnomalyEnsemble:
        ensemble = AnomalyEnsemble(n_estimators=100, majority_threshold=2, random_state=42)
        ensemble.fit(_make_normal_population(n=150))
        return ensemble

    def test_normal_observations_are_mostly_not_flagged(
        self, fitted_ensemble: AnomalyEnsemble
    ) -> None:
        normal = _make_normal_population(n=40, seed=7)
        verdicts = fitted_ensemble.predict(normal)

        anomaly_ratio = sum(1 for v in verdicts if v.is_anomaly) / len(verdicts)
        # La grande majorité des observations « normales » ne doit pas être signalée
        assert anomaly_ratio < 0.25

    def test_extreme_outliers_are_flagged_as_anomalies(
        self, fitted_ensemble: AnomalyEnsemble
    ) -> None:
        outliers = _make_extreme_outliers(n=5)
        verdicts = fitted_ensemble.predict(outliers)

        assert all(v.is_anomaly for v in verdicts)
        assert all(v.vote_count >= 2 for v in verdicts)

    def test_verdict_exposes_individual_model_votes(self, fitted_ensemble: AnomalyEnsemble) -> None:
        verdicts = fitted_ensemble.predict(_make_extreme_outliers(n=1))
        verdict = verdicts[0]

        assert set(verdict.votes) == {"isolation_forest", "one_class_svm", "autoencoder"}
        assert verdict.anomaly_score == pytest.approx(verdict.vote_count / ENSEMBLE_SIZE)

    def test_majority_threshold_controls_sensitivity(self) -> None:
        population = _make_normal_population(n=150)
        outliers = _make_extreme_outliers(n=5)

        strict_ensemble = AnomalyEnsemble(n_estimators=100, majority_threshold=3, random_state=42)
        strict_ensemble.fit(population)

        lenient_ensemble = AnomalyEnsemble(n_estimators=100, majority_threshold=1, random_state=42)
        lenient_ensemble.fit(population)

        strict_alerts = sum(1 for v in strict_ensemble.predict(outliers) if v.is_anomaly)
        lenient_alerts = sum(1 for v in lenient_ensemble.predict(outliers) if v.is_anomaly)

        # Un seuil plus permissif (>=1 vote) ne peut détecter strictement moins d'anomalies
        # qu'un seuil plus strict (3 votes unanimes) sur les mêmes observations extrêmes
        assert lenient_alerts >= strict_alerts

    def test_predict_is_deterministic_given_random_state(self) -> None:
        population = _make_normal_population(n=120)
        sample = _make_normal_population(n=20, seed=99)

        ensemble_a = AnomalyEnsemble(n_estimators=80, random_state=42)
        ensemble_a.fit(population)
        ensemble_b = AnomalyEnsemble(n_estimators=80, random_state=42)
        ensemble_b.fit(population)

        verdicts_a = [v.is_anomaly for v in ensemble_a.predict(sample)]
        verdicts_b = [v.is_anomaly for v in ensemble_b.predict(sample)]
        assert verdicts_a == verdicts_b


class TestSvmNu:
    """Vérifie l'effet du paramètre svm_nu sur les faux positifs."""

    def test_lower_nu_reduces_false_positives_on_normal(self) -> None:
        population = _make_normal_population(n=300, seed=0)

        loose = AnomalyEnsemble(n_estimators=100, svm_nu=0.5, random_state=42)
        loose.fit(population)
        strict = AnomalyEnsemble(n_estimators=100, svm_nu=0.05, random_state=42)
        strict.fit(population)

        loose_fp = sum(1 for v in loose.predict(population) if v.is_anomaly)
        strict_fp = sum(1 for v in strict.predict(population) if v.is_anomaly)

        # Un nu plus bas resserre la frontière « normale » → moins de faux positifs.
        assert strict_fp < loose_fp

    def test_invalid_nu_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            AnomalyEnsemble(svm_nu=0.0)
        with pytest.raises(ValueError):
            AnomalyEnsemble(svm_nu=1.5)
