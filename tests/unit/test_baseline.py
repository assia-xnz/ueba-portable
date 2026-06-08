"""Tests unitaires des baselines comportementales robustes (médiane/MAD)."""

import math

from ueba.domain.baseline import BaselineRepository, UserBaseline


class TestUserBaselineRobustZScore:
    """Vérifie le calcul du z-score robuste médiane/MAD."""

    def test_value_equal_to_median_has_zero_z_score(self) -> None:
        baseline = UserBaseline(user="a.amrani", metric="login_count", median=5.0, mad=1.0, n_observations=10)
        assert baseline.robust_z_score(5.0) == 0.0

    def test_value_above_median_has_positive_z_score(self) -> None:
        baseline = UserBaseline(user="a.amrani", metric="login_count", median=5.0, mad=1.0, n_observations=10)
        assert baseline.robust_z_score(8.0) > 0

    def test_value_below_median_has_negative_z_score(self) -> None:
        baseline = UserBaseline(user="a.amrani", metric="login_count", median=5.0, mad=1.0, n_observations=10)
        assert baseline.robust_z_score(2.0) < 0

    def test_zero_mad_does_not_raise_division_by_zero(self) -> None:
        baseline = UserBaseline(user="a.amrani", metric="login_count", median=1.0, mad=0.0, n_observations=10)
        z = baseline.robust_z_score(5.0)
        assert math.isfinite(z)
        assert z > 0

    def test_zero_mad_and_value_equal_to_median_returns_zero(self) -> None:
        baseline = UserBaseline(user="a.amrani", metric="login_count", median=1.0, mad=0.0, n_observations=10)
        assert baseline.robust_z_score(1.0) == 0.0

    def test_is_reliable_requires_minimum_observations(self) -> None:
        assert UserBaseline("u", "m", 0.0, 1.0, n_observations=0).is_reliable is False
        assert UserBaseline("u", "m", 0.0, 1.0, n_observations=1).is_reliable is False
        assert UserBaseline("u", "m", 0.0, 1.0, n_observations=2).is_reliable is True


class TestBaselineRepository:
    """Vérifie l'apprentissage et la restitution des baselines par utilisateur."""

    def test_fit_computes_median_and_mad_per_user_and_metric(self) -> None:
        repo = BaselineRepository(min_observations=2)
        repo.fit({"a.amrani": {"login_count": [4.0, 5.0, 6.0, 5.0, 100.0]}})

        baseline = repo.get("a.amrani", "login_count")
        # Médiane robuste à l'outlier 100.0
        assert baseline.median == 5.0
        # MAD = médiane des |x - 5| = médiane([1, 0, 1, 0, 95]) = 1.0
        assert baseline.mad == 1.0
        assert baseline.n_observations == 5

    def test_outlier_does_not_inflate_baseline_dispersion(self) -> None:
        """Le levier anti-FP : un seul pic historique ne doit pas masquer les futures anomalies."""
        repo = BaselineRepository(min_observations=2)
        repo.fit({"a.amrani": {"login_count": [4.0, 5.0, 6.0, 5.0, 100.0]}})
        baseline = repo.get("a.amrani", "login_count")

        # Une nouvelle valeur de 9 reste un écart significatif malgré l'outlier 100 dans l'historique
        assert baseline.robust_z_score(9.0) > 2.0

    def test_get_returns_neutral_baseline_for_unknown_user(self) -> None:
        repo = BaselineRepository()
        repo.fit({"a.amrani": {"login_count": [1.0, 2.0, 3.0]}})

        baseline = repo.get("unknown.user", "login_count")
        assert baseline.n_observations == 0
        assert baseline.is_reliable is False
        assert baseline.median == 0.0
        assert baseline.mad == 0.0

    def test_get_returns_neutral_baseline_for_unknown_metric(self) -> None:
        repo = BaselineRepository()
        repo.fit({"a.amrani": {"login_count": [1.0, 2.0, 3.0]}})

        baseline = repo.get("a.amrani", "process_count")
        assert baseline.n_observations == 0

    def test_fit_handles_empty_observation_lists(self) -> None:
        repo = BaselineRepository()
        repo.fit({"a.amrani": {"login_count": []}})

        baseline = repo.get("a.amrani", "login_count")
        assert baseline.n_observations == 0
        assert baseline.median == 0.0

    def test_fit_resets_previous_state(self) -> None:
        repo = BaselineRepository()
        repo.fit({"a.amrani": {"login_count": [1.0, 2.0, 3.0]}})
        repo.fit({"l.idrissi": {"login_count": [10.0, 20.0, 30.0]}})

        # L'ancien utilisateur ne doit plus avoir de baseline après un nouvel apprentissage
        assert repo.get("a.amrani", "login_count").n_observations == 0
        assert repo.get("l.idrissi", "login_count").n_observations == 3
