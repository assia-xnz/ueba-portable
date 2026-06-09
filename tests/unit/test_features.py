"""Tests unitaires de l'extracteur de features comportementales UEBA."""

from datetime import datetime, timedelta

import pytest

from ueba.domain.baseline import BaselineRepository
from ueba.domain.features import FEATURE_NAMES, UEBAFeatureExtractor
from ueba.domain.schema import NormalizedEvent

USER = "a.amrani"
HOST = "soc-dc01"


def _event(
    event_id: str,
    *,
    minute: int = 0,
    hour: int = 9,
    day: int = 11,
    user: str = USER,
    host: str = HOST,
    logon_type: str | None = "3",
    process_name: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=datetime(2026, 5, day, hour, minute, 0),
        user=user,
        host=host,
        event_id=event_id,
        logon_type=logon_type,
        process_name=process_name,
    )


@pytest.fixture
def extractor() -> UEBAFeatureExtractor:
    return UEBAFeatureExtractor(window_size=timedelta(hours=1), window_step=timedelta(minutes=30))


class TestUEBAFeatureExtractorBasics:
    """Vérifie le comportement structurel de l'extracteur."""

    def test_extract_returns_empty_list_for_no_events(
        self, extractor: UEBAFeatureExtractor
    ) -> None:
        assert extractor.extract([]) == []

    def test_feature_vector_exposes_exactly_sixteen_features(
        self, extractor: UEBAFeatureExtractor
    ) -> None:
        events = [_event("4624", minute=0), _event("4624", minute=10)]
        vectors = extractor.extract(events)

        assert len(vectors) >= 1
        assert len(FEATURE_NAMES) == 16
        assert len(vectors[0].to_vector()) == 16

    def test_invalid_window_parameters_are_rejected(self) -> None:
        with pytest.raises(ValueError):
            UEBAFeatureExtractor(window_size=timedelta(0), window_step=timedelta(minutes=30))
        with pytest.raises(ValueError):
            UEBAFeatureExtractor(window_size=timedelta(hours=1), window_step=timedelta(0))

    def test_events_are_grouped_independently_per_user(
        self, extractor: UEBAFeatureExtractor
    ) -> None:
        events = [
            _event("4624", minute=0, user="a.amrani"),
            _event("4624", minute=5, user="l.idrissi"),
        ]
        vectors = extractor.extract(events)
        users = {v.user for v in vectors}
        assert users == {"a.amrani", "l.idrissi"}


class TestVolumeFeatures:
    """Vérifie login_count, failed_login_count et failed_login_ratio."""

    def test_login_count_counts_successful_logon_event_ids(
        self, extractor: UEBAFeatureExtractor
    ) -> None:
        events = [
            _event("4624", minute=0),
            _event("4648", minute=5),
            _event("4768", minute=10),
            _event("4776", minute=15),
        ]
        vectors = extractor.extract(events)
        assert vectors[0].login_count == 4.0

    def test_failed_login_count_counts_failure_event_ids(
        self, extractor: UEBAFeatureExtractor
    ) -> None:
        events = [_event("4625", minute=0), _event("4771", minute=5), _event("4624", minute=10)]
        vectors = extractor.extract(events)
        assert vectors[0].failed_login_count == 2.0

    def test_failed_login_ratio_is_computed_over_logon_attempts(
        self, extractor: UEBAFeatureExtractor
    ) -> None:
        events = [
            _event("4624", minute=0),
            _event("4625", minute=5),
            _event("4625", minute=10),
            _event("4625", minute=15),
        ]
        vectors = extractor.extract(events)
        # 3 échecs / 4 tentatives totales
        assert vectors[0].failed_login_ratio == pytest.approx(0.75)

    def test_failed_login_ratio_is_zero_without_logon_attempts(
        self, extractor: UEBAFeatureExtractor
    ) -> None:
        events = [_event("4688", minute=0, process_name="cmd.exe")]
        vectors = extractor.extract(events)
        assert vectors[0].failed_login_ratio == 0.0


class TestDiversityAndProcessFeatures:
    """Vérifie unique_hosts, unique_logon_types, process_entropy, unique_processes,
    process_count."""

    def test_unique_hosts_counts_distinct_hosts(self, extractor: UEBAFeatureExtractor) -> None:
        events = [
            _event("4624", minute=0, host="soc-dc01"),
            _event("4624", minute=5, host="soc-endpoint01"),
            _event("4624", minute=10, host="soc-dc01"),
        ]
        vectors = extractor.extract(events)
        assert vectors[0].unique_hosts == 2.0

    def test_unique_logon_types_counts_distinct_types(
        self, extractor: UEBAFeatureExtractor
    ) -> None:
        events = [
            _event("4624", minute=0, logon_type="2"),
            _event("4624", minute=5, logon_type="3"),
            _event("4624", minute=10, logon_type="3"),
        ]
        vectors = extractor.extract(events)
        assert vectors[0].unique_logon_types == 2.0

    def test_process_entropy_is_zero_for_single_repeated_process(
        self, extractor: UEBAFeatureExtractor
    ) -> None:
        events = [_event("4688", minute=m, process_name="powershell.exe") for m in (0, 5, 10)]
        vectors = extractor.extract(events)
        assert vectors[0].process_entropy == 0.0

    def test_process_entropy_is_positive_for_diverse_processes(
        self, extractor: UEBAFeatureExtractor
    ) -> None:
        events = [
            _event("4688", minute=0, process_name="powershell.exe"),
            _event("4688", minute=5, process_name="cmd.exe"),
            _event("4688", minute=10, process_name="whoami.exe"),
            _event("4688", minute=15, process_name="net.exe"),
        ]
        vectors = extractor.extract(events)
        assert vectors[0].process_entropy > 0.0
        assert vectors[0].unique_processes == 4.0

    def test_process_count_counts_only_4688_events(self, extractor: UEBAFeatureExtractor) -> None:
        events = [
            _event("4688", minute=0, process_name="cmd.exe"),
            _event("4688", minute=5, process_name="net.exe"),
            _event("4624", minute=10),
        ]
        vectors = extractor.extract(events)
        assert vectors[0].process_count == 2.0


class TestPrivilegeAndKerberosFeatures:
    """Vérifie priv_logon_count et kerberos_count, signaux clés T1078.003/T1558.003."""

    def test_priv_logon_count_counts_4672_events(self, extractor: UEBAFeatureExtractor) -> None:
        events = [_event("4672", minute=0), _event("4672", minute=5), _event("4624", minute=10)]
        vectors = extractor.extract(events)
        assert vectors[0].priv_logon_count == 2.0

    def test_kerberos_count_counts_4769_events(self, extractor: UEBAFeatureExtractor) -> None:
        events = [_event("4769", minute=m) for m in range(5)]
        vectors = extractor.extract(events)
        assert vectors[0].kerberos_count == 5.0


class TestTemporalFeatures:
    """Vérifie off_hours_ratio, weekend_ratio, login_velocity, host_velocity."""

    def test_off_hours_ratio_flags_events_outside_business_hours(self) -> None:
        extractor = UEBAFeatureExtractor(
            window_size=timedelta(hours=1),
            window_step=timedelta(minutes=30),
            business_hour_start=8,
            business_hour_end=18,
        )
        events = [
            _event("4624", hour=22, minute=0),  # hors heures
            _event("4624", hour=22, minute=10),  # hors heures
            _event("4624", hour=9, minute=20),  # heures de bureau -> mais fenêtre différente
        ]
        # On force les trois événements dans la même fenêtre en restant proches
        events = [
            _event("4624", hour=22, minute=0),
            _event("4624", hour=22, minute=10),
            _event("4624", hour=22, minute=20, logon_type="3"),
        ]
        vectors = extractor.extract(events)
        assert vectors[0].off_hours_ratio == 1.0

    def test_off_hours_ratio_is_zero_during_business_hours(
        self, extractor: UEBAFeatureExtractor
    ) -> None:
        events = [_event("4624", hour=9, minute=m) for m in (0, 10, 20)]
        vectors = extractor.extract(events)
        assert vectors[0].off_hours_ratio == 0.0

    def test_weekend_ratio_flags_saturday_and_sunday(self, extractor: UEBAFeatureExtractor) -> None:
        # 16 mai 2026 est un samedi
        events = [_event("4624", day=16, hour=10, minute=m) for m in (0, 10, 20)]
        vectors = extractor.extract(events)
        assert vectors[0].weekend_ratio == 1.0

    def test_login_velocity_is_logins_per_minute_of_window(
        self, extractor: UEBAFeatureExtractor
    ) -> None:
        events = [_event("4624", minute=m) for m in (0, 5, 10, 15)]
        vectors = extractor.extract(events)
        # 4 logons sur une fenêtre de 60 minutes
        assert vectors[0].login_velocity == pytest.approx(4 / 60)

    def test_host_velocity_counts_only_newly_seen_hosts(
        self, extractor: UEBAFeatureExtractor
    ) -> None:
        events = [
            _event("4624", minute=0, host="soc-dc01"),
            _event("4624", minute=35, host="soc-dc01"),
            _event("4624", minute=40, host="soc-endpoint01"),
        ]
        vectors = extractor.extract(events)
        # Première fenêtre [t0, t0+1h): les deux hôtes y apparaissent pour la première fois
        assert vectors[0].host_velocity == pytest.approx(2 / 60)
        # Une fenêtre suivante ne revoyant que des hôtes déjà connus a une vélocité nulle
        later = next(v for v in vectors if v.window_start > vectors[0].window_start)
        assert later.host_velocity == pytest.approx(0.0)


class TestBaselineFeatures:
    """Vérifie z_login_count et z_process_count."""

    def test_z_scores_are_zero_without_baseline_repository(
        self, extractor: UEBAFeatureExtractor
    ) -> None:
        events = [_event("4624", minute=0), _event("4688", minute=5, process_name="cmd.exe")]
        vectors = extractor.extract(events)
        assert vectors[0].z_login_count == 0.0
        assert vectors[0].z_process_count == 0.0

    def test_z_scores_use_baseline_repository_when_provided(self) -> None:
        repo = BaselineRepository(min_observations=2)
        repo.fit({USER: {"login_count": [1.0, 1.0, 1.0, 1.0], "process_count": [0.0, 0.0, 0.0]}})

        extractor = UEBAFeatureExtractor(
            window_size=timedelta(hours=1),
            window_step=timedelta(minutes=30),
            baseline_repository=repo,
        )
        # Pic anormal de connexions par rapport à une baseline très stable (médiane=1)
        events = [_event("4624", minute=m) for m in range(0, 50, 5)]
        vectors = extractor.extract(events)

        assert vectors[0].z_login_count > 0.0


class TestBaselineRepositoryProperty:
    """Vérifie le property setter exposé pour RollingBaselineEngine."""

    def test_baseline_repository_getter_returns_initial_value(self) -> None:
        repo = BaselineRepository()
        extractor = UEBAFeatureExtractor(
            window_size=timedelta(hours=1),
            window_step=timedelta(minutes=30),
            baseline_repository=repo,
        )
        assert extractor.baseline_repository is repo

    def test_baseline_repository_setter_updates_active_repo(self) -> None:
        extractor = UEBAFeatureExtractor(
            window_size=timedelta(hours=1), window_step=timedelta(minutes=30)
        )
        assert extractor.baseline_repository is None

        new_repo = BaselineRepository()
        extractor.baseline_repository = new_repo
        assert extractor.baseline_repository is new_repo

    def test_baseline_repository_setter_accepts_none(self) -> None:
        repo = BaselineRepository()
        extractor = UEBAFeatureExtractor(
            window_size=timedelta(hours=1),
            window_step=timedelta(minutes=30),
            baseline_repository=repo,
        )
        extractor.baseline_repository = None
        assert extractor.baseline_repository is None


class TestExtractForWindow:
    """Vérifie la méthode extract_for_window utilisée par RollingBaselineEngine."""

    def test_returns_empty_list_for_empty_window(self) -> None:
        extractor = UEBAFeatureExtractor(
            window_size=timedelta(hours=1), window_step=timedelta(minutes=30)
        )
        window_start = datetime(2026, 5, 13, 9, 0)
        window_end = datetime(2026, 5, 13, 10, 0)
        result = extractor.extract_for_window([], window_start, window_end)
        assert result == []

    def test_uses_exact_provided_window_bounds(self) -> None:
        extractor = UEBAFeatureExtractor(
            window_size=timedelta(hours=1), window_step=timedelta(minutes=30)
        )
        # day=11 est la valeur par défaut du helper _event
        window_start = datetime(2026, 5, 11, 9, 0)
        window_end = datetime(2026, 5, 11, 10, 0)
        events = [
            _event("4624", hour=9, minute=0),  # dans fenêtre (day=11)
            _event("4624", hour=10, minute=30),  # hors fenêtre (day=11 10h30)
        ]
        vectors = extractor.extract_for_window(events, window_start, window_end)
        assert len(vectors) == 1
        assert vectors[0].window_start == window_start
        assert vectors[0].window_end == window_end
        assert vectors[0].login_count == 1.0

    def test_excludes_events_outside_window(self) -> None:
        extractor = UEBAFeatureExtractor(
            window_size=timedelta(hours=1), window_step=timedelta(minutes=30)
        )
        window_start = datetime(2026, 5, 11, 10, 0)
        window_end = datetime(2026, 5, 11, 11, 0)
        events = [
            _event("4624", hour=9, minute=30),  # avant fenêtre (day=11)
            _event("4624", hour=10, minute=30),  # dans fenêtre (day=11)
            _event("4624", hour=11, minute=30),  # après fenêtre (day=11)
        ]
        vectors = extractor.extract_for_window(events, window_start, window_end)
        assert len(vectors) == 1
        assert vectors[0].login_count == 1.0

    def test_first_seen_hosts_state_is_shared_across_calls(self) -> None:
        extractor = UEBAFeatureExtractor(
            window_size=timedelta(hours=1), window_step=timedelta(minutes=30)
        )
        shared_state: dict[str, set[str]] = {}
        w1_start = datetime(2026, 5, 11, 9, 0)
        w1_end = datetime(2026, 5, 11, 10, 0)
        w2_start = datetime(2026, 5, 11, 9, 30)
        w2_end = datetime(2026, 5, 11, 10, 30)

        events = [
            _event("4624", hour=9, minute=10, host="soc-dc01"),
            _event("4624", hour=9, minute=45, host="soc-dc01"),  # déjà vu
        ]
        extractor.extract_for_window(events, w1_start, w1_end, shared_state)
        vectors2 = extractor.extract_for_window(events, w2_start, w2_end, shared_state)

        # Dans la deuxième fenêtre, soc-dc01 est déjà connu → host_velocity = 0
        if vectors2:
            assert vectors2[0].host_velocity == pytest.approx(0.0)

    def test_produces_one_vector_per_active_user(self) -> None:
        extractor = UEBAFeatureExtractor(
            window_size=timedelta(hours=1), window_step=timedelta(minutes=30)
        )
        window_start = datetime(2026, 5, 11, 9, 0)
        window_end = datetime(2026, 5, 11, 10, 0)
        events = [
            _event("4624", hour=9, minute=0, user="a.amrani"),
            _event("4624", hour=9, minute=10, user="l.idrissi"),
            _event("4624", hour=9, minute=20, user="a.amrani"),
        ]
        vectors = extractor.extract_for_window(events, window_start, window_end)
        assert {v.user for v in vectors} == {"a.amrani", "l.idrissi"}


class TestSlidingWindows:
    """Vérifie le fenêtrage glissant (taille/pas configurables)."""

    def test_overlapping_windows_are_generated_per_step(self) -> None:
        extractor = UEBAFeatureExtractor(
            window_size=timedelta(hours=1), window_step=timedelta(minutes=30)
        )
        events = [_event("4624", hour=9, minute=0), _event("4624", hour=10, minute=30)]
        vectors = extractor.extract(events)

        # Avec un pas de 30min sur ~1h30 d'activité, on attend plusieurs fenêtres chevauchantes
        assert len(vectors) > 1
        starts = [v.window_start for v in vectors]
        assert starts == sorted(starts)

    def test_window_step_controls_number_of_windows(self) -> None:
        events = [_event("4624", hour=9, minute=0), _event("4624", hour=11, minute=0)]

        fine = UEBAFeatureExtractor(
            window_size=timedelta(hours=1), window_step=timedelta(minutes=15)
        )
        coarse = UEBAFeatureExtractor(
            window_size=timedelta(hours=1), window_step=timedelta(hours=1)
        )

        assert len(fine.extract(events)) > len(coarse.extract(events))
