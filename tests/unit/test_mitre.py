"""Tests unitaires du mapping des anomalies vers MITRE ATT&CK."""

from datetime import datetime, timedelta

import pytest

from ueba.domain.features import FEATURE_NAMES, FeatureVector
from ueba.domain.mitre import MitreMapper

WINDOW_START = datetime(2026, 5, 13, 11, 0)
WINDOW_END = WINDOW_START + timedelta(hours=1)


def _vector(user: str = "a.amrani", **overrides: float) -> FeatureVector:
    """Construit un FeatureVector « neutre » (toutes features à 0) avec overrides ciblés."""
    values: dict[str, float] = dict.fromkeys(FEATURE_NAMES, 0.0)
    values.update(overrides)
    return FeatureVector(user=user, window_start=WINDOW_START, window_end=WINDOW_END, **values)


@pytest.fixture
def mapper() -> MitreMapper:
    return MitreMapper()


class TestIndividualHeuristics:
    """Vérifie chaque correspondance heuristique individuelle (§ 5.8)."""

    def test_high_failed_login_count_maps_to_brute_force(self, mapper: MitreMapper) -> None:
        vector = _vector(failed_login_count=10.0)
        techniques = {m.technique_id for m in mapper.match_individual(vector)}
        assert "T1110" in techniques

    def test_high_priv_logon_count_maps_to_local_accounts(self, mapper: MitreMapper) -> None:
        vector = _vector(priv_logon_count=5.0)
        techniques = {m.technique_id for m in mapper.match_individual(vector)}
        assert "T1078.003" in techniques

    def test_high_kerberos_count_maps_to_kerberoasting(self, mapper: MitreMapper) -> None:
        vector = _vector(kerberos_count=8.0)
        techniques = {m.technique_id for m in mapper.match_individual(vector)}
        assert "T1558.003" in techniques

    def test_high_process_entropy_maps_to_command_and_scripting(self, mapper: MitreMapper) -> None:
        vector = _vector(process_entropy=3.5)
        techniques = {m.technique_id for m in mapper.match_individual(vector)}
        assert "T1059" in techniques

    def test_off_hours_and_unique_hosts_combo_maps_to_valid_accounts(self, mapper: MitreMapper) -> None:
        vector = _vector(off_hours_ratio=0.8, unique_hosts=4.0)
        techniques = {m.technique_id for m in mapper.match_individual(vector)}
        assert "T1078" in techniques

    def test_off_hours_alone_does_not_trigger_valid_accounts(self, mapper: MitreMapper) -> None:
        vector = _vector(off_hours_ratio=0.9, unique_hosts=1.0)
        techniques = {m.technique_id for m in mapper.match_individual(vector)}
        assert "T1078" not in techniques

    def test_high_host_velocity_maps_to_remote_services(self, mapper: MitreMapper) -> None:
        vector = _vector(host_velocity=0.5)
        techniques = {m.technique_id for m in mapper.match_individual(vector)}
        assert "T1021" in techniques

    def test_quiet_vector_yields_no_heuristic_matches(self, mapper: MitreMapper) -> None:
        vector = _vector()
        assert mapper.match_individual(vector) == []

    def test_match_includes_rationale_and_source(self, mapper: MitreMapper) -> None:
        vector = _vector(failed_login_count=12.0)
        matches = mapper.match_individual(vector)
        match = next(m for m in matches if m.technique_id == "T1110")
        assert "12" in match.rationale
        assert match.source == "heuristic"
        assert match.tactic == "Credential Access"


class TestSiemNativeMapping:
    """Vérifie l'exploitation prioritaire des champs natifs rule.mitre.id/tactic."""

    def test_siem_native_technique_is_included_first(self, mapper: MitreMapper) -> None:
        vector = _vector(failed_login_count=10.0)
        matches = mapper.match_individual(
            vector, siem_mitre_technique="T1110.001", siem_mitre_tactic="Credential Access"
        )
        assert matches[0].technique_id == "T1110.001"
        assert matches[0].source == "siem_native"
        assert matches[0].tactic == "Credential Access"

    def test_siem_native_technique_complements_heuristics(self, mapper: MitreMapper) -> None:
        vector = _vector(failed_login_count=10.0)
        matches = mapper.match_individual(vector, siem_mitre_technique="T1110.001")
        technique_ids = [m.technique_id for m in matches]
        assert "T1110.001" in technique_ids
        assert "T1110" in technique_ids

    def test_no_siem_technique_yields_only_heuristic_matches(self, mapper: MitreMapper) -> None:
        vector = _vector(failed_login_count=10.0)
        matches = mapper.match_individual(vector)
        assert all(m.source == "heuristic" for m in matches)


class TestPasswordSprayingDetection:
    """Vérifie la détection collective du password spraying (T1110.003)."""

    def test_synchronized_failures_across_multiple_users_trigger_password_spray(
        self, mapper: MitreMapper
    ) -> None:
        vectors = [
            _vector(user="a.amrani", failed_login_count=3.0),
            _vector(user="l.idrissi", failed_login_count=4.0),
            _vector(user="l.mus", failed_login_count=3.0),
            _vector(user="y.ben", failed_login_count=2.0),
        ]
        matches = mapper.match_population(vectors)

        assert len(matches) == 1
        assert matches[0].technique_id == "T1110.003"
        assert "a.amrani" in matches[0].rationale
        assert "y.ben" in matches[0].rationale

    def test_single_user_high_failures_is_not_classified_as_spraying(self, mapper: MitreMapper) -> None:
        vectors = [_vector(user="a.amrani", failed_login_count=20.0)]
        assert mapper.match_population(vectors) == []

    def test_few_users_below_threshold_is_not_classified_as_spraying(self, mapper: MitreMapper) -> None:
        vectors = [
            _vector(user="a.amrani", failed_login_count=3.0),
            _vector(user="l.idrissi", failed_login_count=3.0),
        ]
        assert mapper.match_population(vectors) == []

    def test_low_failure_counts_do_not_count_toward_spraying(self, mapper: MitreMapper) -> None:
        vectors = [
            _vector(user="a.amrani", failed_login_count=1.0),
            _vector(user="l.idrissi", failed_login_count=1.0),
            _vector(user="l.mus", failed_login_count=1.0),
            _vector(user="y.ben", failed_login_count=1.0),
        ]
        assert mapper.match_population(vectors) == []

    def test_distinct_windows_produce_distinct_matches(self, mapper: MitreMapper) -> None:
        other_window_start = WINDOW_START + timedelta(days=3, hours=7)
        other_window_end = other_window_start + timedelta(hours=1)

        first_window = [
            FeatureVector(
                user=user,
                window_start=WINDOW_START,
                window_end=WINDOW_END,
                **{**dict.fromkeys(FEATURE_NAMES, 0.0), "failed_login_count": 3.0},
            )
            for user in ("a.amrani", "l.idrissi", "l.mus")
        ]
        second_window = [
            FeatureVector(
                user=user,
                window_start=other_window_start,
                window_end=other_window_end,
                **{**dict.fromkeys(FEATURE_NAMES, 0.0), "failed_login_count": 4.0},
            )
            for user in ("n.alam", "s.ed", "k.alaa")
        ]
        matches = mapper.match_population(first_window + second_window)

        assert len(matches) == 2
        windows = {(m.rationale[-30:]) for m in matches}
        assert len(windows) == 2

    def test_empty_input_yields_no_matches(self, mapper: MitreMapper) -> None:
        assert mapper.match_population([]) == []
