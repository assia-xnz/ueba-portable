"""Test d'intégration : détection du password spraying T1110.003 sur la fixture synthétique.

Ce test charge le CSV synthétique sample_logs.csv via WazuhAdapter,
extrait les features comportementales, et vérifie que le MitreMapper
détecte le scénario de password spray du 16 mai 2026 14h00–14h08 :
7 utilisateurs distincts avec des échecs de connexion synchronisés
depuis la même IP (10.10.0.50).
"""

from __future__ import annotations

import csv
from datetime import timedelta
from pathlib import Path

import pytest

from ueba.adapters.wazuh import WazuhAdapter
from ueba.domain.features import UEBAFeatureExtractor
from ueba.domain.mitre import MitreMapper

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_logs.csv"

PASSWORD_SPRAY_WINDOW_START_HOUR = 14
PASSWORD_SPRAY_DATE = (2026, 5, 16)
PASSWORD_SPRAY_USERS = {
    "alice.martin",
    "bob.chen",
    "charlie.kim",
    "diana.wolf",
    "eric.santos",
    "fiona.lee",
    "george.nasir",
}
MIN_SPRAY_USERS = 3  # seuil PASSWORD_SPRAY_MIN_USERS dans mitre.py


@pytest.fixture(scope="module")
def normalized_events():
    """Charge et normalise les événements depuis la fixture CSV."""
    assert FIXTURE_PATH.exists(), f"Fixture manquante : {FIXTURE_PATH}"

    with FIXTURE_PATH.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = list(reader)

    adapter = WazuhAdapter()
    events = adapter.normalize(records)
    assert len(events) > 0, "Aucun événement normalisé depuis la fixture"
    return events


@pytest.fixture(scope="module")
def feature_vectors(normalized_events):
    """Extrait les vecteurs de features depuis les événements normalisés."""
    extractor = UEBAFeatureExtractor(
        window_size=timedelta(hours=1),
        window_step=timedelta(minutes=30),
    )
    return extractor.extract(normalized_events)


class TestFixtureLoading:
    """Vérifie le chargement et la normalisation de la fixture synthétique."""

    def test_fixture_file_exists(self) -> None:
        assert FIXTURE_PATH.exists()

    def test_adapter_parses_all_non_machine_records(self, normalized_events) -> None:
        assert len(normalized_events) >= 90

    def test_all_expected_users_present(self, normalized_events) -> None:
        users = {e.user for e in normalized_events}
        assert PASSWORD_SPRAY_USERS.issubset(users)

    def test_machine_accounts_are_filtered_out(self, normalized_events) -> None:
        for event in normalized_events:
            assert not event.user.endswith("$"), f"Compte machine non filtré : {event.user}"
            assert event.user.upper() not in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}

    def test_timestamps_span_both_dates(self, normalized_events) -> None:
        days = {e.timestamp.day for e in normalized_events}
        assert 13 in days
        assert 16 in days

    def test_both_event_types_are_present(self, normalized_events) -> None:
        event_ids = {e.event_id for e in normalized_events}
        assert "4624" in event_ids  # logon
        assert "4625" in event_ids  # failed logon
        assert "4688" in event_ids  # process creation


class TestPasswordSprayScenario:
    """Vérifie la détection du scénario password spray (T1110.003) du 16 mai 14h."""

    def test_failed_logins_are_present_in_spray_window(self, normalized_events) -> None:
        spray_events = [
            e
            for e in normalized_events
            if e.event_id == "4625" and e.timestamp.day == 16 and e.timestamp.hour == 14
        ]
        spray_users = {e.user for e in spray_events}
        assert len(spray_users) >= MIN_SPRAY_USERS, (
            f"Scénario de spray insuffisant : seulement {len(spray_users)} utilisateurs "
            f"avec des échecs à 14h le 16 mai (min attendu : {MIN_SPRAY_USERS})"
        )

    def test_failed_logins_originate_from_same_ip(self, normalized_events) -> None:
        spray_events = [
            e for e in normalized_events if e.event_id == "4625" and e.timestamp.day == 16
        ]
        spray_ips = {e.src_ip for e in spray_events if e.src_ip}
        assert "10.10.0.50" in spray_ips

    def test_mitre_mapper_detects_password_spray(self, feature_vectors) -> None:
        mapper = MitreMapper()

        spray_vectors = [
            v
            for v in feature_vectors
            if v.window_start.day == 16
            and v.window_start.hour == PASSWORD_SPRAY_WINDOW_START_HOUR
            and v.failed_login_count > 0
        ]
        assert len(spray_vectors) >= MIN_SPRAY_USERS, (
            f"Pas assez de vecteurs avec failed_login_count > 0 dans la fenêtre 14h du 16 mai : "
            f"{len(spray_vectors)} (min : {MIN_SPRAY_USERS})"
        )

        mitre_matches = mapper.match_population(spray_vectors)
        technique_ids = [m.technique_id for m in mitre_matches]

        assert "T1110.003" in technique_ids, (
            f"Password Spraying (T1110.003) non détecté. " f"Matches obtenus : {technique_ids}"
        )

    def test_password_spray_match_identifies_targeted_users(self, feature_vectors) -> None:
        mapper = MitreMapper()

        spray_vectors = [
            v
            for v in feature_vectors
            if v.window_start.day == 16
            and v.window_start.hour == PASSWORD_SPRAY_WINDOW_START_HOUR
            and v.failed_login_count > 0
        ]
        mitre_matches = mapper.match_population(spray_vectors)
        spray_match = next((m for m in mitre_matches if m.technique_id == "T1110.003"), None)
        assert spray_match is not None

        for user in ("alice.martin", "bob.chen", "charlie.kim"):
            assert (
                user in spray_match.rationale
            ), f"Utilisateur {user!r} absent du rationale T1110.003 : {spray_match.rationale!r}"

    def test_password_spray_source_is_heuristic(self, feature_vectors) -> None:
        mapper = MitreMapper()
        spray_vectors = [
            v
            for v in feature_vectors
            if v.window_start.day == 16
            and v.window_start.hour == PASSWORD_SPRAY_WINDOW_START_HOUR
            and v.failed_login_count > 0
        ]
        mitre_matches = mapper.match_population(spray_vectors)
        spray_match = next((m for m in mitre_matches if m.technique_id == "T1110.003"), None)
        assert spray_match is not None
        assert spray_match.source == "heuristic"


class TestNormalActivityBaseline:
    """Vérifie que l'activité normale du 13 mai ne génère pas de faux positifs bruts."""

    def test_no_failed_logins_on_may_13(self, normalized_events) -> None:
        failed_may13 = [
            e for e in normalized_events if e.event_id == "4625" and e.timestamp.day == 13
        ]
        assert len(failed_may13) == 0

    def test_feature_vectors_cover_both_days(self, feature_vectors) -> None:
        days = {v.window_start.day for v in feature_vectors}
        assert 13 in days
        assert 16 in days

    def test_failed_login_count_zero_on_may_13_windows(self, feature_vectors) -> None:
        may13_vectors = [v for v in feature_vectors if v.window_start.day == 13]
        assert len(may13_vectors) > 0
        for v in may13_vectors:
            assert v.failed_login_count == 0.0
