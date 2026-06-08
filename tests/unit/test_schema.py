"""Tests unitaires du schéma normalisé et du filtre de comptes machine."""

from datetime import datetime

from ueba.domain.schema import MachineAccountFilter, NormalizedEvent


def _event(event_id: str, **overrides: object) -> NormalizedEvent:
    base: dict[str, object] = {
        "timestamp": datetime(2026, 5, 13, 11, 0, 0),
        "user": "a.amrani",
        "host": "soc-dc01",
        "event_id": event_id,
    }
    base.update(overrides)
    return NormalizedEvent(**base)  # type: ignore[arg-type]


class TestNormalizedEventClassification:
    """Vérifie les propriétés de classification dérivées de l'event_id."""

    def test_login_event_ids_are_recognized(self) -> None:
        for event_id in ("4624", "4648", "4768", "4776"):
            assert _event(event_id).is_login is True
            assert _event(event_id).is_failed_login is False

    def test_failed_login_event_ids_are_recognized(self) -> None:
        for event_id in ("4625", "4771"):
            assert _event(event_id).is_failed_login is True
            assert _event(event_id).is_login is False

    def test_process_creation_event_is_recognized(self) -> None:
        event = _event("4688")
        assert event.is_process_creation is True
        assert event.is_login is False

    def test_privileged_logon_event_is_recognized(self) -> None:
        assert _event("4672").is_privileged_logon is True

    def test_kerberos_tgs_event_is_recognized(self) -> None:
        assert _event("4769").is_kerberos_tgs_request is True

    def test_unrelated_event_id_is_not_misclassified(self) -> None:
        event = _event("4634")
        assert event.is_login is False
        assert event.is_failed_login is False
        assert event.is_process_creation is False
        assert event.is_privileged_logon is False
        assert event.is_kerberos_tgs_request is False


class TestMachineAccountFilter:
    """Vérifie le premier levier anti-FP : exclusion des comptes machine/système."""

    def test_default_filter_excludes_machine_accounts_by_suffix(self) -> None:
        filt = MachineAccountFilter.default()
        assert filt.is_machine_account("SOC-ENDPOINT01$") is True

    def test_default_filter_excludes_known_system_accounts(self) -> None:
        filt = MachineAccountFilter.default()
        for name in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"):
            assert filt.is_machine_account(name) is True
            assert filt.is_machine_account(name.lower()) is True

    def test_default_filter_excludes_session_accounts_by_prefix(self) -> None:
        filt = MachineAccountFilter.default()
        assert filt.is_machine_account("DWM-1") is True
        assert filt.is_machine_account("UMFD-0") is True

    def test_default_filter_keeps_real_human_accounts(self) -> None:
        filt = MachineAccountFilter.default()
        for name in ("a.amrani", "l.idrissi", "soc-admin", "y.ben"):
            assert filt.is_machine_account(name) is False

    def test_empty_or_blank_user_is_excluded(self) -> None:
        filt = MachineAccountFilter.default()
        assert filt.is_machine_account("") is True
        assert filt.is_machine_account("   ") is True

    def test_custom_filter_rules_are_applied(self) -> None:
        filt = MachineAccountFilter(
            suffixes=["_svc"], exact_names=["guest"], prefixes=["test-"]
        )
        assert filt.is_machine_account("backup_svc") is True
        assert filt.is_machine_account("Guest") is True
        assert filt.is_machine_account("test-runner") is True
        assert filt.is_machine_account("a.amrani") is False
