"""Tests unitaires de la couche adapters : contrat abstrait, Wazuh, Elastic, Splunk, QRadar, registry."""

from collections.abc import Mapping
from datetime import datetime

import pytest

from ueba.adapters.base import AdapterParsingError, SIEMAdapter
from ueba.domain.schema import MachineAccountFilter, NormalizedEvent

# ---------------------------------------------------------------------------
# Contrat abstrait SIEMAdapter (via une implémentation factice minimale)
# ---------------------------------------------------------------------------


class _FakeAdapter(SIEMAdapter):
    """Implémentation minimale de SIEMAdapter pour tester le contrat commun."""

    name = "fake"

    def parse_record(self, record: Mapping[str, object]) -> NormalizedEvent | None:
        if record.get("skip"):
            return None
        if "user" not in record:
            raise AdapterParsingError("champ 'user' manquant")
        return NormalizedEvent(
            timestamp=datetime(2026, 5, 13, 11, 0),
            user=str(record["user"]),
            host=str(record.get("host", "host01")),
            event_id=str(record.get("event_id", "4624")),
        )


class TestSIEMAdapterContract:
    """Vérifie l'orchestration commune assurée par SIEMAdapter.normalize."""

    def test_normalize_applies_machine_account_filter(self) -> None:
        adapter = _FakeAdapter()
        records = [{"user": "a.amrani"}, {"user": "SOC-DC01$"}, {"user": "SYSTEM"}]

        events = adapter.normalize(records)
        assert [e.user for e in events] == ["a.amrani"]

    def test_normalize_skips_records_raising_parsing_error(self) -> None:
        adapter = _FakeAdapter()
        records = [{"user": "a.amrani"}, {"no_user_field": True}, {"user": "l.idrissi"}]

        events = adapter.normalize(records)
        assert [e.user for e in events] == ["a.amrani", "l.idrissi"]

    def test_normalize_skips_records_returning_none(self) -> None:
        adapter = _FakeAdapter()
        records = [{"user": "a.amrani"}, {"skip": True, "user": "l.idrissi"}]

        events = adapter.normalize(records)
        assert [e.user for e in events] == ["a.amrani"]

    def test_normalize_accepts_custom_machine_account_filter(self) -> None:
        custom_filter = MachineAccountFilter(exact_names=["a.amrani"])
        adapter = _FakeAdapter(machine_account_filter=custom_filter)
        records = [{"user": "a.amrani"}, {"user": "l.idrissi"}]

        events = adapter.normalize(records)
        assert [e.user for e in events] == ["l.idrissi"]


# ---------------------------------------------------------------------------
# WazuhAdapter — adapter principal (production)
# ---------------------------------------------------------------------------


from ueba.adapters.wazuh import WazuhAdapter  # noqa: E402


def _wazuh_record(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "@timestamp": "May 13, 2026 @ 11:08:16.256",
        "agent.name": "soc-dc01",
        "data.win.system.eventID": "4624",
        "data.win.eventdata.targetUserName": "a.amrani",
        "data.win.eventdata.subjectUserName": "soc-dc01$",
        "data.win.eventdata.logonType": "3",
        "data.win.eventdata.workstationName": "soc-endpoint01",
        "data.win.eventdata.ipAddress": "192.168.1.50",
        "data.win.eventdata.processName": "C:\\Windows\\System32\\cmd.exe",
        "data.win.eventdata.parentProcessName": "C:\\Windows\\explorer.exe",
        "rule.level": "5",
        "rule.mitre.id": "T1078",
        "rule.mitre.tactic": "Initial Access",
    }
    base.update(overrides)
    return base


class TestWazuhAdapter:
    """Vérifie le mapping du schéma Wazuh natif (data.win.eventdata.*) vers le schéma normalisé."""

    @pytest.fixture
    def adapter(self) -> WazuhAdapter:
        return WazuhAdapter()

    def test_parses_kibana_timestamp_format(self, adapter: WazuhAdapter) -> None:
        event = adapter.parse_record(_wazuh_record())
        assert event is not None
        assert event.timestamp == datetime(2026, 5, 13, 11, 8, 16, 256000)

    def test_logon_event_uses_target_user_name(self, adapter: WazuhAdapter) -> None:
        event = adapter.parse_record(_wazuh_record(**{"data.win.system.eventID": "4624"}))
        assert event is not None
        assert event.user == "a.amrani"

    def test_process_creation_event_uses_subject_user_name(self, adapter: WazuhAdapter) -> None:
        """Particularité Windows : pour 4688, l'utilisateur réel est dans subjectUserName."""
        record = _wazuh_record(**{
            "data.win.system.eventID": "4688",
            "data.win.eventdata.targetUserName": "",
            "data.win.eventdata.subjectUserName": "l.idrissi",
        })
        event = adapter.parse_record(record)
        assert event is not None
        assert event.user == "l.idrissi"
        assert event.event_id == "4688"

    def test_maps_native_fields_to_normalized_schema(self, adapter: WazuhAdapter) -> None:
        event = adapter.parse_record(_wazuh_record())
        assert event is not None
        assert event.host == "soc-dc01"
        assert event.logon_type == "3"
        assert event.workstation == "soc-endpoint01"
        assert event.src_ip == "192.168.1.50"
        assert event.process_name == "C:\\Windows\\System32\\cmd.exe"
        assert event.parent_process == "C:\\Windows\\explorer.exe"
        assert event.rule_level == 5
        assert event.mitre_technique == "T1078"
        assert event.mitre_tactic == "Initial Access"

    def test_missing_timestamp_raises_parsing_error(self, adapter: WazuhAdapter) -> None:
        record = _wazuh_record(**{"@timestamp": ""})
        with pytest.raises(AdapterParsingError):
            adapter.parse_record(record)

    def test_unparsable_timestamp_raises_parsing_error(self, adapter: WazuhAdapter) -> None:
        record = _wazuh_record(**{"@timestamp": "not-a-date"})
        with pytest.raises(AdapterParsingError):
            adapter.parse_record(record)

    def test_missing_event_id_raises_parsing_error(self, adapter: WazuhAdapter) -> None:
        record = _wazuh_record(**{"data.win.system.eventID": ""})
        with pytest.raises(AdapterParsingError):
            adapter.parse_record(record)

    def test_normalize_excludes_machine_accounts_via_subject_user_name(self, adapter: WazuhAdapter) -> None:
        records = [
            _wazuh_record(**{
                "data.win.system.eventID": "4688",
                "data.win.eventdata.targetUserName": "",
                "data.win.eventdata.subjectUserName": "SOC-ENDPOINT01$",
            }),
            _wazuh_record(**{
                "data.win.system.eventID": "4688",
                "data.win.eventdata.targetUserName": "",
                "data.win.eventdata.subjectUserName": "y.ben",
            }),
        ]
        events = adapter.normalize(records)
        assert [e.user for e in events] == ["y.ben"]

    def test_optional_fields_default_to_none_when_absent(self, adapter: WazuhAdapter) -> None:
        record = _wazuh_record()
        for key in (
            "data.win.eventdata.logonType",
            "data.win.eventdata.workstationName",
            "data.win.eventdata.ipAddress",
            "data.win.eventdata.processName",
            "data.win.eventdata.parentProcessName",
            "rule.level",
            "rule.mitre.id",
            "rule.mitre.tactic",
        ):
            record.pop(key, None)

        event = adapter.parse_record(record)
        assert event is not None
        assert event.logon_type is None
        assert event.workstation is None
        assert event.src_ip is None
        assert event.process_name is None
        assert event.parent_process is None
        assert event.rule_level is None
        assert event.mitre_technique is None
        assert event.mitre_tactic is None


# ---------------------------------------------------------------------------
# ElasticAdapter — Winlogbeat/ECS natif (sans Wazuh)
# ---------------------------------------------------------------------------

from ueba.adapters.elastic import ElasticAdapter  # noqa: E402


def _ecs_record(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "@timestamp": "2026-05-13T11:08:16.256Z",
        "host.name": "soc-dc01",
        "event.code": "4624",
        "winlog.event_data.TargetUserName": "a.amrani",
        "winlog.event_data.SubjectUserName": "soc-dc01$",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.WorkstationName": "soc-endpoint01",
        "source.ip": "192.168.1.50",
        "process.name": "cmd.exe",
        "process.parent.name": "explorer.exe",
        "event.severity": "5",
    }
    base.update(overrides)
    return base


class TestElasticAdapter:
    """Vérifie le mapping du schéma ECS/Winlogbeat (sans Wazuh) vers le schéma normalisé."""

    @pytest.fixture
    def adapter(self) -> ElasticAdapter:
        return ElasticAdapter()

    def test_parses_iso8601_timestamp(self, adapter: ElasticAdapter) -> None:
        event = adapter.parse_record(_ecs_record())
        assert event is not None
        assert event.timestamp == datetime(2026, 5, 13, 11, 8, 16, 256000)

    def test_logon_event_uses_target_user_name(self, adapter: ElasticAdapter) -> None:
        event = adapter.parse_record(_ecs_record(**{"event.code": "4624"}))
        assert event is not None
        assert event.user == "a.amrani"

    def test_process_creation_event_uses_subject_user_name(self, adapter: ElasticAdapter) -> None:
        record = _ecs_record(**{
            "event.code": "4688",
            "winlog.event_data.TargetUserName": "",
            "winlog.event_data.SubjectUserName": "l.idrissi",
        })
        event = adapter.parse_record(record)
        assert event is not None
        assert event.user == "l.idrissi"

    def test_maps_ecs_fields_to_normalized_schema(self, adapter: ElasticAdapter) -> None:
        event = adapter.parse_record(_ecs_record())
        assert event is not None
        assert event.host == "soc-dc01"
        assert event.logon_type == "3"
        assert event.src_ip == "192.168.1.50"
        assert event.process_name == "cmd.exe"
        assert event.parent_process == "explorer.exe"
        assert event.rule_level == 5

    def test_missing_required_fields_raise_parsing_error(self, adapter: ElasticAdapter) -> None:
        with pytest.raises(AdapterParsingError):
            adapter.parse_record(_ecs_record(**{"event.code": ""}))
        with pytest.raises(AdapterParsingError):
            adapter.parse_record(_ecs_record(**{"@timestamp": "not-a-date"}))


# ---------------------------------------------------------------------------
# SplunkAdapter
# ---------------------------------------------------------------------------

from ueba.adapters.splunk import SplunkAdapter  # noqa: E402


def _splunk_record(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "_time": "2026-05-13T11:08:16.256+00:00",
        "ComputerName": "soc-dc01",
        "EventCode": "4624",
        "TargetUserName": "a.amrani",
        "SubjectUserName": "soc-dc01$",
        "LogonType": "3",
        "WorkstationName": "soc-endpoint01",
        "ip": "192.168.1.50",
        "process_name": "cmd.exe",
        "parent_process_name": "explorer.exe",
    }
    base.update(overrides)
    return base


class TestSplunkAdapter:
    """Vérifie le mapping du format Splunk (recherche/export CIM) vers le schéma normalisé."""

    @pytest.fixture
    def adapter(self) -> SplunkAdapter:
        return SplunkAdapter()

    def test_parses_splunk_time_field(self, adapter: SplunkAdapter) -> None:
        event = adapter.parse_record(_splunk_record())
        assert event is not None
        assert event.timestamp == datetime(2026, 5, 13, 11, 8, 16, 256000)

    def test_logon_event_uses_target_user_name(self, adapter: SplunkAdapter) -> None:
        event = adapter.parse_record(_splunk_record(**{"EventCode": "4624"}))
        assert event is not None
        assert event.user == "a.amrani"

    def test_process_creation_event_uses_subject_user_name(self, adapter: SplunkAdapter) -> None:
        record = _splunk_record(**{
            "EventCode": "4688",
            "TargetUserName": "",
            "SubjectUserName": "y.ben",
        })
        event = adapter.parse_record(record)
        assert event is not None
        assert event.user == "y.ben"

    def test_maps_splunk_fields_to_normalized_schema(self, adapter: SplunkAdapter) -> None:
        event = adapter.parse_record(_splunk_record())
        assert event is not None
        assert event.host == "soc-dc01"
        assert event.logon_type == "3"
        assert event.src_ip == "192.168.1.50"
        assert event.process_name == "cmd.exe"
        assert event.parent_process == "explorer.exe"

    def test_missing_required_fields_raise_parsing_error(self, adapter: SplunkAdapter) -> None:
        with pytest.raises(AdapterParsingError):
            adapter.parse_record(_splunk_record(**{"EventCode": ""}))
        with pytest.raises(AdapterParsingError):
            adapter.parse_record(_splunk_record(**{"_time": "not-a-date"}))


# ---------------------------------------------------------------------------
# QRadarAdapter
# ---------------------------------------------------------------------------

from ueba.adapters.qradar import QRadarAdapter  # noqa: E402


def _qradar_record(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "starttime": "2026-05-13T11:08:16.256",
        "sourcehostname": "soc-dc01",
        "qid": "4624",
        "targetusername": "a.amrani",
        "subjectusername": "soc-dc01$",
        "logontype": "3",
        "workstationname": "soc-endpoint01",
        "sourceip": "192.168.1.50",
        "processname": "cmd.exe",
        "parentprocessname": "explorer.exe",
        "severity": "5",
    }
    base.update(overrides)
    return base


class TestQRadarAdapter:
    """Vérifie le mapping du format QRadar (offenses/export) vers le schéma normalisé."""

    @pytest.fixture
    def adapter(self) -> QRadarAdapter:
        return QRadarAdapter()

    def test_parses_qradar_timestamp(self, adapter: QRadarAdapter) -> None:
        event = adapter.parse_record(_qradar_record())
        assert event is not None
        assert event.timestamp == datetime(2026, 5, 13, 11, 8, 16, 256000)

    def test_logon_event_uses_target_username(self, adapter: QRadarAdapter) -> None:
        event = adapter.parse_record(_qradar_record(**{"qid": "4624"}))
        assert event is not None
        assert event.user == "a.amrani"

    def test_process_creation_event_uses_subject_username(self, adapter: QRadarAdapter) -> None:
        record = _qradar_record(**{
            "qid": "4688",
            "targetusername": "",
            "subjectusername": "k.alaa",
        })
        event = adapter.parse_record(record)
        assert event is not None
        assert event.user == "k.alaa"

    def test_maps_qradar_fields_to_normalized_schema(self, adapter: QRadarAdapter) -> None:
        event = adapter.parse_record(_qradar_record())
        assert event is not None
        assert event.host == "soc-dc01"
        assert event.logon_type == "3"
        assert event.src_ip == "192.168.1.50"
        assert event.process_name == "cmd.exe"
        assert event.parent_process == "explorer.exe"
        assert event.rule_level == 5

    def test_missing_required_fields_raise_parsing_error(self, adapter: QRadarAdapter) -> None:
        with pytest.raises(AdapterParsingError):
            adapter.parse_record(_qradar_record(**{"qid": ""}))
        with pytest.raises(AdapterParsingError):
            adapter.parse_record(_qradar_record(**{"starttime": "not-a-date"}))


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

from ueba.adapters.registry import UnknownAdapterError, get_adapter  # noqa: E402


class TestAdapterRegistry:
    """Vérifie la résolution des adapters par nom (portabilité plug-and-play)."""

    @pytest.mark.parametrize(
        ("adapter_name", "expected_type"),
        [
            ("wazuh", WazuhAdapter),
            ("elastic", ElasticAdapter),
            ("splunk", SplunkAdapter),
            ("qradar", QRadarAdapter),
        ],
    )
    def test_get_adapter_returns_expected_type(self, adapter_name: str, expected_type: type) -> None:
        adapter = get_adapter(adapter_name)
        assert isinstance(adapter, expected_type)

    def test_get_adapter_is_case_insensitive(self) -> None:
        assert isinstance(get_adapter("WAZUH"), WazuhAdapter)
        assert isinstance(get_adapter("Elastic"), ElasticAdapter)

    def test_unknown_adapter_name_raises_explicit_error(self) -> None:
        with pytest.raises(UnknownAdapterError):
            get_adapter("unknown-siem")

    def test_get_adapter_forwards_machine_account_filter(self) -> None:
        custom_filter = MachineAccountFilter(exact_names=["a.amrani"])
        adapter = get_adapter("wazuh", machine_account_filter=custom_filter)

        events = adapter.normalize([_wazuh_record(**{"data.win.eventdata.targetUserName": "a.amrani"})])
        assert events == []
