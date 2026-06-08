"""Adapter pour les exports Splunk (recherches sur des logs Windows Security/Sysmon).

Cet adapter cible les organisations utilisant Splunk comme SIEM, où les
événements Windows sont généralement indexés via le *Splunk Add-on for
Microsoft Windows* ou le *Common Information Model* (CIM), exposant des
champs tels que `EventCode`, `TargetUserName`, `ComputerName`, etc.

Mapping appliqué :

    _time                       -> timestamp (ISO 8601 avec offset)
    ComputerName                -> host
    EventCode                   -> event_id
    TargetUserName              -> user (connexions)
    SubjectUserName             -> user (création de processus, 4688)
    LogonType                   -> logon_type
    WorkstationName             -> workstation
    ip                          -> src_ip
    process_name                -> process_name
    parent_process_name         -> parent_process

Splunk ne fournit pas nativement de mapping MITRE ATT&CK dans ces champs
(contrairement à `rule.mitre.id` chez Wazuh) : `mitre_technique` et
`mitre_tactic` restent donc `None`, et le mapping repose entièrement sur les
heuristiques du domaine (`MitreMapper`).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from ueba.adapters.base import AdapterParsingError, SIEMAdapter, clean_field
from ueba.domain.schema import PROCESS_CREATION_EVENT_ID, NormalizedEvent

#: Formats de timestamp couramment rencontrés dans le champ `_time` d'un export Splunk.
SPLUNK_TIMESTAMP_FORMATS: tuple[str, ...] = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f %z",
    "%Y-%m-%d %H:%M:%S %z",
)


class SplunkAdapter(SIEMAdapter):
    """Traduit les résultats de recherche Splunk (logs Windows) en événements normalisés."""

    name = "splunk"

    def parse_record(self, record: Mapping[str, object]) -> NormalizedEvent | None:
        """Convertit un résultat de recherche Splunk en `NormalizedEvent`.

        Paramètres
        ----------
        record : Mapping[str, object]
            Un événement Splunk indexé par les noms de champs natifs
            (ex. `EventCode`, `TargetUserName`, `ComputerName`).

        Retours
        -------
        NormalizedEvent | None
            L'événement normalisé correspondant.

        Lève
        ----
        AdapterParsingError
            Si le timestamp ou le code d'événement sont absents ou non parsables.
        """
        timestamp = self._parse_timestamp(record.get("_time"))
        event_id = clean_field(record.get("EventCode"))
        if event_id is None:
            raise AdapterParsingError("EventCode manquant ou vide")

        user = self._resolve_user(record, event_id)

        return NormalizedEvent(
            timestamp=timestamp,
            user=user or "",
            host=clean_field(record.get("ComputerName")) or "",
            event_id=event_id,
            logon_type=clean_field(record.get("LogonType")),
            workstation=clean_field(record.get("WorkstationName")),
            src_ip=clean_field(record.get("ip")),
            process_name=clean_field(record.get("process_name")),
            parent_process=clean_field(record.get("parent_process_name")),
            rule_level=None,
            mitre_technique=None,
            mitre_tactic=None,
        )

    def _resolve_user(self, record: Mapping[str, object], event_id: str) -> str | None:
        """Sélectionne `TargetUserName` ou `SubjectUserName` selon le type d'événement Windows.

        Même logique que pour Wazuh/Elastic : le champ pertinent dépend du
        type d'événement Windows (4688 -> sujet), pas du SIEM source.
        """
        target_user = clean_field(record.get("TargetUserName"))
        subject_user = clean_field(record.get("SubjectUserName"))

        if event_id == PROCESS_CREATION_EVENT_ID:
            return subject_user or target_user
        return target_user or subject_user

    def _parse_timestamp(self, raw_timestamp: object) -> datetime:
        """Parse le champ `_time` d'un export Splunk.

        Lève
        ----
        AdapterParsingError
            Si la valeur est absente ou ne correspond à aucun des formats
            connus d'export Splunk.
        """
        text = clean_field(raw_timestamp)
        if text is None:
            raise AdapterParsingError("Timestamp manquant ou vide")
        for fmt in SPLUNK_TIMESTAMP_FORMATS:
            try:
                return datetime.strptime(text, fmt).replace(tzinfo=None)
            except ValueError:
                continue
        raise AdapterParsingError(f"Timestamp non parsable: {text!r}")


__all__ = ["SPLUNK_TIMESTAMP_FORMATS", "SplunkAdapter"]
