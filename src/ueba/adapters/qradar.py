"""Adapter pour les exports IBM QRadar (offenses / recherches AQL sur événements Windows).

Cet adapter cible les organisations utilisant QRadar comme SIEM. Les
événements y sont généralement accessibles via l'API REST ou des exports AQL
(*Ariel Query Language*), exposant des champs en minuscules tels que `qid`
(Event/Category ID — ici l'EventID Windows), `targetusername`,
`sourcehostname`, etc.

Mapping appliqué :

    starttime               -> timestamp (ISO 8601, sans offset)
    sourcehostname          -> host
    qid                     -> event_id
    targetusername          -> user (connexions)
    subjectusername         -> user (création de processus, 4688)
    logontype               -> logon_type
    workstationname         -> workstation
    sourceip                -> src_ip
    processname             -> process_name
    parentprocessname       -> parent_process
    severity                -> rule_level

Comme pour Splunk, QRadar ne fournit pas de mapping MITRE ATT&CK natif dans
ces champs : `mitre_technique`/`mitre_tactic` restent `None`, et l'attribution
MITRE repose sur les heuristiques internes (`MitreMapper`).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from dateutil import parser as dateutil_parser

from ueba.adapters.base import AdapterParsingError, SIEMAdapter, clean_field, clean_int_field
from ueba.domain.schema import PROCESS_CREATION_EVENT_ID, NormalizedEvent

#: Formats de timestamp couramment rencontrés dans le champ `starttime` d'un export QRadar.
QRADAR_TIMESTAMP_FORMATS: tuple[str, ...] = (
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
)


class QRadarAdapter(SIEMAdapter):
    """Traduit les événements QRadar (logs Windows) en événements normalisés."""

    name = "qradar"

    def parse_record(self, record: Mapping[str, object]) -> NormalizedEvent | None:
        """Convertit un événement QRadar en `NormalizedEvent`.

        Paramètres
        ----------
        record : Mapping[str, object]
            Un événement QRadar indexé par les noms de champs natifs en
            minuscules (ex. `qid`, `targetusername`, `sourcehostname`).

        Retours
        -------
        NormalizedEvent | None
            L'événement normalisé correspondant.

        Lève
        ----
        AdapterParsingError
            Si le timestamp ou l'identifiant d'événement (`qid`) sont absents
            ou non parsables.
        """
        timestamp = self._parse_timestamp(record.get("starttime"))
        event_id = clean_field(record.get("qid"))
        if event_id is None:
            raise AdapterParsingError("qid (Event ID) manquant ou vide")

        user = self._resolve_user(record, event_id)

        return NormalizedEvent(
            timestamp=timestamp,
            user=user or "",
            host=clean_field(record.get("sourcehostname")) or "",
            event_id=event_id,
            logon_type=clean_field(record.get("logontype")),
            workstation=clean_field(record.get("workstationname")),
            src_ip=clean_field(record.get("sourceip")),
            process_name=clean_field(record.get("processname")),
            parent_process=clean_field(record.get("parentprocessname")),
            rule_level=clean_int_field(record.get("severity")),
            mitre_technique=None,
            mitre_tactic=None,
        )

    def _resolve_user(self, record: Mapping[str, object], event_id: str) -> str | None:
        """Sélectionne `targetusername` ou `subjectusername` selon le type d'événement Windows.

        Même logique que pour les autres adapters : la bascule dépend du type
        d'événement Windows (4688 -> sujet), pas du SIEM source.
        """
        target_user = clean_field(record.get("targetusername"))
        subject_user = clean_field(record.get("subjectusername"))

        if event_id == PROCESS_CREATION_EVENT_ID:
            return subject_user or target_user
        return target_user or subject_user

    def _parse_timestamp(self, raw_timestamp: object) -> datetime:
        """Parse le champ `starttime` d'un export QRadar.

        Lève
        ----
        AdapterParsingError
            Si la valeur est absente ou ne correspond à aucun des formats
            connus d'export QRadar.
        """
        text = clean_field(raw_timestamp)
        if text is None:
            raise AdapterParsingError("Timestamp manquant ou vide")
        try:
            return dateutil_parser.parse(text, dayfirst=False).replace(tzinfo=None)
        except ValueError as exc:
            raise AdapterParsingError(f"Timestamp non parsable: {text!r}") from exc


__all__ = ["QRADAR_TIMESTAMP_FORMATS", "QRadarAdapter"]
