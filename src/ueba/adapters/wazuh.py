"""Adapter pour le schéma Wazuh natif (`data.win.eventdata.*`).

**Adapter principal** de ce pipeline : dans l'architecture hybride décrite en
README (Wazuh Manager → Filebeat → Elasticsearch officiel → Kibana officiel),
Filebeat ne transforme pas les champs des alertes — les documents stockés dans
Elasticsearch conservent donc le schéma natif produit par Wazuh, et non un
schéma ECS. C'est ce schéma que cet adapter sait traduire.

Les colonnes attendues correspondent à un export CSV depuis Kibana Discover
sur l'index `wazuh-alerts-*` (cf. cahier des charges § 3) :

    @timestamp                              -> timestamp
    agent.name                              -> host
    data.win.system.eventID                 -> event_id
    data.win.eventdata.targetUserName       -> user (connexions)
    data.win.eventdata.subjectUserName      -> user (création de processus, 4688)
    data.win.eventdata.logonType            -> logon_type
    data.win.eventdata.workstationName      -> workstation
    data.win.eventdata.ipAddress            -> src_ip
    data.win.eventdata.processName          -> process_name
    data.win.eventdata.parentProcessName    -> parent_process
    rule.level                              -> rule_level
    rule.mitre.id                           -> mitre_technique
    rule.mitre.tactic                       -> mitre_tactic

⚠️ Particularité Windows exploitée ici : pour l'EventID 4688 (création de
processus), le champ `targetUserName` est vide ou non pertinent — l'identité
réelle de l'utilisateur ayant lancé le processus se trouve dans
`subjectUserName`. L'adapter bascule automatiquement entre les deux champs
selon l'`event_id`, afin que le domaine reçoive toujours le bon utilisateur.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from dateutil import parser as dateutil_parser  # type: ignore[import-untyped]

from ueba.adapters.base import AdapterParsingError, SIEMAdapter, clean_field, clean_int_field
from ueba.domain.schema import PROCESS_CREATION_EVENT_ID, NormalizedEvent

#: Format du timestamp tel qu'exporté par Kibana Discover (cf. cahier des charges § 3).
KIBANA_TIMESTAMP_FORMAT: str = "%b %d, %Y @ %H:%M:%S.%f"


class WazuhAdapter(SIEMAdapter):
    """Traduit les alertes Wazuh natives (export Kibana) en événements normalisés."""

    name = "wazuh"

    def parse_record(self, record: Mapping[str, object]) -> NormalizedEvent | None:
        """Convertit une ligne d'export Wazuh/Kibana en `NormalizedEvent`.

        Paramètres
        ----------
        record : Mapping[str, object]
            Une ligne de l'export CSV Kibana Discover, indexée par les noms
            de colonnes natifs Wazuh (ex. `data.win.eventdata.targetUserName`).

        Retours
        -------
        NormalizedEvent | None
            L'événement normalisé correspondant.

        Lève
        ----
        AdapterParsingError
            Si le timestamp ou l'EventID sont absents ou non parsables.
        """
        timestamp = self._parse_timestamp(record.get("@timestamp"))
        event_id = clean_field(record.get("data.win.system.eventID"))
        if event_id is None:
            raise AdapterParsingError("EventID Windows manquant ou vide")

        user = self._resolve_user(record, event_id)

        return NormalizedEvent(
            timestamp=timestamp,
            user=user or "",
            host=clean_field(record.get("agent.name")) or "",
            event_id=event_id,
            logon_type=clean_field(record.get("data.win.eventdata.logonType")),
            workstation=clean_field(record.get("data.win.eventdata.workstationName")),
            src_ip=clean_field(record.get("data.win.eventdata.ipAddress")),
            process_name=clean_field(record.get("data.win.eventdata.processName")),
            parent_process=clean_field(record.get("data.win.eventdata.parentProcessName")),
            rule_level=clean_int_field(record.get("rule.level")),
            mitre_technique=clean_field(record.get("rule.mitre.id")),
            mitre_tactic=clean_field(record.get("rule.mitre.tactic")),
        )

    def _resolve_user(self, record: Mapping[str, object], event_id: str) -> str | None:
        """Sélectionne le bon champ utilisateur selon le type d'événement Windows.

        Pour la création de processus (4688), l'identité pertinente est le
        sujet (`subjectUserName`), qui a lancé le processus — `targetUserName`
        est dans ce cas vide ou sans rapport. Pour tous les autres événements
        de connexion, c'est `targetUserName` qui porte l'identité du compte
        ayant initié ou subi la connexion.
        """
        target_user = clean_field(record.get("data.win.eventdata.targetUserName"))
        subject_user = clean_field(record.get("data.win.eventdata.subjectUserName"))

        if event_id == PROCESS_CREATION_EVENT_ID:
            return subject_user or target_user
        return target_user or subject_user

    def _parse_timestamp(self, raw_timestamp: object) -> datetime:
        """Parse un timestamp au format d'export Kibana Discover.

        Lève
        ----
        AdapterParsingError
            Si la valeur est absente ou ne respecte pas le format attendu
            (`KIBANA_TIMESTAMP_FORMAT`, ex. "May 21, 2026 @ 07:08:16.256").
        """
        text = clean_field(raw_timestamp)
        if text is None:
            raise AdapterParsingError("Timestamp manquant ou vide")
        try:
            # Le format Kibana Discover contient ' @ ' (ex: "May 13, 2026 @ 11:08:16.256")
            # que dateutil ne reconnaît pas — on le remplace par un espace avant parsing.
            normalized = text.replace(" @ ", " ")
            parsed: datetime = dateutil_parser.parse(normalized, dayfirst=False)
            return parsed.replace(tzinfo=None)
        except ValueError as exc:
            raise AdapterParsingError(f"Timestamp non parsable: {text!r}") from exc


__all__ = ["KIBANA_TIMESTAMP_FORMAT", "WazuhAdapter"]
