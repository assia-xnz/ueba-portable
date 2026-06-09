"""Adapter pour le schéma Elastic Common Schema (ECS) / Winlogbeat natif.

Cet adapter cible les déploiements où les logs Windows sont collectés
**directement par Winlogbeat vers Elasticsearch**, sans passer par Wazuh — un
scénario fréquent chez les organisations utilisant la stack Elastic seule pour
la sécurité. Les champs y sont normalisés selon ECS (`event.code`,
`winlog.event_data.*`, `host.name`, `process.name`, ...), un schéma
sensiblement différent du schéma Wazuh natif traité par `WazuhAdapter`.

C'est cette différence de schéma — et non l'utilisation d'Elasticsearch en
tant que telle — qui justifie l'existence de deux adapters distincts : dans
l'architecture hybride de production décrite en README, c'est `WazuhAdapter`
qui est utilisé, car Filebeat y transmet les alertes Wazuh sans les transformer
au format ECS.

Mapping appliqué :

    @timestamp (ISO 8601)                     -> timestamp
    host.name                                 -> host
    event.code                                -> event_id
    winlog.event_data.TargetUserName          -> user (connexions)
    winlog.event_data.SubjectUserName         -> user (création de processus, 4688)
    winlog.event_data.LogonType               -> logon_type
    winlog.event_data.WorkstationName         -> workstation
    source.ip                                 -> src_ip
    process.name                              -> process_name
    process.parent.name                       -> parent_process
    event.severity                            -> rule_level
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from dateutil import parser as dateutil_parser

from ueba.adapters.base import AdapterParsingError, SIEMAdapter, clean_field, clean_int_field
from ueba.domain.schema import PROCESS_CREATION_EVENT_ID, NormalizedEvent

#: Format ISO 8601 utilisé par défaut par Winlogbeat/Elasticsearch pour `@timestamp`.
ECS_TIMESTAMP_FORMATS: tuple[str, ...] = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
)


class ElasticAdapter(SIEMAdapter):
    """Traduit les documents ECS/Winlogbeat (sans Wazuh) en événements normalisés."""

    name = "elastic"

    def parse_record(self, record: Mapping[str, object]) -> NormalizedEvent | None:
        """Convertit un document ECS/Winlogbeat en `NormalizedEvent`.

        Paramètres
        ----------
        record : Mapping[str, object]
            Un document indexé par les noms de champs ECS
            (ex. `winlog.event_data.TargetUserName`).

        Retours
        -------
        NormalizedEvent | None
            L'événement normalisé correspondant.

        Lève
        ----
        AdapterParsingError
            Si le timestamp ou le code d'événement sont absents ou non parsables.
        """
        timestamp = self._parse_timestamp(record.get("@timestamp"))
        event_id = clean_field(record.get("event.code"))
        if event_id is None:
            raise AdapterParsingError("event.code manquant ou vide")

        user = self._resolve_user(record, event_id)

        return NormalizedEvent(
            timestamp=timestamp,
            user=user or "",
            host=clean_field(record.get("host.name")) or "",
            event_id=event_id,
            logon_type=clean_field(record.get("winlog.event_data.LogonType")),
            workstation=clean_field(record.get("winlog.event_data.WorkstationName")),
            src_ip=clean_field(record.get("source.ip")),
            process_name=clean_field(record.get("process.name")),
            parent_process=clean_field(record.get("process.parent.name")),
            rule_level=clean_int_field(record.get("event.severity")),
            mitre_technique=None,
            mitre_tactic=None,
        )

    def _resolve_user(self, record: Mapping[str, object], event_id: str) -> str | None:
        """Sélectionne `TargetUserName` ou `SubjectUserName` selon le type d'événement Windows.

        Même logique que pour Wazuh (cf. `WazuhAdapter._resolve_user`) : la
        bascule dépend du type d'événement Windows, pas du SIEM qui le rapporte.
        """
        target_user = clean_field(record.get("winlog.event_data.TargetUserName"))
        subject_user = clean_field(record.get("winlog.event_data.SubjectUserName"))

        if event_id == PROCESS_CREATION_EVENT_ID:
            return subject_user or target_user
        return target_user or subject_user

    def _parse_timestamp(self, raw_timestamp: object) -> datetime:
        """Parse un timestamp `@timestamp` au format ISO 8601 (Elasticsearch/ECS).

        Lève
        ----
        AdapterParsingError
            Si la valeur est absente ou ne correspond à aucun des formats
            ISO 8601 connus de Winlogbeat/Elasticsearch.
        """
        text = clean_field(raw_timestamp)
        if text is None:
            raise AdapterParsingError("Timestamp manquant ou vide")
        try:
            return dateutil_parser.parse(text, dayfirst=False).replace(tzinfo=None)
        except ValueError as exc:
            raise AdapterParsingError(f"Timestamp non parsable: {text!r}") from exc


__all__ = ["ECS_TIMESTAMP_FORMATS", "ElasticAdapter"]
