"""Indexation bulk des anomalies détectées dans Elasticsearch.

Les anomalies sont indexées dans `ueba-anomalies-YYYY.MM.DD`.
Chaque document contient le vecteur de features, les matches MITRE,
et les métadonnées de la fenêtre temporelle.

Usage:
    from ueba.infrastructure.elastic_writer import ElasticWriter
    writer = ElasticWriter.from_env()
    writer.bulk_index(feature_vectors, mitre_matches)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from base64 import b64encode
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ueba.domain.features import FeatureVector
    from ueba.domain.mitre import MitreMatch
    from ueba.pipeline import AnomalyRecord


class ElasticWriterError(Exception):
    """Erreur levée lors de l'indexation dans Elasticsearch."""


class ElasticWriter:
    """Envoie les vecteurs de features et les matches MITRE vers Elasticsearch.

    Paramètres
    ----------
    host : str
        URL de l'instance Elasticsearch.
    username : str
        Nom d'utilisateur.
    password : str
        Mot de passe.
    index_prefix : str
        Préfixe d'index (défaut : "ueba-anomalies").
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        index_prefix: str = "ueba-anomalies",
    ) -> None:
        self._host = host.rstrip("/")
        credentials = b64encode(f"{username}:{password}".encode()).decode()
        self._auth_header = f"Basic {credentials}"
        self._index_prefix = index_prefix

    @classmethod
    def from_env(cls) -> ElasticWriter:
        """Construit le writer depuis les variables d'environnement."""
        host = os.environ.get("ES_HOST", "https://localhost:9200")
        username = os.environ.get("ES_USERNAME", "elastic")
        password = os.environ.get("ES_PASSWORD", "")
        prefix = os.environ.get("ES_INDEX_PREFIX", "ueba-anomalies")
        if not password:
            raise ElasticWriterError("ES_PASSWORD absent — définir dans .env")
        return cls(host=host, username=username, password=password, index_prefix=prefix)

    def bulk_index(
        self,
        vectors: list[FeatureVector],
        mitre_matches: list[MitreMatch] | None = None,
    ) -> int:
        """Indexe les vecteurs de features et les matches MITRE en bulk.

        Paramètres
        ----------
        vectors : list[FeatureVector]
            Vecteurs de features (anomalies ou tous les vecteurs selon le mode).
        mitre_matches : list[MitreMatch] | None
            Matches MITRE ATT&CK associés à cette fenêtre (optionnel).

        Retours
        -------
        int
            Nombre de documents indexés avec succès.
        """
        if not vectors:
            return 0

        date_str = datetime.now(tz=timezone.utc).strftime("%Y.%m.%d")
        index = f"{self._index_prefix}-{date_str}"

        mitre_by_user: dict[str, list[dict[str, Any]]] = {}
        if mitre_matches:
            for m in mitre_matches:
                mitre_by_user.setdefault("_population", []).append(
                    {
                        "technique_id": m.technique_id,
                        "technique_name": m.technique_name,
                        "tactic": m.tactic,
                        "rationale": m.rationale,
                        "source": m.source,
                    }
                )

        lines: list[str] = []
        for v in vectors:
            meta = json.dumps({"index": {"_index": index}})
            doc: dict[str, Any] = {
                "@timestamp": v.window_start.isoformat() + "Z",
                "ueba": {
                    "user": v.user,
                    "window_start": v.window_start.isoformat(),
                    "window_end": v.window_end.isoformat(),
                    "features": {
                        "login_count": v.login_count,
                        "failed_login_count": v.failed_login_count,
                        "failed_login_ratio": v.failed_login_ratio,
                        "unique_hosts": v.unique_hosts,
                        "unique_logon_types": v.unique_logon_types,
                        "process_entropy": v.process_entropy,
                        "unique_processes": v.unique_processes,
                        "process_count": v.process_count,
                        "priv_logon_count": v.priv_logon_count,
                        "kerberos_count": v.kerberos_count,
                        "off_hours_ratio": v.off_hours_ratio,
                        "weekend_ratio": v.weekend_ratio,
                        "login_velocity": v.login_velocity,
                        "host_velocity": v.host_velocity,
                        "z_login_count": v.z_login_count,
                        "z_process_count": v.z_process_count,
                    },
                    "mitre": mitre_by_user.get("_population", []),
                },
            }
            lines.append(meta)
            lines.append(json.dumps(doc, ensure_ascii=False))

        body = "\n".join(lines) + "\n"
        result = self._post_bulk(body)
        errors = result.get("errors", False)
        items = result.get("items", [])
        indexed = sum(1 for item in items if item.get("index", {}).get("status") in (200, 201))
        if errors:
            failed = len(items) - indexed
            raise ElasticWriterError(f"Bulk indexation partielle : {indexed} OK, {failed} erreurs")
        return indexed

    def bulk_index_anomalies(self, records: list[AnomalyRecord]) -> int:
        """Indexe des verdicts d'anomalies (détection) en bulk dans Elasticsearch.

        Contrairement à :meth:`bulk_index` (centré features + MITRE), cette
        méthode indexe le **verdict** orienté analyste SOC : utilisateur,
        fenêtre, décision, modèle utilisé et votes des sous-modèles — de quoi
        trier l'alerte dans Kibana.

        Paramètres
        ----------
        records : list[AnomalyRecord]
            Verdicts à indexer (typiquement filtrés sur ``is_anomaly``).

        Retours
        -------
        int
            Nombre de documents indexés avec succès.
        """
        if not records:
            return 0

        date_str = datetime.now(tz=timezone.utc).strftime("%Y.%m.%d")
        index = f"{self._index_prefix}-{date_str}"

        lines: list[str] = []
        for record in records:
            lines.append(json.dumps({"index": {"_index": index}}))
            lines.append(json.dumps(self._anomaly_doc(record), ensure_ascii=False))

        body = "\n".join(lines) + "\n"
        result = self._post_bulk(body)
        items = result.get("items", [])
        indexed = sum(1 for item in items if item.get("index", {}).get("status") in (200, 201))
        if result.get("errors", False):
            failed = len(items) - indexed
            raise ElasticWriterError(f"Bulk indexation partielle : {indexed} OK, {failed} erreurs")
        return indexed

    @staticmethod
    def _anomaly_doc(record: AnomalyRecord) -> dict[str, Any]:
        """Construit le document Elasticsearch d'un verdict d'anomalie."""
        return {
            "@timestamp": record.window_start.isoformat() + "Z",
            "ueba": {
                "user": record.user,
                "window_start": record.window_start.isoformat(),
                "window_end": record.window_end.isoformat(),
                "is_anomaly": record.is_anomaly,
                "mode": record.mode,
                "used_model": record.used_model,
                "vote_count": record.vote_count,
                "votes": record.votes,
            },
        }

    def _post_bulk(self, ndjson_body: str) -> dict[str, Any]:
        url = f"{self._host}/_bulk"
        req = urllib.request.Request(
            url,
            data=ndjson_body.encode(),
            headers={
                "Content-Type": "application/x-ndjson",
                "Authorization": self._auth_header,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())  # type: ignore[no-any-return]
        except urllib.error.HTTPError as exc:
            raise ElasticWriterError(
                f"HTTP {exc.code} lors du bulk POST: {exc.read().decode()[:300]}"
            ) from exc
        except OSError as exc:
            raise ElasticWriterError(f"Connexion échouée: {exc}") from exc


__all__ = ["ElasticWriter", "ElasticWriterError"]
