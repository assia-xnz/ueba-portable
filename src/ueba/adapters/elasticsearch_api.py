"""Lecteur direct Elasticsearch — alternative aux exports CSV/JSON Kibana.

Lit les événements directement depuis l'API Elasticsearch en utilisant
les credentials de `.env` (ES_HOST, ES_USERNAME, ES_PASSWORD).

Usage:
    from ueba.adapters.elasticsearch_api import ElasticsearchReader
    reader = ElasticsearchReader.from_env()
    records = reader.fetch(index="wazuh-alerts-*", hours=24)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from base64 import b64encode
from datetime import datetime, timedelta, timezone
from typing import Any


class ElasticsearchError(Exception):
    """Erreur levée lors d'une communication avec l'API Elasticsearch."""


class ElasticsearchReader:
    """Interroge l'API Elasticsearch pour récupérer des événements de sécurité.

    Paramètres
    ----------
    host : str
        URL de l'instance Elasticsearch (ex. https://localhost:9200).
    username : str
        Nom d'utilisateur Elasticsearch.
    password : str
        Mot de passe Elasticsearch.
    verify_ssl : bool
        Vérifier le certificat TLS (désactiver uniquement en développement).
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
    ) -> None:
        self._host = host.rstrip("/")
        credentials = b64encode(f"{username}:{password}".encode()).decode()
        self._auth_header = f"Basic {credentials}"
        self._verify_ssl = verify_ssl

    @classmethod
    def from_env(cls) -> ElasticsearchReader:
        """Construit le reader depuis les variables d'environnement (.env)."""
        host = os.environ.get("ES_HOST", "https://localhost:9200")
        username = os.environ.get("ES_USERNAME", "elastic")
        password = os.environ.get("ES_PASSWORD", "")
        if not password:
            raise ElasticsearchError("ES_PASSWORD absent de l'environnement — définir dans .env")
        return cls(host=host, username=username, password=password)

    def fetch(
        self,
        index: str = "wazuh-alerts-*",
        hours: int = 24,
        size: int = 10_000,
        query_filter: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Récupère les événements de sécurité des `hours` dernières heures.

        Paramètres
        ----------
        index : str
            Pattern d'index Elasticsearch (ex. "wazuh-alerts-*").
        hours : int
            Fenêtre temporelle de recherche (heures).
        size : int
            Nombre maximum de documents retournés (défaut : 10 000).
        query_filter : dict | None
            Filtre DSL additionnel (ex. filtre sur agent.name).

        Retours
        -------
        list[dict]
            Liste de documents `_source` bruts Elasticsearch.
        """
        now = datetime.now(tz=timezone.utc)
        since = now - timedelta(hours=hours)

        must_clauses: list[dict[str, Any]] = [
            {
                "range": {
                    "@timestamp": {
                        "gte": since.isoformat(),
                        "lte": now.isoformat(),
                    }
                }
            }
        ]
        if query_filter:
            must_clauses.append(query_filter)

        body = {
            "size": size,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {"bool": {"must": must_clauses}},
            "_source": True,
        }

        url = f"{self._host}/{index}/_search"
        response = self._post(url, body)
        hits = response.get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]

    def _post(self, url: str, body: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": self._auth_header,
            },
            method="POST",
        )
        try:
            import ssl

            ctx: ssl.SSLContext | None = None
            if not self._verify_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                return json.loads(resp.read())  # type: ignore[no-any-return]
        except urllib.error.HTTPError as exc:
            raise ElasticsearchError(
                f"HTTP {exc.code} depuis {url}: {exc.read().decode()[:300]}"
            ) from exc
        except OSError as exc:
            raise ElasticsearchError(f"Connexion échouée vers {url}: {exc}") from exc


__all__ = ["ElasticsearchReader", "ElasticsearchError"]
