"""Client Elasticsearch unifié — point d'accès unique à ES pour tout le projet.

Remplace les implémentations dupliquées de chargement `.env` / authentification /
requêtes HTTP éparpillées dans les scripts. Apporte les garanties attendues d'un
déploiement SOC :

* **HTTPS par défaut** et contexte TLS configurable (`verify_ssl`) ;
* authentification par **clé API** (recommandée, privilèges restreints) *ou* Basic
  Auth en repli ;
* **retry avec backoff** sur les erreurs transitoires (réseau, 502/503/504) ;
* gestion d'erreurs typée (`ESClientError`) au lieu de tracebacks bruts.

Toute la couche réseau passe par :func:`ESClient._urlopen`, ce qui rend le client
entièrement testable en remplaçant cette seule fonction.
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request
from base64 import b64encode
from pathlib import Path
from typing import Any

#: Codes HTTP considérés comme transitoires (justifient un retry).
TRANSIENT_STATUS = frozenset({502, 503, 504, 429})


class ESClientError(Exception):
    """Erreur de communication avec Elasticsearch."""


def load_dotenv(path: str | Path) -> None:
    """Charge un fichier `.env` minimal (``KEY=VALUE``) dans ``os.environ``.

    Les variables déjà présentes dans l'environnement ne sont pas écrasées
    (``setdefault``). Les lignes vides et les commentaires (``#``) sont ignorés.
    Fonction sûre : ne lève jamais si le fichier est absent.
    """
    p = Path(path)
    if not p.exists():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


class ESClient:
    """Client HTTP minimal et robuste pour Elasticsearch.

    Paramètres
    ----------
    host : str
        URL de base (ex. ``https://localhost:9200``). Le ``/`` final est retiré.
    api_key : str | None
        Clé API encodée (``id:api_key`` en base64, ou la valeur ``encoded``
        renvoyée par ES). Prioritaire sur Basic Auth si fournie.
    username, password : str | None
        Identifiants Basic Auth (repli si ``api_key`` absente).
    verify_ssl : bool
        Vérifier le certificat TLS (défaut : ``True``). À ne désactiver qu'en labo.
    max_retries : int
        Nombre de tentatives supplémentaires sur erreur transitoire (défaut : 3).
    backoff : float
        Délai de base (s) du backoff exponentiel entre tentatives (défaut : 0.5).
    timeout : float
        Timeout par requête en secondes (défaut : 30).
    """

    def __init__(
        self,
        host: str,
        *,
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool = True,
        max_retries: int = 3,
        backoff: float = 0.5,
        timeout: float = 30.0,
    ) -> None:
        self._host = host.rstrip("/")
        if api_key:
            self._auth_header = f"ApiKey {api_key}"
        elif username is not None and password is not None:
            token = b64encode(f"{username}:{password}".encode()).decode()
            self._auth_header = f"Basic {token}"
        else:
            raise ESClientError("Authentification manquante : fournir api_key ou username+password")
        self._verify_ssl = verify_ssl
        self._max_retries = max_retries
        self._backoff = backoff
        self._timeout = timeout

    @classmethod
    def from_env(cls, dotenv_path: str | Path | None = None) -> ESClient:
        """Construit le client depuis l'environnement (et un `.env` optionnel).

        Variables lues : ``ES_HOST`` (défaut ``https://localhost:9200``),
        ``ES_API_KEY`` (prioritaire) ou ``ES_USERNAME``/``ES_PASSWORD``,
        ``ES_VERIFY_SSL`` (``true``/``false``, défaut ``true``).
        """
        if dotenv_path is not None:
            load_dotenv(dotenv_path)
        host = os.environ.get("ES_HOST", "https://localhost:9200")
        api_key = os.environ.get("ES_API_KEY") or None
        username = os.environ.get("ES_USERNAME", "elastic")
        password = os.environ.get("ES_PASSWORD", "")
        verify_ssl = os.environ.get("ES_VERIFY_SSL", "true").strip().lower() not in {
            "false",
            "0",
            "no",
        }
        if not api_key and not password:
            raise ESClientError("ES_PASSWORD ou ES_API_KEY absent — vérifier le .env")
        return cls(
            host,
            api_key=api_key,
            username=None if api_key else username,
            password=None if api_key else password,
            verify_ssl=verify_ssl,
        )

    # ── couche réseau (isolée pour la testabilité) ──────────────────────────
    def _ssl_context(self) -> ssl.SSLContext | None:
        if self._host.startswith("https") and not self._verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return None

    def _urlopen(self, req: urllib.request.Request) -> bytes:  # pragma: no cover - I/O réseau
        """Exécute la requête et renvoie le corps brut. Point d'injection des tests."""
        with urllib.request.urlopen(req, timeout=self._timeout, context=self._ssl_context()) as r:
            return r.read()  # type: ignore[no-any-return]

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        raw_body: str | None = None,
        ndjson: bool = False,
    ) -> dict[str, Any]:
        """Effectue une requête ES avec retry sur erreurs transitoires.

        Fournir soit ``body`` (dict sérialisé en JSON), soit ``raw_body`` (déjà
        sérialisé, utile pour le NDJSON du _bulk).
        """
        url = f"{self._host}/{path.lstrip('/')}"
        content_type = "application/x-ndjson" if ndjson else "application/json"
        data: bytes | None = None
        if raw_body is not None:
            data = raw_body.encode()
        elif body is not None:
            data = json.dumps(body).encode()

        last_err: Exception | None = None
        for attempt in range(self._max_retries + 1):
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": content_type, "Authorization": self._auth_header},
                method=method,
            )
            try:
                return json.loads(self._urlopen(req))  # type: ignore[no-any-return]
            except urllib.error.HTTPError as exc:
                if exc.code in TRANSIENT_STATUS and attempt < self._max_retries:
                    last_err = exc
                    time.sleep(self._backoff * (2**attempt))
                    continue
                detail = exc.read().decode(errors="replace")[:300]
                raise ESClientError(f"HTTP {exc.code} sur {method} {url}: {detail}") from exc
            except (urllib.error.URLError, OSError) as exc:
                if attempt < self._max_retries:
                    last_err = exc
                    time.sleep(self._backoff * (2**attempt))
                    continue
                raise ESClientError(f"Connexion échouée vers {url}: {exc}") from exc
        raise ESClientError(f"Échec après {self._max_retries + 1} tentatives: {last_err}")

    # ── opérations de haut niveau ───────────────────────────────────────────
    def search(self, index: str, query: dict[str, Any]) -> dict[str, Any]:
        """Exécute une recherche et renvoie la réponse ES complète."""
        return self.request("POST", f"{index}/_search", query)

    def count(self, index: str, query: dict[str, Any] | None = None) -> int:
        """Renvoie le nombre de documents correspondant à la requête."""
        body = {"query": query} if query else None
        resp = self.request("POST", f"{index}/_count", body)
        return int(resp.get("count", 0))

    def bulk(self, lines: list[str], *, refresh: bool = False) -> dict[str, Any]:
        """Envoie un lot d'actions NDJSON (`_bulk`). ``lines`` = lignes déjà sérialisées."""
        path = "_bulk?refresh=true" if refresh else "_bulk"
        return self.request("POST", path, raw_body="\n".join(lines) + "\n", ndjson=True)

    def index_exists(self, index: str) -> bool:
        """Indique si l'index existe (HEAD ne renvoyant pas de corps, on tente un GET)."""
        try:
            self.request("GET", index)
            return True
        except ESClientError:
            return False

    def put_index_template(self, name: str, template: dict[str, Any]) -> dict[str, Any]:
        """Crée/met à jour un index template composable."""
        return self.request("PUT", f"_index_template/{name}", template)

    def put_ilm_policy(self, name: str, policy: dict[str, Any]) -> dict[str, Any]:
        """Crée/met à jour une politique ILM."""
        return self.request("PUT", f"_ilm/policy/{name}", policy)


__all__ = ["ESClient", "ESClientError", "load_dotenv", "TRANSIENT_STATUS"]
