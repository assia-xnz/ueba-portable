"""Tests unitaires du client Elasticsearch unifié."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from typing import Any

import pytest

from ueba.infrastructure.es_client import ESClient, ESClientError, load_dotenv


def _client(**kw: Any) -> ESClient:
    kw.setdefault("api_key", "abc")
    kw.setdefault("backoff", 0.0)  # pas d'attente réelle dans les tests
    return ESClient("https://es:9200", **kw)


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://es:9200/x", code, "err", {}, None)  # type: ignore[arg-type]


# ── load_dotenv ─────────────────────────────────────────────────────────────
def test_load_dotenv_populates_and_skips_comments(tmp_path: Path, monkeypatch: Any) -> None:
    env = tmp_path / ".env"
    env.write_text("# commentaire\nES_HOST=https://h:9200\n\nBAD LINE\nES_PASSWORD=secret\n")
    monkeypatch.delenv("ES_HOST", raising=False)
    monkeypatch.delenv("ES_PASSWORD", raising=False)
    load_dotenv(env)
    import os

    assert os.environ["ES_HOST"] == "https://h:9200"
    assert os.environ["ES_PASSWORD"] == "secret"


def test_load_dotenv_does_not_overwrite(tmp_path: Path, monkeypatch: Any) -> None:
    env = tmp_path / ".env"
    env.write_text("ES_HOST=https://fromfile:9200\n")
    monkeypatch.setenv("ES_HOST", "https://existing:9200")
    load_dotenv(env)
    import os

    assert os.environ["ES_HOST"] == "https://existing:9200"


def test_load_dotenv_missing_file_is_safe(tmp_path: Path) -> None:
    load_dotenv(tmp_path / "absent.env")  # ne lève pas


# ── authentification ────────────────────────────────────────────────────────
def test_api_key_auth_header() -> None:
    c = ESClient("https://es:9200", api_key="KEY")
    assert c._auth_header == "ApiKey KEY"


def test_basic_auth_header() -> None:
    c = ESClient("https://es:9200", username="elastic", password="pw")
    assert c._auth_header.startswith("Basic ")


def test_missing_auth_raises() -> None:
    with pytest.raises(ESClientError, match="Authentification"):
        ESClient("https://es:9200")


def test_from_env_https_default_and_api_key_precedence(monkeypatch: Any) -> None:
    monkeypatch.delenv("ES_HOST", raising=False)
    monkeypatch.setenv("ES_API_KEY", "K")
    monkeypatch.setenv("ES_PASSWORD", "pw")
    c = ESClient.from_env()
    assert c._host == "https://localhost:9200"
    assert c._auth_header == "ApiKey K"


def test_from_env_missing_credentials_raises(monkeypatch: Any) -> None:
    monkeypatch.delenv("ES_API_KEY", raising=False)
    monkeypatch.delenv("ES_PASSWORD", raising=False)
    with pytest.raises(ESClientError, match="absent"):
        ESClient.from_env()


# ── request / retry ─────────────────────────────────────────────────────────
def test_request_success(monkeypatch: Any) -> None:
    c = _client()
    monkeypatch.setattr(c, "_urlopen", lambda req: json.dumps({"ok": True}).encode())
    assert c.request("GET", "x") == {"ok": True}


def test_request_non_transient_http_error_raises(monkeypatch: Any) -> None:
    c = _client()

    def boom(_req: Any) -> bytes:
        raise _http_error(400)

    monkeypatch.setattr(c, "_urlopen", boom)
    with pytest.raises(ESClientError, match="HTTP 400"):
        c.request("GET", "x")


def test_request_retries_then_succeeds_on_transient(monkeypatch: Any) -> None:
    c = _client(max_retries=2)
    calls = {"n": 0}

    def flaky(_req: Any) -> bytes:
        calls["n"] += 1
        if calls["n"] < 3:
            raise _http_error(503)
        return json.dumps({"ok": True}).encode()

    monkeypatch.setattr(c, "_urlopen", flaky)
    assert c.request("GET", "x") == {"ok": True}
    assert calls["n"] == 3


def test_request_url_error_retries_then_raises(monkeypatch: Any) -> None:
    c = _client(max_retries=1)
    calls = {"n": 0}

    def down(_req: Any) -> bytes:
        calls["n"] += 1
        raise urllib.error.URLError("connexion refusée")

    monkeypatch.setattr(c, "_urlopen", down)
    with pytest.raises(ESClientError, match="Connexion échouée"):
        c.request("GET", "x")
    assert calls["n"] == 2  # 1 essai + 1 retry


# ── opérations de haut niveau ────────────────────────────────────────────────
def test_search_count_bulk(monkeypatch: Any) -> None:
    c = _client()
    captured: dict[str, Any] = {}

    def fake(req: Any) -> bytes:
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        if req.full_url.endswith("_count"):
            return json.dumps({"count": 7}).encode()
        if req.full_url.endswith("_bulk") or "_bulk" in req.full_url:
            return json.dumps({"errors": False, "items": []}).encode()
        return json.dumps({"hits": {"hits": []}}).encode()

    monkeypatch.setattr(c, "_urlopen", fake)
    assert c.search("idx", {"query": {"match_all": {}}})["hits"]["hits"] == []
    assert c.count("idx") == 7
    assert c.bulk(['{"index":{}}', "{}"], refresh=True)["errors"] is False
    assert "_bulk?refresh=true" in captured["url"]


def test_index_exists(monkeypatch: Any) -> None:
    c = _client()

    def fake(req: Any) -> bytes:
        if "missing" in req.full_url:
            raise _http_error(404)
        return json.dumps({}).encode()

    monkeypatch.setattr(c, "_urlopen", fake)
    assert c.index_exists("present") is True
    assert c.index_exists("missing") is False
