"""Tests unitaires de l'indexation des anomalies (sans Elasticsearch live)."""

from __future__ import annotations

from datetime import datetime

from ueba.infrastructure.elastic_writer import ElasticWriter
from ueba.pipeline import AnomalyRecord


def _record() -> AnomalyRecord:
    return AnomalyRecord(
        user="a.amrani",
        window_start=datetime(2026, 5, 16, 14, 0, 0),
        window_end=datetime(2026, 5, 16, 15, 0, 0),
        is_anomaly=True,
        mode="per-user",
        used_model="a.amrani",
        vote_count=3,
        votes={"isolation_forest": True, "one_class_svm": True, "autoencoder": True},
    )


class TestAnomalyDoc:
    """Transformation d'un verdict en document Elasticsearch."""

    def test_doc_carries_verdict_fields(self) -> None:
        doc = ElasticWriter._anomaly_doc(_record())

        assert doc["@timestamp"] == "2026-05-16T14:00:00Z"
        ueba = doc["ueba"]
        assert ueba["user"] == "a.amrani"
        assert ueba["is_anomaly"] is True
        assert ueba["mode"] == "per-user"
        assert ueba["used_model"] == "a.amrani"
        assert ueba["vote_count"] == 3
        assert ueba["votes"]["isolation_forest"] is True

    def test_doc_carries_risk_fields(self) -> None:
        """Le risque est calculé dès l'indexation (RiskScorer câblé au flux live)."""
        doc = ElasticWriter._anomaly_doc(_record())
        # 3/3 votes + contexte par défaut 0.5 -> 80.0 = CRITIQUE
        assert doc["risk_score"] == 80.0
        assert doc["risk_level"] == "CRITIQUE"
        assert doc["recommended_action"]

    def test_doc_is_json_serializable(self) -> None:
        import json

        json.dumps(ElasticWriter._anomaly_doc(_record()))


class TestBulkIndexAnomalies:
    """Logique d'indexation bulk (sans réseau : _post_bulk monkeypatché)."""

    def _writer(self) -> ElasticWriter:
        return ElasticWriter(host="https://es:9200", username="elastic", password="pw")

    def test_empty_records_returns_zero(self) -> None:
        assert self._writer().bulk_index_anomalies([]) == 0

    def test_uses_deterministic_id_and_counts(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        writer = self._writer()
        captured: dict[str, str] = {}

        def fake_post(body: str) -> dict:
            captured["body"] = body
            return {"errors": False, "items": [{"index": {"status": 201}}]}

        monkeypatch.setattr(writer, "_post_bulk", fake_post)
        indexed = writer.bulk_index_anomalies([_record()])
        assert indexed == 1
        # _id déterministe présent dans l'action bulk
        assert '"_id": "a.amrani_2026-05-16T14:00:00"' in captured["body"]

    def test_partial_failure_raises(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        writer = self._writer()
        monkeypatch.setattr(
            writer,
            "_post_bulk",
            lambda body: {"errors": True, "items": [{"index": {"status": 400}}]},
        )
        try:
            writer.bulk_index_anomalies([_record()])
        except Exception as exc:  # noqa: BLE001
            assert "partielle" in str(exc)
        else:
            raise AssertionError("ElasticWriterError attendue")


class TestDotenvLoader:
    """Chargement d'un fichier .env sans dépendance."""

    def test_load_dotenv_sets_missing_keys(self, tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from ueba.cli import _load_dotenv

        env = tmp_path / ".env"
        env.write_text("# commentaire\nES_HOST=https://es:9200\nES_PASSWORD=secret\n")
        monkeypatch.delenv("ES_HOST", raising=False)
        monkeypatch.delenv("ES_PASSWORD", raising=False)

        _load_dotenv(str(env))

        import os

        assert os.environ["ES_HOST"] == "https://es:9200"
        assert os.environ["ES_PASSWORD"] == "secret"

    def test_existing_env_takes_precedence(self, tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from ueba.cli import _load_dotenv

        env = tmp_path / ".env"
        env.write_text("ES_HOST=https://from-file:9200\n")
        monkeypatch.setenv("ES_HOST", "https://from-env:9200")

        _load_dotenv(str(env))

        import os

        assert os.environ["ES_HOST"] == "https://from-env:9200"
