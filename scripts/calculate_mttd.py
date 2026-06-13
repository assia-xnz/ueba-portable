#!/usr/bin/env python3
"""Calcule le MTTD (Mean Time To Detect) de la campagne T1110.003 depuis Elasticsearch.

Charge les anomalies détectées (``ueba-anomalies-*``) pour les utilisateurs ciblés,
calcule le délai entre le début connu de l'attaque et la première détection, affiche
un tableau récapitulatif, sauvegarde ``data/processed/mttd_report.json`` et indexe le
résultat dans l'index ``ueba-mttd``.

Usage:
    python scripts/calculate_mttd.py
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import urllib.error
import urllib.request
from base64 import b64encode
from datetime import datetime, timezone
from pathlib import Path

# Rendre le package `ueba` importable depuis src/ sans installation.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ueba.domain.features import FEATURE_NAMES, FeatureVector  # noqa: E402
from ueba.domain.per_user_ensemble import PerUserVerdict  # noqa: E402
from ueba.metrics.mttd import MTTDCalculator, MTTDReport  # noqa: E402

# ── Paramètres de la campagne connue ───────────────────────────────────────
TARGET_USERS = ["a.amrani", "l.idrissi", "l.mus", "y.ben", "n.alam", "s.ed", "k.alaa"]
# Première vague de password spraying — référence pour le MTTD.
ATTACK_START = datetime(2026, 5, 13, 11, 0, 0)
ANOM_INDEX = "ueba-anomalies-*"
MTTD_INDEX = "ueba-mttd"


def load_env(path: Path) -> None:
    """Charge un fichier .env minimal (KEY=VALUE) dans os.environ."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


def es_auth() -> tuple[str, str]:
    host = os.environ.get("ES_HOST", "http://localhost:9200").rstrip("/")
    user = os.environ.get("ES_USERNAME", "elastic")
    pwd = os.environ.get("ES_PASSWORD", "")
    if not pwd:
        raise SystemExit("ES_PASSWORD absent — vérifier ~/ueba-portable/.env")
    token = b64encode(f"{user}:{pwd}".encode()).decode()
    return host, f"Basic {token}"


def es_request(url: str, header: str, body: str | None = None, method: str = "GET") -> dict:
    req = urllib.request.Request(
        url,
        data=body.encode() if body else None,
        headers={"Content-Type": "application/json", "Authorization": header},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def fetch_anomalies(host: str, header: str) -> list[dict]:
    """Récupère les fenêtres anormales des utilisateurs ciblés."""
    query = {
        "size": 10_000,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"ueba.is_anomaly": True}},
                    {"terms": {"ueba.user.keyword": TARGET_USERS}},
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "asc"}}],
    }
    resp = es_request(f"{host}/{ANOM_INDEX}/_search", header, json.dumps(query), "POST")
    return [hit["_source"] for hit in resp.get("hits", {}).get("hits", [])]


def build_inputs(
    docs: list[dict],
) -> tuple[list[PerUserVerdict], list[FeatureVector]]:
    """Reconstruit les verdicts + fenêtres alignés depuis les documents ES."""
    detections: list[PerUserVerdict] = []
    vectors: list[FeatureVector] = []
    zero_features = {name: 0.0 for name in FEATURE_NAMES}
    for doc in docs:
        ueba = doc.get("ueba", {})
        user = ueba.get("user", "")
        try:
            window_start = datetime.fromisoformat(ueba["window_start"])
            window_end = datetime.fromisoformat(ueba["window_end"])
        except (KeyError, ValueError):
            continue
        detections.append(
            PerUserVerdict(
                is_anomaly=bool(ueba.get("is_anomaly", False)),
                user=user,
                used_model=ueba.get("used_model", user),
                was_in_training=True,
                vote_count=ueba.get("vote_count"),
            )
        )
        vectors.append(
            FeatureVector(
                user=user, window_start=window_start, window_end=window_end, **zero_features
            )
        )
    return detections, vectors


def report_to_payload(report: MTTDReport) -> dict:
    """Sérialise le rapport MTTD en dictionnaire JSON-compatible."""
    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "attack_start": ATTACK_START.isoformat(),
        "global_mttd_minutes": round(report.global_mttd_minutes, 2),
        "detection_rate": round(report.detection_rate, 4),
        "detected_users": report.detected_users,
        "missed_users": report.missed_users,
        "per_user": [
            {
                "user": user,
                "attack_start": ATTACK_START.isoformat(),
                "first_detection": report.first_detection_times[user].isoformat(),
                "mttd_minutes": round(report.per_user_mttd[user].total_seconds() / 60.0, 2),
                "detected": True,
            }
            for user in report.detected_users
        ]
        + [
            {
                "user": user,
                "attack_start": ATTACK_START.isoformat(),
                "first_detection": None,
                "mttd_minutes": None,
                "detected": False,
            }
            for user in report.missed_users
        ],
    }


def print_table(payload: dict) -> None:
    print("\n" + "=" * 78)
    print(" MTTD — Mean Time To Detect (campagne T1110.003, 1ère vague 13 mai 11h00)")
    print("=" * 78)
    print(f"{'Utilisateur':<14}{'Début attaque':<18}{'1ère détection':<22}{'MTTD (min)':>12}")
    print("-" * 78)
    for row in payload["per_user"]:
        first = row["first_detection"][:19].replace("T", " ") if row["first_detection"] else "—"
        mttd = f"{row['mttd_minutes']:.1f}" if row["mttd_minutes"] is not None else "MANQUÉ"
        start = row["attack_start"][:16].replace("T", " ")
        print(f"{row['user']:<14}{start:<18}{first:<22}{mttd:>12}")
    print("-" * 78)
    print(
        f" MTTD global : {payload['global_mttd_minutes']:.1f} min"
        f"   |   Taux de détection : {payload['detection_rate'] * 100:.1f}%"
        f"   ({len(payload['detected_users'])}/{len(payload['per_user'])})"
    )
    print("=" * 78 + "\n")


def index_mttd(host: str, header: str, payload: dict) -> int:
    """Indexe chaque ligne MTTD dans l'index ueba-mttd (recréé proprement)."""
    # Recréer l'index pour éviter les doublons entre exécutions.
    with contextlib.suppress(urllib.error.HTTPError):
        es_request(f"{host}/{MTTD_INDEX}", header, method="DELETE")
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "user": {"type": "keyword"},
                "attack_start": {"type": "date"},
                "first_detection": {"type": "date"},
                "mttd_minutes": {"type": "float"},
                "detected": {"type": "boolean"},
                "global_mttd_minutes": {"type": "float"},
                "detection_rate": {"type": "float"},
            }
        }
    }
    es_request(f"{host}/{MTTD_INDEX}", header, json.dumps(mapping), "PUT")

    lines: list[str] = []
    for row in payload["per_user"]:
        lines.append(json.dumps({"index": {"_index": MTTD_INDEX}}))
        lines.append(
            json.dumps(
                {
                    "@timestamp": row["first_detection"] or payload["attack_start"],
                    "user": row["user"],
                    "attack_start": row["attack_start"],
                    "first_detection": row["first_detection"],
                    "mttd_minutes": row["mttd_minutes"],
                    "detected": row["detected"],
                    "global_mttd_minutes": payload["global_mttd_minutes"],
                    "detection_rate": payload["detection_rate"],
                }
            )
        )
    body = "\n".join(lines) + "\n"
    req = urllib.request.Request(
        f"{host}/_bulk",
        data=body.encode(),
        headers={"Content-Type": "application/x-ndjson", "Authorization": header},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
    return sum(1 for i in result.get("items", []) if i.get("index", {}).get("status") in (200, 201))


def main() -> int:
    load_env(ROOT / ".env")
    host, header = es_auth()

    docs = fetch_anomalies(host, header)
    print(f"[*] {len(docs)} fenêtres anormales chargées pour {len(TARGET_USERS)} utilisateurs")

    detections, vectors = build_inputs(docs)
    attack_start_times = {user: ATTACK_START for user in TARGET_USERS}
    report = MTTDCalculator().calculate(attack_start_times, detections, vectors)
    payload = report_to_payload(report)

    print_table(payload)

    out_path = ROOT / "data" / "processed" / "mttd_report.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    print(f"[*] Rapport JSON -> {out_path}")

    indexed = index_mttd(host, header, payload)
    print(f"[*] {indexed} documents indexés dans '{MTTD_INDEX}'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
