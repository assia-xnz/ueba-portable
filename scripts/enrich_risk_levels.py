#!/usr/bin/env python3
"""Enrichit les anomalies (``ueba-anomalies-*``) avec un score et un niveau de risque.

Pour chaque fenêtre anormale des utilisateurs ciblés, calcule :

* ``risk_score`` (0–100) via :class:`ueba.scoring.risk.RiskScorer`, combinant le
  consensus ML (``vote_count``) et l'intensité (densité de fenêtres anormales de
  l'utilisateur sur la journée) ;
* ``risk_level`` (FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE) dérivé du score.

Les champs sont écrits dans chaque document via l'API ``_bulk`` (action update).

Usage:
    python scripts/enrich_risk_levels.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from base64 import b64encode
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ueba.scoring.risk import RiskScorer  # noqa: E402

TARGET_USERS = ["a.amrani", "l.idrissi", "l.mus", "y.ben", "n.alam", "s.ed", "k.alaa"]
ANOM_INDEX = "ueba-anomalies-*"


def load_env(path: Path) -> None:
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


def es_post(url: str, header: str, body: str, ndjson: bool = False) -> dict:
    ctype = "application/x-ndjson" if ndjson else "application/json"
    req = urllib.request.Request(
        url,
        data=body.encode(),
        headers={"Content-Type": ctype, "Authorization": header},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def fetch_docs(host: str, header: str) -> list[dict]:
    """Récupère les anomalies des utilisateurs ciblés avec leur _id et _index."""
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
    }
    resp = es_post(f"{host}/{ANOM_INDEX}/_search", header, json.dumps(query))
    return resp.get("hits", {}).get("hits", [])


def day_intensity_map(hits: list[dict]) -> dict[tuple[str, str], float]:
    """Calcule l'intensité normalisée (densité user×jour) sur [0, 1]."""
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for hit in hits:
        ueba = hit["_source"].get("ueba", {})
        user = ueba.get("user", "")
        ts = hit["_source"].get("@timestamp", "")[:10]  # YYYY-MM-DD
        counts[(user, ts)] += 1
    if not counts:
        return {}
    max_count = max(counts.values())
    return {key: c / max_count for key, c in counts.items()}


def main() -> int:
    load_env(ROOT / ".env")
    host, header = es_auth()
    scorer = RiskScorer()

    hits = fetch_docs(host, header)
    print(f"[*] {len(hits)} anomalies à enrichir")
    intensity = day_intensity_map(hits)

    level_counts: dict[str, int] = defaultdict(int)
    lines: list[str] = []
    for hit in hits:
        src = hit["_source"]
        ueba = src.get("ueba", {})
        user = ueba.get("user", "")
        day = src.get("@timestamp", "")[:10]
        assessment = scorer.assess(
            vote_count=ueba.get("vote_count"),
            intensity=intensity.get((user, day), 0.0),
        )
        level_counts[assessment.risk_level.value] += 1
        lines.append(json.dumps({"update": {"_id": hit["_id"], "_index": hit["_index"]}}))
        lines.append(
            json.dumps(
                {
                    "doc": {
                        "risk_score": assessment.risk_score,
                        "risk_level": assessment.risk_level.value,
                    }
                }
            )
        )

    if not lines:
        print("[!] Aucun document à enrichir")
        return 0

    body = "\n".join(lines) + "\n"
    result = es_post(f"{host}/_bulk?refresh=true", header, body, ndjson=True)
    updated = sum(
        1 for i in result.get("items", []) if i.get("update", {}).get("status") in (200, 201)
    )
    print(f"[*] {updated} documents enrichis (risk_score + risk_level)")
    print("[*] Distribution des niveaux d'alerte :")
    for level in ("CRITIQUE", "ÉLEVÉ", "MOYEN", "FAIBLE"):
        if level_counts.get(level):
            print(f"      {level:<10} : {level_counts[level]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
