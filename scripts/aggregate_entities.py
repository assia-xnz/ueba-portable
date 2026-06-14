#!/usr/bin/env python3
"""Agrège les anomalies par entité (utilisateur × jour) et indexe ``ueba-entity-alerts``.

Restitution SOC : au lieu d'un flux d'alertes par fenêtre (bruyant, ~26% de
précision), on présente une **liste d'entités classées par risque** — les attaques
(multi-fenêtres, consensus fort) remontent en tête, ce qui élève fortement la
précision en haut de pile sans perdre de recall.

Alimente le panneau « Top entités à risque » du dashboard v3.

Usage:
    python scripts/aggregate_entities.py
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ueba.infrastructure.es_client import ESClient  # noqa: E402
from ueba.pipeline import AnomalyRecord  # noqa: E402
from ueba.scoring.entity_risk import aggregate_entities  # noqa: E402

ANOM_INDEX = "ueba-anomalies-*"
ENTITY_INDEX = "ueba-entity-alerts"

ENTITY_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "user": {"type": "keyword"},
            "day": {"type": "keyword"},
            "anomaly_count": {"type": "integer"},
            "strong_count": {"type": "integer"},
            "peak_votes": {"type": "integer"},
            "max_risk_score": {"type": "float"},
            "risk_level": {"type": "keyword"},
            "mitre_technique": {"type": "keyword"},
            "first_detection": {"type": "date"},
            "last_detection": {"type": "date"},
        }
    }
}

_LEVEL_ORDER = {"CRITIQUE": 3, "ÉLEVÉ": 2, "MOYEN": 1, "FAIBLE": 0}


def fetch_anomalies(client: ESClient) -> list[dict]:
    query = {"size": 10_000, "query": {"term": {"ueba.is_anomaly": True}}}
    resp = client.search(ANOM_INDEX, query)
    return [h["_source"] for h in resp.get("hits", {}).get("hits", [])]


def main() -> int:
    client = ESClient.from_env(ROOT / ".env")
    docs = fetch_anomalies(client)
    print(f"[*] {len(docs)} fenêtres anormales chargées")

    records: list[AnomalyRecord] = []
    # Métadonnées de risque par (user, jour), non portées par AnomalyRecord.
    risk_by_entity: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"max_risk": 0.0, "level": "FAIBLE", "mitre": None}
    )
    for d in docs:
        ueba = d.get("ueba", {})
        try:
            ws = datetime.fromisoformat(ueba["window_start"])
            we = datetime.fromisoformat(ueba["window_end"])
        except (KeyError, ValueError):
            continue
        user = ueba.get("user", "")
        records.append(
            AnomalyRecord(
                user=user,
                window_start=ws,
                window_end=we,
                is_anomaly=True,
                mode=ueba.get("mode", "per-user"),
                used_model=ueba.get("used_model", user),
                vote_count=ueba.get("vote_count"),
                votes=ueba.get("votes"),
            )
        )
        key = (user, ws.date().isoformat())
        meta = risk_by_entity[key]
        rs = float(d.get("risk_score") or 0.0)
        if rs >= meta["max_risk"]:
            meta["max_risk"] = rs
        lvl = d.get("risk_level")
        if lvl and _LEVEL_ORDER.get(lvl, 0) > _LEVEL_ORDER.get(meta["level"], 0):
            meta["level"] = lvl
        if d.get("mitre_technique"):
            meta["mitre"] = d["mitre_technique"]

    alerts = aggregate_entities(records, strong_vote=3)
    print(f"[*] {len(alerts)} entités (utilisateur × jour) à risque")

    if not client.index_exists(ENTITY_INDEX):
        client.request("PUT", ENTITY_INDEX, ENTITY_MAPPING)

    lines: list[str] = []
    for a in alerts:
        meta = risk_by_entity[(a.user, a.day)]
        lines.append(json.dumps({"index": {"_index": ENTITY_INDEX, "_id": f"{a.user}_{a.day}"}}))
        lines.append(
            json.dumps(
                {
                    "@timestamp": a.last_detection.isoformat(),
                    "user": a.user,
                    "day": a.day,
                    "anomaly_count": a.anomaly_count,
                    "strong_count": a.strong_count,
                    "peak_votes": a.peak_votes,
                    "max_risk_score": round(meta["max_risk"], 1),
                    "risk_level": meta["level"],
                    "mitre_technique": meta["mitre"],
                    "first_detection": a.first_detection.isoformat(),
                    "last_detection": a.last_detection.isoformat(),
                }
            )
        )
    if lines:
        result = client.bulk(lines, refresh=True)
        ok = sum(
            1 for i in result.get("items", []) if i.get("index", {}).get("status") in (200, 201)
        )
        print(f"[*] {ok} entités indexées dans '{ENTITY_INDEX}' (classées par risque)")

    print("\n  Top 10 entités à risque :")
    print(f"    {'Utilisateur':<14}{'Jour':<12}{'votes forts':>12}{'fenêtres':>10}{'risk':>7}")
    for a in alerts[:10]:
        meta = risk_by_entity[(a.user, a.day)]
        print(
            f"    {a.user:<14}{a.day:<12}{a.strong_count:>12}{a.anomaly_count:>10}"
            f"{meta['max_risk']:>7.0f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
