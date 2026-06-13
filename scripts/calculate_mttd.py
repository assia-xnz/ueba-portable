#!/usr/bin/env python3
"""Calcule le MTTD (Mean Time To Detect) de la campagne T1110.003 depuis Elasticsearch.

Mesure le délai entre le début **de chaque vague** d'attaque connue et la première
détection émise par l'UEBA, par utilisateur ciblé. L'attaque ayant eu lieu en deux
vagues (13 et 16 mai 2026), le MTTD est calculé **par vague** puis agrégé — une
seule date de référence mélangerait les vagues et rendrait la métrique
ininterprétable.

Sorties : tableau console, ``data/processed/mttd_report.json`` et index ``ueba-mttd``
(indexation idempotente par ``_id = <vague>_<user>``, sans suppression d'index).

Usage:
    python scripts/calculate_mttd.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ueba.domain.features import FEATURE_NAMES, FeatureVector  # noqa: E402
from ueba.domain.per_user_ensemble import PerUserVerdict  # noqa: E402
from ueba.infrastructure.es_client import ESClient  # noqa: E402
from ueba.metrics.mttd import MTTDCalculator  # noqa: E402

TARGET_USERS = ["a.amrani", "l.idrissi", "l.mus", "y.ben", "n.alam", "s.ed", "k.alaa"]
# Vagues de password spraying connues (campagne T1110.003).
WAVES = [
    {"name": "vague1-13mai", "start": datetime(2026, 5, 13, 11, 0, 0)},
    {"name": "vague2-16mai", "start": datetime(2026, 5, 16, 18, 0, 0)},
]
ANOM_INDEX = "ueba-anomalies-*"
MTTD_INDEX = "ueba-mttd"

MTTD_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "wave": {"type": "keyword"},
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


def fetch_anomalies(client: ESClient) -> list[dict]:
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
    resp = client.search(ANOM_INDEX, query)
    return [hit["_source"] for hit in resp.get("hits", {}).get("hits", [])]


def build_inputs(docs: list[dict]) -> tuple[list[PerUserVerdict], list[FeatureVector]]:
    """Reconstruit les verdicts + fenêtres alignés depuis les documents ES.

    Les features sont mises à zéro : seules ``window_start``/``window_end`` et
    ``is_anomaly`` interviennent dans le calcul du MTTD.
    """
    detections: list[PerUserVerdict] = []
    vectors: list[FeatureVector] = []
    zero_features = {name: 0.0 for name in FEATURE_NAMES}
    skipped = 0
    for doc in docs:
        ueba = doc.get("ueba", {})
        user = ueba.get("user", "")
        try:
            window_start = datetime.fromisoformat(ueba["window_start"])
            window_end = datetime.fromisoformat(ueba["window_end"])
        except (KeyError, ValueError):
            skipped += 1
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
    if skipped:
        print(f"[!] {skipped} documents ignorés (timestamps malformés)")
    return detections, vectors


def build_payload(detections: list[PerUserVerdict], vectors: list[FeatureVector]) -> dict:
    """Calcule le MTTD par vague et agrège."""
    calc = MTTDCalculator()
    rows: list[dict] = []
    all_mttd_minutes: list[float] = []
    detected_total = 0
    expected_total = 0

    for wave in WAVES:
        start: datetime = wave["start"]  # type: ignore[assignment]
        report = calc.calculate({u: start for u in TARGET_USERS}, detections, vectors)
        expected_total += len(TARGET_USERS)
        detected_total += len(report.detected_users)
        for user in report.detected_users:
            mins = round(report.per_user_mttd[user].total_seconds() / 60.0, 2)
            all_mttd_minutes.append(mins)
            rows.append(
                {
                    "wave": wave["name"],
                    "user": user,
                    "attack_start": start.isoformat(),
                    "first_detection": report.first_detection_times[user].isoformat(),
                    "mttd_minutes": mins,
                    "detected": True,
                }
            )
        for user in report.missed_users:
            rows.append(
                {
                    "wave": wave["name"],
                    "user": user,
                    "attack_start": start.isoformat(),
                    "first_detection": None,
                    "mttd_minutes": None,
                    "detected": False,
                }
            )

    global_mttd = (
        round(sum(all_mttd_minutes) / len(all_mttd_minutes), 2) if all_mttd_minutes else 0.0
    )
    detection_rate = round(detected_total / expected_total, 4) if expected_total else 0.0
    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "waves": [{"name": w["name"], "start": w["start"].isoformat()} for w in WAVES],  # type: ignore[union-attr]
        "global_mttd_minutes": global_mttd,
        "detection_rate": detection_rate,
        "rows": rows,
    }


def print_table(payload: dict) -> None:
    print("\n" + "=" * 80)
    print(" MTTD — Mean Time To Detect (campagne T1110.003, par vague)")
    print("=" * 80)
    for wave in payload["waves"]:
        print(f"\n  ▼ {wave['name']}  (début attaque : {wave['start'][:16].replace('T', ' ')})")
        print(f"    {'Utilisateur':<14}{'1ère détection':<22}{'MTTD (min)':>12}")
        print("    " + "-" * 48)
        for row in [r for r in payload["rows"] if r["wave"] == wave["name"]]:
            first = row["first_detection"][:19].replace("T", " ") if row["first_detection"] else "—"
            mttd = f"{row['mttd_minutes']:.1f}" if row["mttd_minutes"] is not None else "MANQUÉ"
            print(f"    {row['user']:<14}{first:<22}{mttd:>12}")
    print("\n" + "-" * 80)
    print(
        f" MTTD global (toutes vagues) : {payload['global_mttd_minutes']:.1f} min"
        f"   |   Taux de détection : {payload['detection_rate'] * 100:.1f}%"
    )
    print("=" * 80 + "\n")


def index_mttd(client: ESClient, payload: dict) -> int:
    """Indexe chaque ligne MTTD de façon idempotente (_id = vague_user)."""
    if not client.index_exists(MTTD_INDEX):
        client.request("PUT", MTTD_INDEX, MTTD_MAPPING)
    lines: list[str] = []
    for row in payload["rows"]:
        doc_id = f"{row['wave']}_{row['user']}"
        lines.append(json.dumps({"index": {"_index": MTTD_INDEX, "_id": doc_id}}))
        lines.append(
            json.dumps(
                {
                    **row,
                    "@timestamp": row["first_detection"] or row["attack_start"],
                    "global_mttd_minutes": payload["global_mttd_minutes"],
                    "detection_rate": payload["detection_rate"],
                }
            )
        )
    if not lines:
        return 0
    result = client.bulk(lines, refresh=True)
    return sum(1 for i in result.get("items", []) if i.get("index", {}).get("status") in (200, 201))


def main() -> int:
    client = ESClient.from_env(ROOT / ".env")
    docs = fetch_anomalies(client)
    print(f"[*] {len(docs)} fenêtres anormales chargées pour {len(TARGET_USERS)} utilisateurs")

    detections, vectors = build_inputs(docs)
    payload = build_payload(detections, vectors)
    print_table(payload)

    out_path = ROOT / "data" / "processed" / "mttd_report.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    print(f"[*] Rapport JSON -> {out_path}")

    indexed = index_mttd(client, payload)
    print(f"[*] {indexed} documents indexés dans '{MTTD_INDEX}' (idempotent)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
