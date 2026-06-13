#!/usr/bin/env python3
"""Enrichit les anomalies (``ueba-anomalies-*``) avec score et niveau de risque.

Pour chaque fenêtre anormale, calcule via :class:`ueba.scoring.risk.RiskScorer` :

* ``risk_score`` (0–100) = consensus ML (``vote_count``) + contexte de menace
  **indépendant** (criticité de la technique MITRE mappée, champ ``mitre_technique``) ;
* ``risk_level`` (FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE) ;
* ``recommended_action`` : consigne SOC dérivée du niveau.

Le score est **reproductible** (aucune normalisation relative au lot). L'écriture
se fait via ``_bulk update`` (idempotent).

Usage:
    python scripts/enrich_risk_levels.py
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ueba.infrastructure.es_client import ESClient  # noqa: E402
from ueba.scoring.risk import RiskScorer, mitre_context, recommended_action  # noqa: E402

TARGET_USERS = ["a.amrani", "l.idrissi", "l.mus", "y.ben", "n.alam", "s.ed", "k.alaa"]
ANOM_INDEX = "ueba-anomalies-*"


def fetch_docs(client: ESClient) -> list[dict]:
    """Récupère les anomalies des utilisateurs ciblés (avec _id et _index)."""
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
    resp = client.search(ANOM_INDEX, query)
    return resp.get("hits", {}).get("hits", [])


def main() -> int:
    client = ESClient.from_env(ROOT / ".env")
    scorer = RiskScorer()

    hits = fetch_docs(client)
    print(f"[*] {len(hits)} anomalies à enrichir")

    level_counts: dict[str, int] = defaultdict(int)
    lines: list[str] = []
    for hit in hits:
        ueba = hit["_source"].get("ueba", {})
        technique = hit["_source"].get("mitre_technique")
        assessment = scorer.assess(
            vote_count=ueba.get("vote_count"),
            context_score=mitre_context(technique),
        )
        level_counts[assessment.risk_level.value] += 1
        lines.append(json.dumps({"update": {"_id": hit["_id"], "_index": hit["_index"]}}))
        lines.append(
            json.dumps(
                {
                    "doc": {
                        "risk_score": assessment.risk_score,
                        "risk_level": assessment.risk_level.value,
                        "recommended_action": recommended_action(assessment.risk_level),
                    }
                }
            )
        )

    if not lines:
        print("[!] Aucun document à enrichir")
        return 0

    result = client.bulk(lines, refresh=True)
    updated = sum(
        1 for i in result.get("items", []) if i.get("update", {}).get("status") in (200, 201)
    )
    print(f"[*] {updated} documents enrichis (risk_score + risk_level + recommended_action)")
    print("[*] Distribution des niveaux d'alerte :")
    for level in ("CRITIQUE", "ÉLEVÉ", "MOYEN", "FAIBLE"):
        if level_counts.get(level):
            print(f"      {level:<10} : {level_counts[level]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
