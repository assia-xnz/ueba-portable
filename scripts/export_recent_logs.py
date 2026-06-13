#!/usr/bin/env python3
"""Exporte les logs Wazuh récents depuis Elasticsearch au format CSV WazuhAdapter.

Interroge ``wazuh-alerts-*`` sur les N dernières minutes et écrit un CSV dont les
colonnes correspondent exactement aux clés natives attendues par
:class:`ueba.adapters.wazuh.WazuhAdapter` (clés Wazuh « aplaties » en notation
pointée). Le fichier produit est directement consommable par ``ueba detect``.

Usage:
    python scripts/export_recent_logs.py --minutes 30 --output data/raw/recent.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ueba.infrastructure.es_client import ESClient  # noqa: E402

# Colonnes natives Wazuh attendues par WazuhAdapter.parse_record.
WAZUH_COLUMNS = [
    "@timestamp",
    "data.win.system.eventID",
    "agent.name",
    "data.win.eventdata.targetUserName",
    "data.win.eventdata.subjectUserName",
    "data.win.eventdata.logonType",
    "data.win.eventdata.workstationName",
    "data.win.eventdata.ipAddress",
    "data.win.eventdata.processName",
    "data.win.eventdata.parentProcessName",
    "rule.level",
    "rule.mitre.id",
    "rule.mitre.tactic",
]


def flatten(obj: Any, prefix: str = "", depth: int = 0, max_depth: int = 20) -> dict[str, Any]:
    """Aplati récursivement un dict imbriqué en clés pointées (notation Wazuh).

    La profondeur est bornée (``max_depth``) pour éviter tout déni de service sur
    un document JSON pathologiquement profond.
    """
    flat: dict[str, Any] = {}
    if isinstance(obj, dict) and depth < max_depth:
        for key, value in obj.items():
            child = f"{prefix}.{key}" if prefix else key
            flat.update(flatten(value, child, depth + 1, max_depth))
    else:
        flat[prefix] = obj
    return flat


def csv_safe(value: Any) -> str:
    """Neutralise l'injection de formules CSV (valeurs commençant par = + - @)."""
    text = "" if value is None else str(value)
    if text and text[0] in ("=", "+", "-", "@"):
        return "'" + text
    return text


def fetch(client: ESClient, index: str, minutes: int, size: int) -> list[dict[str, Any]]:
    since = (datetime.now(tz=timezone.utc) - timedelta(minutes=minutes)).isoformat()
    query = {
        "size": size,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"range": {"@timestamp": {"gte": since}}},
    }
    resp = client.search(index, query)
    return [hit["_source"] for hit in resp.get("hits", {}).get("hits", [])]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export Wazuh récent -> CSV format UEBA")
    parser.add_argument("--minutes", type=int, default=30, help="Fenêtre récente (défaut : 30)")
    parser.add_argument("--index", default="wazuh-alerts-*", help="Index source Elasticsearch")
    parser.add_argument(
        "--output",
        default=str(ROOT / "data" / "raw" / "recent_logs.csv"),
        help="Chemin du CSV de sortie",
    )
    parser.add_argument("--size", type=int, default=10_000, help="Nombre max d'événements")
    args = parser.parse_args(argv)

    client = ESClient.from_env(ROOT / ".env")
    sources = fetch(client, args.index, args.minutes, args.size)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=WAZUH_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for src in sources:
            flat = flatten(src)
            writer.writerow({col: csv_safe(flat.get(col, "")) for col in WAZUH_COLUMNS})
            written += 1

    print(f"[*] {written} événements exportés ({args.minutes} dernières min) -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
