#!/usr/bin/env python3
"""Pousse les alertes UEBA de niveau CRITIQUE vers un webhook (notification SOC).

Comble la lacune SOC-04 : sans notification, un SOC n'est jamais *poussé* l'alerte.
Le script interroge ``ueba-anomalies-*`` pour les fenêtres ``risk_level:CRITIQUE``
des N dernières minutes et envoie un résumé au webhook ``UEBA_WEBHOOK`` (format
JSON générique, compatible Slack/Mattermost/Teams via un champ ``text``). Sans
webhook configuré, le résumé est affiché (mode dry-run).

Alternative recommandée en production : Kibana Alerting (règle sur
``risk_level:CRITIQUE`` -> connecteur natif). Voir docs/deployment.md.

Usage:
    UEBA_WEBHOOK=https://hooks.example/... python scripts/notify_critical.py --minutes 30
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ueba.infrastructure.es_client import ESClient, load_dotenv  # noqa: E402

ANOM_INDEX = "ueba-anomalies-*"


def fetch_critical(client: ESClient, minutes: int) -> list[dict]:
    since = (datetime.now(tz=timezone.utc) - timedelta(minutes=minutes)).isoformat()
    query = {
        "size": 100,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"risk_level.keyword": "CRITIQUE"}},
                    {"range": {"@timestamp": {"gte": since}}},
                ]
            }
        },
    }
    resp = client.search(ANOM_INDEX, query)
    return [h["_source"] for h in resp.get("hits", {}).get("hits", [])]


def format_message(alerts: list[dict], minutes: int) -> str:
    users = sorted({a.get("ueba", {}).get("user", "?") for a in alerts})
    lines = [
        f":rotating_light: UEBA — {len(alerts)} alerte(s) CRITIQUE sur {minutes} min",
        f"Utilisateurs : {', '.join(users)}",
    ]
    for a in alerts[:10]:
        ueba = a.get("ueba", {})
        lines.append(
            f"• {ueba.get('user', '?')} @ {a.get('@timestamp', '')[:19]} "
            f"(risk {a.get('risk_score', '?')}) — {a.get('recommended_action', '')}"
        )
    return "\n".join(lines)


def post_webhook(url: str, message: str) -> int:
    payload = json.dumps({"text": message}).encode()
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # pragma: no cover - I/O réseau
        return int(resp.status)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Notifie les alertes CRITIQUE UEBA")
    parser.add_argument("--minutes", type=int, default=30, help="Fenêtre récente (défaut 30)")
    args = parser.parse_args(argv)

    load_dotenv(ROOT / ".env")
    client = ESClient.from_env()
    alerts = fetch_critical(client, args.minutes)

    if not alerts:
        print(f"[*] Aucune alerte CRITIQUE sur les {args.minutes} dernières minutes.")
        return 0

    message = format_message(alerts, args.minutes)
    webhook = os.environ.get("UEBA_WEBHOOK")
    if not webhook:
        print("[!] UEBA_WEBHOOK non défini — mode dry-run, message non envoyé :\n")
        print(message)
        return 0

    status = post_webhook(webhook, message)
    print(f"[*] {len(alerts)} alerte(s) CRITIQUE notifiée(s) (HTTP {status}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
