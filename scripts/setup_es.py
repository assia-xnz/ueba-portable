#!/usr/bin/env python3
"""Provisionne Elasticsearch pour l'UEBA : politique ILM + index templates explicites.

Corrige deux lacunes d'exploitation SOC :

* **SOC-01** — sans ILM, les index ``ueba-anomalies-*`` grossissent indéfiniment.
  On installe une politique *hot → delete* avec rétention configurable.
* **SOC-02** — sans mapping explicite, le typage dépend du premier document
  indexé (ex. ``risk_level`` deviné en ``text``). On fige un index template.

Les mappings string conservent le sous-champ ``.keyword`` (multi-field) pour rester
**compatibles avec les dashboards existants** tout en étant déterministes.

Idempotent : relançable sans effet de bord (PUT policy/template).

Usage:
    python scripts/setup_es.py [--retention-days 90]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ueba.infrastructure.es_client import ESClient  # noqa: E402

ILM_POLICY = "ueba-ilm"

#: Champ string déterministe : texte + sous-champ keyword (agrégations Kibana).
_TEXT_KW = {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}}


def ilm_policy(retention_days: int) -> dict:
    return {
        "policy": {
            "phases": {
                "hot": {
                    "actions": {"rollover": {"max_age": "1d", "max_primary_shard_size": "10gb"}}
                },
                "delete": {"min_age": f"{retention_days}d", "actions": {"delete": {}}},
            }
        }
    }


def anomalies_template() -> dict:
    return {
        "index_patterns": ["ueba-anomalies-*"],
        "template": {
            "settings": {"number_of_replicas": 0, "index.lifecycle.name": ILM_POLICY},
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "risk_score": {"type": "float"},
                    "risk_level": _TEXT_KW,
                    "recommended_action": {"type": "text"},
                    "mitre_technique": _TEXT_KW,
                    "mitre_tactic": _TEXT_KW,
                    "mitre_technique_name": _TEXT_KW,
                    "ueba": {
                        "properties": {
                            "user": _TEXT_KW,
                            "is_anomaly": {"type": "boolean"},
                            "mode": _TEXT_KW,
                            "used_model": _TEXT_KW,
                            "vote_count": {"type": "integer"},
                            "window_start": {"type": "date"},
                            "window_end": {"type": "date"},
                            "votes": {
                                "properties": {
                                    "isolation_forest": {"type": "boolean"},
                                    "one_class_svm": {"type": "boolean"},
                                    "autoencoder": {"type": "boolean"},
                                }
                            },
                        }
                    },
                }
            },
        },
    }


def ops_template() -> dict:
    """Template pour les index opérationnels (mttd, métriques, heartbeat)."""
    return {
        "index_patterns": ["ueba-mttd", "ueba-metrics", "ueba-heartbeat", "ueba-entity-alerts"],
        "template": {
            "settings": {"number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "user": {"type": "keyword"},
                    "wave": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "mttd_minutes": {"type": "float"},
                    "detection_rate": {"type": "float"},
                }
            },
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Provisionne ES (ILM + index templates)")
    parser.add_argument("--retention-days", type=int, default=90, help="Rétention ILM (défaut 90)")
    args = parser.parse_args(argv)

    client = ESClient.from_env(ROOT / ".env")

    client.put_ilm_policy(ILM_POLICY, ilm_policy(args.retention_days))
    print(f"[*] Politique ILM '{ILM_POLICY}' (rétention {args.retention_days} j) appliquée")

    client.put_index_template("ueba-anomalies", anomalies_template())
    print("[*] Index template 'ueba-anomalies' (ueba-anomalies-*) appliqué")

    client.put_index_template("ueba-ops", ops_template())
    print("[*] Index template 'ueba-ops' (ueba-mttd / ueba-metrics / ueba-heartbeat) appliqué")

    print("[✓] Provisionnement Elasticsearch terminé.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
