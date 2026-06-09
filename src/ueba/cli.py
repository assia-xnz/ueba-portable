"""Point d'entrée CLI : `ueba` (défini dans pyproject.toml [tool.poetry.scripts])."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ueba",
        description="UEBA portable — détection d'anomalies comportementales Windows",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    run_p = sub.add_parser("run", help="Lancer le pipeline d'analyse sur un export SIEM")
    run_p.add_argument("input", help="Chemin vers le fichier d'événements (CSV / JSON)")
    run_p.add_argument(
        "--source",
        choices=["wazuh", "elastic", "splunk", "qradar"],
        default="wazuh",
        help="Format source du SIEM (défaut : wazuh)",
    )
    run_p.add_argument(
        "--output",
        default="anomalies.json",
        help="Fichier de sortie pour les anomalies détectées (défaut : anomalies.json)",
    )
    run_p.add_argument(
        "--window-hours",
        type=float,
        default=1.0,
        help="Taille de la fenêtre glissante en heures (défaut : 1.0)",
    )
    run_p.add_argument(
        "--step-minutes",
        type=int,
        default=30,
        help="Pas de glissement en minutes (défaut : 30)",
    )
    run_p.add_argument(
        "--lookback-days",
        type=int,
        default=7,
        help="Fenêtre de lookback pour la baseline glissante (défaut : 7)",
    )

    version_p = sub.add_parser("version", help="Afficher la version")  # noqa: F841

    args = parser.parse_args(argv)

    if args.command == "version":
        from importlib.metadata import version as pkg_version

        try:
            print(pkg_version("ueba-portable"))
        except Exception:
            print("ueba-portable (version inconnue — paquet non installé)")
        return 0

    if args.command == "run":
        return _cmd_run(args)

    parser.print_help()
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    from datetime import timedelta
    from pathlib import Path

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Erreur : fichier introuvable : {input_path}", file=sys.stderr)
        return 1

    print(f"[ueba] Source        : {args.source}")
    print(f"[ueba] Fichier       : {input_path}")
    print(f"[ueba] Fenêtre       : {args.window_hours}h / pas {args.step_minutes}min")
    print(f"[ueba] Lookback      : {args.lookback_days} jours")

    from ueba.adapters.registry import get_adapter
    from ueba.scoring.rolling_baseline import RollingBaselineEngine

    adapter = get_adapter(args.source)
    records = _load_records(input_path)
    events = adapter.normalize(records)
    print(f"[ueba] Événements    : {len(events)} après normalisation et filtrage")

    engine = RollingBaselineEngine(
        window_size=timedelta(hours=args.window_hours),
        window_step=timedelta(minutes=args.step_minutes),
        lookback_days=args.lookback_days,
    )
    vectors = engine.extract(events)
    print(f"[ueba] Vecteurs      : {len(vectors)} (utilisateur × fenêtre)")

    output_path = Path(args.output)
    _write_json(vectors, output_path)
    print(f"[ueba] Résultats     : {output_path} ({len(vectors)} entrées)")
    return 0


def _load_records(path: Path) -> list[dict[str, Any]]:
    import csv
    import json

    if path.suffix.lower() == ".json":
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else [data]

    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _write_json(vectors: list[Any], output_path: Path) -> None:
    import json

    rows = []
    for v in vectors:
        rows.append(
            {
                "user": v.user,
                "window_start": v.window_start.isoformat(),
                "window_end": v.window_end.isoformat(),
                "features": v.to_vector(),
            }
        )
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
