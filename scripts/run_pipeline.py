"""Script d'orchestration du pipeline UEBA de bout en bout.

Usage:
    python scripts/run_pipeline.py --input data/export.csv --source wazuh
    python scripts/run_pipeline.py --input data/export.csv --source elastic --lookback 14
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pipeline UEBA : normalisation → features → MITRE ATT&CK"
    )
    parser.add_argument("--input", required=True, help="Fichier source (CSV ou JSON)")
    parser.add_argument(
        "--source",
        default="wazuh",
        choices=["wazuh", "elastic", "splunk", "qradar"],
        help="Format SIEM (défaut : wazuh)",
    )
    parser.add_argument("--output", default="anomalies.json", help="Fichier de sortie JSON")
    parser.add_argument(
        "--window-hours", type=float, default=1.0, help="Taille de fenêtre en heures"
    )
    parser.add_argument("--step-minutes", type=int, default=30, help="Pas de glissement en minutes")
    parser.add_argument(
        "--lookback", type=int, default=7, dest="lookback_days", help="Lookback baseline (jours)"
    )
    parser.add_argument("--mitre", action="store_true", help="Activer le mapping MITRE ATT&CK")
    return parser.parse_args()


def _load(path: Path) -> list[dict]:  # type: ignore[type-arg]
    import csv
    import json as _json

    if path.suffix.lower() == ".json":
        with path.open(encoding="utf-8") as f:
            data = _json.load(f)
        return data if isinstance(data, list) else [data]
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main() -> int:
    args = _parse_args()
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[ERREUR] Fichier introuvable : {input_path}", file=sys.stderr)
        return 1

    from ueba.adapters.registry import get_adapter
    from ueba.domain.mitre import MitreMapper
    from ueba.scoring.rolling_baseline import RollingBaselineEngine

    print(f"[pipeline] Chargement  : {input_path}  (source={args.source})")
    records = _load(input_path)
    adapter = get_adapter(args.source)
    events = adapter.normalize(records)
    print(f"[pipeline] Événements  : {len(events)} après normalisation")

    engine = RollingBaselineEngine(
        window_size=timedelta(hours=args.window_hours),
        window_step=timedelta(minutes=args.step_minutes),
        lookback_days=args.lookback_days,
    )
    vectors = engine.extract(events)
    print(f"[pipeline] Vecteurs    : {len(vectors)} (utilisateur × fenêtre)")

    results: list[dict] = []  # type: ignore[type-arg]
    mapper = MitreMapper()

    feature_names = [
        "login_count",
        "failed_login_count",
        "failed_login_ratio",
        "unique_hosts",
        "unique_logon_types",
        "process_entropy",
        "unique_processes",
        "process_count",
        "priv_logon_count",
        "kerberos_count",
        "off_hours_ratio",
        "weekend_ratio",
        "login_velocity",
        "host_velocity",
        "z_login_count",
        "z_process_count",
    ]
    for v in vectors:
        entry: dict = {  # type: ignore[type-arg]
            "user": v.user,
            "window_start": v.window_start.isoformat(),
            "window_end": v.window_end.isoformat(),
            "features": dict(zip(feature_names, v.to_vector(), strict=False)),
        }
        if args.mitre:
            matches = mapper.match_individual(v)
            entry["mitre"] = [
                {"technique_id": m.technique_id, "rationale": m.rationale, "source": m.source}
                for m in matches
            ]
        results.append(entry)

    # Population-level detection
    if args.mitre:
        pop_matches = mapper.match_population(vectors)
        if pop_matches:
            print(f"[pipeline] MITRE pop.  : {len(pop_matches)} match(es) collectif(s)")
            for m in pop_matches:
                print(f"           [{m.technique_id}] {m.rationale}")

    output_path = Path(args.output)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"[pipeline] Résultats   : {output_path}  ({len(results)} entrées)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
