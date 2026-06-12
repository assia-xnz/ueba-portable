"""Point d'entrée CLI : `ueba` (défini dans pyproject.toml [tool.poetry.scripts]).

Trois sous-commandes d'analyse complètent `version` :

* ``run``    — pipeline complet apprentissage + détection en une passe ;
* ``train``  — apprentissage seul, puis sauvegarde du modèle sur disque ;
* ``detect`` — détection seule à partir d'un modèle préalablement sauvegardé.

Le **mode d'apprentissage** (``--mode``) gouverne la stratégie : ``per-user``
(défaut, recommandé — un modèle dédié par utilisateur) ou ``global`` (un
unique modèle pour toute la population).
"""

from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ueba.domain.schema import NormalizedEvent
    from ueba.pipeline import AnomalyRecord, UEBAPipeline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ueba",
        description="UEBA portable — détection d'anomalies comportementales Windows",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    _add_run_parser(sub)
    _add_train_parser(sub)
    _add_detect_parser(sub)
    sub.add_parser("version", help="Afficher la version")

    args = parser.parse_args(argv)

    if args.command == "version":
        return _cmd_version()
    if args.command == "run":
        return _cmd_run(args)
    if args.command == "train":
        return _cmd_train(args)
    if args.command == "detect":
        return _cmd_detect(args)

    parser.print_help()
    return 0


def _add_window_args(p: argparse.ArgumentParser) -> None:
    """Ajoute les arguments communs de fenêtrage glissant."""
    p.add_argument(
        "--source",
        choices=["wazuh", "elastic", "splunk", "qradar"],
        default="wazuh",
        help="Format source du SIEM (défaut : wazuh)",
    )
    p.add_argument(
        "--window-hours",
        type=float,
        default=1.0,
        help="Taille de la fenêtre glissante en heures (défaut : 1.0)",
    )
    p.add_argument(
        "--step-minutes",
        type=int,
        default=30,
        help="Pas de glissement en minutes (défaut : 30)",
    )
    p.add_argument(
        "--lookback-days",
        type=int,
        default=7,
        help="Fenêtre de lookback pour la baseline glissante (défaut : 7)",
    )


def _add_mode_args(p: argparse.ArgumentParser) -> None:
    """Ajoute les arguments de mode d'apprentissage et de seuil de baseline."""
    p.add_argument(
        "--mode",
        choices=["per-user", "global"],
        default="per-user",
        help=(
            "Mode d'apprentissage. 'per-user' (défaut, recommandé) : un modèle "
            "dédié par utilisateur, véritable UEBA personnalisée. 'global' : un "
            "unique modèle pour toute la population (baseline collective biaisée)."
        ),
    )
    p.add_argument(
        "--min-windows-per-user",
        type=int,
        default=30,
        help=(
            "Mode per-user : nombre minimal de fenêtres pour qu'un utilisateur "
            "obtienne un modèle dédié (défaut : 30). En deçà, l'entité est "
            "traitée en default-deny. À calibrer selon la longueur de la baseline."
        ),
    )
    p.add_argument(
        "--svm-nu",
        type=float,
        default=0.05,
        help=(
            "Fraction d'outliers tolérée par le OneClassSVM (défaut : 0.05, "
            "adapté à une baseline propre). Plus bas = moins de faux positifs."
        ),
    )


def _add_run_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    run_p = sub.add_parser("run", help="Apprentissage + détection en une passe sur un export SIEM")
    run_p.add_argument("input", help="Chemin vers le fichier d'événements (CSV / JSON)")
    run_p.add_argument(
        "--output",
        default="anomalies.json",
        help="Fichier de sortie pour les anomalies détectées (défaut : anomalies.json)",
    )
    _add_window_args(run_p)
    _add_mode_args(run_p)
    run_p.add_argument(
        "--train-ratio",
        type=float,
        default=0.8,
        help=(
            "Part chronologique des fenêtres servant à l'apprentissage en mode "
            "per-user (défaut : 0.8, le reste sert de holdout pour le scoring)."
        ),
    )


def _add_train_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    train_p = sub.add_parser("train", help="Apprentissage seul puis sauvegarde du modèle")
    train_p.add_argument("--input", required=True, help="Fichier d'événements (CSV / JSON)")
    train_p.add_argument(
        "--save-model", required=True, help="Chemin de sauvegarde du modèle (.joblib)"
    )
    _add_window_args(train_p)
    _add_mode_args(train_p)
    train_p.add_argument(
        "--train-ratio",
        type=float,
        default=1.0,
        help=(
            "Part chronologique des fenêtres servant à l'apprentissage en mode "
            "per-user (défaut : 1.0 — apprend sur l'INTÉGRALITÉ du jeu propre "
            "fourni, pour une baseline 'normale' complète)."
        ),
    )


def _add_detect_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    detect_p = sub.add_parser("detect", help="Détection à partir d'un modèle sauvegardé")
    detect_p.add_argument("--input", required=True, help="Fichier d'événements (CSV / JSON)")
    detect_p.add_argument(
        "--load-model", required=True, help="Chemin du modèle à charger (.joblib)"
    )
    detect_p.add_argument(
        "--output",
        default="anomalies.json",
        help="Fichier de sortie pour les anomalies détectées (défaut : anomalies.json)",
    )
    detect_p.add_argument(
        "--source",
        choices=["wazuh", "elastic", "splunk", "qradar"],
        default="wazuh",
        help="Format source du SIEM (défaut : wazuh)",
    )


def _cmd_version() -> int:
    from importlib.metadata import version as pkg_version

    try:
        print(pkg_version("ueba-portable"))
    except Exception:
        print("ueba-portable (version inconnue — paquet non installé)")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not _check_input(input_path):
        return 1

    print(f"[ueba] Mode          : {args.mode}")
    print(f"[ueba] Source        : {args.source}")
    print(f"[ueba] Fichier       : {input_path}")
    print(f"[ueba] Fenêtre       : {args.window_hours}h / pas {args.step_minutes}min")
    print(f"[ueba] Lookback      : {args.lookback_days} jours")

    events = _load_events(input_path, args.source)
    print(f"[ueba] Événements    : {len(events)} après normalisation et filtrage")

    pipeline = _build_pipeline(args)
    records = pipeline.run(events)
    print(f"[ueba] Fenêtres      : {len(records)} (utilisateur × fenêtre)")

    return _emit_anomalies(records, Path(args.output))


def _cmd_train(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not _check_input(input_path):
        return 1

    print(f"[ueba] Mode          : {args.mode}")
    print(f"[ueba] Source        : {args.source}")
    print(f"[ueba] Fichier       : {input_path}")

    events = _load_events(input_path, args.source)
    print(f"[ueba] Événements    : {len(events)} après normalisation et filtrage")

    pipeline = _build_pipeline(args)
    vectors = pipeline.extract(events)
    print(f"[ueba] Vecteurs      : {len(vectors)} (utilisateur × fenêtre)")
    pipeline.fit(vectors)

    model_path = Path(args.save_model)
    pipeline.save_model(str(model_path))
    print(f"[ueba] Modèle        : sauvegardé dans {model_path}")
    return 0


def _cmd_detect(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not _check_input(input_path):
        return 1

    model_path = Path(args.load_model)
    if not model_path.exists():
        print(f"Erreur : modèle introuvable : {model_path}", file=sys.stderr)
        return 1

    from ueba.pipeline import UEBAPipeline

    pipeline = UEBAPipeline.load_model(str(model_path))
    print(f"[ueba] Mode          : {pipeline.mode}")
    print(f"[ueba] Modèle        : {model_path}")
    print(f"[ueba] Source        : {args.source}")
    print(f"[ueba] Fichier       : {input_path}")

    events = _load_events(input_path, args.source)
    print(f"[ueba] Événements    : {len(events)} après normalisation et filtrage")

    vectors = pipeline.extract(events)
    records = pipeline.predict(vectors)
    print(f"[ueba] Fenêtres      : {len(records)} (utilisateur × fenêtre)")

    return _emit_anomalies(records, Path(args.output))


def _check_input(input_path: Path) -> bool:
    if not input_path.exists():
        print(f"Erreur : fichier introuvable : {input_path}", file=sys.stderr)
        return False
    return True


def _build_pipeline(args: argparse.Namespace) -> UEBAPipeline:
    """Instancie un pipeline à partir des arguments de la ligne de commande."""
    from ueba.pipeline import UEBAPipeline

    return UEBAPipeline(
        window_size=timedelta(hours=args.window_hours),
        window_step=timedelta(minutes=args.step_minutes),
        lookback_days=args.lookback_days,
        ensemble_mode=args.mode,
        min_windows_per_user=getattr(args, "min_windows_per_user", 30),
        train_ratio=getattr(args, "train_ratio", 0.8),
        svm_nu=getattr(args, "svm_nu", 0.05),
    )


def _load_events(input_path: Path, source: str) -> list[NormalizedEvent]:
    from ueba.adapters.registry import get_adapter

    adapter = get_adapter(source)
    records = _load_records(input_path)
    return adapter.normalize(records)


def _emit_anomalies(records: list[AnomalyRecord], output_path: Path) -> int:
    """Sérialise les anomalies détectées et affiche une synthèse."""
    anomalies = [r for r in records if r.is_anomaly]
    flagged_users = sorted({r.user for r in anomalies})
    print(f"[ueba] Anomalies     : {len(anomalies)} sur {len(records)} fenêtres")
    print(f"[ueba] Utilisateurs  : {len(flagged_users)} entité(s) signalée(s)")

    _write_anomalies(anomalies, output_path)
    print(f"[ueba] Résultats     : {output_path} ({len(anomalies)} anomalies)")
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


def _write_anomalies(records: list[AnomalyRecord], output_path: Path) -> None:
    import json

    rows = [
        {
            "user": r.user,
            "window_start": r.window_start.isoformat(),
            "window_end": r.window_end.isoformat(),
            "is_anomaly": r.is_anomaly,
            "mode": r.mode,
            "used_model": r.used_model,
            "vote_count": r.vote_count,
            "votes": r.votes,
        }
        for r in records
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    raise SystemExit(main())
