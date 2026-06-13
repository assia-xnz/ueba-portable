#!/usr/bin/env python3
"""Mesure recall vs taux de faux positifs et compare des configurations anti-FP.

Protocole **sans fuite** : la vérité terrain d'une fenêtre (utilisateur, temps) est
« attaque » si l'utilisateur est ciblé ET que la fenêtre contient un vrai burst
d'échecs de connexion (``failed_login_count >= MIN_BURST``). Le modèle per-user est
entraîné **uniquement sur les fenêtres non-attaque** (clean), puis évalué sur tout.

Pour chaque configuration, on rapporte précision / rappel / F1 / **FP rate** (sur
les fenêtres normales) et le **recall opérationnel** (paires user×jour d'attaque
détectées). Les vecteurs ne dépendant pas de la config, ils sont extraits une fois.

Usage:
    python scripts/evaluate_fp.py [--input data/raw/wazuh-export.csv]
"""

from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ueba.adapters.registry import get_adapter  # noqa: E402
from ueba.domain.features import FeatureVector  # noqa: E402
from ueba.domain.persistence import PersistenceFilter  # noqa: E402
from ueba.infrastructure.io import read_csv_records  # noqa: E402
from ueba.metrics.classification import confusion_matrix  # noqa: E402
from ueba.pipeline import UEBAPipeline  # noqa: E402

TARGETS = {"a.amrani", "l.idrissi", "l.mus", "y.ben", "n.alam", "s.ed", "k.alaa"}
MIN_BURST = 3.0  # nombre d'échecs dans une fenêtre pour la considérer « attaque »


def is_attack(v: FeatureVector) -> bool:
    return v.user in TARGETS and v.failed_login_count >= MIN_BURST


def operational_recall(vectors: list[FeatureVector], preds: list[bool]) -> tuple[int, int]:
    """Paires (user, jour) d'attaque détectées / total (recall opérationnel)."""
    attack_days: set[tuple[str, str]] = set()
    detected: set[tuple[str, str]] = set()
    for v, pred in zip(vectors, preds, strict=True):
        if is_attack(v):
            key = (v.user, v.window_start.date().isoformat())
            attack_days.add(key)
            if pred:
                detected.add(key)
    return len(detected), len(attack_days)


def evaluate(
    vectors: list[FeatureVector],
    *,
    ae_pct: float,
    svm_nu: float,
    majority: int,
    persist: int,
    min_windows: int,
    default_deny: bool = True,
) -> dict:
    pipe = UEBAPipeline(
        window_size=timedelta(hours=1),
        window_step=timedelta(minutes=30),
        lookback_days=7,
        ensemble_mode="per-user",
        min_windows_per_user=min_windows,
        svm_nu=svm_nu,
        majority_threshold=majority,
        reconstruction_error_percentile=ae_pct,
        default_deny=default_deny,
    )
    clean = [v for v in vectors if not is_attack(v)]  # entraînement sans fuite
    pipe.fit(clean)
    records = pipe.predict(vectors)
    if persist > 1:
        records = PersistenceFilter(min_consecutive=persist).apply(records)

    y_true = [is_attack(v) for v in vectors]
    y_pred = [r.is_anomaly for r in records]
    cm = confusion_matrix(y_true, y_pred)
    det, tot = operational_recall(vectors, y_pred)
    # Diagnostic : composition des faux positifs (default-deny vs modèle entraîné).
    fp_unknown = sum(
        1
        for v, r in zip(vectors, records, strict=True)
        if r.is_anomaly and not is_attack(v) and r.used_model == "unknown"
    )
    fp_total = cm.fp
    return {"cm": cm, "op_det": det, "op_tot": tot, "fp_unknown": fp_unknown, "fp_total": fp_total}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Évaluation FP/recall et comparaison de configs")
    parser.add_argument("--input", default=str(ROOT / "data" / "raw" / "wazuh-export.csv"))
    args = parser.parse_args(argv)

    print(f"[*] Chargement des événements depuis {args.input} ...")
    adapter = get_adapter("wazuh")
    events = adapter.normalize(list(read_csv_records(args.input)))
    print(f"[*] {len(events)} événements normalisés")

    extractor = UEBAPipeline(window_size=timedelta(hours=1), window_step=timedelta(minutes=30))
    vectors = extractor.extract(events)
    n_attack = sum(is_attack(v) for v in vectors)
    print(f"[*] {len(vectors)} fenêtres extraites — {n_attack} d'attaque (vérité terrain)\n")

    # dd = default_deny ; mw = min_windows_per_user
    configs = [
        {
            "name": "baseline (actuel)",
            "ae_pct": 95,
            "svm_nu": 0.05,
            "majority": 2,
            "persist": 1,
            "min_windows": 30,
            "dd": True,
        },
        {
            "name": "sans default-deny",
            "ae_pct": 95,
            "svm_nu": 0.05,
            "majority": 2,
            "persist": 1,
            "min_windows": 30,
            "dd": False,
        },
        {
            "name": "no-dd + min_win=10",
            "ae_pct": 95,
            "svm_nu": 0.05,
            "majority": 2,
            "persist": 1,
            "min_windows": 10,
            "dd": False,
        },
        {
            "name": "no-dd + persist≥2",
            "ae_pct": 95,
            "svm_nu": 0.05,
            "majority": 2,
            "persist": 2,
            "min_windows": 10,
            "dd": False,
        },
        {
            "name": "no-dd + strict",
            "ae_pct": 99,
            "svm_nu": 0.02,
            "majority": 2,
            "persist": 1,
            "min_windows": 10,
            "dd": False,
        },
        {
            "name": "no-dd strict+persist",
            "ae_pct": 99,
            "svm_nu": 0.02,
            "majority": 2,
            "persist": 2,
            "min_windows": 10,
            "dd": False,
        },
    ]

    header = (
        f"{'Configuration':<22}{'Recall':>8}{'Précision':>11}{'F1':>7}"
        f"{'FP rate':>9}{'Recall op.':>12}{'FP dd/tot':>12}"
    )
    print(header)
    print("-" * len(header))
    for c in configs:
        r = evaluate(
            vectors,
            ae_pct=c["ae_pct"],
            svm_nu=c["svm_nu"],
            majority=c["majority"],
            persist=c["persist"],
            min_windows=c["min_windows"],
            default_deny=c["dd"],
        )
        cm = r["cm"]
        op = f"{r['op_det']}/{r['op_tot']}"
        fpd = f"{r['fp_unknown']}/{r['fp_total']}"
        print(
            f"{c['name']:<22}{cm.recall * 100:>7.1f}%{cm.precision * 100:>10.1f}%"
            f"{cm.f1:>7.2f}{cm.false_positive_rate * 100:>8.1f}%{op:>12}{fpd:>12}"
        )
    print("-" * len(header))
    print("FP dd/tot = part des FP due au default-deny (modèle 'unknown') sur le total des FP")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
