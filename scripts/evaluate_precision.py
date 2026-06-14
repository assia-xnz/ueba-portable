#!/usr/bin/env python3
"""Compare la précision au niveau FENÊTRE vs au niveau ENTITÉ (utilisateur × jour).

Hypothèse SOC : un détecteur d'anomalies non supervisé est bruyant par fenêtre,
mais une vraie attaque persiste -> en agrégeant les fenêtres anormales par
(utilisateur, jour) et en n'alertant qu'au-delà d'un seuil de fenêtres, on
améliore fortement la précision sans perdre de recall.

Protocole sans fuite (entraînement sur fenêtres non-attaque). Affiche :
- la précision/recall/FP au niveau fenêtre (vote ≥2 et ≥3) ;
- la précision/recall au niveau entité (user×jour) en balayant le seuil K.

Usage:
    python scripts/evaluate_precision.py
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ueba.adapters.registry import get_adapter  # noqa: E402
from ueba.domain.features import FeatureVector  # noqa: E402
from ueba.infrastructure.io import read_csv_records  # noqa: E402
from ueba.metrics.classification import confusion_matrix  # noqa: E402
from ueba.pipeline import UEBAPipeline  # noqa: E402

TARGETS = {"a.amrani", "l.idrissi", "l.mus", "y.ben", "n.alam", "s.ed", "k.alaa"}
MIN_BURST = 3.0


def is_attack(v: FeatureVector) -> bool:
    return v.user in TARGETS and v.failed_login_count >= MIN_BURST


def main() -> int:
    print("[*] Chargement + extraction ...")
    events = get_adapter("wazuh").normalize(
        list(read_csv_records(ROOT / "data/raw/wazuh-export.csv"))
    )
    pipe = UEBAPipeline(
        window_size=timedelta(hours=1),
        window_step=timedelta(minutes=30),
        ensemble_mode="per-user",
        min_windows_per_user=10,
        default_deny=False,
    )
    vectors = pipe.extract(events)
    pipe.fit([v for v in vectors if not is_attack(v)])  # sans fuite
    records = pipe.predict(vectors)
    y_true = [is_attack(v) for v in vectors]

    # ── Niveau FENÊTRE ──
    print("\n=== Niveau FENÊTRE ===")
    print(f"{'Vote ML':<10}{'Recall':>9}{'Précision':>11}{'F1':>7}{'FP rate':>9}")
    for maj in (2, 3):
        y_pred = [(r.vote_count or 0) >= maj and r.is_anomaly for r in records]
        cm = confusion_matrix(y_true, y_pred)
        print(
            f"{'≥' + str(maj):<10}{cm.recall * 100:>8.1f}%{cm.precision * 100:>10.1f}%"
            f"{cm.f1:>7.2f}{cm.false_positive_rate * 100:>8.1f}%"
        )

    # ── Niveau ENTITÉ (utilisateur × jour) ──
    # Vérité terrain entité : (user cible, jour contenant >=1 fenêtre d'attaque).
    attack_days: set[tuple[str, str]] = set()
    anom_count: dict[tuple[str, str], int] = {}
    all_entities: set[tuple[str, str]] = set()
    for v, r in zip(vectors, records, strict=True):
        key = (v.user, v.window_start.date().isoformat())
        all_entities.add(key)
        if is_attack(v):
            attack_days.add(key)
        if r.is_anomaly:
            anom_count[key] = anom_count.get(key, 0) + 1

    # Variante : n'agréger que les fenêtres à vote FORT (≥3 modèles).
    strong_count: dict[tuple[str, str], int] = {}
    for v, r in zip(vectors, records, strict=True):
        if r.is_anomaly and (r.vote_count or 0) >= 3:
            key = (v.user, v.window_start.date().isoformat())
            strong_count[key] = strong_count.get(key, 0) + 1

    entities = sorted(all_entities)
    truth = [e in attack_days for e in entities]

    def entity_table(counts: dict[tuple[str, str], int], title: str) -> None:
        print(f"\n=== Niveau ENTITÉ (user×jour) — {title} ===")
        print(f"{'Seuil K':<10}{'Recall':>9}{'Précision':>11}{'F1':>7}{'Alertes':>9}")
        for k in (1, 2, 3, 4):
            pred = [counts.get(e, 0) >= k for e in entities]
            cm = confusion_matrix(truth, pred)
            print(
                f"{'≥' + str(k):<10}{cm.recall * 100:>8.1f}%{cm.precision * 100:>10.1f}%"
                f"{cm.f1:>7.2f}{sum(pred):>9}"
            )

    entity_table(anom_count, "K fenêtres anormales (vote ≥2)")
    entity_table(strong_count, "K fenêtres à vote FORT (≥3)")
    print(f"\n  (entités d'attaque : {len(attack_days)} / {len(entities)} couples user×jour)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
