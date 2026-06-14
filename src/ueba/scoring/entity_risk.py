"""Agrégation des anomalies par entité (utilisateur × jour) — amélioration de la précision.

Un détecteur d'anomalies non supervisé est bruyant **par fenêtre** (faible précision).
Mais une vraie attaque persiste : elle déclenche plusieurs fenêtres anormales, souvent
à consensus fort (3/3 modèles). En agrégeant les verdicts par **entité (utilisateur,
jour)** et en classant les entités par risque, l'analyste traite d'abord le haut de la
pile — là où la précision est élevée — sans sacrifier le recall (toutes les entités
restent présentes).

C'est le mode de restitution des produits UEBA matures : on présente un **score de
risque d'entité**, pas un flux d'alertes par fenêtre.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ueba.pipeline import AnomalyRecord


@dataclass(frozen=True, slots=True)
class EntityAlert:
    """Alerte agrégée pour une entité (utilisateur sur un jour donné).

    Attributs
    ---------
    user : str
        Compte utilisateur concerné.
    day : str
        Jour de l'activité anormale, au format ISO ``YYYY-MM-DD``.
    anomaly_count : int
        Nombre de fenêtres anormales de l'entité sur la journée.
    strong_count : int
        Sous-ensemble de ``anomaly_count`` à consensus fort (``vote_count >= strong_vote``).
    peak_votes : int
        Vote maximal observé (0–3), indicateur de confiance de la détection.
    first_detection, last_detection : datetime
        Bornes temporelles des fenêtres anormales de l'entité.
    """

    user: str
    day: str
    anomaly_count: int
    strong_count: int
    peak_votes: int
    first_detection: datetime
    last_detection: datetime

    @property
    def priority(self) -> tuple[int, int, int]:
        """Clé de tri décroissante : votes forts, puis volume, puis pic de votes."""
        return (self.strong_count, self.anomaly_count, self.peak_votes)


def aggregate_entities(records: list[AnomalyRecord], *, strong_vote: int = 3) -> list[EntityAlert]:
    """Agrège les verdicts anormaux en alertes par entité (utilisateur × jour).

    Paramètres
    ----------
    records : list[AnomalyRecord]
        Verdicts produits par le pipeline (anormaux et non anormaux ; seuls les
        anormaux sont agrégés).
    strong_vote : int
        Seuil de vote pour qu'une fenêtre compte comme « consensus fort »
        (défaut : 3, soit l'unanimité des 3 modèles).

    Retours
    -------
    list[EntityAlert]
        Une alerte par entité ayant au moins une fenêtre anormale, **triée par
        risque décroissant** (votes forts, puis volume). Le tri stable place les
        attaques (multi-fenêtres, consensus fort) en tête de pile.
    """
    grouped: dict[tuple[str, str], list[AnomalyRecord]] = {}
    for rec in records:
        if not rec.is_anomaly:
            continue
        key = (rec.user, rec.window_start.date().isoformat())
        grouped.setdefault(key, []).append(rec)

    alerts: list[EntityAlert] = []
    for (user, day), recs in grouped.items():
        votes = [r.vote_count or 0 for r in recs]
        starts = [r.window_start for r in recs]
        ends = [r.window_end for r in recs]
        alerts.append(
            EntityAlert(
                user=user,
                day=day,
                anomaly_count=len(recs),
                strong_count=sum(1 for v in votes if v >= strong_vote),
                peak_votes=max(votes) if votes else 0,
                first_detection=min(starts),
                last_detection=max(ends),
            )
        )

    alerts.sort(key=lambda a: a.priority, reverse=True)
    return alerts


__all__ = ["EntityAlert", "aggregate_entities"]
