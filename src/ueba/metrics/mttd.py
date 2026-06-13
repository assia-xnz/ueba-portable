"""Calcul du MTTD (*Mean Time To Detect*) — métrique opérationnelle SOC.

Le MTTD mesure le délai entre le **début réel d'une attaque** (connu lors
d'un exercice de simulation ou reconstitué *a posteriori*) et la **première
détection** émise par le système UEBA pour l'utilisateur ciblé.

Définition retenue
------------------
Pour un utilisateur ciblé, la première détection est la fenêtre anormale
*la plus précoce* dont l'intervalle chevauche ou suit le début de l'attaque
(``window_end >= attack_start``). L'instant de détection est l'**heure de
clôture de la fenêtre** (``window_end``) : c'est le moment où le verdict est
réellement disponible pour l'analyste. Le MTTD vaut alors
``window_end - attack_start`` (toujours positif par construction).

Cette convention est volontairement conservatrice (elle ne sous-estime pas le
délai) et reproductible : aucune information postérieure n'est utilisée.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ueba.domain.features import FeatureVector
from ueba.domain.per_user_ensemble import PerUserVerdict


@dataclass(frozen=True, slots=True)
class MTTDReport:
    """Rapport MTTD agrégé sur une campagne de détection.

    Attributs
    ---------
    per_user_mttd : dict[str, timedelta]
        Délai de détection pour chaque utilisateur effectivement détecté.
    global_mttd : timedelta
        Moyenne des MTTD individuels (sur les utilisateurs détectés). Vaut
        ``timedelta(0)`` si aucun utilisateur n'a été détecté.
    first_detection_times : dict[str, datetime]
        Heure de la première détection (``window_end``) par utilisateur détecté.
    detected_users : list[str]
        Utilisateurs ciblés pour lesquels une détection a été émise (triés).
    missed_users : list[str]
        Utilisateurs ciblés sans aucune détection qualifiante (triés).
    """

    per_user_mttd: dict[str, timedelta] = field(default_factory=dict)
    global_mttd: timedelta = timedelta(0)
    first_detection_times: dict[str, datetime] = field(default_factory=dict)
    detected_users: list[str] = field(default_factory=list)
    missed_users: list[str] = field(default_factory=list)

    @property
    def detection_rate(self) -> float:
        """Fraction d'utilisateurs ciblés effectivement détectés (recall opérationnel)."""
        total = len(self.detected_users) + len(self.missed_users)
        if total == 0:
            return 0.0
        return len(self.detected_users) / total

    @property
    def global_mttd_minutes(self) -> float:
        """MTTD global exprimé en minutes (pratique pour Kibana / rapports)."""
        return self.global_mttd.total_seconds() / 60.0


class MTTDCalculator:
    """Calcule le MTTD à partir des verdicts per-user et de leurs fenêtres.

    Les listes ``detections`` et ``vectors`` sont **alignées par index** :
    ``detections[i]`` est le verdict porté sur la fenêtre ``vectors[i]``. C'est
    le contrat naturel produit par :class:`PerUserAnomalyEnsemble.predict`, qui
    conserve l'ordre des vecteurs d'entrée.
    """

    def calculate(
        self,
        attack_start_times: dict[str, datetime],
        detections: list[PerUserVerdict],
        vectors: list[FeatureVector],
    ) -> MTTDReport:
        """Calcule le rapport MTTD pour une campagne d'attaque connue.

        Paramètres
        ----------
        attack_start_times : dict[str, datetime]
            Heure de début d'attaque connue pour chaque utilisateur ciblé.
        detections : list[PerUserVerdict]
            Verdicts per-user, alignés par index avec ``vectors``.
        vectors : list[FeatureVector]
            Fenêtres ayant produit chaque verdict (même longueur que ``detections``).

        Retours
        -------
        MTTDReport
            Rapport agrégé (par utilisateur + global).

        Exceptions
        ----------
        ValueError
            Si ``detections`` et ``vectors`` n'ont pas la même longueur.
        """
        if len(detections) != len(vectors):
            raise ValueError(
                "detections et vectors doivent avoir la même longueur "
                f"({len(detections)} != {len(vectors)})"
            )

        # Pour chaque utilisateur ciblé : fenêtre anormale la plus précoce
        # dont l'intervalle chevauche ou suit le début de l'attaque.
        earliest: dict[str, FeatureVector] = {}
        for verdict, vector in zip(detections, vectors, strict=True):
            user = verdict.user
            attack_start = attack_start_times.get(user)
            if attack_start is None or not verdict.is_anomaly:
                continue
            if vector.window_end < attack_start:
                continue  # fenêtre antérieure à l'attaque — non qualifiante
            current = earliest.get(user)
            if current is None or vector.window_start < current.window_start:
                earliest[user] = vector

        per_user_mttd: dict[str, timedelta] = {}
        first_detection_times: dict[str, datetime] = {}
        for user, vector in earliest.items():
            attack_start = attack_start_times[user]
            per_user_mttd[user] = vector.window_end - attack_start
            first_detection_times[user] = vector.window_end

        detected_users = sorted(earliest)
        missed_users = sorted(set(attack_start_times) - set(earliest))

        if per_user_mttd:
            total = sum((d for d in per_user_mttd.values()), timedelta(0))
            global_mttd = total / len(per_user_mttd)
        else:
            global_mttd = timedelta(0)

        return MTTDReport(
            per_user_mttd=per_user_mttd,
            global_mttd=global_mttd,
            first_detection_times=first_detection_times,
            detected_users=detected_users,
            missed_users=missed_users,
        )


__all__ = ["MTTDCalculator", "MTTDReport"]
