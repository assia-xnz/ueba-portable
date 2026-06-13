"""Filtre de persistance temporelle — réducteur de faux positifs.

Principe SOC bien établi : une attaque réelle (password spraying, brute force,
exfiltration) **persiste dans le temps** et déclenche plusieurs fenêtres anormales
consécutives, tandis qu'un faux positif est souvent une **fenêtre isolée** (pic
bénin ponctuel, variation de comportement). En n'alertant que sur les séries d'au
moins ``min_consecutive`` fenêtres anormales rapprochées, on supprime la plupart
des faux positifs isolés **sans perdre** les attaques (qui s'étalent sur la durée).

Le filtre opère **par utilisateur** sur les verdicts triés chronologiquement et
renvoie de nouveaux verdicts (les fenêtres isolées passent à ``is_anomaly=False``).
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ueba.pipeline import AnomalyRecord


class PersistenceFilter:
    """Supprime les anomalies isolées, ne conservant que les séries persistantes.

    Paramètres
    ----------
    min_consecutive : int
        Nombre minimal de fenêtres anormales rapprochées pour qu'une alerte soit
        conservée (défaut : 2). ``1`` désactive le filtre.
    max_gap : timedelta
        Écart maximal entre les débuts de deux fenêtres anormales pour qu'elles
        appartiennent à la même série (défaut : 60 min ; couvre un pas de 30 min
        avec recouvrement). Au-delà, une nouvelle série commence.

    Exceptions
    ----------
    ValueError
        Si ``min_consecutive < 1``.
    """

    def __init__(
        self, min_consecutive: int = 2, max_gap: timedelta = timedelta(minutes=60)
    ) -> None:
        if min_consecutive < 1:
            raise ValueError("min_consecutive doit être supérieur ou égal à 1")
        self._min_consecutive = min_consecutive
        self._max_gap = max_gap

    def apply(self, records: list[AnomalyRecord]) -> list[AnomalyRecord]:
        """Renvoie de nouveaux verdicts où les anomalies isolées sont neutralisées.

        Les verdicts non anormaux sont renvoyés inchangés. L'ordre d'entrée est
        préservé.
        """
        if self._min_consecutive <= 1:
            return list(records)

        # Indices des fenêtres anormales, groupés par utilisateur et triés par temps.
        anomalous_by_user: dict[str, list[int]] = {}
        for idx, rec in enumerate(records):
            if rec.is_anomaly:
                anomalous_by_user.setdefault(rec.user, []).append(idx)

        keep: set[int] = set()
        for user_indices in anomalous_by_user.values():
            ordered = sorted(user_indices, key=lambda i: records[i].window_start)
            run: list[int] = []
            prev_start = None
            for i in ordered:
                start = records[i].window_start
                if prev_start is not None and (start - prev_start) > self._max_gap:
                    if len(run) >= self._min_consecutive:
                        keep.update(run)
                    run = []
                run.append(i)
                prev_start = start
            if len(run) >= self._min_consecutive:
                keep.update(run)

        result: list[AnomalyRecord] = []
        for idx, rec in enumerate(records):
            if rec.is_anomaly and idx not in keep:
                result.append(replace(rec, is_anomaly=False))
            else:
                result.append(rec)
        return result


__all__ = ["PersistenceFilter"]
