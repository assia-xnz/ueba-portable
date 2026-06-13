"""Métriques de classification pour l'évaluation honnête de la détection.

Fournit la matrice de confusion et les métriques dérivées (précision, rappel, F1,
taux de faux positifs) afin de **présenter le rappel ET la précision ensemble** —
un rappel élevé seul, sans son taux de faux positifs, est trompeur en contexte SOC.

Usage typique : comparer les verdicts du système (``y_pred``) à une vérité terrain
(``y_true``) sur un jeu de validation **sans fuite** (train et test disjoints).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ConfusionMatrix:
    """Matrice de confusion binaire (positif = anomalie / attaque)."""

    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def support(self) -> int:
        """Nombre total d'observations."""
        return self.tp + self.fp + self.fn + self.tn

    @property
    def precision(self) -> float:
        """TP / (TP + FP) — proportion d'alertes correctes. 0 si aucune alerte."""
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        """TP / (TP + FN) — proportion d'attaques détectées. 0 si aucun positif réel."""
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        """Moyenne harmonique précision/rappel. 0 si les deux sont nuls."""
        denom = self.precision + self.recall
        return 2 * self.precision * self.recall / denom if denom else 0.0

    @property
    def false_positive_rate(self) -> float:
        """FP / (FP + TN) — proportion de normal flaggé à tort. 0 si aucun négatif réel."""
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def accuracy(self) -> float:
        """(TP + TN) / total. 0 si aucune observation."""
        return (self.tp + self.tn) / self.support if self.support else 0.0

    def as_dict(self) -> dict[str, float | int]:
        """Sérialise la matrice et toutes les métriques (pour rapport/ES)."""
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "support": self.support,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "accuracy": round(self.accuracy, 4),
        }


def confusion_matrix(y_true: Sequence[bool], y_pred: Sequence[bool]) -> ConfusionMatrix:
    """Calcule la matrice de confusion binaire.

    Paramètres
    ----------
    y_true, y_pred : Sequence[bool]
        Étiquettes réelles et prédites, alignées par index et de même longueur.
        ``True`` = anomalie/attaque (positif).

    Exceptions
    ----------
    ValueError
        Si les deux séquences n'ont pas la même longueur.
    """
    if len(y_true) != len(y_pred):
        raise ValueError(
            f"y_true et y_pred de longueurs différentes ({len(y_true)} != {len(y_pred)})"
        )
    tp = fp = fn = tn = 0
    for truth, pred in zip(y_true, y_pred, strict=True):
        if truth and pred:
            tp += 1
        elif not truth and pred:
            fp += 1
        elif truth and not pred:
            fn += 1
        else:
            tn += 1
    return ConfusionMatrix(tp=tp, fp=fp, fn=fn, tn=tn)


def classification_report(y_true: Sequence[bool], y_pred: Sequence[bool]) -> dict[str, float | int]:
    """Renvoie la matrice de confusion et toutes les métriques sous forme de dict."""
    return confusion_matrix(y_true, y_pred).as_dict()


__all__ = ["ConfusionMatrix", "confusion_matrix", "classification_report"]
