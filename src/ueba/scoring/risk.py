"""Score de risque et niveaux d'alerte SOC pour les anomalies UEBA.

Transforme le verdict brut de l'ensemble ML (combien de modèles ont voté
« anomalie ») en un **score de risque** continu sur 0–100, puis en un
**niveau d'alerte** lisible par un analyste (FAIBLE → CRITIQUE).

Le score combine deux signaux :

* le **consensus ML** : fraction de modèles d'accord (``vote_count / n_models``) —
  un accord unanime est plus fiable qu'un vote serré ;
* l'**intensité** : signal contextuel normalisé sur 0–1 (par défaut 0), par
  exemple la densité de fenêtres anormales de l'utilisateur sur la journée.

``risk_score = 100 * (consensus_weight * consensus + intensity_weight * intensity)``
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RiskLevel(str, Enum):
    """Niveaux d'alerte SOC, du plus faible au plus critique."""

    FAIBLE = "FAIBLE"
    MOYEN = "MOYEN"
    ELEVE = "ÉLEVÉ"
    CRITIQUE = "CRITIQUE"


#: Seuils par défaut (borne inférieure incluse) appliqués au ``risk_score``.
DEFAULT_THRESHOLDS: dict[RiskLevel, float] = {
    RiskLevel.CRITIQUE: 80.0,
    RiskLevel.ELEVE: 60.0,
    RiskLevel.MOYEN: 40.0,
    RiskLevel.FAIBLE: 0.0,
}


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Évaluation de risque d'une observation : score continu + niveau discret."""

    risk_score: float
    risk_level: RiskLevel


class RiskScorer:
    """Calcule le score de risque et le niveau d'alerte d'une anomalie.

    Paramètres
    ----------
    n_models : int, optionnel
        Nombre de modèles dans l'ensemble (défaut : 3 — IsolationForest,
        OneClassSVM, autoencodeur).
    consensus_weight : float, optionnel
        Poids du consensus ML dans le score (défaut : 0.7).
    intensity_weight : float, optionnel
        Poids du signal d'intensité contextuel (défaut : 0.3).
    thresholds : dict[RiskLevel, float] | None, optionnel
        Seuils de classification. Par défaut :data:`DEFAULT_THRESHOLDS`.

    Exceptions
    ----------
    ValueError
        Si ``n_models < 1`` ou si les poids ne somment pas à 1 (à 1e-6 près)
        ou sont négatifs.
    """

    def __init__(
        self,
        n_models: int = 3,
        consensus_weight: float = 0.7,
        intensity_weight: float = 0.3,
        thresholds: dict[RiskLevel, float] | None = None,
    ) -> None:
        if n_models < 1:
            raise ValueError("n_models doit être supérieur ou égal à 1")
        if consensus_weight < 0 or intensity_weight < 0:
            raise ValueError("les poids doivent être positifs")
        if abs((consensus_weight + intensity_weight) - 1.0) > 1e-6:
            raise ValueError("consensus_weight + intensity_weight doit valoir 1.0")

        self._n_models = n_models
        self._consensus_weight = consensus_weight
        self._intensity_weight = intensity_weight
        self._thresholds = dict(thresholds) if thresholds is not None else dict(DEFAULT_THRESHOLDS)

    def score(self, vote_count: int | None, intensity: float = 0.0) -> float:
        """Calcule le score de risque sur 0–100.

        Paramètres
        ----------
        vote_count : int | None
            Nombre de modèles ayant voté « anomalie ». ``None`` (utilisateur
            inconnu, *default-deny*) est traité comme un consensus maximal.
        intensity : float, optionnel
            Signal contextuel normalisé, écrêté sur [0, 1] (défaut : 0.0).

        Retours
        -------
        float
            Score de risque arrondi à 0,1 près, dans [0, 100].
        """
        if vote_count is None:
            consensus = 1.0
        else:
            consensus = max(0, min(vote_count, self._n_models)) / self._n_models
        intensity = max(0.0, min(intensity, 1.0))
        raw = 100.0 * (self._consensus_weight * consensus + self._intensity_weight * intensity)
        return round(max(0.0, min(raw, 100.0)), 1)

    def classify(self, risk_score: float) -> RiskLevel:
        """Associe un score de risque à un niveau d'alerte (seuil inférieur inclus)."""
        for level in (RiskLevel.CRITIQUE, RiskLevel.ELEVE, RiskLevel.MOYEN):
            if risk_score >= self._thresholds[level]:
                return level
        return RiskLevel.FAIBLE

    def assess(self, vote_count: int | None, intensity: float = 0.0) -> RiskAssessment:
        """Évalue une observation : renvoie le score et le niveau d'alerte."""
        risk_score = self.score(vote_count, intensity)
        return RiskAssessment(risk_score=risk_score, risk_level=self.classify(risk_score))


__all__ = ["RiskAssessment", "RiskLevel", "RiskScorer", "DEFAULT_THRESHOLDS"]
