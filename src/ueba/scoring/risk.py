"""Score de risque et niveaux d'alerte SOC pour les anomalies UEBA.

Transforme le verdict de l'ensemble ML en un **score de risque** continu 0–100,
puis en un **niveau d'alerte** lisible (FAIBLE → CRITIQUE).

Le score combine **deux axes indépendants** (corrige la circularité d'une version
antérieure qui amplifiait deux fois le même signal ML) :

* le **consensus ML** : fraction de modèles d'accord (``vote_count / n_models``) —
  mesure la *confiance* de la détection ;
* le **contexte de menace** : gravité *indépendante du ML*, dans [0, 1], typiquement
  dérivée de la **criticité de la technique MITRE** mappée (voir
  :data:`MITRE_CRITICALITY`) ou du privilège du compte.

``risk_score = 100 · (consensus_weight · consensus + context_weight · context)``

Cette définition est **reproductible** (aucune normalisation relative à un lot) et
permet à une détection unanime sur une technique critique d'atteindre CRITIQUE par
le seul mérite du signal — sans dépendre du volume d'anomalies des autres entités.
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

#: Criticité de menace par technique MITRE ATT&CK (0–1), indépendante du ML.
#: Sert de facteur contextuel reproductible. Valeur par défaut : 0.5 (inconnue).
MITRE_CRITICALITY: dict[str, float] = {
    "T1110.003": 0.85,  # Password Spraying (Credential Access) — accès initial à fort impact
    "T1110": 0.80,  # Brute Force
    "T1078": 0.90,  # Valid Accounts — compromission de compte légitime
    "T1078.003": 0.90,  # Valid Accounts: Local Accounts
    "T1558.003": 0.85,  # Kerberoasting
    "T1021": 0.75,  # Remote Services (Lateral Movement)
    "T1059": 0.70,  # Command and Scripting Interpreter
}

#: Criticité par défaut si la technique est inconnue ou absente.
DEFAULT_CRITICALITY = 0.5


def mitre_context(technique: str | None) -> float:
    """Renvoie la criticité contextuelle [0, 1] associée à une technique MITRE."""
    if not technique:
        return DEFAULT_CRITICALITY
    return MITRE_CRITICALITY.get(technique, DEFAULT_CRITICALITY)


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
        Nombre de modèles dans l'ensemble (défaut : 3).
    consensus_weight : float, optionnel
        Poids du consensus ML (défaut : 0.6).
    context_weight : float, optionnel
        Poids du contexte de menace indépendant (défaut : 0.4).
    thresholds : dict[RiskLevel, float] | None, optionnel
        Seuils de classification (défaut : :data:`DEFAULT_THRESHOLDS`).

    Exceptions
    ----------
    ValueError
        Si ``n_models < 1``, si les poids sont négatifs ou ne somment pas à 1.
    """

    def __init__(
        self,
        n_models: int = 3,
        consensus_weight: float = 0.6,
        context_weight: float = 0.4,
        thresholds: dict[RiskLevel, float] | None = None,
    ) -> None:
        if n_models < 1:
            raise ValueError("n_models doit être supérieur ou égal à 1")
        if consensus_weight < 0 or context_weight < 0:
            raise ValueError("les poids doivent être positifs")
        if abs((consensus_weight + context_weight) - 1.0) > 1e-6:
            raise ValueError("consensus_weight + context_weight doit valoir 1.0")
        self._n_models = n_models
        self._consensus_weight = consensus_weight
        self._context_weight = context_weight
        self._thresholds = dict(thresholds) if thresholds is not None else dict(DEFAULT_THRESHOLDS)

    def score(self, vote_count: int | None, context_score: float = DEFAULT_CRITICALITY) -> float:
        """Calcule le score de risque sur 0–100.

        Paramètres
        ----------
        vote_count : int | None
            Nombre de modèles ayant voté « anomalie ». ``None`` (utilisateur
            inconnu, *default-deny*) est traité comme un consensus maximal.
        context_score : float, optionnel
            Gravité contextuelle indépendante du ML, écrêtée sur [0, 1]
            (défaut : :data:`DEFAULT_CRITICALITY`). Typiquement
            :func:`mitre_context` de la technique mappée.
        """
        if vote_count is None:
            consensus = 1.0
        else:
            consensus = max(0, min(vote_count, self._n_models)) / self._n_models
        context = max(0.0, min(context_score, 1.0))
        raw = 100.0 * (self._consensus_weight * consensus + self._context_weight * context)
        return round(max(0.0, min(raw, 100.0)), 1)

    def classify(self, risk_score: float) -> RiskLevel:
        """Associe un score de risque à un niveau d'alerte (seuil inférieur inclus)."""
        for level in (RiskLevel.CRITIQUE, RiskLevel.ELEVE, RiskLevel.MOYEN):
            if risk_score >= self._thresholds[level]:
                return level
        return RiskLevel.FAIBLE

    def assess(
        self, vote_count: int | None, context_score: float = DEFAULT_CRITICALITY
    ) -> RiskAssessment:
        """Évalue une observation : renvoie le score et le niveau d'alerte."""
        risk_score = self.score(vote_count, context_score)
        return RiskAssessment(risk_score=risk_score, risk_level=self.classify(risk_score))


def recommended_action(level: RiskLevel) -> str:
    """Action SOC recommandée pour un niveau d'alerte (exploitable en alerting)."""
    return {
        RiskLevel.CRITIQUE: "Investigation immédiate : isoler le compte, couper les identifiants.",
        RiskLevel.ELEVE: "Trier sous 1 h : corréler logs d'authentification et IP source.",
        RiskLevel.MOYEN: "Revue analyste sous 24 h : vérifier le contexte métier.",
        RiskLevel.FAIBLE: "Surveillance passive : conserver pour corrélation.",
    }[level]


__all__ = [
    "RiskAssessment",
    "RiskLevel",
    "RiskScorer",
    "DEFAULT_THRESHOLDS",
    "MITRE_CRITICALITY",
    "DEFAULT_CRITICALITY",
    "mitre_context",
    "recommended_action",
]
