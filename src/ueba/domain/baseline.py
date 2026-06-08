"""Baselines comportementales robustes, calculées individuellement par utilisateur.

UEBA signifie *User and Entity Behavior Analytics* : la pierre angulaire de
l'approche est que chaque utilisateur a son propre rythme de travail, et que
« anormal » ne se définit que par rapport à *son propre historique*, pas par
rapport à la population globale (cf. cahier des charges § 5.3).

Ce module implémente le second pilier anti-faux-positifs : des z-scores
**robustes**, fondés sur la médiane et la MAD (Median Absolute Deviation)
plutôt que sur la moyenne et l'écart-type. Une moyenne et un écart-type sont
très sensibles aux valeurs extrêmes déjà présentes dans la fenêtre
d'apprentissage : quelques pics d'activité légitimes (fin de mois, audit, ...)
suffisent à gonfler l'écart-type et à « noyer » statistiquement les futures
anomalies. La médiane et la MAD, elles, restent stables face à ces outliers.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

#: Facteur de correction faisant de la MAD un estimateur cohérent de l'écart-type
#: pour une distribution normale (1 / Φ⁻¹(3/4) ≈ 1.4826).
MAD_NORMAL_CONSTANT: float = 1.4826


@dataclass(frozen=True, slots=True)
class UserBaseline:
    """Baseline robuste d'un utilisateur pour une métrique comportementale donnée.

    Attributs
    ---------
    user : str
        Nom du compte utilisateur concerné.
    metric : str
        Nom de la métrique sur laquelle porte la baseline (ex. "login_count").
    median : float
        Médiane des observations historiques de la métrique.
    mad : float
        Median Absolute Deviation (MAD), c'est-à-dire la médiane des écarts
        absolus à la médiane : `median(|x_i - median(x)|)`.
    n_observations : int
        Nombre d'observations ayant servi à construire la baseline.
    """

    user: str
    metric: str
    median: float
    mad: float
    n_observations: int

    @property
    def is_reliable(self) -> bool:
        """Indique si la baseline repose sur suffisamment d'observations.

        Une baseline construite sur trop peu de fenêtres d'historique ne permet
        pas d'estimer raisonnablement la dispersion du comportement utilisateur :
        son z-score serait soit inexploitable (MAD nulle), soit trompeur.
        """
        return self.n_observations >= 2

    def robust_z_score(self, value: float) -> float:
        """Calcule le z-score robuste (médiane/MAD) d'une nouvelle observation.

        Le z-score robuste est défini par :

            z = (x - médiane) / (MAD x constante_normalité)

        Lorsque la MAD est nulle (utilisateur dont la métrique est parfaitement
        stable, ex. toujours exactement 1 connexion par fenêtre), tout écart à
        la médiane est par définition une rupture de comportement : on retourne
        alors un z-score signé de grande magnitude plutôt qu'une division par
        zéro, afin que l'anomalie reste détectable par l'ensemble en aval.

        Paramètres
        ----------
        value : float
            Nouvelle observation à comparer à la baseline.

        Retours
        -------
        float
            Z-score robuste de `value` par rapport à cette baseline.
        """
        deviation = value - self.median
        scaled_mad = self.mad * MAD_NORMAL_CONSTANT
        if scaled_mad == 0.0:
            if deviation == 0.0:
                return 0.0
            return float(np.sign(deviation)) * 10.0
        return deviation / scaled_mad


class BaselineRepository:
    """Construit et fournit les baselines robustes par (utilisateur, métrique).

    Cette classe encapsule la logique de calcul à partir d'un historique
    d'observations « fenêtre × métrique » par utilisateur, indépendamment de
    la manière dont ces observations ont été produites (extraction de
    features, agrégation SIEM, ...).

    Paramètres
    ----------
    min_observations : int, optionnel
        Nombre minimal d'observations en deçà duquel une baseline est jugée
        non fiable (`UserBaseline.is_reliable` renverra `False`). Par défaut 5,
        conformément à `config/pipeline.yaml`.
    """

    def __init__(self, min_observations: int = 5) -> None:
        self._min_observations = min_observations
        self._baselines: dict[tuple[str, str], UserBaseline] = {}

    def fit(self, observations: dict[str, dict[str, list[float]]]) -> None:
        """Calcule les baselines robustes à partir d'un historique d'observations.

        Paramètres
        ----------
        observations : dict[str, dict[str, list[float]]]
            Dictionnaire `{utilisateur: {métrique: [valeurs historiques]}}`,
            typiquement construit à partir des `lookback_days` derniers jours
            de fenêtres glissantes (cf. `config/pipeline.yaml > baseline`).
        """
        self._baselines.clear()
        for user, metrics in observations.items():
            for metric, values in metrics.items():
                self._baselines[(user, metric)] = self._compute_baseline(user, metric, values)

    def get(self, user: str, metric: str) -> UserBaseline:
        """Retourne la baseline robuste d'un utilisateur pour une métrique.

        Si aucune baseline n'a été apprise pour ce couple (utilisateur,
        métrique) — par exemple un nouvel utilisateur sans historique —, une
        baseline neutre (médiane=0, MAD=0, n_observations=0) est retournée :
        son `robust_z_score` traitera alors toute valeur non nulle comme un
        écart significatif, ce qui est le comportement prudent attendu pour
        un compte sans historique connu.

        Paramètres
        ----------
        user : str
            Nom du compte utilisateur.
        metric : str
            Nom de la métrique comportementale.

        Retours
        -------
        UserBaseline
            La baseline robuste correspondante (éventuellement neutre).
        """
        return self._baselines.get(
            (user, metric),
            UserBaseline(user=user, metric=metric, median=0.0, mad=0.0, n_observations=0),
        )

    def _compute_baseline(self, user: str, metric: str, values: list[float]) -> UserBaseline:
        """Calcule la médiane et la MAD d'une série d'observations historiques."""
        if not values:
            return UserBaseline(user=user, metric=metric, median=0.0, mad=0.0, n_observations=0)

        array = np.asarray(values, dtype=float)
        median = float(np.median(array))
        mad = float(np.median(np.abs(array - median)))
        return UserBaseline(
            user=user,
            metric=metric,
            median=median,
            mad=mad,
            n_observations=len(values),
        )
