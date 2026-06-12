"""Ensemble de détection d'anomalies par vote majoritaire.

Ce module implémente le troisième levier de réduction des faux positifs
(cf. cahier des charges § 5.4-c) : plutôt que de se reposer sur un unique
modèle non supervisé — dont les faux positifs seraient directement remontés
à l'analyste — trois familles de modèles aux biais différents votent
indépendamment, et seule une **majorité d'au moins 2 voix sur 3** déclenche
une alerte :

* **IsolationForest** : isole les observations en construisant des arbres
  aléatoires ; une anomalie nécessite, en moyenne, moins de partitions pour
  être isolée. Robuste en haute dimension, peu sensible à la forme de la
  distribution.
* **OneClassSVM** (noyau RBF) : apprend la frontière englobant la masse
  « normale » des observations dans un espace de caractéristiques projeté ;
  détecte des anomalies de forme non linéaire que IsolationForest peut
  manquer.
* **Autoencoder** (MLPRegressor 8-4-8) : apprend à reconstruire le vecteur de
  features d'entrée à travers un goulot d'étranglement ; une erreur de
  reconstruction élevée (au-delà du 95ᵉ percentile appris) trahit un
  comportement que le modèle n'a jamais appris à compresser fidèlement.

Les trois modèles ont des hypothèses et des angles morts différents : leur
combinaison par vote réduit la probabilité qu'une fluctuation bénigne, mal
modélisée par un seul algorithme, soit remontée comme une alerte isolée.

La standardisation des features est assurée par un `RobustScaler` (médiane et
IQR) plutôt qu'un `StandardScaler` (moyenne et écart-type), pour la même
raison que les baselines robustes : ne pas laisser les outliers historiques
dicter l'échelle de référence.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import numpy.typing as npt
from sklearn.ensemble import IsolationForest  # type: ignore[import-untyped]
from sklearn.neural_network import MLPRegressor  # type: ignore[import-untyped]
from sklearn.preprocessing import RobustScaler  # type: ignore[import-untyped]
from sklearn.svm import OneClassSVM  # type: ignore[import-untyped]

#: Nombre de modèles constituant l'ensemble (IsolationForest, OneClassSVM, Autoencoder).
ENSEMBLE_SIZE: int = 3


@dataclass(frozen=True, slots=True)
class EnsembleVerdict:
    """Verdict de l'ensemble pour une observation donnée.

    Attributs
    ---------
    is_anomaly : bool
        Décision finale : `True` si au moins `majority_threshold` modèles
        (par défaut 2 sur 3) ont voté « anomalie ».
    votes : dict[str, bool]
        Vote individuel de chaque modèle (`True` = anomalie détectée),
        indexé par son nom (`isolation_forest`, `one_class_svm`, `autoencoder`).
    anomaly_score : float
        Score agrégé continu (proportion de votes « anomalie », entre 0 et 1),
        utile pour trier ou prioriser les alertes au-delà du simple seuil binaire.
    """

    is_anomaly: bool
    votes: dict[str, bool]
    anomaly_score: float

    @property
    def vote_count(self) -> int:
        """Nombre de modèles ayant voté « anomalie »."""
        return sum(1 for vote in self.votes.values() if vote)


class AnomalyEnsemble:
    """Ensemble {IsolationForest, OneClassSVM, Autoencoder} avec vote majoritaire.

    Paramètres
    ----------
    n_estimators : int, optionnel
        Nombre d'arbres de l'IsolationForest, par défaut 200.
    svm_kernel : str, optionnel
        Noyau du OneClassSVM, par défaut "rbf".
    svm_gamma : str, optionnel
        Coefficient gamma du noyau RBF, par défaut "scale".
    svm_nu : float, optionnel
        Borne supérieure de la fraction d'erreurs d'apprentissage tolérée par
        le OneClassSVM (et borne inférieure de la fraction de vecteurs de
        support), dans l'intervalle ]0, 1], par défaut 0.5. Sur une baseline
        *propre* (UEBA), une valeur basse (~0.05) est appropriée : on n'attend
        que peu d'outliers dans des données déjà filtrées de tout incident.
    autoencoder_hidden_layers : tuple[int, ...], optionnel
        Tailles des couches cachées du MLPRegressor formant l'autoencodeur,
        par défaut (8, 4, 8) — un goulot d'étranglement à 4 neurones pour
        16 features en entrée/sortie.
    reconstruction_error_percentile : float, optionnel
        Percentile de la distribution des erreurs de reconstruction sur les
        données d'apprentissage utilisé comme seuil d'anomalie, par défaut 95.
    majority_threshold : int, optionnel
        Nombre minimal de votes « anomalie » déclenchant une alerte,
        par défaut 2 (sur 3, soit ≥2/3 conformément au cahier des charges).
    random_state : int, optionnel
        Graine aléatoire commune aux modèles stochastiques, par défaut 42
        (reproductibilité — exigence académique de défendabilité).
    """

    def __init__(
        self,
        n_estimators: int = 200,
        svm_kernel: str = "rbf",
        svm_gamma: str = "scale",
        svm_nu: float = 0.5,
        autoencoder_hidden_layers: tuple[int, ...] = (8, 4, 8),
        reconstruction_error_percentile: float = 95.0,
        majority_threshold: int = 2,
        random_state: int = 42,
    ) -> None:
        if not 1 <= majority_threshold <= ENSEMBLE_SIZE:
            raise ValueError(f"majority_threshold doit être compris entre 1 et {ENSEMBLE_SIZE}")
        if not 0.0 < svm_nu <= 1.0:
            raise ValueError("svm_nu doit être compris dans l'intervalle ]0, 1]")

        self._majority_threshold = majority_threshold
        self._reconstruction_error_percentile = reconstruction_error_percentile

        self._scaler = RobustScaler()
        self._isolation_forest = IsolationForest(
            n_estimators=n_estimators, random_state=random_state
        )
        self._one_class_svm = OneClassSVM(kernel=svm_kernel, gamma=svm_gamma, nu=svm_nu)
        self._autoencoder = MLPRegressor(
            hidden_layer_sizes=autoencoder_hidden_layers,
            random_state=random_state,
            max_iter=1000,
        )

        self._reconstruction_error_threshold: float = 0.0
        self._is_fitted: bool = False

    def fit(self, feature_matrix: npt.ArrayLike) -> None:
        """Entraîne les trois modèles et calibre le seuil de l'autoencodeur.

        Paramètres
        ----------
        feature_matrix : array-like de forme (n_observations, 16)
            Matrice des vecteurs de features extraits par `UEBAFeatureExtractor`.

        Lève
        ----
        ValueError
            Si la matrice de features est vide.
        """
        matrix = np.asarray(feature_matrix, dtype=float)
        if matrix.size == 0 or matrix.shape[0] == 0:
            raise ValueError("La matrice de features ne peut pas être vide pour l'apprentissage")

        scaled = self._scaler.fit_transform(matrix)

        self._isolation_forest.fit(scaled)
        self._one_class_svm.fit(scaled)
        self._autoencoder.fit(scaled, scaled)

        reconstruction = self._autoencoder.predict(scaled)
        errors = np.mean((scaled - reconstruction) ** 2, axis=1)
        self._reconstruction_error_threshold = float(
            np.percentile(errors, self._reconstruction_error_percentile)
        )
        self._is_fitted = True

    def predict(self, feature_matrix: npt.ArrayLike) -> list[EnsembleVerdict]:
        """Évalue chaque observation et retourne le verdict de l'ensemble.

        Paramètres
        ----------
        feature_matrix : array-like de forme (n_observations, 16)
            Vecteurs de features à évaluer (même schéma que pour `fit`).

        Retours
        -------
        list[EnsembleVerdict]
            Un verdict par observation, dans l'ordre d'entrée.

        Lève
        ----
        RuntimeError
            Si `predict` est appelé avant `fit`.
        """
        if not self._is_fitted:
            raise RuntimeError("L'ensemble doit être entraîné via fit() avant toute prédiction")

        matrix = np.asarray(feature_matrix, dtype=float)
        if matrix.size == 0 or matrix.shape[0] == 0:
            return []

        scaled = self._scaler.transform(matrix)

        if_votes = self._isolation_forest.predict(scaled) == -1
        svm_votes = self._one_class_svm.predict(scaled) == -1
        ae_votes = self._autoencoder_votes(scaled)

        verdicts: list[EnsembleVerdict] = []
        for if_vote, svm_vote, ae_vote in zip(if_votes, svm_votes, ae_votes, strict=True):
            votes = {
                "isolation_forest": bool(if_vote),
                "one_class_svm": bool(svm_vote),
                "autoencoder": bool(ae_vote),
            }
            vote_count = sum(votes.values())
            verdicts.append(
                EnsembleVerdict(
                    is_anomaly=vote_count >= self._majority_threshold,
                    votes=votes,
                    anomaly_score=vote_count / ENSEMBLE_SIZE,
                )
            )
        return verdicts

    def _autoencoder_votes(self, scaled: npt.NDArray[np.float64]) -> npt.NDArray[np.bool_]:
        """Détermine, pour chaque observation, si l'erreur de reconstruction
        dépasse le seuil appris."""
        reconstruction: npt.NDArray[np.float64] = self._autoencoder.predict(scaled)
        errors: npt.NDArray[np.float64] = np.mean((scaled - reconstruction) ** 2, axis=1)
        result: npt.NDArray[np.bool_] = errors > self._reconstruction_error_threshold
        return result

    def save(self, path: str) -> None:
        """Persiste les modèles entraînés sur le disque (format joblib).

        Paramètres
        ----------
        path : str
            Chemin du fichier de sauvegarde (ex. "models/ensemble.joblib").
        """
        from pathlib import Path

        import joblib  # type: ignore[import-untyped]

        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "scaler": self._scaler,
            "isolation_forest": self._isolation_forest,
            "one_class_svm": self._one_class_svm,
            "autoencoder": self._autoencoder,
            "reconstruction_error_threshold": self._reconstruction_error_threshold,
            "majority_threshold": self._majority_threshold,
        }
        joblib.dump(payload, out)

    @classmethod
    def load(cls, path: str) -> AnomalyEnsemble:
        """Recharge un ensemble précédemment sauvegardé avec `save()`.

        Paramètres
        ----------
        path : str
            Chemin du fichier joblib.

        Retours
        -------
        AnomalyEnsemble
            Instance restaurée, prête à appeler `predict()`.
        """
        import joblib

        payload = joblib.load(path)
        instance = cls.__new__(cls)
        instance._scaler = payload["scaler"]
        instance._isolation_forest = payload["isolation_forest"]
        instance._one_class_svm = payload["one_class_svm"]
        instance._autoencoder = payload["autoencoder"]
        instance._reconstruction_error_threshold = payload["reconstruction_error_threshold"]
        instance._majority_threshold = payload["majority_threshold"]
        return instance


__all__ = ["ENSEMBLE_SIZE", "AnomalyEnsemble", "EnsembleVerdict"]
