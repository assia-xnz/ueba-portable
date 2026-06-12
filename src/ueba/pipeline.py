"""Orchestration du pipeline UEBA : extraction → apprentissage → détection.

Ce module relie les briques existantes (normalisation via les adaptateurs,
extraction de features à baseline glissante, ensemble d'anomalies) en un
flux unique, paramétré par le **mode d'apprentissage** :

* ``global`` — un unique :class:`AnomalyEnsemble` appris sur la population
  entière. Simple, mais sa baseline collective est biaisée vers les comptes
  les plus actifs (faux positifs systématiques sur les autres entités).
* ``per-user`` (défaut) — un :class:`PerUserAnomalyEnsemble` qui entraîne un
  modèle dédié par utilisateur. Véritable UEBA personnalisée, conforme à la
  littérature (Salem & Stolfo 2011 ; Veeramachaneni et al. 2016).

Le pipeline produit une liste homogène d':class:`AnomalyRecord`, quel que
soit le mode, de sorte que la CLI et les consommateurs en aval n'ont pas à
connaître la mécanique interne de chaque ensemble.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from ueba.domain.ensemble import AnomalyEnsemble
from ueba.domain.features import FeatureVector
from ueba.domain.per_user_ensemble import PerUserAnomalyEnsemble
from ueba.domain.schema import NormalizedEvent
from ueba.scoring.rolling_baseline import RollingBaselineEngine

#: Modes d'apprentissage acceptés par le pipeline.
EnsembleMode = Literal["global", "per-user"]

#: Étiquette du « modèle » en mode global (un seul modèle pour tous).
GLOBAL_MODEL_LABEL: str = "global"


@dataclass(frozen=True, slots=True)
class AnomalyRecord:
    """Verdict homogène pour une observation (utilisateur, fenêtre).

    Représentation commune aux deux modes, prête à être sérialisée.

    Attributs
    ---------
    user : str
        Compte utilisateur concerné.
    window_start, window_end : datetime
        Bornes de la fenêtre temporelle évaluée.
    is_anomaly : bool
        Décision finale de l'ensemble.
    mode : str
        Mode d'apprentissage ayant produit le verdict (``global`` / ``per-user``).
    used_model : str
        Modèle ayant statué : ``global``, le nom de l'utilisateur, ou
        ``unknown`` (utilisateur jamais vu à l'apprentissage, en *default-deny*).
    vote_count : int | None
        Nombre de modèles ayant voté « anomalie » (``None`` si indisponible,
        cas d'un utilisateur inconnu en mode per-user).
    votes : dict[str, bool] | None
        Vote individuel de chaque modèle, ou ``None`` si indisponible.
    """

    user: str
    window_start: datetime
    window_end: datetime
    is_anomaly: bool
    mode: str
    used_model: str
    vote_count: int | None
    votes: dict[str, bool] | None


class UEBAPipeline:
    """Pipeline de détection UEBA paramétré par le mode d'apprentissage.

    Paramètres
    ----------
    window_size : timedelta
        Largeur de la fenêtre glissante d'agrégation des features.
    window_step : timedelta
        Pas de glissement entre deux fenêtres consécutives.
    lookback_days : int, optionnel
        Profondeur de l'historique servant à la baseline glissante, par défaut 7.
    ensemble_mode : {"global", "per-user"}, optionnel
        Stratégie d'apprentissage, par défaut ``"per-user"`` (recommandée).
    min_windows_per_user : int, optionnel
        Seuil minimal de fenêtres par utilisateur en mode ``per-user``, par
        défaut 30.
    train_ratio : float, optionnel
        Proportion chronologique des fenêtres utilisée pour l'apprentissage en
        mode ``per-user``, par défaut 0.8. Mettre ``1.0`` pour apprendre sur
        l'**intégralité** d'un jeu de données propre dédié (cas d'usage SOC :
        constitution d'une baseline « normale »).
    svm_nu : float, optionnel
        Fraction d'outliers tolérée par le OneClassSVM, par défaut 0.05 (adapté
        à une baseline propre — réduit fortement les faux positifs).
    n_estimators, majority_threshold, random_state
        Hyperparamètres transmis à l'ensemble (mêmes valeurs par défaut que
        :class:`AnomalyEnsemble`).

    Lève
    ----
    ValueError
        Si ``ensemble_mode`` n'est ni ``"global"`` ni ``"per-user"``.
    """

    def __init__(
        self,
        window_size: timedelta,
        window_step: timedelta,
        lookback_days: int = 7,
        ensemble_mode: EnsembleMode = "per-user",
        min_windows_per_user: int = 30,
        train_ratio: float = 0.8,
        svm_nu: float = 0.05,
        n_estimators: int = 200,
        majority_threshold: int = 2,
        random_state: int = 42,
    ) -> None:
        if ensemble_mode not in ("global", "per-user"):
            raise ValueError("ensemble_mode doit valoir 'global' ou 'per-user'")

        self._window_size = window_size
        self._window_step = window_step
        self._lookback_days = lookback_days
        self._mode: EnsembleMode = ensemble_mode
        self._min_windows_per_user = min_windows_per_user
        self._train_ratio = train_ratio
        self._svm_nu = svm_nu
        self._n_estimators = n_estimators
        self._majority_threshold = majority_threshold
        self._random_state = random_state

        self._engine = RollingBaselineEngine(
            window_size=window_size,
            window_step=window_step,
            lookback_days=lookback_days,
        )
        self._ensemble: AnomalyEnsemble | PerUserAnomalyEnsemble | None = None

    @property
    def mode(self) -> EnsembleMode:
        """Mode d'apprentissage actif du pipeline."""
        return self._mode

    def extract(self, events: list[NormalizedEvent]) -> list[FeatureVector]:
        """Extrait les vecteurs de features (utilisateur × fenêtre) des événements."""
        return self._engine.extract(events)

    def fit(self, vectors: list[FeatureVector]) -> None:
        """Entraîne l'ensemble correspondant au mode courant.

        Paramètres
        ----------
        vectors : list[FeatureVector]
            Vecteurs de features produits par :meth:`extract`.

        Lève
        ----
        ValueError
            Si aucun vecteur n'est fourni.
        """
        if not vectors:
            raise ValueError("Aucun vecteur de features à apprendre")

        if self._mode == "global":
            ensemble = AnomalyEnsemble(
                n_estimators=self._n_estimators,
                svm_nu=self._svm_nu,
                majority_threshold=self._majority_threshold,
                random_state=self._random_state,
            )
            ensemble.fit([v.to_vector() for v in vectors])
            self._ensemble = ensemble
        else:
            per_user = PerUserAnomalyEnsemble(
                min_windows_per_user=self._min_windows_per_user,
                train_ratio=self._train_ratio,
                svm_nu=self._svm_nu,
                n_estimators=self._n_estimators,
                majority_threshold=self._majority_threshold,
                random_state=self._random_state,
            )
            per_user.fit(vectors)
            self._ensemble = per_user

    def predict(self, vectors: list[FeatureVector]) -> list[AnomalyRecord]:
        """Évalue les vecteurs et retourne un verdict homogène par observation.

        Paramètres
        ----------
        vectors : list[FeatureVector]
            Vecteurs à scorer.

        Retours
        -------
        list[AnomalyRecord]
            Un enregistrement par vecteur, dans l'ordre d'entrée.

        Lève
        ----
        RuntimeError
            Si l'ensemble n'a pas encore été entraîné ou chargé.
        """
        if self._ensemble is None:
            raise RuntimeError("Le pipeline doit être entraîné (fit) ou chargé avant predict")

        if isinstance(self._ensemble, AnomalyEnsemble):
            return self._predict_global(self._ensemble, vectors)
        return self._predict_per_user(self._ensemble, vectors)

    def _predict_global(
        self, ensemble: AnomalyEnsemble, vectors: list[FeatureVector]
    ) -> list[AnomalyRecord]:
        """Construit les enregistrements en mode global."""
        if not vectors:
            return []
        verdicts = ensemble.predict([v.to_vector() for v in vectors])
        return [
            AnomalyRecord(
                user=vector.user,
                window_start=vector.window_start,
                window_end=vector.window_end,
                is_anomaly=verdict.is_anomaly,
                mode=self._mode,
                used_model=GLOBAL_MODEL_LABEL,
                vote_count=verdict.vote_count,
                votes=dict(verdict.votes),
            )
            for vector, verdict in zip(vectors, verdicts, strict=True)
        ]

    def _predict_per_user(
        self, ensemble: PerUserAnomalyEnsemble, vectors: list[FeatureVector]
    ) -> list[AnomalyRecord]:
        """Construit les enregistrements en mode per-user."""
        verdicts = ensemble.predict(vectors)
        records: list[AnomalyRecord] = []
        for vector, verdict in zip(vectors, verdicts, strict=True):
            if verdict.was_in_training:
                votes = {
                    "isolation_forest": bool(verdict.score_iforest),
                    "one_class_svm": bool(verdict.score_ocsvm),
                    "autoencoder": bool(verdict.score_autoencoder),
                }
            else:
                votes = None
            records.append(
                AnomalyRecord(
                    user=vector.user,
                    window_start=vector.window_start,
                    window_end=vector.window_end,
                    is_anomaly=verdict.is_anomaly,
                    mode=self._mode,
                    used_model=verdict.used_model,
                    vote_count=verdict.vote_count,
                    votes=votes,
                )
            )
        return records

    def run(self, events: list[NormalizedEvent]) -> list[AnomalyRecord]:
        """Exécute le flux complet : extraction → apprentissage → détection.

        Apprend et score sur le même jeu d'événements fourni. La préparation
        d'un jeu d'apprentissage propre (p. ex. retrait en amont des périodes
        connues comme contaminées) relève de l'appelant.

        Paramètres
        ----------
        events : list[NormalizedEvent]
            Événements normalisés en entrée.

        Retours
        -------
        list[AnomalyRecord]
            Verdicts pour toutes les fenêtres observées.
        """
        vectors = self.extract(events)
        self.fit(vectors)
        return self.predict(vectors)

    def save_model(self, path: str) -> None:
        """Persiste le modèle entraîné et la configuration de fenêtrage (joblib).

        L'ensemble est sérialisé comme objet vivant, ce qui préserve son état
        entraîné y compris en mode global (contournement du bug ``_is_fitted``
        de ``AnomalyEnsemble.load``, sans modifier cette classe).

        Lève
        ----
        RuntimeError
            Si aucun modèle n'a encore été entraîné.
        """
        if self._ensemble is None:
            raise RuntimeError("Aucun modèle à sauvegarder : appelez fit() au préalable")

        from pathlib import Path

        import joblib  # type: ignore[import-untyped]

        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "mode": self._mode,
            "ensemble": self._ensemble,
            "config": {
                "window_seconds": self._window_size.total_seconds(),
                "step_seconds": self._window_step.total_seconds(),
                "lookback_days": self._lookback_days,
            },
        }
        joblib.dump(payload, out)

    @classmethod
    def load_model(cls, path: str) -> UEBAPipeline:
        """Recharge un pipeline entraîné depuis un fichier produit par :meth:`save_model`.

        La configuration de fenêtrage sauvegardée est restaurée, afin que
        :meth:`extract` traite les nouveaux événements de façon cohérente avec
        l'apprentissage.

        Retours
        -------
        UEBAPipeline
            Pipeline restauré, prêt à appeler :meth:`extract` puis :meth:`predict`.
        """
        import joblib

        payload = joblib.load(path)
        config = payload["config"]
        pipeline = cls(
            window_size=timedelta(seconds=config["window_seconds"]),
            window_step=timedelta(seconds=config["step_seconds"]),
            lookback_days=config["lookback_days"],
            ensemble_mode=payload["mode"],
        )
        pipeline._ensemble = payload["ensemble"]
        return pipeline


__all__ = [
    "GLOBAL_MODEL_LABEL",
    "AnomalyRecord",
    "EnsembleMode",
    "UEBAPipeline",
]
