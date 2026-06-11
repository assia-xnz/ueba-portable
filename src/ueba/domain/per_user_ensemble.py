"""Ensemble d'anomalies personnalisé : un modèle dédié par utilisateur.

Ce module implémente la véritable UEBA *personnalisée* attendue par la
littérature (Salem & Stolfo 2011 ; Veeramachaneni et al. 2016) : plutôt
qu'un unique modèle global appris sur la population entière — dont la
baseline collective est biaisée vers les comptes les plus actifs et fait
paraître anormaux par défaut tous les autres utilisateurs — chaque
utilisateur dispose de son **propre** :class:`AnomalyEnsemble`, entraîné
exclusivement sur son historique comportemental.

`PerUserAnomalyEnsemble` encapsule cette logique sans modifier
:class:`AnomalyEnsemble` (réutilisé tel quel en interne) :

* **Groupement** des :class:`FeatureVector` par utilisateur ;
* **Filtrage** des comptes machine/système et des utilisateurs au volume
  d'observation insuffisant pour apprendre une baseline fiable ;
* **Exclusion optionnelle des jours d'attaque connus** de l'ensemble
  d'apprentissage, afin que chaque modèle apprenne une baseline *propre*
  (méthodologie standard d'évaluation supervisée d'un détecteur non
  supervisé) ;
* **Split chronologique** train/holdout par utilisateur, respectant la
  flèche du temps (jamais d'apprentissage sur le futur).

À la prédiction, un utilisateur inconnu (jamais vu à l'apprentissage)
déclenche une alerte par défaut (*default-deny*) : en contexte SOC, une
entité sans baseline établie est traitée comme suspecte jusqu'à preuve du
contraire.
"""

from __future__ import annotations

from dataclasses import dataclass

from ueba.domain.ensemble import AnomalyEnsemble, EnsembleVerdict
from ueba.domain.features import FeatureVector
from ueba.domain.schema import MachineAccountFilter

#: Étiquette du « modèle » fictif renvoyée pour un utilisateur inconnu.
UNKNOWN_MODEL_LABEL: str = "unknown"


@dataclass(frozen=True, slots=True)
class PerUserVerdict:
    """Verdict per-user pour une observation (utilisateur, fenêtre) donnée.

    Attributs
    ---------
    is_anomaly : bool
        Décision finale. Pour un utilisateur connu, reprend le vote
        majoritaire de son :class:`AnomalyEnsemble` dédié ; pour un
        utilisateur inconnu, vaut toujours `True` (*default-deny*).
    user : str
        Compte utilisateur de l'observation évaluée.
    used_model : str
        Identifiant du modèle ayant produit le verdict : le nom de
        l'utilisateur si un modèle dédié existe, sinon
        :data:`UNKNOWN_MODEL_LABEL`.
    was_in_training : bool
        `True` si l'utilisateur disposait d'un modèle entraîné, `False`
        sinon (entité jamais observée à l'apprentissage).
    score_iforest : bool | None
        Vote individuel de l'IsolationForest (`None` pour un inconnu).
    score_ocsvm : bool | None
        Vote individuel du OneClassSVM (`None` pour un inconnu).
    score_autoencoder : bool | None
        Vote individuel de l'autoencodeur (`None` pour un inconnu).
    vote_count : int | None
        Nombre de modèles ayant voté « anomalie » (`None` pour un inconnu).
    """

    is_anomaly: bool
    user: str
    used_model: str
    was_in_training: bool
    score_iforest: bool | None = None
    score_ocsvm: bool | None = None
    score_autoencoder: bool | None = None
    vote_count: int | None = None


class PerUserAnomalyEnsemble:
    """Ensemble d'anomalies personnalisé : un :class:`AnomalyEnsemble` par utilisateur.

    Cette classe expose la même API publique que :class:`AnomalyEnsemble`
    (`fit`, `predict`, `save`, `load`), mais opère au niveau du
    :class:`FeatureVector` (et non d'une matrice brute) car elle a besoin du
    champ `user` pour router chaque observation vers le bon modèle, et du
    champ `window_start` pour le tri chronologique et l'exclusion des jours
    d'attaque.

    Paramètres
    ----------
    min_windows_per_user : int, optionnel
        Nombre minimal de fenêtres qu'un utilisateur doit présenter pour
        qu'un modèle dédié lui soit entraîné, par défaut 30. En deçà, la
        baseline serait statistiquement non fiable et l'utilisateur est
        ignoré à l'apprentissage (donc traité en *default-deny* à la
        prédiction).
    exclude_machine_accounts : bool, optionnel
        Si `True` (défaut), les comptes machine/système (`HOST$`, `SYSTEM`,
        `LOCAL SERVICE`, `NETWORK SERVICE`, `ANONYMOUS LOGON`, `DWM-*`,
        `UMFD-*`) sont exclus via :meth:`MachineAccountFilter.default`.
    train_attack_dates : list[str] | None, optionnel
        Liste de dates `YYYY-MM-DD` à retirer de l'ensemble d'apprentissage
        de chaque utilisateur, pour apprendre une baseline propre exempte de
        l'attaque connue. Si `None` (défaut), toutes les fenêtres sont
        candidates à l'apprentissage.
    train_ratio : float, optionnel
        Proportion chronologique des fenêtres (propres) servant à
        l'apprentissage, par défaut 0.8. Le reliquat constitue un holdout
        temporel non vu à l'apprentissage.
    n_estimators, svm_kernel, svm_gamma, autoencoder_hidden_layers, \
reconstruction_error_percentile, majority_threshold, random_state
        Hyperparamètres transmis tels quels à chaque :class:`AnomalyEnsemble`
        sous-jacent (mêmes valeurs par défaut).

    Lève
    ----
    ValueError
        Si `min_windows_per_user < 1` ou si `train_ratio` n'est pas dans
        l'intervalle ]0, 1].
    """

    def __init__(
        self,
        min_windows_per_user: int = 30,
        exclude_machine_accounts: bool = True,
        train_attack_dates: list[str] | None = None,
        train_ratio: float = 0.8,
        n_estimators: int = 200,
        svm_kernel: str = "rbf",
        svm_gamma: str = "scale",
        autoencoder_hidden_layers: tuple[int, ...] = (8, 4, 8),
        reconstruction_error_percentile: float = 95.0,
        majority_threshold: int = 2,
        random_state: int = 42,
    ) -> None:
        if min_windows_per_user < 1:
            raise ValueError("min_windows_per_user doit être supérieur ou égal à 1")
        if not 0.0 < train_ratio <= 1.0:
            raise ValueError("train_ratio doit être compris dans l'intervalle ]0, 1]")

        self._min_windows_per_user = min_windows_per_user
        self._exclude_machine_accounts = exclude_machine_accounts
        self._train_attack_dates: frozenset[str] = frozenset(train_attack_dates or ())
        self._train_ratio = train_ratio
        self._n_estimators = n_estimators
        self._svm_kernel = svm_kernel
        self._svm_gamma = svm_gamma
        self._autoencoder_hidden_layers = autoencoder_hidden_layers
        self._reconstruction_error_percentile = reconstruction_error_percentile
        self._majority_threshold = majority_threshold
        self._random_state = random_state

        self._machine_account_filter = MachineAccountFilter.default()
        self._models: dict[str, AnomalyEnsemble] = {}
        self._trained_users: list[str] = []
        self._is_fitted: bool = False

    @property
    def is_fitted(self) -> bool:
        """Indique si :meth:`fit` (ou :meth:`load`) a déjà été exécuté."""
        return self._is_fitted

    @property
    def trained_users(self) -> list[str]:
        """Liste triée des utilisateurs disposant d'un modèle dédié entraîné."""
        return list(self._trained_users)

    def _is_valid_user(self, user: str, window_count: int) -> bool:
        """Détermine si un utilisateur est éligible à l'apprentissage d'un modèle.

        Un utilisateur est écarté s'il s'agit d'un compte vide ou anonyme
        (`""`, `"-"`), d'un compte machine/système lorsque
        `exclude_machine_accounts` est actif, ou s'il présente moins de
        `min_windows_per_user` fenêtres.

        Paramètres
        ----------
        user : str
            Nom du compte évalué.
        window_count : int
            Nombre de fenêtres observées pour ce compte.

        Retours
        -------
        bool
            `True` si un modèle dédié doit être entraîné pour cet utilisateur.
        """
        if user.strip() in {"", "-"}:
            return False
        if self._exclude_machine_accounts and self._machine_account_filter.is_machine_account(user):
            return False
        return window_count >= self._min_windows_per_user

    def _training_subset(self, user_vectors: list[FeatureVector]) -> list[FeatureVector]:
        """Extrait le sous-ensemble d'apprentissage d'un utilisateur.

        Les fenêtres sont d'abord triées chronologiquement, puis (si
        `train_attack_dates` est fourni) débarrassées des jours d'attaque
        connus, et enfin tronquées à la part `train_ratio` la plus ancienne
        (split chronologique respectant la flèche du temps).

        Paramètres
        ----------
        user_vectors : list[FeatureVector]
            Toutes les fenêtres d'un même utilisateur, dans un ordre arbitraire.

        Retours
        -------
        list[FeatureVector]
            Les fenêtres retenues pour l'apprentissage (peut être vide si
            toutes les fenêtres tombent un jour d'attaque).
        """
        ordered = sorted(user_vectors, key=lambda v: v.window_start)
        if self._train_attack_dates:
            ordered = [
                v
                for v in ordered
                if v.window_start.date().isoformat() not in self._train_attack_dates
            ]
        split_index = int(len(ordered) * self._train_ratio)
        return ordered[:split_index]

    def fit(self, vectors: list[FeatureVector]) -> None:
        """Entraîne un :class:`AnomalyEnsemble` dédié par utilisateur valide.

        Paramètres
        ----------
        vectors : list[FeatureVector]
            Vecteurs de features de tous les utilisateurs et toutes les
            fenêtres, dans un ordre arbitraire.

        Notes
        -----
        Un utilisateur valide (cf. :meth:`_is_valid_user`) dont le
        sous-ensemble d'apprentissage est vide après exclusion des jours
        d'attaque est silencieusement ignoré : aucun modèle ne lui est
        associé et il sera traité en *default-deny* à la prédiction.
        """
        grouped: dict[str, list[FeatureVector]] = {}
        for vector in vectors:
            grouped.setdefault(vector.user, []).append(vector)

        self._models = {}
        for user in sorted(grouped):
            user_vectors = grouped[user]
            if not self._is_valid_user(user, len(user_vectors)):
                continue

            training = self._training_subset(user_vectors)
            if not training:
                continue

            ensemble = self._build_ensemble()
            ensemble.fit([v.to_vector() for v in training])
            self._models[user] = ensemble

        self._trained_users = sorted(self._models)
        self._is_fitted = True

    def predict(self, vectors: list[FeatureVector]) -> list[PerUserVerdict]:
        """Évalue chaque vecteur via le modèle dédié de son utilisateur.

        Paramètres
        ----------
        vectors : list[FeatureVector]
            Vecteurs à scorer, dans un ordre arbitraire.

        Retours
        -------
        list[PerUserVerdict]
            Un verdict par vecteur, dans l'ordre d'entrée. Les utilisateurs
            inconnus reçoivent un verdict *default-deny* (`is_anomaly=True`).

        Lève
        ----
        RuntimeError
            Si :meth:`predict` est appelé avant :meth:`fit` (ou :meth:`load`).
        """
        if not self._is_fitted:
            raise RuntimeError(
                "PerUserAnomalyEnsemble doit être entraîné via fit() avant toute prédiction"
            )

        verdicts: list[PerUserVerdict] = []
        for vector in vectors:
            ensemble = self._models.get(vector.user)
            if ensemble is None:
                verdicts.append(
                    PerUserVerdict(
                        is_anomaly=True,
                        user=vector.user,
                        used_model=UNKNOWN_MODEL_LABEL,
                        was_in_training=False,
                    )
                )
                continue

            verdict: EnsembleVerdict = ensemble.predict([vector.to_vector()])[0]
            verdicts.append(
                PerUserVerdict(
                    is_anomaly=verdict.is_anomaly,
                    user=vector.user,
                    used_model=vector.user,
                    was_in_training=True,
                    score_iforest=verdict.votes["isolation_forest"],
                    score_ocsvm=verdict.votes["one_class_svm"],
                    score_autoencoder=verdict.votes["autoencoder"],
                    vote_count=verdict.vote_count,
                )
            )
        return verdicts

    def _build_ensemble(self) -> AnomalyEnsemble:
        """Instancie un :class:`AnomalyEnsemble` avec les hyperparamètres courants."""
        return AnomalyEnsemble(
            n_estimators=self._n_estimators,
            svm_kernel=self._svm_kernel,
            svm_gamma=self._svm_gamma,
            autoencoder_hidden_layers=self._autoencoder_hidden_layers,
            reconstruction_error_percentile=self._reconstruction_error_percentile,
            majority_threshold=self._majority_threshold,
            random_state=self._random_state,
        )

    def _config(self) -> dict[str, object]:
        """Reconstitue le dictionnaire des arguments du constructeur."""
        return {
            "min_windows_per_user": self._min_windows_per_user,
            "exclude_machine_accounts": self._exclude_machine_accounts,
            "train_attack_dates": sorted(self._train_attack_dates),
            "train_ratio": self._train_ratio,
            "n_estimators": self._n_estimators,
            "svm_kernel": self._svm_kernel,
            "svm_gamma": self._svm_gamma,
            "autoencoder_hidden_layers": self._autoencoder_hidden_layers,
            "reconstruction_error_percentile": self._reconstruction_error_percentile,
            "majority_threshold": self._majority_threshold,
            "random_state": self._random_state,
        }

    def save(self, path: str) -> None:
        """Persiste l'ensemble per-user complet sur le disque (format joblib).

        Les :class:`AnomalyEnsemble` sont sérialisés en tant qu'objets vivants
        (et non via leur propre `save`), ce qui préserve fidèlement leur état
        entraîné — y compris l'indicateur interne d'ajustement — et garantit
        que :meth:`load` restaure un ensemble immédiatement prédictible.

        Paramètres
        ----------
        path : str
            Chemin du fichier de sauvegarde (ex. "models/per_user.joblib").
        """
        from pathlib import Path

        import joblib  # type: ignore[import-untyped]

        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "config": self._config(),
            "models": self._models,
            "trained_users": self._trained_users,
            "is_fitted": self._is_fitted,
        }
        joblib.dump(payload, out)

    @classmethod
    def load(cls, path: str) -> PerUserAnomalyEnsemble:
        """Recharge un ensemble per-user précédemment sauvegardé via :meth:`save`.

        Contrairement au bug historique de `AnomalyEnsemble.load`, cette
        méthode restaure explicitement l'indicateur d'ajustement
        (`_is_fitted = True`), de sorte que :meth:`predict` est immédiatement
        utilisable sur l'instance restaurée.

        Paramètres
        ----------
        path : str
            Chemin du fichier joblib produit par :meth:`save`.

        Retours
        -------
        PerUserAnomalyEnsemble
            Instance restaurée, prête à appeler :meth:`predict`.
        """
        import joblib

        payload = joblib.load(path)
        config: dict[str, object] = payload["config"]
        instance = cls(**config)  # type: ignore[arg-type]
        instance._models = payload["models"]
        instance._trained_users = payload["trained_users"]
        instance._is_fitted = bool(payload["is_fitted"])
        return instance


__all__ = ["UNKNOWN_MODEL_LABEL", "PerUserAnomalyEnsemble", "PerUserVerdict"]
