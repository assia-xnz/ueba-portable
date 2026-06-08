"""Extraction des features comportementales UEBA par fenêtre glissante.

Ce module transforme un flux d'événements normalisés (`NormalizedEvent`) en
une matrice « observation = (utilisateur, fenêtre temporelle) → 16 features »,
qui constitue l'entrée de l'ensemble de détection d'anomalies (`ensemble.py`).

Les 16 features couvrent cinq dimensions du comportement (cf. cahier des
charges § 5.5) :

* **Volume** : intensité de l'activité de connexion (login_count,
  failed_login_count, failed_login_ratio) ;
* **Diversité** : étendue des ressources et processus sollicités
  (unique_hosts, unique_logon_types, process_entropy, unique_processes) ;
* **Process** : activité de création de processus (process_count) ;
* **Privilèges & Kerberos** : signaux à fort pouvoir discriminant pour la
  détection d'escalade de privilèges et de Kerberoasting (priv_logon_count,
  kerberos_count) ;
* **Temporalité** : régularité du rythme de travail (off_hours_ratio,
  weekend_ratio, login_velocity, host_velocity) ;
* **Baseline** : écart au comportement individuel passé, cœur du dispositif
  anti-faux-positifs (z_login_count, z_process_count).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, fields
from datetime import datetime, timedelta
from math import log2

from ueba.domain.baseline import BaselineRepository
from ueba.domain.schema import NormalizedEvent

#: Noms des 16 features, dans l'ordre stable utilisé par l'ensemble ML.
FEATURE_NAMES: tuple[str, ...] = (
    "login_count",
    "failed_login_count",
    "failed_login_ratio",
    "unique_hosts",
    "unique_logon_types",
    "process_entropy",
    "unique_processes",
    "process_count",
    "priv_logon_count",
    "kerberos_count",
    "off_hours_ratio",
    "weekend_ratio",
    "login_velocity",
    "host_velocity",
    "z_login_count",
    "z_process_count",
)

#: Métriques brutes pour lesquelles une baseline robuste par utilisateur est apprise.
BASELINE_METRICS: tuple[str, ...] = ("login_count", "process_count")


@dataclass(frozen=True, slots=True)
class FeatureVector:
    """Vecteur des 16 features comportementales pour un (utilisateur, fenêtre).

    Attributs
    ---------
    user : str
        Compte utilisateur concerné.
    window_start : datetime
        Horodatage de début de la fenêtre temporelle glissante.
    window_end : datetime
        Horodatage de fin de la fenêtre temporelle glissante.
    login_count, failed_login_count, ..., z_process_count : float
        Les 16 features comportementales, décrites dans le module.
    """

    user: str
    window_start: datetime
    window_end: datetime
    login_count: float
    failed_login_count: float
    failed_login_ratio: float
    unique_hosts: float
    unique_logon_types: float
    process_entropy: float
    unique_processes: float
    process_count: float
    priv_logon_count: float
    kerberos_count: float
    off_hours_ratio: float
    weekend_ratio: float
    login_velocity: float
    host_velocity: float
    z_login_count: float
    z_process_count: float

    def to_vector(self) -> list[float]:
        """Retourne les 16 features sous forme de liste ordonnée (`FEATURE_NAMES`).

        Cette représentation est celle consommée par l'ensemble ML
        (`RobustScaler` puis `IsolationForest`/`OneClassSVM`/`Autoencoder`).
        """
        return [getattr(self, name) for name in FEATURE_NAMES]


def _shannon_entropy(counter: Counter[str]) -> float:
    """Calcule l'entropie de Shannon (en bits) d'une distribution de fréquences.

    Une entropie élevée traduit une grande variété de processus distincts
    exécutés sur une courte période — signal caractéristique d'un script
    d'automatisation, d'un outil de reconnaissance ou d'une chaîne d'attaque
    de type *Living-off-the-Land* (T1059, T1218).

    Paramètres
    ----------
    counter : Counter[str]
        Décompte d'occurrences par valeur distincte (ex. par nom de processus).

    Retours
    -------
    float
        Entropie de Shannon en bits ; `0.0` si moins de deux valeurs distinctes.
    """
    total = sum(counter.values())
    if total == 0 or len(counter) <= 1:
        return 0.0
    entropy = 0.0
    for count in counter.values():
        probability = count / total
        entropy -= probability * log2(probability)
    return entropy


class UEBAFeatureExtractor:
    """Extrait les 16 features comportementales par fenêtre glissante et par utilisateur.

    Paramètres
    ----------
    window_size : timedelta
        Largeur de chaque fenêtre temporelle d'agrégation (ex. 1 heure).
    window_step : timedelta
        Pas de glissement entre deux fenêtres consécutives (ex. 30 minutes).
        Un pas inférieur à la taille produit des fenêtres chevauchantes
        (*sliding windows*), ce qui améliore la sensibilité de détection sans
        attendre la fin d'une fenêtre complète.
    business_hour_start : int, optionnel
        Heure de début de la plage horaire de bureau (incluse), par défaut 8.
    business_hour_end : int, optionnel
        Heure de fin de la plage horaire de bureau (exclue), par défaut 18.
    baseline_repository : BaselineRepository | None, optionnel
        Référentiel de baselines robustes par utilisateur, utilisé pour
        calculer `z_login_count` et `z_process_count`. Si `None`, ces deux
        features valent `0.0` (mode sans baseline, ex. tout premier
        apprentissage sur une fenêtre temporelle insuffisante).
    """

    def __init__(
        self,
        window_size: timedelta,
        window_step: timedelta,
        business_hour_start: int = 8,
        business_hour_end: int = 18,
        baseline_repository: BaselineRepository | None = None,
    ) -> None:
        if window_size <= timedelta(0):
            raise ValueError("window_size doit être strictement positif")
        if window_step <= timedelta(0):
            raise ValueError("window_step doit être strictement positif")

        self._window_size = window_size
        self._window_step = window_step
        self._business_hour_start = business_hour_start
        self._business_hour_end = business_hour_end
        self._baseline_repository = baseline_repository

    def extract(self, events: list[NormalizedEvent]) -> list[FeatureVector]:
        """Construit les vecteurs de features pour chaque (utilisateur, fenêtre).

        Paramètres
        ----------
        events : list[NormalizedEvent]
            Événements normalisés déjà filtrés des comptes machine, dans un
            ordre arbitraire (ils sont triés en interne par horodatage).

        Retours
        -------
        list[FeatureVector]
            Un vecteur de features par couple (utilisateur, fenêtre) non vide,
            trié par utilisateur puis par début de fenêtre.
        """
        if not events:
            return []

        events_by_user = self._group_by_user(events)
        vectors: list[FeatureVector] = []
        for user in sorted(events_by_user):
            user_events = sorted(events_by_user[user], key=lambda e: e.timestamp)
            vectors.extend(self._extract_for_user(user, user_events))
        return vectors

    def _group_by_user(self, events: list[NormalizedEvent]) -> dict[str, list[NormalizedEvent]]:
        """Regroupe les événements normalisés par compte utilisateur."""
        grouped: dict[str, list[NormalizedEvent]] = {}
        for event in events:
            grouped.setdefault(event.user, []).append(event)
        return grouped

    def _extract_for_user(
        self, user: str, user_events: list[NormalizedEvent]
    ) -> list[FeatureVector]:
        """Construit les vecteurs de features d'un utilisateur sur toutes ses fenêtres."""
        vectors: list[FeatureVector] = []
        first_seen_hosts: set[str] = set()

        for window_start, window_end in self._iter_windows(user_events):
            window_events = [e for e in user_events if window_start <= e.timestamp < window_end]
            if not window_events:
                continue
            vectors.append(
                self._build_feature_vector(
                    user, window_start, window_end, window_events, first_seen_hosts
                )
            )
        return vectors

    def _iter_windows(
        self, user_events: list[NormalizedEvent]
    ) -> list[tuple[datetime, datetime]]:
        """Génère les bornes des fenêtres glissantes couvrant la plage d'activité.

        La première fenêtre démarre à l'horodatage du premier événement de
        l'utilisateur (aligné, en pratique, sur le début de l'export), et les
        fenêtres suivantes glissent par pas de `window_step` tant qu'elles
        contiennent au moins une partie de la plage d'activité observée.
        """
        first_timestamp = user_events[0].timestamp
        last_timestamp = user_events[-1].timestamp

        windows: list[tuple[datetime, datetime]] = []
        window_start = first_timestamp
        while window_start <= last_timestamp:
            windows.append((window_start, window_start + self._window_size))
            window_start += self._window_step
        return windows

    def _build_feature_vector(
        self,
        user: str,
        window_start: datetime,
        window_end: datetime,
        window_events: list[NormalizedEvent],
        first_seen_hosts: set[str],
    ) -> FeatureVector:
        """Calcule les 16 features pour une fenêtre (utilisateur, intervalle) donnée."""
        login_count = sum(1 for e in window_events if e.is_login)
        failed_login_count = sum(1 for e in window_events if e.is_failed_login)
        total_logon_attempts = login_count + failed_login_count
        failed_login_ratio = (
            failed_login_count / total_logon_attempts if total_logon_attempts > 0 else 0.0
        )

        hosts = {e.host for e in window_events if e.host}
        logon_types = {e.logon_type for e in window_events if e.logon_type}
        processes = [e.process_name for e in window_events if e.is_process_creation and e.process_name]
        process_entropy = _shannon_entropy(Counter(processes))
        unique_processes = len(set(processes))
        process_count = sum(1 for e in window_events if e.is_process_creation)

        priv_logon_count = sum(1 for e in window_events if e.is_privileged_logon)
        kerberos_count = sum(1 for e in window_events if e.is_kerberos_tgs_request)

        off_hours_ratio = self._off_hours_ratio(window_events)
        weekend_ratio = self._weekend_ratio(window_events)

        window_minutes = max(self._window_size.total_seconds() / 60.0, 1.0)
        login_velocity = login_count / window_minutes

        new_hosts = hosts - first_seen_hosts
        host_velocity = len(new_hosts) / window_minutes
        first_seen_hosts.update(hosts)

        z_login_count = self._robust_z(user, "login_count", float(login_count))
        z_process_count = self._robust_z(user, "process_count", float(process_count))

        return FeatureVector(
            user=user,
            window_start=window_start,
            window_end=window_end,
            login_count=float(login_count),
            failed_login_count=float(failed_login_count),
            failed_login_ratio=failed_login_ratio,
            unique_hosts=float(len(hosts)),
            unique_logon_types=float(len(logon_types)),
            process_entropy=process_entropy,
            unique_processes=float(unique_processes),
            process_count=float(process_count),
            priv_logon_count=float(priv_logon_count),
            kerberos_count=float(kerberos_count),
            off_hours_ratio=off_hours_ratio,
            weekend_ratio=weekend_ratio,
            login_velocity=login_velocity,
            host_velocity=host_velocity,
            z_login_count=z_login_count,
            z_process_count=z_process_count,
        )

    def _off_hours_ratio(self, window_events: list[NormalizedEvent]) -> float:
        """Proportion d'événements survenus en dehors de la plage horaire de bureau."""
        if not window_events:
            return 0.0
        off_hours = sum(
            1
            for e in window_events
            if not (self._business_hour_start <= e.timestamp.hour < self._business_hour_end)
        )
        return off_hours / len(window_events)

    def _weekend_ratio(self, window_events: list[NormalizedEvent]) -> float:
        """Proportion d'événements survenus un samedi ou un dimanche."""
        if not window_events:
            return 0.0
        weekend = sum(1 for e in window_events if e.timestamp.weekday() >= 5)
        return weekend / len(window_events)

    def _robust_z(self, user: str, metric: str, value: float) -> float:
        """Calcule le z-score robuste d'une valeur via le référentiel de baselines.

        Retourne `0.0` lorsqu'aucun référentiel de baselines n'a été fourni
        (par exemple lors d'une exécution sans historique suffisant).
        """
        if self._baseline_repository is None:
            return 0.0
        return self._baseline_repository.get(user, metric).robust_z_score(value)


__all__ = [
    "BASELINE_METRICS",
    "FEATURE_NAMES",
    "FeatureVector",
    "UEBAFeatureExtractor",
]

# Garde-fou de cohérence : le nombre de features déclarées dans FeatureVector
# (hors identifiants user/window_start/window_end) doit correspondre exactement
# aux 16 features attendues par le cahier des charges.
_NON_FEATURE_FIELDS = {"user", "window_start", "window_end"}
assert len([f for f in fields(FeatureVector) if f.name not in _NON_FEATURE_FIELDS]) == len(
    FEATURE_NAMES
), "FeatureVector doit exposer exactement les 16 features déclarées dans FEATURE_NAMES"
