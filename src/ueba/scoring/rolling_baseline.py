"""Extraction de features comportementales avec baseline glissante par fenêtre (D3).

Principe : pour chaque fenêtre [W_start, W_end) à scorer, la baseline est
calculée sur les N jours qui la précèdent : [W_start − lookback_days, W_start).
La médiane et la MAD sont donc recalculées à chaque fenêtre à partir de
l'historique *immédiatement antérieur*, ce qui reproduit un comportement
production où le modèle apprend continuellement sans fuite d'information future.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from ueba.domain.baseline import BaselineRepository
from ueba.domain.features import BASELINE_METRICS, FeatureVector, UEBAFeatureExtractor
from ueba.domain.schema import NormalizedEvent


class RollingBaselineEngine:
    """Extrait les features comportementales avec une baseline propre à chaque fenêtre.

    Paramètres
    ----------
    window_size : timedelta
        Largeur de chaque fenêtre temporelle (ex. 1 heure).
    window_step : timedelta
        Pas de glissement entre fenêtres consécutives (ex. 30 minutes).
    lookback_days : int, optionnel
        Nombre de jours d'historique précédant chaque fenêtre utilisés pour
        construire la baseline de cette fenêtre. Par défaut 7.
    business_hour_start : int, optionnel
        Heure de début des heures de bureau (pour `off_hours_ratio`). Par défaut 8.
    business_hour_end : int, optionnel
        Heure de fin des heures de bureau (exclue). Par défaut 18.
    min_observations : int, optionnel
        Nombre minimal de fenêtres de lookback pour qu'une baseline soit fiable.
        Par défaut 5.
    """

    def __init__(
        self,
        window_size: timedelta,
        window_step: timedelta,
        lookback_days: int = 7,
        business_hour_start: int = 8,
        business_hour_end: int = 18,
        min_observations: int = 5,
    ) -> None:
        if lookback_days <= 0:
            raise ValueError("lookback_days doit être strictement positif")

        self._window_size = window_size
        self._window_step = window_step
        self._lookback_days = lookback_days
        self._min_observations = min_observations

        self._extractor = UEBAFeatureExtractor(
            window_size=window_size,
            window_step=window_step,
            business_hour_start=business_hour_start,
            business_hour_end=business_hour_end,
            baseline_repository=None,
        )

    @property
    def lookback_days(self) -> int:
        return self._lookback_days

    def extract(self, events: list[NormalizedEvent]) -> list[FeatureVector]:
        """Extrait les features pour chaque fenêtre glissante avec sa baseline propre.

        Pour chaque fenêtre [W_start, W_end) :
        1. Construit la baseline sur [W_start − lookback_days, W_start).
        2. Injecte cette baseline dans l'extracteur.
        3. Extrait les features pour la fenêtre courante via `extract_for_window`.

        Paramètres
        ----------
        events : list[NormalizedEvent]
            Tous les événements disponibles — doivent couvrir la période de
            lookback *et* la période à scorer pour que les z-scores soient
            significatifs. Ordre arbitraire.

        Retours
        -------
        list[FeatureVector]
            Vecteurs de features, un par (utilisateur, fenêtre) non vide,
            triés par fenêtre puis par utilisateur.
        """
        if not events:
            return []

        all_vectors: list[FeatureVector] = []
        first_seen_hosts_by_user: dict[str, set[str]] = {}

        for window_start, window_end in self._iter_windows(events):
            rolling_repo = self._build_rolling_baseline(events, window_start)
            self._extractor.baseline_repository = rolling_repo

            window_vectors = self._extractor.extract_for_window(
                events, window_start, window_end, first_seen_hosts_by_user
            )
            all_vectors.extend(window_vectors)

        return all_vectors

    def _iter_windows(self, events: list[NormalizedEvent]) -> list[tuple[datetime, datetime]]:
        """Génère les bornes de toutes les fenêtres glissantes sur la plage d'activité."""
        first_ts = min(e.timestamp for e in events)
        last_ts = max(e.timestamp for e in events)

        windows: list[tuple[datetime, datetime]] = []
        cursor = first_ts
        while cursor <= last_ts:
            windows.append((cursor, cursor + self._window_size))
            cursor += self._window_step
        return windows

    def _build_rolling_baseline(
        self, events: list[NormalizedEvent], window_start: datetime
    ) -> BaselineRepository:
        """Construit une BaselineRepository sur les N jours précédant window_start.

        Si le lookback est vide (début de dataset sans historique suffisant),
        retourne un repo vide — les z-scores vaudront 0.0, ce qui est le
        comportement prudent attendu (pas de fausse alerte sur données insuffisantes).
        """
        lookback_start = window_start - timedelta(days=self._lookback_days)
        lookback_events = [e for e in events if lookback_start <= e.timestamp < window_start]

        repo = BaselineRepository(min_observations=self._min_observations)
        if not lookback_events:
            return repo

        observations = self._aggregate_observations(lookback_events, lookback_start, window_start)
        if observations:
            repo.fit(observations)
        return repo

    def _aggregate_observations(
        self,
        events: list[NormalizedEvent],
        period_start: datetime,
        period_end: datetime,
    ) -> dict[str, dict[str, list[float]]]:
        """Agrège les événements du lookback en comptages par (utilisateur, métrique, fenêtre).

        Sous-fenêtre le lookback avec le même window_size/step que le scoring,
        puis comptabilise login_count et process_count par utilisateur et par
        sous-fenêtre — ce sont ces valeurs qui alimentent la médiane/MAD.
        """
        observations: dict[str, dict[str, list[float]]] = {}

        cursor = period_start
        while cursor < period_end:
            win_end = cursor + self._window_size
            win_events = [e for e in events if cursor <= e.timestamp < win_end]

            by_user: dict[str, list[NormalizedEvent]] = {}
            for e in win_events:
                by_user.setdefault(e.user, []).append(e)

            for user, user_evts in by_user.items():
                user_obs = observations.setdefault(user, {m: [] for m in BASELINE_METRICS})
                user_obs["login_count"].append(float(sum(1 for e in user_evts if e.is_login)))
                user_obs["process_count"].append(
                    float(sum(1 for e in user_evts if e.is_process_creation))
                )

            cursor += self._window_step

        return observations


__all__ = ["RollingBaselineEngine"]
