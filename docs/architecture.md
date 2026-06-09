# Architecture détaillée — UEBA Portable

## Principe : architecture hexagonale

Le cœur du système (domaine) ignore totalement le format de la source de données.
Les adapters sont les seuls composants à connaître le schéma de chaque SIEM.

```
┌─────────────────────────────────────────────────────────────────┐
│  Sources SIEM (ports d'entrée)                                  │
│  Wazuh ─┐   Elastic ─┐   Splunk ─┐   QRadar ─┐                │
│         ▼            ▼           ▼            ▼                 │
│  ┌──────────────────────────────────────────────────┐           │
│  │  Couche Adapters (traducteurs)                   │           │
│  │  base.py : contrat SIEMAdapter + filtre machines │           │
│  └──────────────────────────┬───────────────────────┘           │
│                             │ NormalizedEvent                   │
│  ┌──────────────────────────▼───────────────────────┐           │
│  │  Domaine (SIEM-agnostique)                       │           │
│  │                                                  │           │
│  │  schema.py ──► features.py ──► ensemble.py       │           │
│  │                   ▲                  │            │           │
│  │  baseline.py ─────┘         mitre.py◄┘            │           │
│  │                                                  │           │
│  │  scoring/rolling_baseline.py (orchestration)     │           │
│  └──────────────────────────┬───────────────────────┘           │
│                             │ MitreMatch + FeatureVector        │
│  ┌──────────────────────────▼───────────────────────┐           │
│  │  Infrastructure (ports de sortie)                │           │
│  │  infrastructure/io.py (JSON, CSV)                │           │
│  │  infrastructure/config.py (.env, YAML)           │           │
│  │  infrastructure/logging.py (structlog)           │           │
│  └──────────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

## Détail des modules

### `domain/schema.py` — NormalizedEvent

Modèle Pydantic représentant un événement de sécurité normalisé.
Calculé à la demande : `is_login`, `is_failed_login`, `is_process_creation`,
`is_privileged_logon`, `is_kerberos_tgs_request`.

### `domain/baseline.py` — Baseline robuste

`UserBaseline` stocke la médiane et le MAD (Median Absolute Deviation) d'une métrique
pour un utilisateur donné. Le z-score robuste est défini par :

```
z = (valeur - médiane) / (1.4826 × MAD)
```

La constante 1.4826 rend le MAD asymptotiquement cohérent avec l'écart-type gaussien.
`is_reliable` est `True` seulement si `n_observations >= min_observations (5)` et `MAD > 0`.

`BaselineRepository` indexe les baselines par `(user, metric)`.

### `domain/features.py` — UEBAFeatureExtractor

Calcule les 16 features pour chaque couple `(utilisateur, fenêtre)`.
`_iter_windows()` ancre la première fenêtre sur le premier événement de l'utilisateur,
puis glisse par `window_step`. `_build_feature_vector()` agrège les événements de la fenêtre.

La méthode `extract_for_window()` (ajout D3) permet à `RollingBaselineEngine` de
calculer une fenêtre à la fois avec sa propre baseline glissante sans recalculer toutes
les bornes de fenêtres.

### `scoring/rolling_baseline.py` — RollingBaselineEngine

Pour chaque fenêtre à scorer :
1. Calcule la plage de lookback = `[window_start - lookback_days, window_start)`
2. Agrège les observations de la plage de lookback par sous-fenêtres identiques
3. Construit un `BaselineRepository` et l'injecte dans l'extracteur
4. Appelle `extract_for_window()` pour obtenir les vecteurs avec z-scores relatifs

### `domain/ensemble.py` — AnomalyEnsemble

Trois détecteurs entraînés sur l'historique « propre » (période sans attaque) :

| Détecteur | Paramètres | Rôle |
|---|---|---|
| `IsolationForest` | `contamination=0.05`, `n_estimators=100` | Détection globale par isolation |
| `OneClassSVM` | `kernel='rbf'`, `nu=0.05` | Frontière non linéaire dans l'espace de features |
| `MLPRegressor` (autoencoder) | `hidden_layer_sizes=(8, 4, 8)` | Reconstruction — erreur = anomalie |

Vote majoritaire : une observation est anormale si ≥ 2/3 détecteurs la marquent.

### `domain/mitre.py` — MitreMapper

- `match_individual()` : applique les heuristiques par (utilisateur, fenêtre)
- `match_population()` : regroupe les vecteurs par bucket temporel de 30 min,
  détecte T1110.003 si ≥ 3 comptes ont `failed_login_count >= 2` sur la même fenêtre

## Flux de données complet

Voir [`docs/data_flow.md`](data_flow.md).

## Couverture MITRE ATT&CK

Voir [`docs/mitre_coverage.md`](mitre_coverage.md).
