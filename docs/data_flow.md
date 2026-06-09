# Flux de données — UEBA Portable

## Vue d'ensemble du pipeline

```
Export SIEM (CSV / JSON)
        │
        ▼
┌───────────────────┐
│  SIEMAdapter      │  • Parser les timestamps (dateutil, D2)
│  .normalize()     │  • Filtrer comptes machine (D4)
│                   │  • Construire NormalizedEvent
└────────┬──────────┘
         │  list[NormalizedEvent]
         ▼
┌───────────────────────────────┐
│  RollingBaselineEngine        │
│  .extract()                   │
│                               │
│  Pour chaque fenêtre :        │
│  ┌─────────────────────────┐  │
│  │  _build_rolling_baseline│  │  Agrège les N jours précédents
│  │  → BaselineRepository   │  │  par sous-fenêtres identiques
│  └────────────┬────────────┘  │
│               │ injecté dans  │
│  ┌────────────▼────────────┐  │
│  │ UEBAFeatureExtractor    │  │
│  │ .extract_for_window()   │  │  16 features + z-scores
│  └────────────┬────────────┘  │
└───────────────┼───────────────┘
                │  list[FeatureVector]
                ▼
┌───────────────────────────────┐
│  AnomalyEnsemble              │
│  .predict()                   │
│                               │
│  IsolationForest ─┐           │
│  OneClassSVM     ─┼─► vote ≥2 │  → label = anomalie / normal
│  Autoencoder MLP ─┘           │
└────────────────┬──────────────┘
                 │  list[FeatureVector] (anomalies only)
                 ▼
┌───────────────────────────────┐
│  MitreMapper                  │
│  .match_individual()          │  Heuristiques + signal SIEM natif
│  .match_population()          │  Détection T1110.003
└────────────────┬──────────────┘
                 │  list[MitreMatch]
                 ▼
┌───────────────────────────────┐
│  Sorties                      │
│  • anomalies.json (local)     │
│  • Elasticsearch bulk index   │  ueba-anomalies-YYYY.MM.DD
│  • Dashboard Kibana           │
└───────────────────────────────┘
```

## Détail : fenêtres glissantes par utilisateur

Chaque utilisateur a son propre calendrier de fenêtres, ancré sur son premier événement.

```
alice.martin  [07:32─08:32)[08:02─09:02)....[14:02─15:02)....
bob.chen      [08:01─09:01)[08:31─09:31)....[14:01─15:01)....
                                              ↑
                                    Fenêtres de spray (jour 16, ~14h)
                                    Regroupées par _window_bucket(30min)
```

Le bucket de 30 min (`_window_bucket()` dans `mitre.py`) aligne les fenêtres décalées
de quelques secondes dans la même période conceptuelle pour la détection population.

## Détail : baseline glissante N-day

```
Temps ──────────────────────────────────────────────────────────►

           ◄─── lookback 7j ───►◄─── fenêtre à scorer ───►
           [window_start-7j    ][window_start            ][window_end]
                  │                      │
         Agrégation en sous-fenêtres    Extraction features
         identiques (1h/30min)          avec baseline injectée
                  │
         BaselineRepository
         médiane + MAD par (user, metric)
                  │
         z_login_count, z_process_count
         dans FeatureVector
```

Si la baseline lookback est vide (premier run, historique < N jours), les z-scores
valent 0.0 (comportement prudent).

## Format NormalizedEvent

```python
NormalizedEvent(
    timestamp  : datetime,          # UTC, sans timezone (tzinfo=None)
    user       : str,               # compte utilisateur (filtré des machines)
    event_id   : str,               # "4624", "4625", "4688", "4672", "4769"
    host       : str | None,        # workstation / hostname
    src_ip     : str | None,        # IP source
    logon_type : str | None,        # "2" interactif, "3" réseau, etc.
    process_name : str | None,      # chemin complet du processus
    parent_process_name : str | None,
    rule_level : int | None,        # niveau de sévérité SIEM
    mitre_technique : str | None,   # "T1078.003" si fourni par le SIEM
    mitre_tactic    : str | None,   # "Privilege Escalation" si fourni
)
```
