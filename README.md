# UEBA Portable — Détection d'anomalies comportementales pour la chasse aux menaces

> **Projet de Fin d'Études** — ENSA Tanger, Génie des Systèmes de Télécommunications et Réseaux (5ème année).
>
> **Titre :** Conception et implémentation d'un système UEBA portable pour la chasse aux menaces,
> basé sur l'apprentissage automatique non supervisé, intégré à un SIEM et mappé au framework MITRE ATT&CK.

[![CI](https://github.com/YOUR_ORG/ueba-portable/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_ORG/ueba-portable/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Architecture](#2-architecture)
3. [Installation](#3-installation)
4. [Quickstart](#4-quickstart)
5. [Mapping des champs SIEM](#5-mapping-des-champs-siem)
6. [Les 16 features comportementales](#6-les-16-features-comportementales)
7. [Réduction des faux positifs — 3 leviers](#7-réduction-des-faux-positifs--3-leviers)
8. [Validation : détection du Password Spray (T1110.003)](#8-validation--détection-du-password-spray-t1110003)
9. [Mapping MITRE ATT&CK](#9-mapping-mitre-attck)
10. [Ajouter un nouveau SIEM](#10-ajouter-un-nouveau-siem)
11. [Configuration `.env`](#11-configuration-env)
12. [Structure du projet](#12-structure-du-projet)
13. [Contribuer](#13-contribuer)
14. [Licence](#14-licence)

---

## 1. Vue d'ensemble

UEBA Portable est un pipeline de détection d'anomalies comportementales sur les journaux de sécurité Windows.
Il est conçu pour être **portable entre SIEMs** : une couche d'adapters découple le format source
(Wazuh, Elastic ECS, Splunk CIM, QRadar) d'un cœur ML non supervisé indépendant de toute source de données.

**Fonctionnalités clés :**

- Fenêtres glissantes par utilisateur (1 h / pas 30 min) — sensibilité sans latence d'alerte excessive
- 16 features comportementales couvrant volume, diversité, privilèges, temporalité et z-scores relatifs à la baseline
- Ensemble de trois détecteurs (IsolationForest + OneClassSVM + Autoencoder MLP) — vote majoritaire ≥ 2/3
- Baseline glissante N-day par utilisateur — z-score robuste (médiane + MAD) pour réduire les faux positifs
- Mapping automatique vers MITRE ATT&CK — heuristique sur les features + signal natif du SIEM
- Détection collective du Password Spraying (T1110.003) — pattern population, pas uniquement individuel
- Filtrage des comptes machine intégré à la couche d'adaptation (avant extraction de features)

---

## 2. Architecture

```mermaid
graph TD
    subgraph Sources["Sources SIEM"]
        W[Wazuh / Kibana]
        E[Elastic ECS]
        S[Splunk CIM]
        Q[QRadar]
    end

    subgraph Adapters["Couche Adapters"]
        WA[WazuhAdapter]
        EA[ElasticAdapter]
        SA[SplunkAdapter]
        QA[QRadarAdapter]
    end

    subgraph Domain["Domaine (SIEM-agnostique)"]
        NE[NormalizedEvent]
        FE[UEBAFeatureExtractor\n16 features · fenêtres 1h/30min]
        RB[RollingBaselineEngine\nlookback N jours · z-score robuste]
        EN[AnomalyEnsemble\nIF + OCSVM + Autoencoder MLP]
        MM[MitreMapper\nheuristique + signal SIEM natif]
    end

    subgraph Output["Sorties"]
        AL[Alertes JSON]
        ES[(Elasticsearch\nueba-anomalies-*)]
        KB[Dashboard Kibana]
    end

    W -->|CSV/JSON export| WA
    E -->|JSON ECS| EA
    S -->|CSV CIM| SA
    Q -->|JSON| QA

    WA --> NE
    EA --> NE
    SA --> NE
    QA --> NE

    NE --> RB
    RB --> FE
    FE -->|FeatureVector × 16| EN
    EN -->|anomalies| MM
    MM --> AL
    AL --> ES
    ES --> KB
```

> Architecture hexagonale : le **domaine** ne dépend d'aucun SIEM.
> Les adapters traduisent les formats sources vers `NormalizedEvent`.
> Voir [`docs/architecture.md`](docs/architecture.md) pour les diagrammes détaillés.

---

## 3. Installation

### Prérequis

- Python ≥ 3.10
- [Poetry](https://python-poetry.org/) ≥ 1.7

### Installation des dépendances

```bash
git clone https://github.com/YOUR_ORG/ueba-portable.git
cd ueba-portable
poetry install
```

### Vérification

```bash
poetry run pytest            # 145 tests, couverture > 80 %
poetry run ueba version
```

---

## 4. Quickstart

### Analyser un export Wazuh (CSV)

```bash
poetry run ueba run data/raw/export.csv --source wazuh --output anomalies.json
```

### Options du sous-commande `run`

| Option | Défaut | Description |
|---|---|---|
| `--source` | `wazuh` | Format SIEM : `wazuh`, `elastic`, `splunk`, `qradar` |
| `--output` | `anomalies.json` | Fichier de sortie JSON |
| `--window-hours` | `1.0` | Taille de la fenêtre glissante (heures) |
| `--step-minutes` | `30` | Pas de glissement (minutes) |
| `--lookback-days` | `7` | Fenêtre de lookback pour la baseline |

### Exemple de sortie JSON

```json
[
  {
    "user": "alice.martin",
    "window_start": "2026-05-16T14:02:10",
    "window_end": "2026-05-16T15:02:10",
    "features": [4.0, 4.0, 0.5, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.067, 0.0, 0.0, 0.0]
  }
]
```

---

## 5. Mapping des champs SIEM

Les adapters traduisent les champs natifs de chaque SIEM vers le schéma `NormalizedEvent`.

| Champ NormalizedEvent | Wazuh (CSV Kibana) | Elastic ECS | Splunk CIM | QRadar |
|---|---|---|---|---|
| `timestamp` | `@timestamp` | `@timestamp` | `_time` | `startTime` |
| `user` | `data.win.eventdata.targetUserName` | `user.name` | `user` | `username` |
| `event_id` | `data.win.system.eventID` | `winlog.event_id` | `EventCode` | `eventId` |
| `host` | `data.win.eventdata.workstationName` | `host.hostname` | `ComputerName` | `deviceAddress` |
| `src_ip` | `data.win.eventdata.ipAddress` | `source.ip` | `src_ip` | `sourceIP` |
| `logon_type` | `data.win.eventdata.logonType` | `winlog.event_data.LogonType` | `LogonType` | `eventProperty` |
| `process_name` | `data.win.eventdata.processName` | `process.name` | `Process_Name` | `commandLine` |
| `rule.mitre.id` | `rule.mitre.id` | `threat.technique.id` | — | — |

**Identifiants d'événements Windows reconnus :**

| Event ID | Signification | Feature impactée |
|---|---|---|
| 4624 | Logon réussi | `login_count` |
| 4625 | Logon échoué | `failed_login_count` |
| 4634 / 4647 | Logoff | — (ignoré) |
| 4672 | Privileges spéciaux | `priv_logon_count` |
| 4688 | Création de processus | `process_count`, `process_entropy` |
| 4769 | Requête ticket Kerberos | `kerberos_count` |

---

## 6. Les 16 features comportementales

Chaque observation est un tuple **(utilisateur, fenêtre 1h)** décrit par 16 features :

### Volume de connexion

| Feature | Description | Signal détecté |
|---|---|---|
| `login_count` | Nombre de connexions réussies | Activité inhabituelle (pic ou creux) |
| `failed_login_count` | Nombre d'échecs de connexion | Brute force, password spray |
| `failed_login_ratio` | Ratio échecs / total tentatives | Attaque ciblée sur un compte |

### Diversité des ressources

| Feature | Description | Signal détecté |
|---|---|---|
| `unique_hosts` | Nombre d'hôtes distincts contactés | Mouvement latéral |
| `unique_logon_types` | Variété des types de logon | Accès hybride inhabituel |
| `process_entropy` | Entropie de Shannon des processus | LoL (Living-off-the-Land), scripts |
| `unique_processes` | Nombre de processus distincts | Toolset offensif |
| `process_count` | Total créations de processus | Activité automatisée |

### Privilèges et Kerberos

| Feature | Description | Signal détecté |
|---|---|---|
| `priv_logon_count` | Connexions avec privilèges spéciaux (4672) | Escalade de privilèges (T1078) |
| `kerberos_count` | Requêtes TGS Kerberos (4769) | Kerberoasting (T1558.003) |

### Temporalité

| Feature | Description | Signal détecté |
|---|---|---|
| `off_hours_ratio` | Fraction d'activité hors heures de bureau | Accès non autorisé, compromission |
| `weekend_ratio` | Fraction d'activité le week-end | Accès hors cycle habituel |
| `login_velocity` | Connexions par minute | Automatisation, credential stuffing |
| `host_velocity` | Nouveaux hôtes par minute | Reconnaissance réseau rapide |

### Baseline individuelle (z-scores robustes)

| Feature | Description | Rôle anti-faux-positif |
|---|---|---|
| `z_login_count` | Z-score robuste de `login_count` vs. baseline N-day | Relativise la volumétrie à l'historique individuel |
| `z_process_count` | Z-score robuste de `process_count` vs. baseline N-day | Relativise l'activité process au comportement habituel |

---

## 7. Réduction des faux positifs — 3 leviers

Le système combine trois mécanismes complémentaires pour réduire le taux de fausse alerte :

### Levier 1 — Vote majoritaire d'ensemble (≥ 2/3)

Trois détecteurs indépendants (IsolationForest, OneClassSVM, Autoencoder MLP) doivent tous
au moins deux d'entre eux déclarer une anomalie pour qu'une alerte soit émise.
Un pic de volume isolé qui n'est anormal que pour un seul modèle est filtré silencieusement.

### Levier 2 — Z-score robuste sur baseline glissante N-day

Les features `z_login_count` et `z_process_count` mesurent l'écart au comportement *individuel*
sur les N jours précédents (médiane + MAD, constante 1.4826). Un administrateur système avec
100 connexions/jour n'est pas anormal *pour lui* : son z-score reste proche de 0.
La baseline est déclarée non fiable (`is_reliable = False`) si elle compte moins de 5 observations,
et les z-scores valent alors 0.0 (comportement prudent sur historique insuffisant).

### Levier 3 — Filtrage des comptes machine à l'adaptation

Les comptes se terminant par `$` (comptes machine Active Directory) et les comptes de service
standards (`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`) sont éliminés dans la couche adapter,
avant toute extraction de feature. Ces comptes génèrent une activité légitime à très haute fréquence
qui polluerait les baselines et produirait des alertes massives sans valeur opérationnelle.

---

## 8. Validation : détection du Password Spray (T1110.003)

La fixture de test `tests/integration/fixtures/sample_logs.csv` inclut un scénario de
**password spraying** synthétique : 7 comptes cibles, 2 à 4 échecs de connexion chacun,
sur une fenêtre de 6 minutes (14h02–14h08 le 16 mai 2026), depuis une IP unique (`10.10.0.50`).

### Résultat attendu

```
T1110.003 — Brute Force: Password Spraying
Tactique : Credential Access
Rationale : 7 comptes distincts (alice.martin, bob.chen, charlie.kim, diana.wolf,
            eric.santos, fiona.lee, george.nasir) présentent des échecs de connexion
            synchronisés sur la fenêtre 2026-05-16 14:00 – 15:05
Source    : heuristic
```

### Pourquoi le password spray échappe au brute force individuel

| Indicateur | Brute Force (T1110) | Password Spray (T1110.003) |
|---|---|---|
| Comptes ciblés | 1 compte, nombreux mots de passe | Nombreux comptes, 1–2 mots de passe chacun |
| `failed_login_count` par compte | Très élevé (déclenche verrouillage) | Modéré (sous le seuil de verrouillage) |
| Détection nécessaire | Individuelle (par compte) | Collective (population de comptes) |
| Seuil `PASSWORD_SPRAY_MIN_USERS` | N/A | ≥ 3 comptes simultanés |

La détection T1110.003 est implémentée dans `MitreMapper.match_population()` et n'est
possible qu'en regroupant les vecteurs de tous les utilisateurs sur la même fenêtre temporelle.

### Lancer les tests d'intégration

```bash
poetry run pytest tests/integration/ -v
```

---

## 9. Mapping MITRE ATT&CK

### Heuristiques individuelles (par utilisateur × fenêtre)

| Technique | Nom | Tactique | Feature déclenchante | Seuil |
|---|---|---|---|---|
| T1110 | Brute Force | Credential Access | `failed_login_count` | > 5 |
| T1078.003 | Valid Accounts: Local Accounts | Privilege Escalation | `priv_logon_count` | > 3 |
| T1558.003 | Kerberoasting | Credential Access | `kerberos_count` | > 5 |
| T1059 | Command and Scripting Interpreter | Execution | `process_entropy` | > 2.0 bits |
| T1021 | Remote Services | Lateral Movement | `host_velocity` | > 0.05 hôtes/min |
| T1078 | Valid Accounts | Defense Evasion | `off_hours_ratio` > 0.5 **ET** `unique_hosts` > 2 | combiné |

### Détection collective (population)

| Technique | Nom | Tactique | Condition | Seuil |
|---|---|---|---|---|
| T1110.003 | Brute Force: Password Spraying | Credential Access | ≥ N comptes avec `failed_login_count` ≥ 2 sur même fenêtre temporelle | N ≥ 3 |

### Signal natif SIEM (prioritaire)

Quand un événement contient le champ `rule.mitre.id` (Wazuh) ou `threat.technique.id` (Elastic),
ce signal est ajouté en tête de liste, avant les heuristiques internes.

---

## 10. Ajouter un nouveau SIEM

1. **Créer l'adapter** dans `src/ueba/adapters/mon_siem.py` :

```python
from ueba.adapters.base import SIEMAdapter, AdapterConfig
from ueba.domain.schema import NormalizedEvent

class MonSiemAdapter(SIEMAdapter):
    SOURCE_NAME = "mon_siem"

    def normalize(self, raw_records: list[dict]) -> list[NormalizedEvent]:
        events = []
        for record in raw_records:
            # 1. Parser le timestamp avec dateutil (D2)
            # 2. Filtrer les comptes machine (D4)
            # 3. Construire NormalizedEvent
            ...
        return events
```

2. **Enregistrer l'adapter** dans `src/ueba/adapters/registry.py` :

```python
from ueba.adapters.mon_siem import MonSiemAdapter
_REGISTRY["mon_siem"] = MonSiemAdapter
```

3. **Ajouter le mapping de champs** dans la section [Mapping SIEM](#5-mapping-des-champs-siem) du README.

4. **Écrire les tests** dans `tests/unit/test_adapter_mon_siem.py` (contrat `SIEMAdapter.normalize()`).

Le cœur ML (`features.py`, `ensemble.py`, `mitre.py`) ne change pas.

---

## 11. Configuration `.env`

Créer un fichier `.env` à la racine (non versionné — voir `.gitignore`) :

```dotenv
# Elasticsearch (optionnel — pour l'indexation des anomalies)
ES_HOST=https://localhost:9200
ES_USERNAME=elastic
ES_PASSWORD=changeme
ES_INDEX_PREFIX=ueba-anomalies

# Pipeline
UEBA_LOOKBACK_DAYS=7
UEBA_WINDOW_HOURS=1
UEBA_STEP_MINUTES=30
UEBA_MIN_OBSERVATIONS=5
```

Les valeurs sont lues par `src/ueba/infrastructure/config.py` via `python-dotenv`.

> **Sécurité :** ne jamais committer de credentials réels. Utiliser un gestionnaire de secrets
> (Vault, AWS Secrets Manager, Variables CI/CD) en production.

---

## 12. Structure du projet

```
ueba-portable/
├── src/ueba/
│   ├── adapters/          # Traducteurs SIEM → NormalizedEvent
│   │   ├── base.py        # Contrat SIEMAdapter + filtrage comptes machine
│   │   ├── wazuh.py       # Wazuh/Kibana CSV
│   │   ├── elastic.py     # Elastic ECS JSON
│   │   ├── splunk.py      # Splunk CIM CSV
│   │   ├── qradar.py      # QRadar JSON
│   │   └── registry.py    # get_adapter(source_name)
│   ├── domain/            # Cœur métier (SIEM-agnostique)
│   │   ├── schema.py      # NormalizedEvent (Pydantic)
│   │   ├── baseline.py    # UserBaseline, BaselineRepository, z-score robuste
│   │   ├── features.py    # UEBAFeatureExtractor (16 features, fenêtres glissantes)
│   │   ├── ensemble.py    # AnomalyEnsemble (IF + OCSVM + Autoencoder MLP)
│   │   └── mitre.py       # MitreMapper (heuristiques + signal SIEM + population)
│   ├── scoring/
│   │   └── rolling_baseline.py  # RollingBaselineEngine (baseline glissante N-day)
│   ├── infrastructure/    # I/O, config YAML/.env, logging structuré
│   ├── cli.py             # Entrée CLI `ueba run` / `ueba version`
│   └── pipeline.py        # Orchestration bout-en-bout
├── tests/
│   ├── unit/              # Tests unitaires (145 au total, couverture > 80 %)
│   └── integration/
│       ├── fixtures/
│       │   └── sample_logs.csv   # 103 événements synthétiques, 7 utilisateurs
│       └── test_password_spray_detection.py
├── notebooks/             # Exploration, analyse des features, visualisation
├── scripts/               # run_pipeline.py, generate_attack_scenarios.py
├── docs/                  # Architecture, data flow, couverture MITRE
├── .github/workflows/     # CI GitHub Actions (Python 3.10/3.11/3.12)
├── pyproject.toml         # Dépendances Poetry + config outils
└── .env.example           # Template de configuration (à copier en .env)
```

---

## 13. Contribuer

```bash
# Installer les dépendances de développement
poetry install --with dev

# Lancer les tests
poetry run pytest

# Linter et formatage
poetry run ruff check src/ tests/
poetry run black src/ tests/

# Type checking
poetry run mypy src/
```

Les pull requests doivent maintenir la couverture de tests > 80 % et passer tous les checks CI.

---

## 14. Licence

Ce projet est distribué sous licence **MIT**. Voir le fichier [`LICENSE`](LICENSE).

```
MIT License

Copyright (c) 2026 — PFE UEBA Portable

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```
