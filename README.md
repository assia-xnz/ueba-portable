# UEBA Portable — Détection d'anomalies comportementales pour la chasse aux menaces

> Projet de Fin d'Études — ENSA Tanger, filière Génie des Systèmes de Télécommunications et
> Réseaux (5ème année), réalisé chez Cires Technologies (filiale Tanger Med Group).
>
> **Titre :** Conception et implémentation d'un système UEBA portable pour la chasse aux
> menaces, basé sur l'apprentissage automatique non supervisé, intégré à un SIEM et mappé
> au framework MITRE ATT&CK.

## Statut

🚧 Documentation complète (architecture, mapping SIEM, features, validation, MITRE ATT&CK)
à venir en fin de développement — voir `docs/`.

## Aperçu rapide

Ce dépôt contient un pipeline UEBA (User and Entity Behavior Analytics) conçu pour être
**portable entre SIEMs** : une couche d'adapters découple le format source (Wazuh, Elastic
ECS, Splunk, QRadar) d'un cœur d'apprentissage automatique non supervisé indépendant de
toute source de données.

```
src/ueba/
├── adapters/        # Traduction SIEM → schéma normalisé (Wazuh, Elastic, Splunk, QRadar)
├── domain/          # Cœur ML : features, baselines robustes, ensemble, mapping MITRE
├── infrastructure/  # I/O, configuration YAML, logging structuré
├── pipeline.py      # Orchestration bout-en-bout
└── cli.py           # Interface en ligne de commande
```

## Installation

```bash
poetry install
```

## Quickstart

```bash
poetry run ueba --siem wazuh --input data/raw/wazuh-export.csv --config config/pipeline.yaml
```

---

*La documentation complète (contexte, architecture détaillée, 16 features, réduction des
faux positifs, validation, mapping MITRE ATT&CK) sera ajoutée en phase de finalisation.*
