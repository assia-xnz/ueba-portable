# Guide de déploiement — UEBA Portable

## Option A — Exécution locale (dev / démonstration PFE)

```bash
git clone https://github.com/YOUR_ORG/ueba-portable.git
cd ueba-portable
poetry install
poetry run pytest            # valider que tout est vert
poetry run ueba run tests/integration/fixtures/sample_logs.csv \
    --source wazuh --output anomalies.json
```

## Option B — Entraînement sur Google Colab

1. Ouvrir `notebooks/colab_training.ipynb` dans Google Colab
2. Remplacer `YOUR_ORG` par l'organisation GitHub du dépôt
3. Exécuter toutes les cellules dans l'ordre
4. Le modèle est sauvegardé dans Google Drive (`/MyDrive/ueba_models/ensemble.joblib`)

### Accéder au notebook Colab

[![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/YOUR_ORG/ueba-portable/blob/master/notebooks/colab_training.ipynb)

### Prérequis Colab

- Compte Google (Drive pour la persistance)
- Python 3.10+ (disponible par défaut sur Colab)
- Aucun GPU requis — le pipeline ML UEBA tourne sur CPU en quelques secondes

## Option C — Intégration Elasticsearch

### Configuration `.env`

```dotenv
ES_HOST=https://your-elastic-cluster:9200
ES_USERNAME=elastic
ES_PASSWORD=YOUR_PASSWORD
ES_INDEX_PREFIX=ueba-anomalies
```

### Indexation des anomalies détectées

```python
from ueba.infrastructure.elastic_writer import ElasticWriter

writer = ElasticWriter.from_env()
n = writer.bulk_index(anomaly_vectors, mitre_matches)
print(f"{n} documents indexés dans ueba-anomalies-{today}")
```

### Lecture directe depuis Elasticsearch

```python
from ueba.adapters.elasticsearch_api import ElasticsearchReader

reader = ElasticsearchReader.from_env()
records = reader.fetch(index="wazuh-alerts-*", hours=24)
```

## Option D — Persistance du modèle

Le modèle entraîné peut être sauvegardé et rechargé avec joblib :

```python
# Entraînement + sauvegarde
ensemble.fit(X_train)
ensemble.save("models/ensemble.joblib")

# Rechargement en production
from ueba.domain.ensemble import AnomalyEnsemble
ensemble = AnomalyEnsemble.load("models/ensemble.joblib")
verdicts = ensemble.predict(X_new)
```

## Architecture de déploiement recommandée

```
┌──────────────────────────────────────────────────────────────┐
│  SIEM (Wazuh / Elastic / Splunk / QRadar)                    │
│  Export périodique (cron, webhook, ou lecteur direct ES API) │
└────────────────────────┬─────────────────────────────────────┘
                         │ CSV / JSON
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  Pipeline UEBA (scripts/run_pipeline.py)                     │
│  • Normalisation (adapter)                                   │
│  • Rolling baseline + extraction features                    │
│  • Prédiction ensemble (modèle rechargé)                     │
│  • Mapping MITRE ATT&CK                                      │
└────────────────────────┬─────────────────────────────────────┘
                         │ anomalies.json + bulk index
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  Elasticsearch / Kibana                                      │
│  Index : ueba-anomalies-YYYY.MM.DD                           │
│  Dashboard : docs/kibana/ueba-dashboard.ndjson (importable)  │
└──────────────────────────────────────────────────────────────┘
```

## Index Elasticsearch

L'index `ueba-anomalies-*` contient un document par `(utilisateur, fenêtre)` anomale :

```json
{
  "@timestamp": "2026-05-16T14:02:10Z",
  "ueba": {
    "user": "alice.martin",
    "window_start": "2026-05-16T14:02:10",
    "window_end": "2026-05-16T15:02:10",
    "features": {
      "login_count": 4.0,
      "failed_login_count": 4.0,
      "failed_login_ratio": 0.5,
      ...
    },
    "mitre": [
      {
        "technique_id": "T1110.003",
        "technique_name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "rationale": "7 comptes distincts ...",
        "source": "heuristic"
      }
    ]
  }
}
```

## Considérations de sécurité

- Ne jamais committer les credentials `.env` dans le dépôt git
- Utiliser les Variables CI/CD (GitHub Secrets) pour le mot de passe Elasticsearch en CI
- En production, préférer une authentification par clé API Elasticsearch plutôt que mot de passe
- Les modèles joblib contiennent du code sérialisé : ne charger que des modèles de sources de confiance
