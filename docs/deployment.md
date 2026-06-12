# Guide de déploiement — UEBA Portable

Le principe directeur est celui de l'UEBA de production : **on apprend la
normalité sur une période propre, on fige le modèle, puis on détecte les
écarts sur des données live.** L'ajustement fin du compromis bruit/détection
se fait ensuite avec le retour des analystes, pas en amont.

---

## Option A — Exécution locale (dev / démonstration PFE)

```bash
git clone https://github.com/assia-xnz/ueba-portable.git
cd ueba-portable
poetry install
poetry run pytest            # valider que tout est vert

# Détection en une passe (apprentissage + scoring sur le même export)
poetry run ueba run tests/integration/fixtures/sample_logs.csv \
    --source wazuh --mode per-user --output anomalies.json
```

## Option B — Entraînement / évaluation sur Google Colab

Deux notebooks, ouvrables directement depuis GitHub :

| Notebook | Rôle | Lien Colab |
|----------|------|------------|
| `colab_training.ipynb` | Apprendre la baseline sur un dataset **normal** et sauvegarder le modèle | [ouvrir](https://colab.research.google.com/github/assia-xnz/ueba-portable/blob/main/notebooks/colab_training.ipynb) |
| `colab_evaluation.ipynb` | Tester le modèle sur un dataset **contenant les attaques** (Recall, Précision, F1, matrice de confusion) | [ouvrir](https://colab.research.google.com/github/assia-xnz/ueba-portable/blob/main/notebooks/colab_evaluation.ipynb) |

Aucun GPU requis — le pipeline tourne sur CPU.

---

## Workflow SOC en production (recommandé)

### 1. Apprendre la baseline (une fois) sur une période propre

```bash
poetry run ueba train --input baseline_normale.csv --mode per-user \
    --min-windows-per-user 30 --train-ratio 1.0 --svm-nu 0.05 \
    --save-model /opt/ueba/models/baseline.joblib
```

Le modèle apprend, **par utilisateur**, le comportement normal. `--train-ratio
1.0` apprend sur l'intégralité du jeu propre ; `--svm-nu 0.05` limite les faux
positifs (baseline censée être propre).

### 2. Détecter périodiquement sur les données live

```bash
poetry run ueba detect --input nouvelles_alertes.json \
    --load-model /opt/ueba/models/baseline.joblib \
    --output /opt/ueba/anomalies.json \
    --to-es
```

Le modèle est **figé** : il ne réapprend pas, il compare le live à la
normalité apprise. Le drapeau `--to-es` **indexe les anomalies dans
Elasticsearch** (visibles dans Kibana). Pour réapprendre (dérive de
comportement, nouveaux comptes), relancer `train`.

### 3. Automatiser (cron, horaire)

```cron
# /etc/cron.d/ueba — détection toutes les heures sur l'export Wazuh des dernières 24 h
0 * * * * soc  cd /opt/ueba && poetry run ueba detect \
    --input /var/ossec/exports/last24h.json \
    --load-model /opt/ueba/models/baseline.joblib \
    --output /opt/ueba/anomalies.json --to-es >> /var/log/ueba.log 2>&1
```

---

## Configuration Elasticsearch (`.env`)

`--to-es` lit la connexion depuis l'environnement, ou un fichier `.env` placé
dans le répertoire courant (jamais committé — il est dans `.gitignore`) :

```dotenv
ES_HOST=https://soc-server:9200
ES_USERNAME=elastic
ES_PASSWORD=VOTRE_MOT_DE_PASSE
ES_INDEX_PREFIX=ueba-anomalies
```

### Lecture directe depuis Elasticsearch (optionnel)

```python
from ueba.adapters.elasticsearch_api import ElasticsearchReader

reader = ElasticsearchReader.from_env()
records = reader.fetch(index="wazuh-alerts-*", hours=24)
```

---

## Architecture de déploiement

```
┌──────────────────────────────────────────────────────────────┐
│  Wazuh Manager → alerts.json → Filebeat → Elasticsearch      │
│  Export périodique (cron) en CSV / JSON natif Wazuh          │
└────────────────────────┬─────────────────────────────────────┘
                         │ CSV / JSON
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  ueba detect --load-model baseline.joblib --to-es            │
│  • Normalisation (WazuhAdapter)                              │
│  • Extraction features (baseline glissante)                  │
│  • Prédiction per-user (modèle figé) → verdicts             │
└────────────────────────┬─────────────────────────────────────┘
                         │ bulk index des anomalies
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  Elasticsearch / Kibana                                      │
│  Index : ueba-anomalies-YYYY.MM.DD                           │
│  Dashboard : docs/kibana/ueba-dashboard.ndjson (importable)  │
└──────────────────────────────────────────────────────────────┘
```

## Index Elasticsearch

`ueba-anomalies-*` contient un document par fenêtre anomale, centré **verdict**
(de quoi trier l'alerte dans Kibana) :

```json
{
  "@timestamp": "2026-05-16T14:02:10Z",
  "ueba": {
    "user": "a.amrani",
    "window_start": "2026-05-16T14:02:10",
    "window_end": "2026-05-16T15:02:10",
    "is_anomaly": true,
    "mode": "per-user",
    "used_model": "a.amrani",
    "vote_count": 3,
    "votes": {"isolation_forest": true, "one_class_svm": true, "autoencoder": true}
  }
}
```

Prioriser dans Kibana les alertes à `vote_count = 3` (les trois modèles
d'accord = plus haute confiance).

## Considérations de sécurité

- Ne jamais committer le fichier `.env` (credentials) dans le dépôt git.
- En CI, utiliser des secrets (GitHub Secrets) pour le mot de passe Elasticsearch.
- En production, préférer une authentification par clé API Elasticsearch.
- Les modèles joblib contiennent du code sérialisé : ne charger que des
  modèles de sources de confiance.
```
