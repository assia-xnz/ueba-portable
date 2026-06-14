# Orchestration UEBA Portable — cibles reproductibles pour dev et exploitation.
# Usage : make <cible>. `make help` liste les cibles.

PYTHON ?= python3
MODEL  ?= models/ueba-model.joblib
BASELINE ?= data/raw/baseline.csv
INPUT    ?= data/raw/recent_logs.csv
# Seuil de fenêtres pour qu'un utilisateur obtienne un modèle dédié. 10 est requis
# pour le recall 100% avec --no-default-deny (les entités sous-représentées comme
# k.alaa doivent obtenir un modèle plutôt que de passer inaperçues). Cf. docs/AUDIT.md.
MIN_WINDOWS ?= 10
PERSISTENCE ?= 2

.PHONY: help install test lint format type check setup-es train detect enrich mttd entities precision notify dashboards demo all-quality

help:  ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:  ## Installe les dépendances (poetry)
	poetry install

test:  ## Lance la suite de tests + couverture
	$(PYTHON) -m pytest

lint:  ## Ruff
	$(PYTHON) -m ruff check src tests scripts

format:  ## Black (vérification)
	$(PYTHON) -m black --check src tests scripts

type:  ## Mypy strict (src/ueba)
	$(PYTHON) -m mypy

check: lint format type test  ## Tous les contrôles qualité

# ── Exploitation SOC ─────────────────────────────────────────────────────────
setup-es:  ## Provisionne ES (politique ILM + index templates)
	$(PYTHON) scripts/setup_es.py

train:  ## Entraîne le modèle per-user (config anti-FP validée : no-default-deny, min_windows=10)
	poetry run ueba train --input $(BASELINE) --mode per-user --train-ratio 1.0 \
		--min-windows-per-user $(MIN_WINDOWS) --save-model $(MODEL)
	$(PYTHON) -c "from ueba.infrastructure.integrity import write_checksum; \
		print('checksum ->', write_checksum('$(MODEL)'))"

detect:  ## Détecte sur des logs récents et indexe dans ES (INPUT=..., persistance anti-FP)
	poetry run ueba detect --input $(INPUT) --load-model $(MODEL) \
		--persistence $(PERSISTENCE) --to-es

enrich:  ## Enrichit les anomalies (MITRE + risk_score/level)
	bash docs/kibana/enrich_mitre.sh
	$(PYTHON) scripts/enrich_risk_levels.py

mttd:  ## Calcule le MTTD par vague et indexe ueba-mttd
	$(PYTHON) scripts/calculate_mttd.py

entities:  ## Agrège les anomalies par entité (user×jour) -> ueba-entity-alerts (précision)
	$(PYTHON) scripts/aggregate_entities.py

precision:  ## Mesure précision/recall fenêtre vs entité (sans fuite)
	$(PYTHON) scripts/evaluate_precision.py

notify:  ## Pousse les alertes CRITIQUE récentes vers le webhook (UEBA_WEBHOOK)
	$(PYTHON) scripts/notify_critical.py

dashboards:  ## (Ré)génère les ndjson des dashboards Kibana
	$(PYTHON) docs/kibana/generate_dashboard_v3.py

demo:  ## Démonstration bout-en-bout
	bash scripts/demo_soutenance.sh
