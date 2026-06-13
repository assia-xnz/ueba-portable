#!/usr/bin/env bash
#
# Démonstration de bout en bout du pipeline UEBA pour la soutenance PFE.
# À lancer sur soc-server (VM1), où tournent Elasticsearch et Kibana.
#
#   1. Exporte les logs Wazuh des 30 dernières minutes depuis Elasticsearch
#   2. Lance la détection UEBA et indexe les anomalies dans Elasticsearch
#   3. Affiche les anomalies détectées
#   4. Donne l'URL du dashboard Kibana à ouvrir
#
# Usage : bash scripts/demo_soutenance.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source "$ROOT/.env"

MINUTES="${MINUTES:-30}"
MODEL_PATH="${MODEL_PATH:-$ROOT/models/ueba-model.joblib}"
RECENT_CSV="$ROOT/data/raw/recent_logs.csv"
ANOMALIES_JSON="$ROOT/data/processed/demo_anomalies.json"
KIBANA_URL="${KIBANA_URL:-http://localhost:5601/app/dashboards}"

echo "=================================================================="
echo " DÉMO UEBA — détection d'insider threats (password spraying)"
echo "=================================================================="

echo
echo "[1/4] Export des logs Wazuh des ${MINUTES} dernières minutes..."
python3 scripts/export_recent_logs.py --minutes "$MINUTES" --output "$RECENT_CSV"

echo
echo "[2/4] Détection UEBA + indexation Elasticsearch..."
if [[ ! -f "$MODEL_PATH" ]]; then
    echo "  ⚠ Modèle introuvable : $MODEL_PATH"
    echo "    Entraîner d'abord un modèle, par ex. :"
    echo "      ueba train --input data/raw/baseline.csv --save-model $MODEL_PATH --mode per-user"
    echo "    Puis relancer cette démo."
    exit 1
fi
ueba detect --input "$RECENT_CSV" --load-model "$MODEL_PATH" \
    --output "$ANOMALIES_JSON" --to-es

echo
echo "[3/4] Anomalies détectées :"
if command -v python3 >/dev/null && [[ -f "$ANOMALIES_JSON" ]]; then
    python3 - "$ANOMALIES_JSON" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
records = data if isinstance(data, list) else data.get("anomalies", [])
anom = [r for r in records if r.get("is_anomaly")]
print(f"  {len(anom)} fenêtres anormales")
for r in anom[:15]:
    print(f"    - {r.get('user'):<14} {r.get('window_start','')}  votes={r.get('vote_count')}")
if len(anom) > 15:
    print(f"    ... (+{len(anom) - 15} autres)")
PY
else
    echo "  (aucune sortie JSON)"
fi

echo
echo "[4/4] Ouvrir le dashboard Kibana :"
echo "  >>> ${KIBANA_URL}"
echo "      Dashboard : « UEBA — SOC Dashboard » (plage 11–21 mai 2026)"
echo "=================================================================="
