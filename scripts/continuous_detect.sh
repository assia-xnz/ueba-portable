#!/usr/bin/env bash
#
# Surveillance continue UEBA — exécuté toutes les 30 minutes (cron ou systemd timer).
# Exporte les logs Wazuh récents, lance la détection et indexe les anomalies dans
# Elasticsearch. Toutes les sorties sont horodatées et journalisées.
#
# Variables d'environnement honorées (sinon valeurs par défaut) :
#   UEBA_HOME   racine du dépôt           (défaut : dossier parent du script)
#   MODEL_PATH  modèle .joblib à charger  (défaut : $UEBA_HOME/models/ueba-model.joblib)
#   WINDOW_MIN  fenêtre d'export en min   (défaut : 35, léger recouvrement des 30 min)
#   LOG_FILE    fichier de log            (défaut : /var/log/ueba/detect.log)
set -euo pipefail

UEBA_HOME="${UEBA_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
MODEL_PATH="${MODEL_PATH:-$UEBA_HOME/models/ueba-model.joblib}"
WINDOW_MIN="${WINDOW_MIN:-35}"
LOG_FILE="${LOG_FILE:-/var/log/ueba/detect.log}"
RECENT_CSV="$UEBA_HOME/data/raw/continuous_recent.csv"
ANOMALIES_JSON="$UEBA_HOME/data/processed/continuous_anomalies.json"

# Crée le répertoire de log ; repli sur un log local si /var/log/ueba n'est pas accessible.
if ! mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null; then
    LOG_FILE="$UEBA_HOME/data/processed/detect.log"
    mkdir -p "$(dirname "$LOG_FILE")"
fi

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

cd "$UEBA_HOME"
# shellcheck disable=SC1091
[[ -f "$UEBA_HOME/.env" ]] && source "$UEBA_HOME/.env"

log "=== Cycle de détection continue (fenêtre ${WINDOW_MIN} min) ==="

if [[ ! -f "$MODEL_PATH" ]]; then
    log "ERREUR : modèle introuvable ($MODEL_PATH) — entraîner via 'ueba train' d'abord."
    exit 1
fi

log "Export des logs Wazuh récents..."
python3 scripts/export_recent_logs.py --minutes "$WINDOW_MIN" --output "$RECENT_CSV" \
    >>"$LOG_FILE" 2>&1

log "Détection UEBA + indexation Elasticsearch..."
if ueba detect --input "$RECENT_CSV" --load-model "$MODEL_PATH" \
    --output "$ANOMALIES_JSON" --to-es >>"$LOG_FILE" 2>&1; then
    log "Détection terminée avec succès."
else
    log "ERREUR : la détection a échoué (voir le log ci-dessus)."
    exit 1
fi

# Notification des alertes CRITIQUE (best-effort, n'échoue pas le cycle).
log "Notification des alertes CRITIQUE..."
python3 scripts/notify_critical.py --minutes "$WINDOW_MIN" >>"$LOG_FILE" 2>&1 \
    || log "AVERTISSEMENT : notification indisponible (cycle poursuivi)."

# Heartbeat + métrique de cycle dans ES (surveillance du détecteur lui-même, SOC-10/11).
python3 - "$WINDOW_MIN" >>"$LOG_FILE" 2>&1 <<'PY' || log "AVERTISSEMENT : heartbeat non indexé."
import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "src"))
from datetime import datetime, timezone
from ueba.infrastructure.es_client import ESClient, load_dotenv
load_dotenv(Path.cwd() / ".env")
client = ESClient.from_env()
now = datetime.now(tz=timezone.utc).isoformat()
client.bulk([
    '{"index": {"_index": "ueba-heartbeat"}}',
    f'{{"@timestamp": "{now}", "status": "ok", "window_minutes": {int(sys.argv[1])}}}',
], refresh=True)
print("[*] Heartbeat indexé dans ueba-heartbeat")
PY

log "Cycle terminé avec succès."
