#!/usr/bin/env bash
# Enrichit les anomalies des 7 utilisateurs ciblés avec la cartographie MITRE ATT&CK.
# La campagne détectée est un password spraying -> T1110.003 (tactique Credential Access).
# Pré-requis : variables ES_HOST / ES_USERNAME / ES_PASSWORD (cf. ~/ueba-portable/.env)
set -euo pipefail
source "$(dirname "$0")/../../.env"

USERS='["a.amrani","l.idrissi","l.mus","y.ben","n.alam","s.ed","k.alaa"]'

curl -s -u "$ES_USERNAME:$ES_PASSWORD" \
  -X POST "$ES_HOST/ueba-anomalies-*/_update_by_query?refresh=true" \
  -H 'Content-Type: application/json' \
  -d "{
    \"query\": {\"terms\": {\"ueba.user.keyword\": $USERS}},
    \"script\": {\"source\": \"ctx._source.mitre_technique='T1110.003'; ctx._source.mitre_technique_name='Password Spraying'; ctx._source.mitre_tactic='Credential Access';\"}
  }"
echo
echo "Enrichissement MITRE terminé."
