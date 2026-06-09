# Couverture MITRE ATT&CK — UEBA Portable

## Matrice de couverture

| Technique ID | Nom | Tactique | Source de détection | Features utilisées |
|---|---|---|---|---|
| **T1110** | Brute Force | Credential Access | Heuristique individuelle | `failed_login_count` > 5 |
| **T1110.003** | Brute Force: Password Spraying | Credential Access | Heuristique population | `failed_login_count` ≥ 2 sur ≥ 3 comptes simultanés |
| **T1078** | Valid Accounts | Defense Evasion | Heuristique individuelle combinée | `off_hours_ratio` > 0.5 ET `unique_hosts` > 2 |
| **T1078.003** | Valid Accounts: Local Accounts | Privilege Escalation | Heuristique individuelle | `priv_logon_count` > 3 |
| **T1558.003** | Steal or Forge Kerberos Tickets: Kerberoasting | Credential Access | Heuristique individuelle | `kerberos_count` > 5 |
| **T1059** | Command and Scripting Interpreter | Execution | Heuristique individuelle | `process_entropy` > 2.0 bits |
| **T1021** | Remote Services | Lateral Movement | Heuristique individuelle | `host_velocity` > 0.05 hôtes/min |
| **ANY** | Toute technique | Toute tactique | Signal natif SIEM (`rule.mitre.id`) | Champ transmis directement |

## Légende des sources de détection

| Source | Description |
|---|---|
| `heuristic` | Mapping interne basé sur les valeurs des 16 features |
| `siem_native` | Champ `rule.mitre.id` (Wazuh) / `threat.technique.id` (Elastic) fourni par la règle de corrélation SIEM |

Le signal `siem_native` est prioritaire (ajouté en tête de liste) et vient enrichir —
sans remplacer — le mapping heuristique.

## Seuils heuristiques

Les seuils suivants sont calibrés empiriquement sur la fixture de validation :

```python
FAILED_LOGIN_COUNT_THRESHOLD    = 5.0   # T1110
PRIV_LOGON_COUNT_THRESHOLD      = 3.0   # T1078.003
KERBEROS_COUNT_THRESHOLD        = 5.0   # T1558.003
PROCESS_ENTROPY_THRESHOLD       = 2.0   # T1059  (bits)
OFF_HOURS_RATIO_THRESHOLD       = 0.5   # T1078 (combiné)
UNIQUE_HOSTS_THRESHOLD          = 2.0   # T1078 (combiné)
HOST_VELOCITY_THRESHOLD         = 0.05  # T1021 (hôtes/min)

PASSWORD_SPRAY_MIN_USERS        = 3     # T1110.003 (population)
PASSWORD_SPRAY_MIN_FAILED_LOGINS= 2.0   # T1110.003 (par compte)
```

## Limites et extensions possibles

### Non couvert actuellement

| Technique | Raison | Extension possible |
|---|---|---|
| T1003 — OS Credential Dumping | Nécessite logs Sysmon (Event 10 / 8) | Adapter + feature `lsass_access_count` |
| T1070.001 — Clear Event Log | Nécessite Event 1102 | Feature `log_clear_count` |
| T1053 — Scheduled Task | Nécessite Event 4698 | Feature `scheduled_task_count` |
| T1547 — Boot Autostart | Nécessite logs registre | Feature `registry_run_count` |
| T1566 — Phishing | Hors périmètre logs Windows purs | Intégration logs email / proxy |

### Extension de la couverture

Pour ajouter une nouvelle technique :

1. Ajouter la feature correspondante dans `domain/features.py` (si non couverte)
2. Ajouter l'entrée dans `_INDIVIDUAL_HEURISTICS` ou créer une méthode dans `MitreMapper`
3. Mettre à jour ce document et le tableau dans `README.md`
4. Écrire un test d'intégration avec une fixture synthétique déclenchant la technique

## Validation par scénario

| Scénario | Technique | Statut |
|---|---|---|
| Password spray depuis IP externe (fixture sample_logs.csv) | T1110.003 | ✅ Validé (test intégration) |
| Connexion hors heures avec multi-hôtes | T1078 | Tests unitaires MitreMapper |
| Volume de tickets Kerberos anormal | T1558.003 | Tests unitaires MitreMapper |
| Pic de créations processus avec entropie élevée | T1059 | Tests unitaires MitreMapper |
| Brute force individuel | T1110 | Tests unitaires MitreMapper |
