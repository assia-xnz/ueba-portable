# Audit du projet UEBA Portable — niveau ingénieur SOC

> Audit réalisé en juin 2026 sur la branche `main`. Quatre revues indépendantes
> (sécurité, méthodologie de détection, maturité opérationnelle, qualité de code
> & tests), recoupées et vérifiées sur le code. Chaque constat porte un
> identifiant, une sévérité, l'emplacement et une recommandation.

## Verdict global

**Excellent prototype de PFE sur une base de code saine — pas encore « niveau SOC »
sur deux plans : la rigueur de validation des résultats et la maturité
d'exploitation en production.** Le cœur ML (features robustes, ensemble, baseline
glissante sans fuite temporelle) et l'ingénierie logicielle (mypy strict, lint,
211 tests) sont d'un bon niveau. Les faiblesses sont concentrées sur la frontière
I/O / exploitation et sur le reporting des métriques.

| Dimension | Note | Synthèse |
|---|---|---|
| Qualité code & tests | B+ (4/5) | mypy strict ✓, ruff/black ✓, 211 tests ✓ ; couverture 97 % flattée par `omit`. |
| Sécurité | 3/5 | Rien n'a fuité en git, requêtes ES sûres ; mais HTTP en clair, superuser ES, pickle non vérifié. |
| Méthodologie / science | 2,5/5 | Détection sans fuite temporelle ✓ ; mais métriques publiées biaisées et non reproductibles. |
| Maturité opérationnelle | 2/5 | Pas d'ILM, pas d'alerting, indexation non idempotente, logging non branché. |

---

## A. Méthodologie & rigueur scientifique

| ID | Sév. | Emplacement | Constat | Recommandation |
|----|------|-------------|---------|----------------|
| A1 | CRITIQUE | `scripts/calculate_mttd.py:36,234` | MTTD calculé avec **une seule** `ATTACK_START` (13 mai) alors que l'attaque a eu lieu les **13 ET 16 mai**. Le « 14.9 min » mélange les vagues → non interprétable. | Modéliser chaque vague (`dict` user→date par campagne), MTTD par vague puis agrégat. |
| A2 | CRITIQUE | `pipeline.py:184-198` ; README §8 | Mode `run` : `fit` sur 80 % mais `predict` sur **tous** les vecteurs (train inclus) ; l'attaque du 13 mai contamine probablement la baseline « normale ». Recall/FP optimistes et non reproductibles. | Protocole train/test physiquement séparé (train = période propre hors 13/16 mai). Ne pas dériver de chiffres depuis `run`. |
| A3 | ÉLEVÉ | `scoring/risk.py:90-112` ; `enrich_risk_levels.py:86-97` | `risk_score` **non reproductible** (intensité normalisée par le `max` du lot → dépend des autres users/du périmètre) et **circulaire** (consensus + densité = même signal ML). CRITIQUE inatteignable par le ML seul. | Intensité **absolue** (seuil fixe) + facteur **contextuel indépendant** (criticité MITRE, privilège compte). Revoir poids/seuils. |
| A4 | ÉLEVÉ | README.md:333 | « Recall 100 % » présenté à côté d'un **FP 31,6 %** sans discussion (≈1 fenêtre/3 en faux positif). | Rapporter Precision / Recall / F1 / taux d'alerte ; ventiler le FP (default-deny vs autoencodeur). |
| A5 | ÉLEVÉ | `generate_attack_scenarios.py:20` ; `test_password_spray_detection.py:25` ; `calculate_mttd.py:34` | **3 jeux users/dates incohérents** (1ᵉʳ juin / 16 mai / 13 mai) présentés comme une validation unique. Chiffres README non régénérables. | Un jeu de validation **canonique unique**, régénérable par commande documentée. |
| B2 | MOYEN | `domain/baseline.py:88-91` | `robust_z` renvoie `±10` en dur quand MAD=0 (mélange petite/grande déviation). | Documenter/justifier ou winsorizing explicite. |
| B3 | MOYEN | `domain/mitre.py:46-59` | Seuils heuristiques calibrés sur le **même** export que la validation (sur-apprentissage des seuils). | Calibrer sur set distinct + analyse de sensibilité. |
| B4 | MOYEN | `domain/mitre.py:58-59,257-265` | T1110.003 collectif : seuils larges (≥3 users, ≥2 échecs, fenêtre 30 min), `src_ip` ignoré → faux positifs collectifs bénins possibles. | Contrainte « même IP source » + test négatif. |
| B5 | FAIBLE | `domain/baseline.py:61` | `is_reliable` codé en dur à `>=2` obs, ignore `min_observations` (défaut 5). | Faire dépendre de `min_observations`. |

**Points solides :** baseline glissante strictement sur le passé (`rolling_baseline.py:128`, pas de fuite de futur) ; split chronologique à l'entraînement ; stats robustes médiane/MAD ; `random_state=42` partout.

---

## B. Maturité opérationnelle SOC

| ID | Sév. | Emplacement | Constat | Recommandation |
|----|------|-------------|---------|----------------|
| SOC-01 | CRITIQUE | `elastic_writer.py:93,173` | Aucune ILM / rétention / rollover ; index créés à la volée → saturation du cluster. | ILM policy (hot/delete 30-90 j) + index template, ou data stream. |
| SOC-04 | CRITIQUE | tout le dépôt | Aucune notification (email/Slack/SOAR/Kibana alerting) ; le SOC n'est jamais poussé l'alerte. | Kibana Alerting sur `risk_level:CRITIQUE` → connecteur, ou webhook dans `continuous_detect.sh`. |
| SOC-09 | ÉLEVÉ | `elastic_writer.py:178` | Indexation sans `_id` déterministe + recouvrement de 5 min → **doublons** faussant KPIs/MTTD. | `_id = <user>_<window_start>` (upsert idempotent). |
| SOC-02 | ÉLEVÉ | `enrich_risk_levels.py:121` | Mapping 100 % dynamique → `risk_level` en `text` ; typage dépend du 1ᵉʳ doc. | Index template explicite (keyword/numérique/date). |
| SOC-03 | ÉLEVÉ | `elastic_writer.py:195` vs dashboards | Schéma incohérent : writer indexe sous `ueba.*`, dashboards lisent tantôt `ueba.user.keyword` tantôt `user`. | Schéma unique (ECS-like) appliqué partout. |
| SOC-06 | MOYEN | `cli.py:330` ; `scoring/risk.py` | `RiskScorer` jamais branché au flux live ; appelé seulement par un script manuel sur 7 users codés en dur. | Calculer risk_score/risk_level/recommended_action à l'indexation. |
| SOC-07 | ÉLEVÉ | `continuous_detect.sh:40` ; scripts | Pas de dégradation gracieuse si ES down (traceback, pas de retry) ; export vide non distingué. | Retry/backoff ; distinguer transitoire (retry) vs fatal. |
| SOC-10 | ÉLEVÉ | `ueba-detect.service/.timer` | Détecteur non surveillé : pas d'`OnFailure`, pas de heartbeat/dead-man-switch. | `OnFailure=` + heartbeat (`ueba-heartbeat`) + alerte sur absence. |
| SOC-11 | ÉLEVÉ | `infrastructure/logging.py` | Module logging fourni mais **jamais appelé** ; 28 `print()` en CLI/scripts. | Brancher `configure_logging` ; émettre métriques par cycle. |
| SOC-12 | ÉLEVÉ | dashboards | Data view `ueba-alerts` (champs `score_cas2`,`n_low`) sans **producteur dans le repo** → vide sur déploiement neuf. | Aligner sur le schéma réellement produit, ou fournir le producteur. |
| SOC-13 | ÉLEVÉ | `models/.gitkeep` ; scripts | Orchestration manuelle, ordre implicite ; `TARGET_USERS`/`ATTACK_START` codés en dur ; pas de Makefile. | Makefile (`setup-es/train/detect/enrich`) ; sortir users/dates en config. |
| SOC-14 | ÉLEVÉ | racine ; `ci.yml:39` | Pas de `poetry.lock` → builds non reproductibles, cache CI cassé. | Committer `poetry.lock`. |
| SOC-15 | MOYEN | scripts `es_*` | Appels ES sans try/except → traceback brut (vs `elastic_writer` propre). | Client ES partagé avec gestion d'erreurs. |
| SOC-16 | MOYEN | `demo_soutenance.sh:17` ; `enrich_mitre.sh:6` | `source .env` sans garde ; exécution shell de `.env`. | Garde d'existence ; charger via loader Python. |
| SOC-18 | MOYEN | `.github/workflows/ci.yml` | CI = qualité seulement ; pas de test d'intégration ES, pas de scan secrets/deps. | Job d'intégration ES (docker), gitleaks, pip-audit. |

**Note de maturité opérationnelle : 2/5.**

---

## C. Sécurité

| ID | Sév. | Emplacement | Constat | Recommandation |
|----|------|-------------|---------|----------------|
| SEC-01 | MOYEN | `.env` (disque) | `.env` en `0664` (lisible groupe) avec mot de passe réel. | `chmod 600 .env` ; rotationner le secret. |
| SEC-02 | ÉLEVÉ (SOC) | `.env` + scripts `es_auth` | Défaut `http://localhost:9200` → Basic Auth en base64 sans TLS. | HTTPS partout. |
| SEC-03 | MOYEN | `elastic_writer.py:207` | `ElasticWriter` sans `SSLContext` (contrairement au reader). | Aligner sur `ElasticsearchReader` (verify_ssl + contexte). |
| SEC-04 | MOYEN | `elasticsearch_api.py:54` | Superuser `elastic` au lieu d'API keys restreintes. | API key `read` sur `wazuh-*` + `write` sur `ueba-*`. |
| SEC-09 | MOYEN | `calculate_mttd.py:178` | `DELETE` d'index complet à chaque run, erreurs supprimées silencieusement. | IDs déterministes (upsert) au lieu de DELETE ; privilèges restreints. |
| SEC-11 | ÉLEVÉ (modèle non fiable) | `ensemble.py:264` ; `cli.py --load-model` | `joblib.load` = pickle → RCE si modèle non fiable. | Vérifier checksum/signature ; restreindre droits sur `models/`. |
| SEC-12 | FAIBLE | `pyproject.toml` | Plancher de versions large, pas de lockfile, pas de scan deps en CI. | `poetry.lock` + `pip-audit` en CI. |
| SEC-06/07/08 | FAIBLE | scripts ES | Requêtes ES sérialisées JSON (pas d'injection) ✓ ; nom d'index interpolé en URL ; CSV non neutralisé (formula injection Excel). | Allowlist d'index ; échappement CSV. |
| SEC-10 | FAIBLE (labo) | `simulate_attack.ps1` | Outil offensif réel, garde-fous **documentaires** seulement (pas de confirmation technique). | Acceptable PFE ; ajouter confirmation interactive + vérif domaine pour durcir. |

**Verdict sécurité :** sain pour un labo documenté (rien n'a fuité en git, requêtes ES sûres), à durcir avant tout déploiement réel (HTTPS+TLS, API keys, intégrité joblib).

---

## D. Qualité de code & tests

Outils (réels) : **211 tests ✓**, ruff `All checks passed`, mypy strict `0 erreur` (scope `src/ueba`), black conforme. Couverture **97 %** *mais sur périmètre amputé*.

| ID | Sév. | Emplacement | Constat | Recommandation |
|----|------|-------------|---------|----------------|
| C1 | ÉLEVÉ | `pyproject.toml:62-66` | `omit` exclut `infrastructure/*`, `cli.py`, `elasticsearch_api.py` (dont du code testé) → « 97 % » flatté. | Resserrer `omit` au niveau **ligne** (pragma) sur le réseau seul. |
| C2 | ÉLEVÉ | `infrastructure/{config,io,logging}.py` | Code pur déterministe **sans aucun test** (parsing YAML/CSV, BOM Kibana). | Tests unitaires en `tmp_path` (triviaux, 0 dépendance). |
| C3 | ÉLEVÉ | `adapters/elasticsearch_api.py` | Composant ES **non testé** ET **code mort** (importé nulle part). | Brancher + tester, ou supprimer. |
| C4 | MOYEN | `cli.py` | Routage CLI quasi non testé ; « covered by integration » non vérifié. | Test bout-en-bout `cli.main([...])`. |
| S1 | ÉLEVÉ | `calculate_mttd.py`, `enrich_risk_levels.py`, `export_recent_logs.py`, `cli.py` | **4 implémentations** de `load_dotenv`/`es_auth`, **divergence http/https**. | Helper unique partagé et testé. |
| S2 | MOYEN | `pyproject.toml:52` | Scripts hors mypy et hors pytest, alors qu'ils écrivent dans ES. | `files=["src/ueba","scripts"]` ; tester fonctions pures. |
| S3 | MOYEN | `calculate_mttd.py:179` | `DELETE` non idempotent, `URLError` non géré. | Upsert par IDs déterministes. |
| E1 | MOYEN | `cli.py:189` | `except Exception` trop large pour la version. | Cibler `PackageNotFoundError`. |
| E2 | FAIBLE | `calculate_mttd.py:102` | Docs malformés ignorés **silencieusement**. | Logguer le nombre de docs écartés. |
| G2 | MOYEN | `cli.py`, scripts | `print()` partout malgré un module logging dédié inutilisé. | Brancher le logging. |
| G4 | FAIBLE | `run_pipeline.py:82` | Liste des 16 features recopiée à la main au lieu d'importer `FEATURE_NAMES`. | Importer `FEATURE_NAMES`. |
| M1/M2 | FAIBLE | `tests/unit/test_mttd.py:143` ; `mttd.py:121` | `try/except` manuel au lieu de `pytest.raises` ; départage de fenêtres égales non déterministe. | Uniformiser ; départager sur `window_end`. |

**Modules exemplaires :** `scoring/risk.py` et `metrics/mttd.py` (typage, docstrings, validation défensive, cas limites — 100 % couverts).

---

## Feuille de route de remédiation (priorisée)

**Phase 1 — Méthodo & reporting (soutenance) :** A1 MTTD par vague · A2 protocole sans fuite + doc · A4 module Precision/Recall/F1 + reporting · A5 jeu canonique · A3 risk_score absolu+contextuel.

**Phase 2 — Exploitation SOC (production) :** SOC-01 ILM+templates · SOC-09 idempotence · SOC-06 RiskScorer live + recommended_action · SOC-04 notification/alerting · SOC-07 robustesse ES · SOC-10 monitoring · SOC-11 logging branché.

**Phase 3 — Sécurité :** SEC-02/03/04 HTTPS+TLS+API keys · SEC-11 intégrité joblib · SEC-09 upsert ciblé · SEC-01 droits.

**Phase 4 — Qualité & dette :** C1/C2/C3 couverture honnête + tests + code mort · S1 client ES partagé · S2 mypy scripts · SOC-14 poetry.lock · SOC-13 Makefile.
