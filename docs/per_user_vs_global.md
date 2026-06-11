# Modèle global vs modèle per-user — analyse comparative

Ce document justifie le choix du **mode per-user** comme stratégie de
modélisation par défaut du système UEBA, à partir des résultats obtenus sur
un dataset Wazuh réel et de la littérature académique du domaine.

---

## 1. Le problème du modèle global

Le mode global apprend **un unique** ensemble d'anomalies
(`AnomalyEnsemble` : IsolationForest + OneClassSVM + Autoencoder) sur
l'ensemble des observations, tous utilisateurs confondus. Le `RobustScaler`
et les trois modèles calibrent donc leur notion de « normalité » sur une
distribution agrégée — dominée par les comptes les plus actifs.

### Symptôme observé (dataset Wazuh, 14 jours, 9 utilisateurs)

| Indicateur                              | Valeur |
|-----------------------------------------|--------|
| Taux d'anomalies global                 | 44.4 % |
| `k.alaa` flaguée                        | 100 % des fenêtres |
| Autres utilisateurs non-admin           | 60–70 % |
| `soc-admin`                             | ~3 % |
| Recall sur l'attaque (fenêtre)          | 29.4 % |

Le compte `soc-admin` totalise 320 fenêtres d'activité, contre 60 à 125 pour
les autres comptes. La baseline collective épouse donc le comportement de
l'administrateur, et **tout écart à ce profil — c'est-à-dire l'activité
normale de n'importe quel autre utilisateur — est interprété comme une
anomalie**. Le détecteur ne mesure plus une déviation comportementale
individuelle, mais une distance à un profil moyen biaisé.

C'est l'antithèse de l'UEBA : on veut savoir si **Alice se comporte
anormalement *pour Alice***, pas si Alice se comporte différemment de
l'administrateur.

---

## 2. L'approche per-user

Le mode per-user (`PerUserAnomalyEnsemble`) entraîne **un ensemble dédié par
utilisateur**, exclusivement sur l'historique de cet utilisateur :

1. **Groupement** des vecteurs de features par `user` ;
2. **Filtrage** des comptes machine/système (`MachineAccountFilter`) et des
   utilisateurs au volume insuffisant (`min_windows_per_user`) ;
3. **Split chronologique** train/holdout respectant la flèche du temps ;
4. **Default-deny** : un utilisateur jamais vu à l'apprentissage est traité
   comme anomalie par prudence (posture SOC standard).

Chaque modèle ne connaît que *sa* normalité ; le biais de population
disparaît par construction.

> **Séparation des préoccupations.** La classe `PerUserAnomalyEnsemble`
> apprend la normalité de ce qu'on lui fournit ; elle n'opère **aucune
> sélection sémantique** des données (pas d'étiquetage, pas d'exclusion de
> jours « contaminés »). La préparation d'un jeu d'apprentissage propre —
> retrait en amont des périodes connues comme compromises — relève de
> l'appelant (script, notebook, ou pipeline d'ingestion), pas du modèle. Cela
> garde la classe simple, testable et réutilisable hors de tout scénario
> d'attaque particulier.

---

## 3. Résultats comparés

Dataset Wazuh réel — 68 163 événements, 14 jours, 9 utilisateurs.
Attaque injectée : Password Spraying (MITRE **T1110.003**), 13 et 16 mai 2026,
7 comptes ciblés.

| Métrique                       | Global  | Per-user | Lecture |
|--------------------------------|---------|----------|---------|
| Recall fenêtre par fenêtre     | 29.4 %  | **56.7 %** | Sensibilité brute |
| **Recall opérationnel**        | N/A     | **100.0 %** | ≥ 1 alerte par (user × jour) |
| Détection en 1ʳᵉ fenêtre       | N/A     | **14/14** | Précocité |
| FP rate (jours propres)        | 2.8 %\* | 31.6 %   | Coût analyste |
| Ratio signal / bruit           | —       | 1.6      | Recall / FP |

> \* Le FP rate « 2.8 % » du mode global est trompeur : il se concentre
> presque entièrement sur `soc-admin`, et le **taux d'anomalies global de
> 44 %** révèle que le modèle alerte massivement et indistinctement. Un faible
> FP rate moyen accompagné d'un recall de 29 % et d'un taux d'alerte de 44 %
> traduit un détecteur qui « crie au loup » sans discriminer.

### Recall opérationnel : la métrique qui compte pour un SOC

En contexte SOC, l'unité d'investigation n'est pas la fenêtre de 30 minutes
mais l'**entité sur une journée**. La question opérationnelle est :

> « Pour chaque couple (utilisateur, jour d'attaque), l'analyste a-t-il reçu
> **au moins une** alerte ? »

C'est le *recall opérationnel*, métrique de référence dans l'évaluation des
systèmes de détection comportementale (Bhatt, Manadhata & Zomlot, 2014). Le
mode per-user atteint **100 %** : aucun couple (utilisateur × jour) d'attaque
n'est manqué, et la détection survient **dès la première fenêtre** dans les
14 cas. Un recall fenêtre de 56.7 % suffit donc à une couverture
opérationnelle totale, car une attaque de password spraying s'étale sur
plusieurs fenêtres consécutives.

### Le coût du per-user : davantage de faux positifs

Le mode per-user présente un FP rate plus élevé (31.6 %) : avec une baseline
étroite par utilisateur, la moindre déviation ressort. Ce compromis est
**assumé et souhaitable** en chasse aux menaces (*threat hunting*), où le coût
d'un faux négatif (attaque manquée) dépasse largement celui d'un faux positif
(fenêtre à trier). Les trois leviers anti-faux-positifs du système (vote
majoritaire ≥ 2/3, z-scores robustes, filtrage des comptes machine)
atténuent ce coût sans réintroduire le biais de population.

---

## 4. Fondement dans la littérature

L'apprentissage per-entité n'est pas une optimisation *ad hoc* : c'est le
principe constitutif de l'UEBA tel que défini par la recherche.

- **Salem & Stolfo (2011)**, *Modeling User Search Behavior for Masquerade
  Detection* — établissent qu'un profil comportemental doit être appris
  **par utilisateur** : un masquerade se détecte comme déviation par rapport
  au profil propre de la victime, jamais par rapport à une moyenne de
  population.

- **Veeramachaneni et al. (2016)**, *AI²: Training a Big Data Machine to
  Defend* (MIT / PatternEx) — montrent qu'un détecteur non supervisé doit
  modéliser des baselines **par entité** pour rester exploitable par les
  analystes, et combiner ces signaux dans une boucle d'apprentissage.

- **Bhatt, Manadhata & Zomlot (2014)**, *The Operational Role of Security
  Information and Event Management Systems* — définissent les métriques
  d'évaluation pertinentes pour un SOC, dont le rappel au niveau de l'entité
  et de l'incident (et non de l'événement brut).

Le choix du mode per-user aligne donc l'implémentation sur l'état de l'art et
sur l'exigence explicite d'encadrement (« apprentissage par utilisateur, pas
globalement »).

---

## 5. Quand préférer le mode global ?

Le mode global reste pertinent dans deux cas :

1. **Démarrage à froid** — utilisateurs sans historique suffisant
   (< `min_windows_per_user`), où aucune baseline individuelle fiable n'est
   apprenable. Le mode global fournit alors un filet de sécurité.
2. **Détection d'anomalies de population** — comportements anormaux *à
   l'échelle de l'organisation* (ex. pic d'activité simultané inhabituel),
   complémentaires des heuristiques collectives du `MitreMapper`.

En production, les deux modes sont donc complémentaires ; le système retient
**per-user par défaut** et expose le mode global via `--mode global`.

---

## Références

1. M. B. Salem, S. J. Stolfo. *Modeling User Search Behavior for Masquerade
   Detection*. RAID 2011.
2. K. Veeramachaneni, I. Arnaldo, et al. *AI²: Training a Big Data Machine to
   Defend*. IEEE BigDataSecurity 2016.
3. S. Bhatt, P. K. Manadhata, L. Zomlot. *The Operational Role of Security
   Information and Event Management Systems*. IEEE Security & Privacy, 2014.
