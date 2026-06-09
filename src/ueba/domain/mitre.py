"""Mapping des anomalies comportementales vers le framework MITRE ATT&CK.

Ce module traduit les anomalies détectées par l'ensemble (`ensemble.py`) en
techniques MITRE ATT&CK exploitables par un analyste SOC, en s'appuyant sur
deux sources complémentaires :

1. **Heuristiques internes** fondées sur les valeurs des 16 features
   (cf. cahier des charges § 5.8) — ex. un `failed_login_count` élevé évoque
   un Brute Force (T1110), un `kerberos_count` élevé évoque un Kerberoasting
   (T1558.003), etc. ;
2. **Champs natifs du SIEM** (`rule.mitre.id` / `rule.mitre.tactic`), lorsque
   la règle de corrélation Wazuh a déjà identifié une technique : ce signal
   est alors prioritaire et vient enrichir — pas remplacer — le mapping
   heuristique, car il provient d'une source experte déjà validée.

Une attention particulière est portée à la **détection collective** : un
password spraying (T1110.003) ne se manifeste pas par un volume d'échecs
élevé chez un seul utilisateur (ce serait un simple brute force, T1110), mais
par des échecs *modérés et synchronisés* chez *plusieurs* comptes sur la même
fenêtre temporelle — d'où la nécessité d'une analyse au niveau de la
population, en plus de l'analyse par individu.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from ueba.domain.features import FeatureVector


def _window_bucket(dt: datetime, step_minutes: int = 30) -> tuple[int, int, int, int, int]:
    """Arrondit un horodatage au bas du bucket de `step_minutes` minutes.

    Utilisé par `match_population` pour regrouper les vecteurs de plusieurs
    utilisateurs dont les fenêtres glissantes démarrent à des secondes légèrement
    différentes (car calculées à partir du premier événement de chaque utilisateur),
    mais appartiennent conceptuellement à la même période temporelle.
    """
    bucketed_minute = (dt.minute // step_minutes) * step_minutes
    return (dt.year, dt.month, dt.day, dt.hour, bucketed_minute)


#: Seuils heuristiques au-delà desquels une feature est jugée « élevée ».
#: Calibrés empiriquement sur l'export de validation (14 jours, 9 utilisateurs).
FAILED_LOGIN_COUNT_THRESHOLD: float = 5.0
PRIV_LOGON_COUNT_THRESHOLD: float = 3.0
KERBEROS_COUNT_THRESHOLD: float = 5.0
PROCESS_ENTROPY_THRESHOLD: float = 2.0
OFF_HOURS_RATIO_THRESHOLD: float = 0.5
UNIQUE_HOSTS_THRESHOLD: float = 2.0
HOST_VELOCITY_THRESHOLD: float = 0.05

#: Nombre minimal de comptes distincts présentant des échecs de connexion sur
#: une même fenêtre temporelle pour évoquer un password spraying (T1110.003)
#: plutôt qu'un simple brute force individuel (T1110).
PASSWORD_SPRAY_MIN_USERS: int = 3
PASSWORD_SPRAY_MIN_FAILED_LOGINS: float = 2.0


@dataclass(frozen=True, slots=True)
class MitreMatch:
    """Correspondance entre une anomalie et une technique MITRE ATT&CK.

    Attributs
    ---------
    technique_id : str
        Identifiant de la technique (ex. "T1110.003").
    technique_name : str
        Nom lisible de la technique (ex. "Password Spraying").
    tactic : str
        Tactique ATT&CK associée (ex. "Credential Access").
    rationale : str
        Justification de la correspondance, fondée sur la ou les features
        ayant déclenché le mapping (utile pour la traçabilité en soutenance).
    source : str
        Origine de la correspondance : "heuristic" (mapping interne basé sur
        les features) ou "siem_native" (champ `rule.mitre.id` fourni par Wazuh).
    """

    technique_id: str
    technique_name: str
    tactic: str
    rationale: str
    source: str


# Table déclarative des heuristiques individuelles (par utilisateur × fenêtre).
# Chaque entrée associe un prédicat sur le FeatureVector à une technique MITRE.
_INDIVIDUAL_HEURISTICS: tuple[tuple[str, str, str, str, str], ...] = (
    # (technique_id, technique_name, tactic, feature_attr, rationale_template)
    (
        "T1110",
        "Brute Force",
        "Credential Access",
        "failed_login_count",
        "Nombre élevé d'échecs de connexion ({value:.0f}) sur la fenêtre",
    ),
    (
        "T1078.003",
        "Valid Accounts: Local Accounts",
        "Privilege Escalation",
        "priv_logon_count",
        "Utilisation fréquente de privilèges spéciaux ({value:.0f} connexions privilégiées)",
    ),
    (
        "T1558.003",
        "Steal or Forge Kerberos Tickets: Kerberoasting",
        "Credential Access",
        "kerberos_count",
        "Volume anormal de demandes de tickets de service Kerberos ({value:.0f})",
    ),
    (
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
        "process_entropy",
        "Diversité anormalement élevée des processus exécutés (entropie={value:.2f} bits)",
    ),
    (
        "T1021",
        "Remote Services",
        "Lateral Movement",
        "host_velocity",
        "Apparition rapide de nouveaux hôtes dans l'activité de l'utilisateur "
        "({value:.3f} nouveaux hôtes/minute)",
    ),
)

_HEURISTIC_THRESHOLDS: dict[str, float] = {
    "failed_login_count": FAILED_LOGIN_COUNT_THRESHOLD,
    "priv_logon_count": PRIV_LOGON_COUNT_THRESHOLD,
    "kerberos_count": KERBEROS_COUNT_THRESHOLD,
    "process_entropy": PROCESS_ENTROPY_THRESHOLD,
    "host_velocity": HOST_VELOCITY_THRESHOLD,
}


class MitreMapper:
    """Associe les anomalies comportementales aux techniques MITRE ATT&CK.

    Le mapper opère à deux niveaux :

    * `match_individual` : analyse un vecteur de features isolé (un
      utilisateur sur une fenêtre) et applique les heuristiques individuelles,
      y compris la combinaison `off_hours_ratio` + `unique_hosts` (Valid
      Accounts, T1078) ;
    * `match_population` : analyse l'ensemble des vecteurs anormaux d'une même
      fenêtre temporelle pour détecter des patterns collectifs, en particulier
      le password spraying (T1110.003), qui n'est visible qu'au niveau de la
      population de comptes ciblés.
    """

    def match_individual(
        self,
        feature_vector: FeatureVector,
        siem_mitre_technique: str | None = None,
        siem_mitre_tactic: str | None = None,
    ) -> list[MitreMatch]:
        """Mappe les anomalies d'un (utilisateur, fenêtre) vers des techniques MITRE.

        Paramètres
        ----------
        feature_vector : FeatureVector
            Vecteur de features de l'observation jugée anormale.
        siem_mitre_technique : str | None, optionnel
            Identifiant de technique fourni nativement par le SIEM
            (`rule.mitre.id`), s'il est présent dans les alertes corrélées
            à cette fenêtre.
        siem_mitre_tactic : str | None, optionnel
            Tactique fournie nativement par le SIEM (`rule.mitre.tactic`).

        Retours
        -------
        list[MitreMatch]
            Les correspondances retenues, le signal natif du SIEM (le cas
            échéant) figurant en tête de liste.
        """
        matches: list[MitreMatch] = []

        if siem_mitre_technique:
            matches.append(
                MitreMatch(
                    technique_id=siem_mitre_technique,
                    technique_name=siem_mitre_technique,
                    tactic=siem_mitre_tactic or "Inconnue",
                    rationale="Technique identifiée nativement par la règle de corrélation SIEM",
                    source="siem_native",
                )
            )

        for (
            technique_id,
            technique_name,
            tactic,
            attribute,
            rationale_template,
        ) in _INDIVIDUAL_HEURISTICS:
            value = getattr(feature_vector, attribute)
            threshold = _HEURISTIC_THRESHOLDS[attribute]
            if value > threshold:
                matches.append(
                    MitreMatch(
                        technique_id=technique_id,
                        technique_name=technique_name,
                        tactic=tactic,
                        rationale=rationale_template.format(value=value),
                        source="heuristic",
                    )
                )

        if (
            feature_vector.off_hours_ratio > OFF_HOURS_RATIO_THRESHOLD
            and feature_vector.unique_hosts > UNIQUE_HOSTS_THRESHOLD
        ):
            matches.append(
                MitreMatch(
                    technique_id="T1078",
                    technique_name="Valid Accounts",
                    tactic="Defense Evasion",
                    rationale=(
                        "Activité hors heures de bureau"
                        f" (ratio={feature_vector.off_hours_ratio:.2f})"
                        " combinée à un nombre élevé d'hôtes distincts"
                        f" ({feature_vector.unique_hosts:.0f})"
                    ),
                    source="heuristic",
                )
            )

        return matches

    def match_population(self, anomalous_vectors: list[FeatureVector]) -> list[MitreMatch]:
        """Détecte les patterns collectifs (password spraying) sur une fenêtre commune.

        Un password spraying (T1110.003) se distingue d'un brute force
        individuel (T1110) par sa signature *distribuée* : plusieurs comptes
        subissent, sur une même fenêtre temporelle, un nombre d'échecs
        modéré — volontairement maintenu sous le seuil de détection par
        compte pour ne pas déclencher de verrouillage — mais simultané.

        Paramètres
        ----------
        anomalous_vectors : list[FeatureVector]
            Vecteurs de features jugés anormaux par l'ensemble ML, toutes
            fenêtres et tous utilisateurs confondus.

        Retours
        -------
        list[MitreMatch]
            Une correspondance T1110.003 par fenêtre temporelle où le pattern
            collectif est observé (liste vide si aucun pattern détecté).
        """
        # Groupe par bucket de 30 min (pas exact) pour gérer les fenêtres par utilisateur
        # dont les window_start diffèrent de quelques secondes selon le premier événement.
        by_bucket: dict[tuple[int, ...], list[FeatureVector]] = defaultdict(list)
        for vector in anomalous_vectors:
            if vector.failed_login_count >= PASSWORD_SPRAY_MIN_FAILED_LOGINS:
                by_bucket[_window_bucket(vector.window_start)].append(vector)

        matches: list[MitreMatch] = []
        for _bucket_key, vectors in sorted(by_bucket.items()):
            distinct_users = {v.user for v in vectors}
            if len(distinct_users) >= PASSWORD_SPRAY_MIN_USERS:
                window_start = min(v.window_start for v in vectors)
                window_end = max(v.window_end for v in vectors)
                matches.append(
                    MitreMatch(
                        technique_id="T1110.003",
                        technique_name="Brute Force: Password Spraying",
                        tactic="Credential Access",
                        rationale=(
                            f"{len(distinct_users)} comptes distincts "
                            f"({', '.join(sorted(distinct_users))}) présentent des échecs de "
                            f"connexion synchronisés sur la fenêtre "
                            f"{window_start:%Y-%m-%d %H:%M} – {window_end:%H:%M}"
                        ),
                        source="heuristic",
                    )
                )
        return matches


__all__ = ["MitreMapper", "MitreMatch"]
