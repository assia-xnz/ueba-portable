"""Schéma normalisé du domaine UEBA.

Ce module définit le contrat unique entre la couche *adapters* (qui traduit
les formats propriétaires de chaque SIEM) et la couche *domain* (cœur ML).
Aucun adapter ne doit exposer de champ spécifique à son SIEM d'origine au-delà
de cette structure : c'est ce découplage qui rend le pipeline portable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

#: Identifiants d'événements Windows correspondant à une connexion réussie.
LOGIN_EVENT_IDS: frozenset[str] = frozenset({"4624", "4648", "4768", "4776"})

#: Identifiants d'événements Windows correspondant à un échec de connexion.
FAILED_LOGIN_EVENT_IDS: frozenset[str] = frozenset({"4625", "4771"})

#: Identifiant de création de processus (Sysmon/Windows Security).
PROCESS_CREATION_EVENT_ID: str = "4688"

#: Identifiant de connexion avec privilèges spéciaux (utilisation de droits sensibles).
PRIVILEGED_LOGON_EVENT_ID: str = "4672"

#: Identifiant de demande de ticket de service Kerberos (vecteur de Kerberoasting).
KERBEROS_TGS_EVENT_ID: str = "4769"

#: Ensemble de tous les EventIDs Windows pris en charge par le pipeline.
SUPPORTED_EVENT_IDS: frozenset[str] = frozenset(
    LOGIN_EVENT_IDS
    | FAILED_LOGIN_EVENT_IDS
    | {PROCESS_CREATION_EVENT_ID, PRIVILEGED_LOGON_EVENT_ID, KERBEROS_TGS_EVENT_ID, "4634"}
)


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """Représentation normalisée d'un événement de sécurité, indépendante du SIEM source.

    C'est le seul type d'objet que la couche *domain* connaît : chaque adapter
    a la responsabilité de produire des instances de cette classe à partir du
    format natif de son SIEM (Wazuh, Elastic ECS, Splunk, QRadar, ...).

    Attributs
    ---------
    timestamp : datetime
        Horodatage de l'événement (timezone-naive, heure locale du SIEM).
    user : str
        Nom du compte utilisateur impliqué dans l'événement (déjà résolu :
        l'adapter a tranché entre `targetUserName`/`subjectUserName` selon
        le type d'événement).
    host : str
        Nom de la machine ayant généré ou reçu l'événement.
    event_id : str
        Identifiant Windows Event Log (ex. "4624", "4688", ...).
    logon_type : str | None
        Type de connexion Windows (2=interactive, 3=réseau, 10=RDP, ...).
    workstation : str | None
        Nom du poste de travail d'origine de la tentative de connexion.
    src_ip : str | None
        Adresse IP source de la connexion, si disponible.
    process_name : str | None
        Nom du processus créé (pertinent pour l'EventID 4688).
    parent_process : str | None
        Nom du processus parent (pertinent pour l'EventID 4688).
    rule_level : int | None
        Niveau de sévérité de la règle SIEM ayant généré l'alerte (si applicable).
    mitre_technique : str | None
        Identifiant de technique MITRE ATT&CK fourni nativement par le SIEM
        (ex. "T1110.003"), à exploiter en complément du mapping interne.
    mitre_tactic : str | None
        Tactique MITRE ATT&CK fournie nativement par le SIEM.
    """

    timestamp: datetime
    user: str
    host: str
    event_id: str
    logon_type: str | None = None
    workstation: str | None = None
    src_ip: str | None = None
    process_name: str | None = None
    parent_process: str | None = None
    rule_level: int | None = None
    mitre_technique: str | None = None
    mitre_tactic: str | None = None

    @property
    def is_login(self) -> bool:
        """Indique si l'événement correspond à une connexion réussie."""
        return self.event_id in LOGIN_EVENT_IDS

    @property
    def is_failed_login(self) -> bool:
        """Indique si l'événement correspond à un échec de connexion."""
        return self.event_id in FAILED_LOGIN_EVENT_IDS

    @property
    def is_process_creation(self) -> bool:
        """Indique si l'événement correspond à une création de processus (4688)."""
        return self.event_id == PROCESS_CREATION_EVENT_ID

    @property
    def is_privileged_logon(self) -> bool:
        """Indique si l'événement correspond à l'utilisation de droits sensibles (4672)."""
        return self.event_id == PRIVILEGED_LOGON_EVENT_ID

    @property
    def is_kerberos_tgs_request(self) -> bool:
        """Indique si l'événement correspond à une demande de ticket Kerberos (4769)."""
        return self.event_id == KERBEROS_TGS_EVENT_ID


class MachineAccountFilter:
    """Filtre d'exclusion des comptes machine et système.

    Premier levier de réduction des faux positifs (cf. cahier des charges § 5.4-a) :
    les comptes machine (`HOST$`), les comptes système Windows (`SYSTEM`,
    `LOCAL SERVICE`, ...) et les comptes de session graphique internes
    (`DWM-1`, `UMFD-0`, ...) génèrent un volume d'événements massif et non
    représentatif d'un comportement humain. Les inclure dans l'apprentissage
    des baselines pollue les statistiques et masque les anomalies réelles.

    Paramètres
    ----------
    suffixes : list[str]
        Suffixes de nom de compte à exclure (ex. "$" pour les comptes machine).
    exact_names : list[str]
        Noms de compte à exclure par correspondance exacte (insensible à la casse).
    prefixes : list[str]
        Préfixes de nom de compte à exclure (ex. "DWM-", "UMFD-").
    """

    def __init__(
        self,
        suffixes: list[str] | None = None,
        exact_names: list[str] | None = None,
        prefixes: list[str] | None = None,
    ) -> None:
        self._suffixes: tuple[str, ...] = tuple(suffixes or [])
        self._exact_names: frozenset[str] = frozenset(
            (name or "").upper() for name in (exact_names or [])
        )
        self._prefixes: tuple[str, ...] = tuple(prefixes or [])

    def is_machine_account(self, user: str) -> bool:
        """Détermine si le nom de compte fourni doit être exclu de l'analyse.

        Paramètres
        ----------
        user : str
            Nom du compte utilisateur à évaluer.

        Retours
        -------
        bool
            `True` si le compte doit être exclu (compte machine ou système).
        """
        normalized = (user or "").strip()
        if not normalized:
            return True
        if normalized.upper() in self._exact_names:
            return True
        if any(normalized.endswith(suffix) for suffix in self._suffixes):
            return True
        if any(normalized.upper().startswith(prefix.upper()) for prefix in self._prefixes):
            return True
        return False

    @classmethod
    def default(cls) -> MachineAccountFilter:
        """Construit un filtre avec les règles par défaut décrites dans le cahier des charges."""
        return cls(
            suffixes=["$"],
            exact_names=["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"],
            prefixes=["DWM-", "UMFD-"],
        )
