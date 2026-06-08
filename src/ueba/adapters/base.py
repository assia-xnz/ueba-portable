"""Classe abstraite définissant le contrat commun à tous les adapters SIEM.

L'exigence de portabilité (cf. cahier des charges § 5.2) impose que le cœur ML
(`ueba.domain`) ne connaisse jamais le format propriétaire d'un SIEM. Chaque
adapter a la responsabilité unique de traduire les enregistrements bruts de
son SIEM source en `NormalizedEvent`, en appliquant au passage le filtre des
comptes machine (premier levier anti-faux-positifs).

Ajouter le support d'un nouveau SIEM se résume donc à :

1. Créer une sous-classe de `SIEMAdapter` implémentant `parse_record` ;
2. L'enregistrer dans `ueba.adapters.registry` ;

— sans toucher une seule ligne du domaine ou du pipeline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping

from ueba.domain.schema import MachineAccountFilter, NormalizedEvent


def clean_field(value: object) -> str | None:
    """Normalise une valeur de champ brute en chaîne non vide, ou `None`.

    Les exports SIEM représentent les valeurs absentes de façons variées
    (chaîne vide, espaces, `NaN` pandas, `None`, ...). Cette fonction
    harmonise ces représentations pour l'ensemble des adapters, afin que le
    domaine ne reçoive jamais de chaîne vide ou de littéral "nan".

    Paramètres
    ----------
    value : object
        Valeur brute issue d'un enregistrement source (cellule CSV, champ JSON, ...).

    Retours
    -------
    str | None
        La valeur nettoyée, ou `None` si elle est absente/vide.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() == "nan":
        return None
    return text


def clean_int_field(value: object) -> int | None:
    """Convertit une valeur de champ brute en entier, ou `None` si non convertible.

    Paramètres
    ----------
    value : object
        Valeur brute potentiellement numérique (ex. "5", "5.0", 5).

    Retours
    -------
    int | None
        L'entier correspondant, ou `None` si la conversion échoue ou si la
        valeur est absente.
    """
    text = clean_field(value)
    if text is None:
        return None
    try:
        return int(float(text))
    except ValueError:
        return None


class AdapterParsingError(Exception):
    """Erreur levée lorsqu'un enregistrement brut ne peut pas être normalisé.

    Cette exception encapsule les erreurs de format (champ manquant,
    timestamp non parsable, etc.) afin que le pipeline puisse les distinguer
    d'erreurs de domaine et choisir d'ignorer l'enregistrement fautif tout en
    journalisant le problème, plutôt que d'interrompre l'ensemble du traitement.
    """


class SIEMAdapter(ABC):
    """Contrat abstrait reliant le format natif d'un SIEM au schéma normalisé.

    Paramètres
    ----------
    machine_account_filter : MachineAccountFilter | None, optionnel
        Filtre d'exclusion des comptes machine/système appliqué à chaque
        enregistrement avant normalisation. Si `None`, le filtre par défaut
        (`MachineAccountFilter.default()`) est utilisé.
    """

    #: Nom court identifiant l'adapter dans la configuration et le registre
    #: (ex. "wazuh", "elastic", "splunk", "qradar"). À redéfinir dans chaque sous-classe.
    name: str = "base"

    def __init__(self, machine_account_filter: MachineAccountFilter | None = None) -> None:
        self._machine_account_filter = machine_account_filter or MachineAccountFilter.default()

    def normalize(self, records: Iterable[Mapping[str, object]]) -> list[NormalizedEvent]:
        """Convertit un flux d'enregistrements bruts en événements normalisés.

        Cette méthode orchestre le contrat commun à tous les adapters :
        parsing du format propriétaire (`parse_record`, délégué aux
        sous-classes) puis exclusion des comptes machine/système (filtre
        commun, appliqué uniformément quel que soit le SIEM source). Les
        enregistrements dont le parsing échoue sont silencieusement ignorés
        (cf. `AdapterParsingError`) : un export SIEM réel contient toujours
        quelques lignes incomplètes ou hors-périmètre, et il est préférable
        de poursuivre l'analyse sur le reste du jeu de données.

        Paramètres
        ----------
        records : Iterable[Mapping[str, object]]
            Enregistrements bruts dans le format natif du SIEM (ex. lignes
            d'un export CSV Kibana, documents JSON Splunk, ...).

        Retours
        -------
        list[NormalizedEvent]
            Événements normalisés, hors comptes machine/système.
        """
        normalized: list[NormalizedEvent] = []
        for record in records:
            try:
                event = self.parse_record(record)
            except AdapterParsingError:
                continue
            if event is None:
                continue
            if self._machine_account_filter.is_machine_account(event.user):
                continue
            normalized.append(event)
        return normalized

    @abstractmethod
    def parse_record(self, record: Mapping[str, object]) -> NormalizedEvent | None:
        """Traduit un enregistrement brut du SIEM source en événement normalisé.

        Paramètres
        ----------
        record : Mapping[str, object]
            Un enregistrement unique dans le format natif du SIEM (ex. une
            ligne de CSV exportée depuis Kibana Discover, représentée comme
            un dictionnaire colonne → valeur).

        Retours
        -------
        NormalizedEvent | None
            L'événement normalisé correspondant, ou `None` si l'enregistrement
            doit être ignoré pour une raison métier (ex. EventID hors périmètre
            UEBA, et non une erreur de format).

        Lève
        ----
        AdapterParsingError
            Si l'enregistrement est malformé (champ requis manquant ou
            timestamp non parsable) et ne peut être normalisé.
        """


__all__ = ["AdapterParsingError", "SIEMAdapter"]
