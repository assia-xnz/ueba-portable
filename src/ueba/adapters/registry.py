"""Registre des adapters SIEM disponibles, résolus par nom.

Ce module est le point d'entrée unique de la couche *adapters* pour le reste
du pipeline (`ueba.pipeline`, `ueba.cli`) : il masque la création concrète des
instances d'adapters derrière une simple résolution par nom (`get_adapter`),
ce qui permet de sélectionner le SIEM source par configuration plutôt que par
modification de code.

**Étendre le pipeline à un nouveau SIEM** se résume à :

1. Implémenter une sous-classe de `SIEMAdapter` dans un nouveau module
   (`ueba/adapters/mon_siem.py`), en définissant `parse_record` ;
2. L'enregistrer ici, dans `_ADAPTER_CLASSES` ;

— le domaine, le pipeline et la CLI n'ont besoin d'aucune autre modification.
"""

from __future__ import annotations

from ueba.adapters.base import SIEMAdapter
from ueba.adapters.elastic import ElasticAdapter
from ueba.adapters.qradar import QRadarAdapter
from ueba.adapters.splunk import SplunkAdapter
from ueba.adapters.wazuh import WazuhAdapter
from ueba.domain.schema import MachineAccountFilter

#: Table de résolution nom -> classe d'adapter. Clés en minuscules (la
#: résolution via `get_adapter` est insensible à la casse).
_ADAPTER_CLASSES: dict[str, type[SIEMAdapter]] = {
    "wazuh": WazuhAdapter,
    "elastic": ElasticAdapter,
    "splunk": SplunkAdapter,
    "qradar": QRadarAdapter,
}


class UnknownAdapterError(Exception):
    """Erreur levée lorsqu'aucun adapter n'est enregistré sous le nom demandé."""

    def __init__(self, name: str) -> None:
        available = ", ".join(sorted(_ADAPTER_CLASSES))
        super().__init__(f"Adapter SIEM inconnu : {name!r}. Adapters disponibles : {available}")
        self.name = name


def get_adapter(
    name: str, machine_account_filter: MachineAccountFilter | None = None
) -> SIEMAdapter:
    """Résout et instancie l'adapter SIEM correspondant au nom fourni.

    Paramètres
    ----------
    name : str
        Nom de l'adapter (ex. "wazuh", "elastic", "splunk", "qradar"),
        typiquement issu de `config.siem.adapter`. La résolution est
        insensible à la casse.
    machine_account_filter : MachineAccountFilter | None, optionnel
        Filtre d'exclusion des comptes machine à transmettre à l'adapter.
        Si `None`, l'adapter utilise le filtre par défaut.

    Retours
    -------
    SIEMAdapter
        Une instance prête à l'emploi de l'adapter demandé.

    Lève
    ----
    UnknownAdapterError
        Si aucun adapter n'est enregistré sous ce nom.
    """
    adapter_class = _ADAPTER_CLASSES.get(name.strip().lower())
    if adapter_class is None:
        raise UnknownAdapterError(name)
    return adapter_class(machine_account_filter=machine_account_filter)


def available_adapters() -> tuple[str, ...]:
    """Retourne les noms des adapters enregistrés, triés par ordre alphabétique.

    Utile pour la CLI (ex. afficher les choix valides de `--siem`) et les tests.
    """
    return tuple(sorted(_ADAPTER_CLASSES))


__all__ = ["UnknownAdapterError", "available_adapters", "get_adapter"]
