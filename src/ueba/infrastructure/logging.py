"""Configuration du logging structuré du pipeline.

Conformément au cahier des charges (§ 8 : « Logging structuré, pas de
print() en production »), toute trace d'exécution transite par le module
`logging` standard, configuré ici depuis `config/logging.yaml` (dictConfig).
Cela permet d'ajuster niveaux, formats et destinations (console, fichier, ...)
sans toucher au code, et de bénéficier d'un format homogène et exploitable
(horodatage, niveau, logger, message).
"""

from __future__ import annotations

import logging
import logging.config
from pathlib import Path

import yaml


class LoggingConfigError(Exception):
    """Erreur levée lorsque la configuration de logging est absente ou invalide."""


def configure_logging(config_path: str | Path) -> None:
    """Configure le logging applicatif depuis un fichier YAML (`logging.config.dictConfig`).

    Paramètres
    ----------
    config_path : str | Path
        Chemin vers le fichier de configuration de logging
        (ex. `config/logging.yaml`).

    Lève
    ----
    LoggingConfigError
        Si le fichier est introuvable, n'est pas un YAML valide, ou si le
        mapping qu'il décrit ne respecte pas le schéma `dictConfig`.
    """
    path = Path(config_path)
    if not path.is_file():
        raise LoggingConfigError(f"Fichier de configuration de logging introuvable : {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise LoggingConfigError(f"Fichier de configuration de logging YAML invalide : {exc}") from exc

    if not isinstance(raw, dict):
        raise LoggingConfigError("La configuration de logging doit décrire un mapping YAML")

    try:
        logging.config.dictConfig(raw)
    except (ValueError, TypeError, AttributeError, ImportError) as exc:
        raise LoggingConfigError(f"Configuration de logging invalide : {exc}") from exc


def get_logger(name: str) -> logging.Logger:
    """Retourne un logger nommé, rattaché à la hiérarchie `ueba`.

    Centraliser la création des loggers ici garantit que tous les modules du
    pipeline héritent de la même configuration (`config/logging.yaml`),
    sans que chacun n'ait à connaître les détails du dictConfig sous-jacent.

    Paramètres
    ----------
    name : str
        Nom du module ou composant appelant (typiquement `__name__`).

    Retours
    -------
    logging.Logger
        Le logger correspondant, rattaché au logger racine `ueba`.
    """
    return logging.getLogger(f"ueba.{name}" if not name.startswith("ueba") else name)


__all__ = ["LoggingConfigError", "configure_logging", "get_logger"]
