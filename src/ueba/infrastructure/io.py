"""Entrées/sorties du pipeline : lecture des exports SIEM, écriture des rapports.

Ce module isole les détails de format de fichier (CSV, JSON) du reste du
pipeline. Le domaine et les adapters ne manipulent que des structures Python
en mémoire (`Mapping`, `dataclass`) : c'est ici, et seulement ici, que le
pipeline touche au système de fichiers.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any


class IOError_(Exception):
    """Erreur levée lors d'une opération d'entrée/sortie sur les artefacts du pipeline.

    Nommée `IOError_` (avec un tiret bas final) pour ne pas masquer
    l'exception native `IOError` (= `OSError`) du langage.
    """


def read_csv_records(csv_path: str | Path) -> Iterator[dict[str, str]]:
    """Lit un export CSV (ex. export Kibana Discover) ligne par ligne.

    Chaque ligne est restituée sous forme de dictionnaire `colonne -> valeur`,
    le format générique attendu par `SIEMAdapter.normalize`.

    Paramètres
    ----------
    csv_path : str | Path
        Chemin vers le fichier CSV source.

    Génère
    ------
    dict[str, str]
        Un dictionnaire par ligne de données (l'en-tête définit les clés).

    Lève
    ----
    IOError_
        Si le fichier est introuvable ou ne peut pas être lu.
    """
    path = Path(csv_path)
    if not path.is_file():
        raise IOError_(f"Fichier d'export introuvable : {path}")

    try:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            yield from (dict(row) for row in reader)
    except (OSError, csv.Error) as exc:
        raise IOError_(f"Impossible de lire l'export CSV {path} : {exc}") from exc


def write_json_report(report: Mapping[str, Any], output_path: str | Path) -> Path:
    """Sérialise un rapport de détection en JSON, en créant les répertoires manquants.

    Paramètres
    ----------
    report : Mapping[str, Any]
        Contenu du rapport (structure JSON-sérialisable : dicts, listes,
        chaînes, nombres, booléens).
    output_path : str | Path
        Chemin du fichier JSON à écrire.

    Retours
    -------
    Path
        Le chemin effectif du fichier écrit (pour journalisation/CLI).

    Lève
    ----
    IOError_
        Si l'écriture échoue (droits, espace disque, ...).
    """
    path = Path(output_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    except OSError as exc:
        raise IOError_(f"Impossible d'écrire le rapport JSON dans {path} : {exc}") from exc
    return path


__all__ = ["IOError_", "read_csv_records", "write_json_report"]
