"""Vérification d'intégrité des modèles sérialisés (défense contre SEC-11).

``joblib.load`` repose sur ``pickle`` : charger un modèle altéré peut exécuter du
code arbitraire. Pour limiter ce risque, on accompagne chaque modèle d'un fichier
de somme de contrôle ``<modèle>.sha256`` et on vérifie la correspondance **avant**
toute désérialisation.

Workflow :

    write_checksum("models/ueba.joblib")          # à la production du modèle
    verify_checksum("models/ueba.joblib")          # avant joblib.load(...)
"""

from __future__ import annotations

import hashlib
from pathlib import Path


class IntegrityError(Exception):
    """Levée quand l'empreinte d'un modèle ne correspond pas à sa référence."""


def sha256_file(path: str | Path, *, chunk_size: int = 65536) -> str:
    """Calcule l'empreinte SHA-256 d'un fichier (lecture par blocs)."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checksum_path(model_path: str | Path) -> Path:
    """Chemin du fichier d'empreinte associé à un modèle (``<modèle>.sha256``)."""
    p = Path(model_path)
    return p.with_name(p.name + ".sha256")


def write_checksum(model_path: str | Path) -> Path:
    """Écrit l'empreinte SHA-256 du modèle dans ``<modèle>.sha256`` et la renvoie."""
    sidecar = checksum_path(model_path)
    sidecar.write_text(sha256_file(model_path) + "\n", encoding="utf-8")
    return sidecar


def verify_checksum(model_path: str | Path, *, required: bool = False) -> bool:
    """Vérifie l'intégrité d'un modèle face à son fichier ``.sha256``.

    Paramètres
    ----------
    model_path : str | Path
        Chemin du modèle à vérifier.
    required : bool
        Si ``True``, l'absence du fichier d'empreinte est une erreur. Si
        ``False`` (défaut), l'absence est tolérée (renvoie ``False``) — utile en
        labo où les modèles auto-entraînés n'ont pas toujours de sidecar.

    Retours
    -------
    bool
        ``True`` si l'empreinte correspond, ``False`` si le sidecar est absent
        et ``required=False``.

    Exceptions
    ----------
    IntegrityError
        Si l'empreinte ne correspond pas, ou si le sidecar est absent alors que
        ``required=True``.
    """
    sidecar = checksum_path(model_path)
    if not sidecar.is_file():
        if required:
            raise IntegrityError(f"Empreinte d'intégrité absente : {sidecar}")
        return False
    expected = sidecar.read_text(encoding="utf-8").strip()
    actual = sha256_file(model_path)
    if expected != actual:
        raise IntegrityError(
            f"Intégrité du modèle compromise : {model_path}\n"
            f"  attendu : {expected}\n  obtenu  : {actual}"
        )
    return True


__all__ = [
    "IntegrityError",
    "sha256_file",
    "checksum_path",
    "write_checksum",
    "verify_checksum",
]
