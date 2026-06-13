"""Tests unitaires de la vérification d'intégrité des modèles."""

from __future__ import annotations

from pathlib import Path

import pytest

from ueba.infrastructure.integrity import (
    IntegrityError,
    checksum_path,
    sha256_file,
    verify_checksum,
    write_checksum,
)


def _model(tmp_path: Path, content: bytes = b"fake-model-bytes") -> Path:
    p = tmp_path / "ueba.joblib"
    p.write_bytes(content)
    return p


def test_sha256_is_stable(tmp_path: Path) -> None:
    m = _model(tmp_path)
    assert sha256_file(m) == sha256_file(m)
    assert len(sha256_file(m)) == 64


def test_checksum_path() -> None:
    assert checksum_path("models/ueba.joblib").name == "ueba.joblib.sha256"


def test_write_then_verify_ok(tmp_path: Path) -> None:
    m = _model(tmp_path)
    write_checksum(m)
    assert verify_checksum(m, required=True) is True


def test_verify_detects_tampering(tmp_path: Path) -> None:
    m = _model(tmp_path)
    write_checksum(m)
    m.write_bytes(b"tampered-model")  # altération après calcul de l'empreinte
    with pytest.raises(IntegrityError, match="compromise"):
        verify_checksum(m)


def test_missing_sidecar_tolerated_by_default(tmp_path: Path) -> None:
    m = _model(tmp_path)
    assert verify_checksum(m) is False


def test_missing_sidecar_required_raises(tmp_path: Path) -> None:
    m = _model(tmp_path)
    with pytest.raises(IntegrityError, match="absente"):
        verify_checksum(m, required=True)
