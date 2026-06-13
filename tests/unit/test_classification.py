"""Tests unitaires des métriques de classification."""

from __future__ import annotations

import pytest

from ueba.metrics.classification import (
    ConfusionMatrix,
    classification_report,
    confusion_matrix,
)


def test_confusion_matrix_counts() -> None:
    y_true = [True, True, False, False, True]
    y_pred = [True, False, True, False, True]
    cm = confusion_matrix(y_true, y_pred)
    assert (cm.tp, cm.fp, cm.fn, cm.tn) == (2, 1, 1, 1)
    assert cm.support == 5


def test_metrics_values() -> None:
    cm = ConfusionMatrix(tp=2, fp=1, fn=1, tn=1)
    assert cm.precision == pytest.approx(2 / 3)
    assert cm.recall == pytest.approx(2 / 3)
    assert cm.f1 == pytest.approx(2 / 3)
    assert cm.false_positive_rate == pytest.approx(0.5)
    assert cm.accuracy == pytest.approx(0.6)


def test_perfect_classifier() -> None:
    cm = confusion_matrix([True, False, True], [True, False, True])
    assert cm.precision == 1.0
    assert cm.recall == 1.0
    assert cm.f1 == 1.0
    assert cm.false_positive_rate == 0.0


def test_no_alerts_precision_zero_not_crash() -> None:
    cm = ConfusionMatrix(tp=0, fp=0, fn=3, tn=2)
    assert cm.precision == 0.0
    assert cm.recall == 0.0
    assert cm.f1 == 0.0
    assert cm.false_positive_rate == 0.0


def test_empty_inputs() -> None:
    cm = confusion_matrix([], [])
    assert cm.support == 0
    assert cm.accuracy == 0.0


def test_length_mismatch_raises() -> None:
    with pytest.raises(ValueError, match="longueurs différentes"):
        confusion_matrix([True], [True, False])


def test_classification_report_dict() -> None:
    report = classification_report([True, False], [True, True])
    assert report["tp"] == 1
    assert report["fp"] == 1
    assert report["precision"] == 0.5
    assert report["false_positive_rate"] == 1.0
    assert set(report) >= {"precision", "recall", "f1", "false_positive_rate", "accuracy"}
