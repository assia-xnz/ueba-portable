"""Métriques opérationnelles SOC pour le système UEBA.

Ce package regroupe les indicateurs de performance utilisés en soutenance
et en exploitation : le MTTD (*Mean Time To Detect*) en premier lieu.
"""

from ueba.metrics.mttd import MTTDCalculator, MTTDReport

__all__ = ["MTTDCalculator", "MTTDReport"]
