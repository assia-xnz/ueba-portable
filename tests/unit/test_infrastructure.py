"""Tests unitaires des modules d'infrastructure purs (config, io, logging)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ueba.infrastructure.config import ConfigError, PipelineConfig, load_pipeline_config
from ueba.infrastructure.io import IOError_, read_csv_records, write_json_report
from ueba.infrastructure.logging import LoggingConfigError, configure_logging, get_logger

_VALID_YAML = """
siem:
  adapter: wazuh
  timestamp_format: "%Y-%m-%dT%H:%M:%S"
windowing:
  size_minutes: 60
  step_minutes: 30
baseline:
  lookback_days: 7
  min_observations: 5
business_hours:
  start_hour: 8
  end_hour: 18
excluded_accounts:
  suffixes: ["$"]
  exact_names: ["SYSTEM"]
  prefixes: ["DWM-"]
ensemble:
  isolation_forest:
    n_estimators: 100
  one_class_svm:
    kernel: rbf
    gamma: scale
  autoencoder:
    hidden_layer_sizes: [8, 4, 8]
    reconstruction_error_percentile: 95
    random_state: 42
  majority_threshold: 2
output:
  processed_dir: data/processed
  report_filename: report.json
"""


# ── config.py ────────────────────────────────────────────────────────────────
def test_load_pipeline_config_valid(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pipeline.yaml"
    cfg_file.write_text(_VALID_YAML)
    cfg = load_pipeline_config(cfg_file)
    assert isinstance(cfg, PipelineConfig)
    assert cfg.siem_adapter == "wazuh"
    assert cfg.windowing.size.total_seconds() == 3600
    assert cfg.baseline.lookback_days == 7
    assert cfg.ensemble.autoencoder_hidden_layers == (8, 4, 8)
    assert cfg.ensemble.majority_threshold == 2
    assert cfg.machine_account_filter.is_machine_account("HOST$") is True


def test_load_pipeline_config_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="introuvable"):
        load_pipeline_config(tmp_path / "absent.yaml")


def test_load_pipeline_config_not_a_mapping(tmp_path: Path) -> None:
    f = tmp_path / "bad.yaml"
    f.write_text("- just\n- a\n- list\n")
    with pytest.raises(ConfigError, match="mapping YAML"):
        load_pipeline_config(f)


def test_load_pipeline_config_missing_key(tmp_path: Path) -> None:
    f = tmp_path / "partial.yaml"
    f.write_text("siem:\n  adapter: wazuh\n")
    with pytest.raises(ConfigError, match="manquante|invalide"):
        load_pipeline_config(f)


def test_load_pipeline_config_invalid_yaml(tmp_path: Path) -> None:
    f = tmp_path / "broken.yaml"
    f.write_text("siem: [unclosed\n")
    with pytest.raises(ConfigError, match="YAML invalide"):
        load_pipeline_config(f)


# ── io.py ────────────────────────────────────────────────────────────────────
def test_read_csv_records(tmp_path: Path) -> None:
    csv_file = tmp_path / "in.csv"
    csv_file.write_text("user,event\na.amrani,4625\nl.mus,4624\n", encoding="utf-8")
    rows = list(read_csv_records(csv_file))
    assert rows == [
        {"user": "a.amrani", "event": "4625"},
        {"user": "l.mus", "event": "4624"},
    ]


def test_read_csv_handles_bom(tmp_path: Path) -> None:
    """Les exports Kibana contiennent souvent un BOM UTF-8."""
    csv_file = tmp_path / "bom.csv"
    csv_file.write_text("user,event\nx,4624\n", encoding="utf-8-sig")
    rows = list(read_csv_records(csv_file))
    assert rows[0]["user"] == "x"  # la clé n'est pas polluée par le BOM


def test_read_csv_missing_file(tmp_path: Path) -> None:
    with pytest.raises(IOError_, match="introuvable"):
        list(read_csv_records(tmp_path / "absent.csv"))


def test_write_json_report_creates_dirs(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "report.json"
    result = write_json_report({"anomalies": 3}, out)
    assert result == out
    assert out.exists()
    assert '"anomalies": 3' in out.read_text()


# ── logging.py ───────────────────────────────────────────────────────────────
def test_get_logger_namespaced() -> None:
    assert get_logger("features").name == "ueba.features"
    assert get_logger("ueba.cli").name == "ueba.cli"


def test_configure_logging_valid(tmp_path: Path) -> None:
    cfg = tmp_path / "logging.yaml"
    cfg.write_text(
        "version: 1\n"
        "formatters:\n  simple:\n    format: '%(levelname)s %(message)s'\n"
        "handlers:\n  console:\n    class: logging.StreamHandler\n    formatter: simple\n"
        "root:\n  level: INFO\n  handlers: [console]\n"
    )
    configure_logging(cfg)  # ne lève pas


def test_configure_logging_missing_file(tmp_path: Path) -> None:
    with pytest.raises(LoggingConfigError, match="introuvable"):
        configure_logging(tmp_path / "absent.yaml")


def test_configure_logging_not_a_mapping(tmp_path: Path) -> None:
    f = tmp_path / "bad.yaml"
    f.write_text("- a\n- b\n")
    with pytest.raises(LoggingConfigError, match="mapping"):
        configure_logging(f)


def test_configure_logging_invalid_schema(tmp_path: Path) -> None:
    f = tmp_path / "bad.yaml"
    f.write_text("version: 99\nhandlers: not_a_dict\n")
    with pytest.raises(LoggingConfigError, match="invalide"):
        configure_logging(f)
