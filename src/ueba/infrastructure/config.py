"""Chargement et validation de la configuration externalisée du pipeline.

Conformément au principe d'externalisation (cf. cahier des charges § 8 :
« Config externalisée en YAML »), aucun paramètre métier ajustable
(fenêtrage, seuils, comptes exclus, hyperparamètres ML, ...) n'est codé en
dur dans le domaine ou le pipeline : tout est lu depuis `config/pipeline.yaml`
et représenté ici par des structures fortement typées.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import yaml

from ueba.domain.schema import MachineAccountFilter


class ConfigError(Exception):
    """Erreur levée lorsque la configuration est absente, malformée ou incohérente."""


@dataclass(frozen=True, slots=True)
class WindowingConfig:
    """Paramètres de fenêtrage temporel glissant.

    Attributs
    ---------
    size : timedelta
        Largeur de chaque fenêtre d'agrégation.
    step : timedelta
        Pas de glissement entre deux fenêtres consécutives.
    """

    size: timedelta
    step: timedelta


@dataclass(frozen=True, slots=True)
class BaselineConfig:
    """Paramètres de construction des baselines comportementales par utilisateur.

    Attributs
    ---------
    lookback_days : int
        Nombre de jours d'historique utilisés pour apprendre la baseline.
    min_observations : int
        Nombre minimal d'observations pour qu'une baseline soit jugée fiable.
    """

    lookback_days: int
    min_observations: int


@dataclass(frozen=True, slots=True)
class BusinessHoursConfig:
    """Plage horaire de référence pour le calcul de `off_hours_ratio`.

    Attributs
    ---------
    start_hour : int
        Heure de début de la plage de bureau (incluse).
    end_hour : int
        Heure de fin de la plage de bureau (exclue).
    """

    start_hour: int
    end_hour: int


@dataclass(frozen=True, slots=True)
class EnsembleConfig:
    """Hyperparamètres de l'ensemble de détection d'anomalies.

    Attributs
    ---------
    n_estimators : int
        Nombre d'arbres de l'IsolationForest.
    svm_kernel : str
        Noyau du OneClassSVM.
    svm_gamma : str
        Coefficient gamma du OneClassSVM.
    autoencoder_hidden_layers : tuple[int, ...]
        Tailles des couches cachées de l'autoencodeur (MLPRegressor).
    reconstruction_error_percentile : float
        Percentile de l'erreur de reconstruction utilisé comme seuil d'anomalie.
    majority_threshold : int
        Nombre minimal de votes « anomalie » déclenchant une alerte (sur 3).
    random_state : int
        Graine aléatoire commune, pour la reproductibilité.
    """

    n_estimators: int
    svm_kernel: str
    svm_gamma: str
    autoencoder_hidden_layers: tuple[int, ...]
    reconstruction_error_percentile: float
    majority_threshold: int
    random_state: int


@dataclass(frozen=True, slots=True)
class PipelineConfig:
    """Configuration complète et typée du pipeline UEBA.

    Attributs
    ---------
    siem_adapter : str
        Nom de l'adapter SIEM source (résolu via `ueba.adapters.registry`).
    timestamp_format : str
        Format du timestamp source (transmis à titre indicatif/documentaire ;
        chaque adapter encapsule en réalité son propre format).
    windowing : WindowingConfig
        Paramètres de fenêtrage glissant.
    baseline : BaselineConfig
        Paramètres de construction des baselines comportementales.
    business_hours : BusinessHoursConfig
        Plage horaire de référence pour la temporalité.
    machine_account_filter : MachineAccountFilter
        Filtre d'exclusion des comptes machine/système.
    ensemble : EnsembleConfig
        Hyperparamètres de l'ensemble ML.
    processed_dir : Path
        Répertoire de sortie des artefacts traités (rapports, features, ...).
    report_filename : str
        Nom du fichier de rapport de détection généré par le pipeline.
    """

    siem_adapter: str
    timestamp_format: str
    windowing: WindowingConfig
    baseline: BaselineConfig
    business_hours: BusinessHoursConfig
    machine_account_filter: MachineAccountFilter
    ensemble: EnsembleConfig
    processed_dir: Path
    report_filename: str = "detection_report.json"


def _require(mapping: dict, *keys: str) -> dict:
    """Navigue dans un dictionnaire imbriqué et lève `ConfigError` si une clé manque."""
    current = mapping
    path: list[str] = []
    for key in keys:
        path.append(key)
        if not isinstance(current, dict) or key not in current:
            raise ConfigError(f"Clé de configuration manquante : {'.'.join(path)}")
        current = current[key]
    return current


def load_pipeline_config(config_path: str | Path) -> PipelineConfig:
    """Charge et valide la configuration du pipeline depuis un fichier YAML.

    Paramètres
    ----------
    config_path : str | Path
        Chemin vers le fichier de configuration (ex. `config/pipeline.yaml`).

    Retours
    -------
    PipelineConfig
        La configuration typée et validée, prête à être consommée par le pipeline.

    Lève
    ----
    ConfigError
        Si le fichier est introuvable, n'est pas un YAML valide, ou si une
        clé requise est absente.
    """
    path = Path(config_path)
    if not path.is_file():
        raise ConfigError(f"Fichier de configuration introuvable : {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Fichier de configuration YAML invalide : {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError("Le fichier de configuration doit décrire un mapping YAML")

    try:
        windowing = WindowingConfig(
            size=timedelta(minutes=int(_require(raw, "windowing", "size_minutes"))),
            step=timedelta(minutes=int(_require(raw, "windowing", "step_minutes"))),
        )
        baseline = BaselineConfig(
            lookback_days=int(_require(raw, "baseline", "lookback_days")),
            min_observations=int(_require(raw, "baseline", "min_observations")),
        )
        business_hours = BusinessHoursConfig(
            start_hour=int(_require(raw, "business_hours", "start_hour")),
            end_hour=int(_require(raw, "business_hours", "end_hour")),
        )

        excluded = raw.get("excluded_accounts", {}) or {}
        machine_account_filter = MachineAccountFilter(
            suffixes=list(excluded.get("suffixes", [])),
            exact_names=list(excluded.get("exact_names", [])),
            prefixes=list(excluded.get("prefixes", [])),
        )

        autoencoder = _require(raw, "ensemble", "autoencoder")
        ensemble = EnsembleConfig(
            n_estimators=int(_require(raw, "ensemble", "isolation_forest", "n_estimators")),
            svm_kernel=str(_require(raw, "ensemble", "one_class_svm", "kernel")),
            svm_gamma=str(_require(raw, "ensemble", "one_class_svm", "gamma")),
            autoencoder_hidden_layers=tuple(int(v) for v in autoencoder["hidden_layer_sizes"]),
            reconstruction_error_percentile=float(autoencoder["reconstruction_error_percentile"]),
            majority_threshold=int(_require(raw, "ensemble", "majority_threshold")),
            random_state=int(autoencoder.get("random_state", 42)),
        )

        output = raw.get("output", {}) or {}
        return PipelineConfig(
            siem_adapter=str(_require(raw, "siem", "adapter")),
            timestamp_format=str(_require(raw, "siem", "timestamp_format")),
            windowing=windowing,
            baseline=baseline,
            business_hours=business_hours,
            machine_account_filter=machine_account_filter,
            ensemble=ensemble,
            processed_dir=Path(output.get("processed_dir", "data/processed")),
            report_filename=str(output.get("report_filename", "detection_report.json")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigError(f"Configuration invalide : {exc}") from exc


__all__ = [
    "BaselineConfig",
    "BusinessHoursConfig",
    "ConfigError",
    "EnsembleConfig",
    "PipelineConfig",
    "WindowingConfig",
    "load_pipeline_config",
]
