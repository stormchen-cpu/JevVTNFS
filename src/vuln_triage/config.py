from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field


class AppConfig(BaseModel):
    database_path: str = "var/triage.db"
    raw_dir: str = "var/raw"
    reports_dir: str = "var/reports"
    datasets_dir: str = "var/datasets"
    models_dir: str = "var/models"
    default_timezone: str = "Asia/Taipei"
    log_level: str = "INFO"


class BackendConfig(BaseModel):
    type: str = "fake"  # 'fake' or 'api'
    api_provider: str = "openai-compatible"
    api_base_url: str = "https://api.openai.com/v1"
    model_name: str = "gpt-4o-mini"
    timeout_seconds: int = 15
    max_retries: int = 2
    api_key: Optional[str] = None


DEFAULT_PRIORITY_MATRIX = {
    "high_criticality": {
        "production": {
            "CRITICAL": "P1",
            "HIGH": "P1",
            "MEDIUM": "P2",
            "LOW": "P3",
        },
        "non_production": {
            "CRITICAL": "P2",
            "HIGH": "P2",
            "MEDIUM": "P3",
            "LOW": "P4",
        },
    },
    "standard_criticality": {
        "production": {
            "CRITICAL": "P1",
            "HIGH": "P2",
            "MEDIUM": "P3",
            "LOW": "P4",
        },
        "non_production": {
            "CRITICAL": "P2",
            "HIGH": "P3",
            "MEDIUM": "P4",
            "LOW": "P4",
        },
    },
}


class PriorityMatrixConfig(BaseModel):
    high_criticality: Dict[str, Dict[str, str]] = Field(
        default_factory=lambda: DEFAULT_PRIORITY_MATRIX["high_criticality"]
    )
    standard_criticality: Dict[str, Dict[str, str]] = Field(
        default_factory=lambda: DEFAULT_PRIORITY_MATRIX["standard_criticality"]
    )


class ActiveSuppressionConfig(BaseModel):
    require_zero_conflicts: bool = True
    require_zero_missing_fields: bool = True
    min_model_confidence: float = 0.95


class PolicyConfig(BaseModel):
    version: str = "1.0.0"
    default_mode: str = "shadow"
    default_suppression_days: int = 30
    priority_matrix: PriorityMatrixConfig = Field(default_factory=PriorityMatrixConfig)
    prohibited_exclusions: List[str] = Field(
        default_factory=lambda: ["intranet_only", "waf_present", "no_upload_endpoint"]
    )
    active_suppression: ActiveSuppressionConfig = Field(default_factory=ActiveSuppressionConfig)


class ProhibitedPattern(BaseModel):
    regex: str
    name: str


class EgressConfig(BaseModel):
    version: str = "1.0.0"
    enabled: bool = True
    allowed_fields: List[str] = Field(
        default_factory=lambda: [
            "vulnerability_id",
            "ecosystem",
            "package_name",
            "package_version",
            "abstract_environment",
            "approved_facts",
        ]
    )
    prohibited_patterns: List[ProhibitedPattern] = Field(default_factory=list)
    allow_unvetted_free_text: bool = False


class RootConfig(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    policy_file: str = "configs/policy.example.yaml"
    egress_file: str = "configs/egress.example.yaml"
    backend: BackendConfig = Field(default_factory=BackendConfig)

    # Loaded sub-configs
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    egress: EgressConfig = Field(default_factory=EgressConfig)


def load_yaml_file(path: str | Path) -> Dict[str, Any]:
    file_path = Path(path)
    if not file_path.exists():
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        return data or {}


def load_config(config_path: Optional[str | Path] = None) -> RootConfig:
    resolved_path = (
        config_path
        or os.getenv("TRIAGE_CONFIG")
        or "configs/app.example.yaml"
    )
    app_data = load_yaml_file(resolved_path)

    # Merge top level
    root_dict: Dict[str, Any] = {}
    if "app" in app_data:
        root_dict["app"] = app_data["app"]
    if "backend" in app_data:
        root_dict["backend"] = app_data["backend"]
    if "policy_file" in app_data:
        root_dict["policy_file"] = app_data["policy_file"]
    if "egress_file" in app_data:
        root_dict["egress_file"] = app_data["egress_file"]

    # Environment variable overrides
    if os.getenv("TRIAGE_DATABASE_PATH"):
        if "app" not in root_dict:
            root_dict["app"] = {}
        root_dict["app"]["database_path"] = os.getenv("TRIAGE_DATABASE_PATH")

    if os.getenv("TRIAGE_BACKEND_TYPE"):
        if "backend" not in root_dict:
            root_dict["backend"] = {}
        root_dict["backend"]["type"] = os.getenv("TRIAGE_BACKEND_TYPE")

    if os.getenv("TRIAGE_API_KEY"):
        if "backend" not in root_dict:
            root_dict["backend"] = {}
        root_dict["backend"]["api_key"] = os.getenv("TRIAGE_API_KEY")

    if os.getenv("TRIAGE_API_BASE_URL"):
        if "backend" not in root_dict:
            root_dict["backend"] = {}
        root_dict["backend"]["api_base_url"] = os.getenv("TRIAGE_API_BASE_URL")

    # Load policy config
    policy_file_path = root_dict.get("policy_file", "configs/policy.example.yaml")
    policy_data = load_yaml_file(policy_file_path)
    if "policy" in policy_data:
        root_dict["policy"] = policy_data["policy"]
    elif policy_data:
        root_dict["policy"] = policy_data

    # Load egress config
    egress_file_path = root_dict.get("egress_file", "configs/egress.example.yaml")
    egress_data = load_yaml_file(egress_file_path)
    if "egress" in egress_data:
        root_dict["egress"] = egress_data["egress"]
    elif egress_data:
        root_dict["egress"] = egress_data

    return RootConfig(**root_dict)
