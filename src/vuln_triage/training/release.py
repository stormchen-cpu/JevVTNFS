from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class ReleaseManifest(BaseModel):
    release_id: str
    created_at: str
    model_revision: str
    policy_version: str
    egress_version: str
    evaluation_report_ref: Optional[str] = None
    status: str = "ACTIVE"  # ACTIVE, ARCHIVED, ROLLED_BACK


def activate_release(manifest_path: str | Path, active_link_path: str | Path = "var/models/active_release.json") -> ReleaseManifest:
    m_path = Path(manifest_path)
    if not m_path.exists():
        raise FileNotFoundError(f"Manifest not found: {m_path}")

    data = json.loads(m_path.read_text(encoding="utf-8"))
    manifest = ReleaseManifest(**data)

    target_link = Path(active_link_path)
    target_link.parent.mkdir(parents=True, exist_ok=True)
    target_link.write_text(json.dumps(manifest.model_dump(), indent=2), encoding="utf-8")
    return manifest
