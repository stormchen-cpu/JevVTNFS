from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def parse_iso_datetime(value: str, default_tz: Optional[str] = "Asia/Taipei") -> datetime:
    """
    Parses ISO-8601 datetime.
    Requires timezone information; if absent and default_tz is provided, localizes to default_tz.
    If no timezone and default_tz is None, raises ValueError.
    """
    cleaned = value.strip()
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        if default_tz:
            try:
                tz = ZoneInfo(default_tz)
                dt = dt.replace(tzinfo=tz)
            except ZoneInfoNotFoundError:
                raise ValueError(f"Invalid timezone specification: {default_tz}")
        else:
            raise ValueError(f"Datetime '{value}' lacks timezone information and no default timezone was specified.")
    return dt


def normalize_string(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    val = value.strip()
    return val if val else None


def normalize_ecosystem(ecosystem: str) -> str:
    cleaned = ecosystem.strip().lower()
    mapping = {
        "pypi": "pypi",
        "python": "pypi",
        "npm": "npm",
        "node": "npm",
        "nodejs": "npm",
        "maven": "maven",
        "golang": "go",
        "go": "go",
        "nuget": "nuget",
        "rubygems": "rubygems",
        "gem": "rubygems",
        "cargo": "cargo",
        "rust": "cargo",
    }
    return mapping.get(cleaned, cleaned)


def normalize_vulnerability_id(vuln_id: str) -> str:
    return vuln_id.strip().upper()
