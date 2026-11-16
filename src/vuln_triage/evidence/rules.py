from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from packaging.version import InvalidVersion, Version


def compare_pypi_version(version_str: str, introduced: Optional[str], fixed: Optional[str]) -> Tuple[Optional[bool], str]:
    """
    Compares PyPI versions using packaging.version.Version.
    Returns (is_in_range, reason).
    If version cannot be parsed, returns (None, 'invalid_version_format').
    """
    try:
        v = Version(version_str)
    except (InvalidVersion, TypeError, ValueError):
        return None, "unsupported_version_format"

    try:
        if introduced:
            intro_v = Version(introduced)
            if v < intro_v:
                return False, f"version {version_str} is below introduced {introduced}"
        if fixed:
            fixed_v = Version(fixed)
            if v >= fixed_v:
                return False, f"version {version_str} is at or above fixed {fixed}"
        return True, f"version {version_str} is in affected range"
    except (InvalidVersion, TypeError, ValueError):
        return None, "unsupported_advisory_range_format"


def _clean_semver(v_str: str) -> Optional[Tuple[int, int, int]]:
    """Simple robust semver tuple extractor (major, minor, patch)."""
    match = re.match(r"^v?(\d+)\.(\d+)(?:\.(\d+))?", v_str.strip())
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3) or 0)
    return (major, minor, patch)


def compare_npm_version(version_str: str, introduced: Optional[str], fixed: Optional[str]) -> Tuple[Optional[bool], str]:
    """
    Compares npm versions according to semver.
    Returns (is_in_range, reason).
    """
    v = _clean_semver(version_str)
    if v is None:
        return None, "unsupported_version_format"

    if introduced:
        intro_v = _clean_semver(introduced)
        if intro_v is None:
            return None, "unsupported_advisory_range_format"
        if v < intro_v:
            return False, f"version {version_str} is below introduced {introduced}"

    if fixed:
        fixed_v = _clean_semver(fixed)
        if fixed_v is None:
            return None, "unsupported_advisory_range_format"
        if v >= fixed_v:
            return False, f"version {version_str} is at or above fixed {fixed}"

    return True, f"version {version_str} is in affected range"


def evaluate_version_range(
    ecosystem: str,
    package_version: Optional[str],
    affected_ranges: List[Dict[str, Any]],
) -> Tuple[Optional[bool], str]:
    """
    Evaluates whether package_version is in the advisory's affected ranges.
    Returns:
      True: Confirmed affected
      False: Confirmed outside affected range
      None: Unknown / cannot parse / missing data
    """
    if not package_version:
        return None, "missing_package_version"

    if not affected_ranges:
        return None, "advisory_lacks_version_ranges"

    eco = ecosystem.lower()
    in_any_range = False
    has_valid_evaluation = False

    for range_def in affected_ranges:
        events = range_def.get("events", [])
        introduced = None
        fixed = None
        for ev in events:
            if "introduced" in ev:
                introduced = ev["introduced"]
            if "fixed" in ev:
                fixed = ev["fixed"]

        if eco == "pypi":
            res, reason = compare_pypi_version(package_version, introduced, fixed)
        elif eco == "npm":
            res, reason = compare_npm_version(package_version, introduced, fixed)
        else:
            # Fallback for generic ecosystem: try pypi parser or semver
            res, reason = compare_npm_version(package_version, introduced, fixed)
            if res is None:
                res, reason = compare_pypi_version(package_version, introduced, fixed)

        if res is None:
            return None, f"version_check_unknown: {reason}"

        has_valid_evaluation = True
        if res is True:
            in_any_range = True
            break

    if not has_valid_evaluation:
        return None, "unable_to_evaluate_advisory_ranges"

    if in_any_range:
        return True, "package version falls inside advisory affected range"
    return False, "package version is outside all advisory affected ranges"


def validate_exclusion_claims(evidence_kinds: List[str], prohibited_exclusions: List[str]) -> List[str]:
    """
    Checks if exclusion relies solely on prohibited negative proofs
    (e.g. only WAF or intranet presence).
    Returns list of violation messages.
    """
    violations = []
    for kind in evidence_kinds:
        if kind in prohibited_exclusions:
            violations.append(
                f"Evidence '{kind}' cannot alone constitute an exclusion proof for vulnerability triage."
            )
    return violations
