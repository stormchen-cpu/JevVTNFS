from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from packaging.version import InvalidVersion, Version


def compare_pypi_version(
    version_str: str,
    introduced: Optional[str] = None,
    fixed: Optional[str] = None,
    *,
    introduced_exclusive: Optional[str] = None,
    last_affected: Optional[str] = None,
    exact_version: Optional[str] = None,
) -> Tuple[Optional[bool], str]:
    """
    Compares PyPI versions using packaging.version.Version.
    Returns (is_in_range, reason).
    If version cannot be parsed, returns (None, 'invalid_version_format').
    """
    if not any([introduced, introduced_exclusive, fixed, last_affected, exact_version]):
        return None, "empty_advisory_range"

    try:
        v = Version(version_str)
    except (InvalidVersion, TypeError, ValueError):
        return None, "unsupported_version_format"

    try:
        if exact_version:
            return (v == Version(exact_version)), (
                f"version {version_str} matches exact {exact_version}"
                if v == Version(exact_version)
                else f"version {version_str} != exact {exact_version}"
            )
        if introduced:
            intro_v = Version(introduced)
            if v < intro_v:
                return False, f"version {version_str} is below introduced {introduced}"
        if introduced_exclusive:
            intro_ex_v = Version(introduced_exclusive)
            if v <= intro_ex_v:
                return False, f"version {version_str} is at or below excluded start {introduced_exclusive}"
        if fixed:
            fixed_v = Version(fixed)
            if v >= fixed_v:
                return False, f"version {version_str} is at or above fixed {fixed}"
        if last_affected:
            last_v = Version(last_affected)
            if v > last_v:
                return False, f"version {version_str} is above last_affected {last_affected}"
        return True, f"version {version_str} is in affected range"
    except (InvalidVersion, TypeError, ValueError):
        return None, "unsupported_advisory_range_format"


def _clean_semver(v_str: str) -> Optional[Tuple[int, int, int]]:
    """Simple robust semver tuple extractor (major, minor, patch)."""
    match = re.match(r"^v?(\d+)\.(\d+)(?:\.(\d+))?$", v_str.strip())
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3) or 0)
    return (major, minor, patch)


def _parse_generic_version(v_str: str) -> Optional[Tuple[Tuple[int, ...], str]]:
    """Parses strict numeric versions (e.g. 7.38.0, 8.2504.0) or OpenSSL-style letter patch (1.1.1n, 1.1.1zd).
    Returns None for vendor/distro/git suffixes (e.g. +insyde, +git) so backports are never misclassified.
    """
    s = v_str.strip()
    if any(ch in s for ch in ("+", "~", "_")):
        return None
    m = re.match(r"^v?(\d+(?:\.\d+)*)([a-z]{1,2})?$", s)
    if not m:
        return None
    nums = tuple(int(p) for p in m.group(1).split("."))
    suffix = m.group(2) or ""
    return (nums, suffix)


def _compare_generic_tuples(
    a: Tuple[Tuple[int, ...], str], b: Tuple[Tuple[int, ...], str]
) -> int:
    # Pad numeric tuples to equal length so 7.38 == 7.38.0
    max_len = max(len(a[0]), len(b[0]))
    na = a[0] + (0,) * (max_len - len(a[0]))
    nb = b[0] + (0,) * (max_len - len(b[0]))
    if na != nb:
        return -1 if na < nb else 1
    if a[1] == b[1]:
        return 0
    # OpenSSL convention: '' < 'a'..'z' < 'za'..'zz'
    ka = (len(a[1]), a[1])
    kb = (len(b[1]), b[1])
    return -1 if ka < kb else 1


def compare_generic_version(
    version_str: str,
    introduced: Optional[str] = None,
    fixed: Optional[str] = None,
    *,
    introduced_exclusive: Optional[str] = None,
    last_affected: Optional[str] = None,
    exact_version: Optional[str] = None,
) -> Tuple[Optional[bool], str]:
    """Conservative version comparison for generic C/C++ packages."""
    if not any([introduced, introduced_exclusive, fixed, last_affected, exact_version]):
        return None, "empty_advisory_range"

    v = _parse_generic_version(version_str)
    if v is None:
        return None, "unsupported_or_vendor_version_format"

    bounds = [
        ("exact", exact_version),
        ("introduced", introduced),
        ("introduced_exclusive", introduced_exclusive),
        ("fixed", fixed),
        ("last_affected", last_affected),
    ]
    parsed_bounds: Dict[str, Tuple[Tuple[int, ...], str]] = {}
    for bname, bval in bounds:
        if bval:
            pb = _parse_generic_version(bval)
            if pb is None:
                return None, "unsupported_advisory_range_format"
            parsed_bounds[bname] = pb

    if "exact" in parsed_bounds:
        eq = _compare_generic_tuples(v, parsed_bounds["exact"]) == 0
        return eq, (
            f"version {version_str} matches exact {exact_version}"
            if eq
            else f"version {version_str} != exact {exact_version}"
        )
    if "introduced" in parsed_bounds and _compare_generic_tuples(v, parsed_bounds["introduced"]) < 0:
        return False, f"version {version_str} is below introduced {introduced}"
    if "introduced_exclusive" in parsed_bounds and _compare_generic_tuples(v, parsed_bounds["introduced_exclusive"]) <= 0:
        return False, f"version {version_str} is at or below excluded start {introduced_exclusive}"
    if "fixed" in parsed_bounds and _compare_generic_tuples(v, parsed_bounds["fixed"]) >= 0:
        return False, f"version {version_str} is at or above fixed {fixed}"
    if "last_affected" in parsed_bounds and _compare_generic_tuples(v, parsed_bounds["last_affected"]) > 0:
        return False, f"version {version_str} is above last_affected {last_affected}"
    return True, f"version {version_str} is in affected range"


def compare_npm_version(
    version_str: str,
    introduced: Optional[str] = None,
    fixed: Optional[str] = None,
    *,
    introduced_exclusive: Optional[str] = None,
    last_affected: Optional[str] = None,
    exact_version: Optional[str] = None,
) -> Tuple[Optional[bool], str]:
    """
    Compares npm versions according to semver.
    Returns (is_in_range, reason).
    """
    if not any([introduced, introduced_exclusive, fixed, last_affected, exact_version]):
        return None, "empty_advisory_range"

    v = _clean_semver(version_str)
    if v is None:
        return None, "unsupported_version_format"

    def _parse_bound(bval: str) -> Optional[Tuple[int, int, int]]:
        return _clean_semver(bval)

    if exact_version:
        ev = _parse_bound(exact_version)
        if ev is None:
            return None, "unsupported_advisory_range_format"
        return (v == ev), f"version {version_str} vs exact {exact_version}"

    if introduced:
        intro_v = _parse_bound(introduced)
        if intro_v is None:
            return None, "unsupported_advisory_range_format"
        if v < intro_v:
            return False, f"version {version_str} is below introduced {introduced}"

    if introduced_exclusive:
        intro_ex_v = _parse_bound(introduced_exclusive)
        if intro_ex_v is None:
            return None, "unsupported_advisory_range_format"
        if v <= intro_ex_v:
            return False, f"version {version_str} is at or below excluded start {introduced_exclusive}"

    if fixed:
        fixed_v = _parse_bound(fixed)
        if fixed_v is None:
            return None, "unsupported_advisory_range_format"
        if v >= fixed_v:
            return False, f"version {version_str} is at or above fixed {fixed}"

    if last_affected:
        last_v = _parse_bound(last_affected)
        if last_v is None:
            return None, "unsupported_advisory_range_format"
        if v > last_v:
            return False, f"version {version_str} is above last_affected {last_affected}"

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
    unknown_reason: Optional[str] = None

    for range_def in affected_ranges:
        events = range_def.get("events", [])
        introduced = range_def.get("introduced")
        introduced_exclusive = range_def.get("introduced_exclusive")
        fixed = range_def.get("fixed")
        last_affected = range_def.get("last_affected")
        exact_version = range_def.get("exact_version")

        for ev in events:
            if "introduced" in ev:
                introduced = ev["introduced"]
            if "introduced_exclusive" in ev:
                introduced_exclusive = ev["introduced_exclusive"]
            if "fixed" in ev:
                fixed = ev["fixed"]
            if "last_affected" in ev:
                last_affected = ev["last_affected"]
            if "exact_version" in ev:
                exact_version = ev["exact_version"]

        kwargs = {
            "introduced": introduced,
            "introduced_exclusive": introduced_exclusive,
            "fixed": fixed,
            "last_affected": last_affected,
            "exact_version": exact_version,
        }

        if eco == "pypi":
            res, reason = compare_pypi_version(package_version, **kwargs)
        elif eco == "npm":
            res, reason = compare_npm_version(package_version, **kwargs)
        else:
            res, reason = compare_generic_version(package_version, **kwargs)

        if res is True:
            in_any_range = True
            has_valid_evaluation = True
            break
        if res is None:
            if unknown_reason is None:
                unknown_reason = reason
            continue
        has_valid_evaluation = True

    if in_any_range:
        return True, "package version falls inside advisory affected range"
    if unknown_reason is not None:
        return None, f"version_check_unknown: {unknown_reason}"
    if not has_valid_evaluation:
        return None, "unable_to_evaluate_advisory_ranges"
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
