"""Severity mapping, fixed-version extraction, and finding ranking."""

from .models import Finding

SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
}

ORDERED_SEVERITIES = ("critical", "high", "medium", "low", "unknown")


def _numeric_score(entry: dict) -> float | None:
    score = entry.get("score")
    if isinstance(score, bool):
        return None
    if isinstance(score, (int, float)):
        return float(score)
    return None


def severity_of(vuln: dict) -> tuple[str, float | None, str | None]:
    """Return (label, score, score_type) for an OSV vulnerability dict.

    Prefers CVSS_V3, else the first entry with a numeric score. Non-numeric
    or absent scores yield ("unknown", None, None).
    """
    entries = vuln.get("severity") or []
    if not isinstance(entries, list):
        entries = []
    scored = [e for e in entries if isinstance(e, dict) and _numeric_score(e) is not None]
    preferred = [e for e in scored if e.get("type") == "CVSS_V3"]
    chosen = preferred[0] if preferred else (scored[0] if scored else None)
    if chosen is None:
        return ("unknown", None, None)
    score = _numeric_score(chosen)
    assert score is not None
    score_type = chosen.get("type")
    if score >= 9.0:
        label = "critical"
    elif score >= 7.0:
        label = "high"
    elif score >= 4.0:
        label = "medium"
    elif score > 0:
        label = "low"
    else:
        label = "unknown"
    return (label, score, score_type)


def fixed_version_of(vuln: dict, ecosystem: str) -> str | None:
    """Return the first `fixed` version from the affected ranges, else None.

    Ranges of type GIT are skipped (a commit hash is not a version). Other
    range types are scanned in order; ECOSYSTEM ranges naturally come first
    in OSV responses.
    """
    affected = vuln.get("affected") or []
    if not isinstance(affected, list):
        return None
    for item in affected:
        if not isinstance(item, dict):
            continue
        ranges = item.get("ranges") or []
        if not isinstance(ranges, list):
            continue
        for rng in ranges:
            if not isinstance(rng, dict) or rng.get("type") == "GIT":
                continue
            events = rng.get("events") or []
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, dict) and "fixed" in event:
                    return str(event["fixed"])
    return None


def rank(findings: list[Finding]) -> list[Finding]:
    """Sort findings: critical → high → medium → low → unknown, then package name."""
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.package.name, f.osv_id),
    )


def meets_threshold(finding: Finding, threshold: str) -> bool:
    """True when the finding's severity rank is at or above the threshold rank."""
    return SEVERITY_RANK.get(finding.severity, 0) >= SEVERITY_RANK.get(threshold, 0)
