"""Severity mapping, fixed-version extraction, and finding ranking.

CVSS v3.x base score computation follows the CVSS 3.1 specification
(https://www.first.org/cvss/v3.1/specification-document), stdlib-only.
"""

import math

from .models import Finding

SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
}

ORDERED_SEVERITIES = ("critical", "high", "medium", "low", "unknown")

# ---------------------------------------------------------------------------
# CVSS v3.x vector → numeric base score
# ---------------------------------------------------------------------------

# Metric value lookup tables (CVSS 3.1 spec, section 7.1)
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED   = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_S  = {"U": "unchanged", "C": "changed"}
_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}


def _roundup(value: float) -> float:
    """CVSS 3.1 'Roundup' function: smallest 0.1 multiple >= value."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return math.floor(int_input / 10000 + 1) / 10.0


def _parse_cvss_v3_vector(vector: str) -> float | None:
    """Parse a CVSS v3.x vector string and return the numeric base score.

    Returns None if the vector is malformed or uses an unsupported version.
    Accepts both 'CVSS:3.0/...' and 'CVSS:3.1/...' prefixes.
    """
    if not isinstance(vector, str):
        return None
    parts = vector.split("/")
    if len(parts) < 9:
        return None
    prefix = parts[0].upper()
    if not (prefix.startswith("CVSS:3")):
        return None

    # Build a key→value map from the remaining metric tokens
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" in part:
            k, _, v = part.partition(":")
            metrics[k.upper()] = v.upper()

    try:
        av  = _AV[metrics["AV"]]
        ac  = _AC[metrics["AC"]]
        scope = _S.get(metrics["S"], "")
        pr  = (_PR_CHANGED if scope == "changed" else _PR_UNCHANGED)[metrics["PR"]]
        ui  = _UI[metrics["UI"]]
        c   = _CIA[metrics["C"]]
        i   = _CIA[metrics["I"]]
        a   = _CIA[metrics["A"]]
    except KeyError:
        return None

    # Exploitability sub-score
    ess = 8.22 * av * ac * pr * ui

    # Impact sub-score
    iss_base = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "unchanged":
        iss = 6.42 * iss_base
    else:
        iss = 7.52 * (iss_base - 0.029) - 3.25 * (iss_base - 0.02) ** 15

    if iss <= 0:
        return 0.0

    if scope == "unchanged":
        score = min(iss + ess, 10)
    else:
        score = min(1.08 * (iss + ess), 10)

    return _roundup(score)


def _extract_numeric_score(entry: dict) -> float | None:
    """Return a numeric CVSS base score from a severity entry dict.

    Accepts:
      - Plain numeric 'score' field (legacy / already-computed)
      - CVSS v3.x vector string in 'score' field (real OSV API format)
    """
    score = entry.get("score")
    if isinstance(score, bool):
        return None
    if isinstance(score, (int, float)):
        return float(score)
    if isinstance(score, str):
        return _parse_cvss_v3_vector(score)
    return None


def severity_of(vuln: dict) -> tuple[str, float | None, str | None]:
    """Return (label, score, score_type) for an OSV vulnerability dict.

    Prefers CVSS_V3, else the first entry with a parseable score. Non-numeric
    and unparseable scores yield ("unknown", None, None).
    """
    entries = vuln.get("severity") or []
    if not isinstance(entries, list):
        entries = []
    scored = [e for e in entries if isinstance(e, dict) and _extract_numeric_score(e) is not None]
    preferred = [e for e in scored if e.get("type") in ("CVSS_V3", "CVSS_V31")]
    chosen = preferred[0] if preferred else (scored[0] if scored else None)
    if chosen is None:
        return ("unknown", None, None)
    score = _extract_numeric_score(chosen)
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
