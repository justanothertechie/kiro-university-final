"""Reporters: to_json() and to_table() render the same finding list."""

import json
from datetime import datetime, timezone

from .models import ScanResult
from .ranker import ORDERED_SEVERITIES, SEVERITY_RANK, rank

NO_FIX_MARKER = "no fix available"
_SUMMARY_TRUNCATE = 60


def _finding_dict(finding) -> dict:
    ids = [finding.osv_id] + [a for a in finding.aliases if a != finding.osv_id]
    return {
        "severity": finding.severity,
        "score": finding.score,
        "score_type": finding.score_type,
        "package": finding.package.name,
        "installed_version": finding.package.version,
        "ecosystem": finding.package.ecosystem,
        "ids": {"osv_id": finding.osv_id, "aliases": finding.aliases},
        "id_display": ", ".join(ids),
        "summary": finding.summary,
        "fixed_version": finding.fixed_version if finding.fixed_version else NO_FIX_MARKER,
    }


def to_json(result: ScanResult) -> str:
    """Render the triage report as a JSON string (REQ-5)."""
    findings = rank(result.findings)
    counts = {sev: 0 for sev in ORDERED_SEVERITIES}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "manifests": result.manifests,
        "findings": [_finding_dict(f) for f in findings],
        "summary": {"counts": counts, "total": len(findings)},
        "skipped": [
            {"source_file": s.source_file, "raw": s.raw, "reason": s.reason}
            for s in result.skipped
        ],
    }
    return json.dumps(payload, indent=2)


def _truncate(text: str, width: int) -> str:
    text = " ".join(text.split())
    if len(text) <= width:
        return text
    return text[: width - 3] + "..."


def to_table(result: ScanResult) -> str:
    """Render the triage report as a human-readable table (REQ-5)."""
    findings = rank(result.findings)
    lines: list[str] = []
    if not findings:
        lines.append("No vulnerabilities found.")
    else:
        headers = ("SEVERITY", "PACKAGE", "INSTALLED", "IDS", "SUMMARY", "FIXED")
        rows: list[tuple[str, ...]] = []
        for finding in findings:
            d = _finding_dict(finding)
            rows.append(
                (
                    d["severity"],
                    d["package"],
                    d["installed_version"],
                    d["id_display"],
                    _truncate(d["summary"], _SUMMARY_TRUNCATE),
                    d["fixed_version"],
                )
            )
        widths = [
            max(len(headers[i]), max(len(row[i]) for row in rows)) for i in range(len(headers))
        ]
        fmt = "  ".join("{:<%d}" % w for w in widths)
        lines.append(fmt.format(*headers))
        lines.append(fmt.format(*("-" * w for w in widths)))
        for row in rows:
            lines.append(fmt.format(*row))
    if result.skipped:
        lines.append("")
        lines.append(f"Skipped ({len(result.skipped)}):")
        for entry in result.skipped:
            lines.append(f"  {entry.source_file}: {entry.raw} — {entry.reason}")
    return "\n".join(lines) + "\n"


def exit_code_for(findings, threshold: str) -> int:
    """0 when no finding meets the threshold, else 1 (REQ-6)."""
    threshold_rank = SEVERITY_RANK.get(threshold, 0)
    for finding in findings:
        if SEVERITY_RANK.get(finding.severity, 0) >= threshold_rank:
            return 1
    return 0
