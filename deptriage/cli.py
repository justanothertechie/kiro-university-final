"""CLI: argparse wiring, exit-code policy, and scan orchestration."""

import argparse
import sys
from pathlib import Path

from . import osv, parsers, ranker, report
from .models import Finding, ManifestError, OsvError, ScanResult
from .ranker import ORDERED_SEVERITIES

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_USAGE = 2
EXIT_NETWORK = 3


def build_parser() -> argparse.ArgumentParser:
    """Build the deptriage argument parser."""
    parser = argparse.ArgumentParser(
        prog="deptriage",
        description="Scan package.json / requirements.txt for known vulnerabilities via OSV.dev.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan manifest files and print a triage report.")
    scan.add_argument(
        "manifests",
        nargs="+",
        help="Manifest files to scan (package.json and/or requirements.txt).",
    )
    scan.add_argument(
        "--format",
        choices=("json", "table"),
        default="table",
        help="Report format (default: table).",
    )
    scan.add_argument(
        "--threshold",
        choices=ORDERED_SEVERITIES[:4],  # critical|high|medium|low
        default="high",
        help="Minimum severity that flips the exit code to 1 (default: high).",
    )
    return parser


def _fail(message: str, code: int) -> int:
    sys.stderr.write(f"error: {message}\n")
    return code


def _parse_one(path: Path):
    """Dispatch to the right parser by file name; returns (packages, skipped)."""
    name = path.name
    if name == "package.json":
        return parsers.parse_package_json(path)
    if name == "requirements.txt":
        return parsers.parse_requirements_txt(path)
    raise ManifestError(f"unsupported manifest {path} (expected package.json or requirements.txt)")


def run_scan(manifest_paths: list[str]) -> ScanResult:
    """Parse manifests, query OSV.dev, and build a ranked ScanResult.

    Raises ManifestError (usage problems) or OsvError (network problems).
    """
    packages: list = []
    skipped: list = []
    manifests: list[str] = []
    for raw in manifest_paths:
        path = Path(raw)
        if not path.is_file():
            raise ManifestError(f"{path} not found")
        parsed, skipped_here = _parse_one(path)
        packages.extend(parsed)
        skipped.extend(skipped_here)
        if str(path) not in manifests:
            manifests.append(str(path))

    pairs = osv.query_batch(packages) if packages else []

    findings: list[Finding] = []
    for package, response in pairs:
        vulns = response.get("vulns") or []
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            label, score, score_type = ranker.severity_of(vuln)
            findings.append(
                Finding(
                    package=package,
                    osv_id=str(vuln.get("id", "UNKNOWN")),
                    aliases=[str(a) for a in (vuln.get("aliases") or []) if isinstance(a, str)],
                    summary=str(vuln.get("summary") or "(no summary provided)"),
                    severity=label,
                    score=score,
                    score_type=score_type,
                    fixed_version=ranker.fixed_version_of(vuln, package.ecosystem),
                )
            )

    ranked = ranker.rank(findings)
    counts = {sev: 0 for sev in ORDERED_SEVERITIES}
    for finding in ranked:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return ScanResult(findings=ranked, skipped=skipped, summary=counts, manifests=manifests)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code."""
    args = build_parser().parse_args(argv)
    try:
        result = run_scan(args.manifests)
    except ManifestError as exc:
        return _fail(str(exc), EXIT_USAGE)
    except OsvError as exc:
        return _fail(str(exc), EXIT_NETWORK)

    if args.format == "json":
        sys.stdout.write(report.to_json(result))
    else:
        sys.stdout.write(report.to_table(result))
    return report.exit_code_for(result.findings, args.threshold)
