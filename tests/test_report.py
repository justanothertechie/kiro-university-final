"""Unit tests for deptriage.report (REQ-5, REQ-6, REQ-7)."""

import json
from pathlib import Path

from deptriage.models import Finding, Package, ScanResult, SkippedEntry
from deptriage.ranker import rank
from deptriage.report import exit_code_for, to_json, to_table

GOLDEN = Path(__file__).parent / "fixtures" / "table_golden.txt"


def make_result():
    pkg_a = Package(name="lodash", ecosystem="npm", version="4.17.20",
                    original_spec="^4.17.20", source_file="package.json")
    pkg_b = Package(name="requests", ecosystem="PyPI", version="2.28.0",
                    original_spec="requests==2.28.0", source_file="requirements.txt")
    findings = [
        Finding(package=pkg_a, osv_id="GHSA-4xc9-xhrj-v574", aliases=["CVE-2020-8203"],
                summary="Prototype pollution in lodash", severity="high",
                score=7.4, score_type="CVSS_V3", fixed_version="4.17.21"),
        Finding(package=pkg_b, osv_id="GHSA-9hjg-9r4m-mvj7", aliases=[],
                summary="Unintended leak of Proxy-Authorization header to destination",
                severity="medium", score=5.9, score_type="CVSS_V3", fixed_version=None),
    ]
    skipped = [SkippedEntry("package.json", "left-pad@latest", "unpinned spec 'latest'")]
    return ScanResult(findings=rank(findings), skipped=skipped,
                      summary={}, manifests=["package.json", "requirements.txt"])


def test_to_json_shape():
    payload = json.loads(to_json(make_result()))
    assert {"generated_at", "manifests", "findings", "summary", "skipped"} <= set(payload)
    assert payload["manifests"] == ["package.json", "requirements.txt"]
    assert set(payload["summary"]["counts"]) == {"critical", "high", "medium", "low", "unknown"}
    assert payload["summary"]["counts"]["high"] == 1
    assert payload["summary"]["counts"]["medium"] == 1
    assert payload["summary"]["total"] == 2
    first = payload["findings"][0]
    # REQ-7 completeness: severity, package, version, ids, summary, fix marker.
    assert first["severity"] == "high"
    assert first["package"] == "lodash"
    assert first["installed_version"] == "4.17.20"
    assert first["ids"]["osv_id"] == "GHSA-4xc9-xhrj-v574"
    assert "CVE-2020-8203" in first["ids"]["aliases"]
    assert first["summary"]
    assert first["fixed_version"] == "4.17.21"
    assert payload["findings"][1]["fixed_version"] == "no fix available"


def test_to_table_golden():
    assert to_table(make_result()) == GOLDEN.read_text(encoding="utf-8")


def test_to_table_empty():
    result = ScanResult(manifests=["package.json"])
    out = to_table(result)
    assert "No vulnerabilities found." in out


def test_exit_code_for():
    result = make_result()
    assert exit_code_for(result.findings, "critical") == 0
    assert exit_code_for(result.findings, "high") == 1
    assert exit_code_for(result.findings, "low") == 1
    assert exit_code_for([], "low") == 0
