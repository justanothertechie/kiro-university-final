"""CLI-level tests for deptriage.cli (REQ-12). OSV client is stubbed."""

import json

import pytest

from deptriage import cli, osv
from deptriage.models import OsvError, Package


def write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


def stub_query_batch(pairs):
    def _stub(packages):
        assert [p.name for p in packages] == [p.name for p, _ in pairs]
        return pairs
    return _stub


def vuln_response(vulns):
    return {"vulns": vulns}


def high_vuln():
    return {
        "id": "GHSA-test-high",
        "aliases": ["CVE-2024-0001"],
        "summary": "Test high severity vuln",
        "severity": [{"type": "CVSS_V3", "score": 8.1}],
        "affected": [
            {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}
        ],
    }


def medium_vuln():
    return {
        "id": "GHSA-test-medium",
        "aliases": [],
        "summary": "Test medium severity vuln",
        "severity": [{"type": "CVSS_V3", "score": 5.0}],
        "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}],
    }


def test_missing_file_is_usage_error(tmp_path, capsys):
    code = cli.main(["scan", str(tmp_path / "package.json")])
    assert code == 2
    assert "not found" in capsys.readouterr().err


def test_malformed_json_is_usage_error(tmp_path, capsys):
    path = write(tmp_path, "package.json", "{oops")
    code = cli.main(["scan", path])
    assert code == 2
    assert "not valid JSON" in capsys.readouterr().err


def test_unsupported_manifest_is_usage_error(tmp_path, capsys):
    path = write(tmp_path, "Pipfile", "[packages]")
    code = cli.main(["scan", path])
    assert code == 2
    assert "unsupported manifest" in capsys.readouterr().err


def test_network_failure_is_exit_3(tmp_path, monkeypatch, capsys):
    path = write(tmp_path, "package.json", json.dumps({"dependencies": {"x": "1.0.0"}}))

    def boom(packages):
        raise OsvError("OSV.dev is unreachable after retries: boom")

    monkeypatch.setattr(osv, "query_batch", boom)
    code = cli.main(["scan", path])
    assert code == 3
    assert capsys.readouterr().err.startswith("error: ")


def test_threshold_met_is_exit_1(tmp_path, monkeypatch, capsys):
    path = write(tmp_path, "package.json", json.dumps({"dependencies": {"x": "1.0.0"}}))
    pkg = Package(name="x", ecosystem="npm", version="1.0.0", original_spec="1.0.0",
                  source_file=path)
    monkeypatch.setattr(osv, "query_batch", stub_query_batch([(pkg, vuln_response([high_vuln()]))]))
    code = cli.main(["scan", path])
    assert code == 1
    out = capsys.readouterr().out
    assert "GHSA-test-high" in out


def test_clean_is_exit_0(tmp_path, monkeypatch, capsys):
    path = write(tmp_path, "package.json", json.dumps({"dependencies": {"x": "1.0.0"}}))
    pkg = Package(name="x", ecosystem="npm", version="1.0.0", original_spec="1.0.0",
                  source_file=path)
    monkeypatch.setattr(osv, "query_batch", stub_query_batch([(pkg, {})]))
    code = cli.main(["scan", path])
    assert code == 0


def test_below_threshold_is_exit_0(tmp_path, monkeypatch):
    path = write(tmp_path, "package.json", json.dumps({"dependencies": {"x": "1.0.0"}}))
    pkg = Package(name="x", ecosystem="npm", version="1.0.0", original_spec="1.0.0",
                  source_file=path)
    monkeypatch.setattr(osv, "query_batch", stub_query_batch([(pkg, vuln_response([medium_vuln()]))]))
    assert cli.main(["scan", path, "--threshold", "critical"]) == 0
    assert cli.main(["scan", path, "--threshold", "low"]) == 1


def test_json_format_parses(tmp_path, monkeypatch, capsys):
    path = write(tmp_path, "requirements.txt", "x==1.0.0\n")
    pkg = Package(name="x", ecosystem="PyPI", version="1.0.0", original_spec="x==1.0.0",
                  source_file=path)
    monkeypatch.setattr(osv, "query_batch", stub_query_batch([(pkg, vuln_response([medium_vuln()]))]))
    code = cli.main(["scan", path, "--format", "json"])
    assert code == 0  # medium is below the default high threshold
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["counts"]["medium"] == 1
    assert payload["findings"][0]["fixed_version"] == "no fix available"
