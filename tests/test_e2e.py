"""End-to-end smoke test (Task 11). Fixture manifests + recorded OSV data.

Fully offline: the urllib transport is replaced with a fake that serves a
recorded batch response keyed by package name.
"""

import json
from pathlib import Path

import pytest

from deptriage import cli, osv

FIXTURES = Path(__file__).parent / "fixtures"
MANIFESTS = FIXTURES / "manifests"


def recorded():
    return json.loads((FIXTURES / "osv" / "batch_basic.json").read_text(encoding="utf-8"))


def fake_post_factory():
    data = recorded()
    by_name = {
        "lodash": data["results"][0],
        "requests": data["results"][1],
        "is-even": {},
        "Django": {},
    }

    def fake_post(url, body, timeout=10):
        queries = json.loads(body.decode("utf-8"))["queries"]
        return {"results": [by_name.get(q["package"]["name"], {}) for q in queries]}

    return fake_post


@pytest.fixture()
def offline(monkeypatch):
    monkeypatch.setattr(osv, "_post_json", fake_post_factory())
    # The fixture stubs already contain full vuln records (severity/affected
    # present), so _get_json is never reached in practice. Patch it anyway
    # to guarantee no live network calls regardless of fixture changes.
    monkeypatch.setattr(osv, "_get_json", lambda url, timeout=10: {})


def manifests():
    return [str(MANIFESTS / "package.json"), str(MANIFESTS / "requirements.txt")]


def test_e2e_table_threshold_low(offline, capsys):
    code = cli.main(["scan", *manifests(), "--format", "table", "--threshold", "low"])
    assert code == 1  # high + medium findings meet the low threshold
    out = capsys.readouterr().out
    assert "GHSA-4xc9-xhrj-v574" in out  # lodash, high
    assert "GHSA-9hjg-9r4m-mvj7" in out  # requests, medium
    assert "Skipped" in out  # left-pad / urllib3 / option lines reported


def test_e2e_table_threshold_critical(offline, capsys):
    code = cli.main(["scan", *manifests(), "--format", "table", "--threshold", "critical"])
    assert code == 0  # nothing critical in the recorded data
    assert "lodash" in capsys.readouterr().out


def test_e2e_json_format(offline, capsys):
    code = cli.main(["scan", *manifests(), "--format", "json", "--threshold", "high"])
    assert code == 1  # lodash high meets the default high threshold
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["counts"]["high"] == 1
    assert payload["summary"]["counts"]["medium"] == 1
    assert payload["summary"]["counts"]["unknown"] == 1  # requests vuln with no severity
    assert len(payload["manifests"]) == 2
    assert len(payload["skipped"]) >= 3  # left-pad, urllib3, -r/-c/--index-url…
