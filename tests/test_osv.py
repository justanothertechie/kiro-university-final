"""Unit tests for deptriage.osv (REQ-3, REQ-10). No live network anywhere."""

import json
import urllib.error
from pathlib import Path

import pytest

from deptriage import osv
from deptriage.models import OsvError, Package

FIXTURES = Path(__file__).parent / "fixtures" / "osv"


def make_package(name, ecosystem="npm", version="1.0.0"):
    return Package(
        name=name,
        ecosystem=ecosystem,
        version=version,
        original_spec=version,
        source_file="package.json",
    )


def recorded_batch():
    return json.loads((FIXTURES / "batch_basic.json").read_text(encoding="utf-8"))


def http_error(code, retry_after=None):
    headers = {"Retry-After": str(retry_after)} if retry_after is not None else {}
    return urllib.error.HTTPError(
        osv.OSV_URL, code, f"HTTP {code}", headers, None
    )


class FakeTransport:
    """Scripted post_json replacement. behaviours: dict | Exception per call."""

    def __init__(self, behaviours):
        self.behaviours = list(behaviours)
        self.calls = []
        self.sleeps = []

    def __call__(self, url, body):
        self.calls.append((url, json.loads(body.decode("utf-8"))))
        behaviour = self.behaviours.pop(0) if self.behaviours else {"results": []}
        if isinstance(behaviour, Exception):
            raise behaviour
        return behaviour

    def sleep(self, seconds):
        self.sleeps.append(seconds)


def test_query_shape_and_order():
    transport = FakeTransport([recorded_batch()])
    packages = [make_package("lodash"), make_package("requests", "PyPI"), make_package("is-even")]
    pairs = osv.query_batch(packages, post_json=transport, sleep=transport.sleep)
    assert [p.name for p, _ in pairs] == ["lodash", "requests", "is-even"]
    assert len(pairs[0][1]["vulns"]) == 1
    assert len(pairs[1][1]["vulns"]) == 2
    assert pairs[2][1] == {}  # no vulns -> empty dict, not an error
    query = transport.calls[0][1]["queries"][0]
    assert query == {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "1.0.0"}


def test_chunks_at_1000():
    transport = FakeTransport([])
    packages = [make_package(f"pkg{i}") for i in range(1001)]
    pairs = osv.query_batch(packages, post_json=transport, sleep=transport.sleep)
    assert len(transport.calls) == 2
    assert len(transport.calls[0][1]["queries"]) == 1000
    assert len(transport.calls[1][1]["queries"]) == 1
    assert len(pairs) == 1001


def test_retry_then_success():
    transport = FakeTransport(
        [
            urllib.error.URLError("boom"),
            urllib.error.URLError("boom"),
            {"results": []},
        ]
    )
    pairs = osv.query_batch([make_package("x")], post_json=transport, sleep=transport.sleep)
    assert len(pairs) == 1 and pairs[0][1] == {}
    assert len(transport.calls) == 3
    assert transport.sleeps == [1, 2]


def test_persistent_failure_raises_after_retries():
    transport = FakeTransport([urllib.error.URLError("down")] * 10)
    with pytest.raises(OsvError):
        osv.query_batch([make_package("x")], post_json=transport, sleep=transport.sleep)
    assert len(transport.calls) == 4  # initial + 3 retries
    assert transport.sleeps == [1, 2, 4]


def test_404_fails_fast():
    transport = FakeTransport([http_error(404)])
    with pytest.raises(OsvError, match="HTTP 404"):
        osv.query_batch([make_package("x")], post_json=transport, sleep=transport.sleep)
    assert len(transport.calls) == 1
    assert transport.sleeps == []


def test_500_retried_then_success():
    transport = FakeTransport([http_error(500), {"results": []}])
    pairs = osv.query_batch([make_package("x")], post_json=transport, sleep=transport.sleep)
    assert len(pairs) == 1
    assert len(transport.calls) == 2
    assert transport.sleeps == [1]


def test_429_honored_once_then_fails():
    transport = FakeTransport([http_error(429, retry_after=0), http_error(429, retry_after=0)])
    with pytest.raises(OsvError):
        osv.query_batch([make_package("x")], post_json=transport, sleep=transport.sleep)
    assert len(transport.calls) == 2
    assert transport.sleeps == [0]


def test_malformed_response_raises():
    transport = FakeTransport([{"results": "nope"}])
    with pytest.raises(OsvError):
        osv.query_batch([make_package("x")], post_json=transport, sleep=transport.sleep)
