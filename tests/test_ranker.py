"""Unit tests for deptriage.ranker (REQ-4, REQ-9)."""

from deptriage.models import Finding, Package
from deptriage.ranker import fixed_version_of, meets_threshold, rank, severity_of


def make_finding(name, severity, osv_id="GHSA-x"):
    pkg = Package(name=name, ecosystem="npm", version="1.0.0", original_spec="1.0.0",
                  source_file="package.json")
    return Finding(package=pkg, osv_id=osv_id, severity=severity)


def test_prefers_cvss_v3_over_higher_v2():
    vuln = {"severity": [{"type": "CVSS_V2", "score": 9.5}, {"type": "CVSS_V3", "score": 7.4}]}
    assert severity_of(vuln) == ("high", 7.4, "CVSS_V3")


def test_threshold_boundaries():
    assert severity_of({"severity": [{"type": "CVSS_V3", "score": 9.0}]})[0] == "critical"
    assert severity_of({"severity": [{"type": "CVSS_V3", "score": 8.9}]})[0] == "high"
    assert severity_of({"severity": [{"type": "CVSS_V3", "score": 7.0}]})[0] == "high"
    assert severity_of({"severity": [{"type": "CVSS_V3", "score": 6.9}]})[0] == "medium"
    assert severity_of({"severity": [{"type": "CVSS_V3", "score": 4.0}]})[0] == "medium"
    assert severity_of({"severity": [{"type": "CVSS_V3", "score": 3.9}]})[0] == "low"
    assert severity_of({"severity": [{"type": "CVSS_V3", "score": 0.1}]})[0] == "low"
    assert severity_of({"severity": [{"type": "CVSS_V3", "score": 0}]})[0] == "unknown"


def test_missing_or_bad_severity_is_unknown():
    assert severity_of({}) == ("unknown", None, None)
    assert severity_of({"severity": []}) == ("unknown", None, None)
    assert severity_of({"severity": [{"type": "CVSS_V3", "score": "high"}]}) == ("unknown", None, None)
    assert severity_of({"severity": [{"type": "CVSS_V3", "score": True}]}) == ("unknown", None, None)


def test_fixed_version_first_ecosystem_event():
    vuln = {
        "affected": [
            {
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                    }
                ]
            }
        ]
    }
    assert fixed_version_of(vuln, "npm") == "4.17.21"


def test_fixed_version_skips_git_ranges():
    vuln = {
        "affected": [
            {
                "ranges": [
                    {"type": "GIT", "events": [{"fixed": "deadbeef"}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]},
                ]
            }
        ]
    }
    assert fixed_version_of(vuln, "PyPI") == "2.31.0"


def test_fixed_version_none_when_absent():
    vuln = {"affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
    assert fixed_version_of(vuln, "npm") is None
    assert fixed_version_of({}, "npm") is None


def test_rank_orders_then_names():
    findings = [
        make_finding("zzz", "low"),
        make_finding("aaa", "critical"),
        make_finding("mmm", "unknown"),
        make_finding("bbb", "high"),
        make_finding("ccc", "medium"),
        make_finding("aaa2", "critical"),
    ]
    ranked = rank(findings)
    assert [(f.severity, f.package.name) for f in ranked] == [
        ("critical", "aaa"),
        ("critical", "aaa2"),
        ("high", "bbb"),
        ("medium", "ccc"),
        ("low", "zzz"),
        ("unknown", "mmm"),
    ]


def test_meets_threshold():
    f = make_finding("x", "high")
    assert meets_threshold(f, "high")
    assert meets_threshold(f, "medium")
    assert not meets_threshold(f, "critical")
    assert meets_threshold(make_finding("x", "unknown"), "low") is False
