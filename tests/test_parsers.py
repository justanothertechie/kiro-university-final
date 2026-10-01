"""Unit tests for deptriage.parsers (REQ-1, REQ-2)."""

import json

import pytest

from deptriage.models import ManifestError
from deptriage.parsers import parse_package_json, parse_requirements_txt


def write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


# --- package.json ---------------------------------------------------------


def test_package_json_basic(tmp_path):
    path = write(
        tmp_path,
        "package.json",
        json.dumps(
            {
                "dependencies": {"lodash": "^4.17.20", "left-pad": "~1.3.0"},
                "devDependencies": {"mocha": ">=10.0.0", "tap": "<=16.0.0", "ava": "=5.0.0"},
            }
        ),
    )
    packages, skipped = parse_package_json(path)
    assert not skipped
    by_name = {p.name: p for p in packages}
    assert by_name["lodash"].version == "4.17.20"
    assert by_name["lodash"].original_spec == "^4.17.20"
    assert by_name["left-pad"].version == "1.3.0"
    assert by_name["mocha"].version == "10.0.0"
    assert by_name["tap"].version == "16.0.0"
    assert by_name["ava"].version == "5.0.0"
    assert all(p.ecosystem == "npm" for p in packages)


def test_package_json_missing_sections_ok(tmp_path):
    path = write(tmp_path, "package.json", json.dumps({"name": "x"}))
    packages, skipped = parse_package_json(path)
    assert packages == [] and skipped == []


def test_package_json_malformed(tmp_path):
    path = write(tmp_path, "package.json", "{not json")
    with pytest.raises(ManifestError):
        parse_package_json(path)


def test_package_json_missing_file(tmp_path):
    with pytest.raises(ManifestError):
        parse_package_json(tmp_path / "package.json")


def test_package_json_skipped_specs(tmp_path):
    path = write(
        tmp_path,
        "package.json",
        json.dumps(
            {
                "dependencies": {
                    "a": "*",
                    "b": "latest",
                    "c": "https://example.com/c.tgz",
                    "d": "git+https://example.com/d.git",
                    "e": "file:../e",
                    "f": ">1.2.3",
                    "g": "1.2.x",
                }
            }
        ),
    )
    packages, skipped = parse_package_json(path)
    assert packages == []
    assert len(skipped) == 7
    assert all(s.reason for s in skipped)


def test_package_json_non_dict_section(tmp_path):
    path = write(tmp_path, "package.json", json.dumps({"dependencies": ["lodash"]}))
    with pytest.raises(ManifestError):
        parse_package_json(path)


# --- requirements.txt ------------------------------------------------------


def test_requirements_basic(tmp_path):
    path = write(
        tmp_path,
        "requirements.txt",
        "requests==2.28.0\nDjango>=3.2\n",
    )
    packages, skipped = parse_requirements_txt(path)
    assert not skipped
    by_name = {p.name: p for p in packages}
    assert by_name["requests"].version == "2.28.0"
    assert by_name["requests"].original_spec == "requests==2.28.0"
    assert by_name["Django"].version == "3.2"  # >= queries the base version
    assert by_name["Django"].original_spec == "Django>=3.2"
    assert all(p.ecosystem == "PyPI" for p in packages)


def test_requirements_noise_forms(tmp_path):
    path = write(
        tmp_path,
        "requirements.txt",
        "# a comment\n"
        "\n"
        "flask[async]==2.3.0  # inline comment\n"
        "celery==5.3.0; python_version > '3.8'\n"
        "urllib3\n"
        "-r other.txt\n"
        "-c constraints.txt\n"
        "--index-url https://example.com/simple\n"
        "weird~=1.0\n",
    )
    packages, skipped = parse_requirements_txt(path)
    by_name = {p.name: p for p in packages}
    assert by_name["flask"].version == "2.3.0"  # extras stripped
    assert by_name["celery"].version == "5.3.0"  # marker stripped
    reasons = {s.raw: s.reason for s in skipped}
    assert reasons["urllib3"] == "no pinned version"
    assert reasons["-r other.txt"] == "option line"
    assert reasons["-c constraints.txt"] == "option line"
    assert reasons["--index-url https://example.com/simple"] == "option line"
    assert "weird~=1.0" in reasons  # unsupported operator -> skipped


def test_requirements_missing_file(tmp_path):
    with pytest.raises(ManifestError):
        parse_requirements_txt(tmp_path / "requirements.txt")
