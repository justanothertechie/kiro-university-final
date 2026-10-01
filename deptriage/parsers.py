"""Manifest parsers: package.json (npm) and requirements.txt (PyPI)."""

import json
import re
from pathlib import Path

from .models import ManifestError, Package, SkippedEntry

_MAX_LINE_BYTES = 10 * 1024

# A concrete version after normalization: 1.2.3, 1.2, 1, 1.2.3-rc.1 …
_CONCRETE_VERSION_RE = re.compile(r"^\d+(\.\d+)*([.-][0-9A-Za-z.-]+)?$")

# PEP 508-ish simplified package name check.
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")

# Prefixes stripped during npm spec normalization (longest first).
_NPM_PREFIXES = (">=", "<=", "^", "~", "=")


def _normalize_npm_spec(spec: str) -> str | None:
    """Strip range prefixes; return a concrete version or None if not concrete."""
    s = spec.strip()
    changed = True
    while changed:
        changed = False
        for prefix in _NPM_PREFIXES:
            if s.startswith(prefix):
                s = s[len(prefix) :].strip()
                changed = True
                break
    if not s or not _CONCRETE_VERSION_RE.match(s):
        return None
    # "1.2.x" style wildcards are ranges, not concrete versions.
    if re.search(r"(^|[.-])x([.-]|$)", s, re.IGNORECASE):
        return None
    return s


def _skip_reason_npm(spec: str) -> str:
    s = spec.strip()
    if s in ("*", "latest"):
        return f"unpinned spec {s!r}"
    if s.startswith(("http://", "https://", "git+", "file:")):
        return "non-registry spec (url/git/file)"
    if re.match(r"^[<>]", s):
        return "non-concrete version range"
    return "could not normalize to a concrete version"


def parse_package_json(path: str | Path) -> tuple[list[Package], list[SkippedEntry]]:
    """Parse dependencies + devDependencies from a package.json file.

    Returns (packages, skipped). Raises ManifestError on missing file or
    malformed JSON.
    """
    p = Path(path)
    if not p.is_file():
        raise ManifestError(f"{p} not found")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        raise ManifestError(f"{p} is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{p} is not valid JSON")

    packages: list[Package] = []
    skipped: list[SkippedEntry] = []
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            raise ManifestError(f"{p}: {section!r} must be an object")
        for name, spec in deps.items():
            if not isinstance(spec, str):
                skipped.append(SkippedEntry(str(p), f"{name}: {spec!r}", "non-string spec"))
                continue
            version = _normalize_npm_spec(spec)
            if version is None:
                skipped.append(SkippedEntry(str(p), f"{name}@{spec}", _skip_reason_npm(spec)))
                continue
            packages.append(
                Package(
                    name=name,
                    ecosystem="npm",
                    version=version,
                    original_spec=spec,
                    source_file=str(p),
                )
            )
    return packages, skipped


def _strip_inline_comment(line: str) -> str:
    if "#" in line:
        line = line.split("#", 1)[0].rstrip()
    return line


def parse_requirements_txt(path: str | Path) -> tuple[list[Package], list[SkippedEntry]]:
    """Parse a requirements.txt file into (packages, skipped).

    Handles name==x.y, name>=x.y, bare names, extras, inline markers, and
    comments. Option lines (-r, -c, --*) are skipped with a reason.
    Raises ManifestError on missing file.
    """
    p = Path(path)
    if not p.is_file():
        raise ManifestError(f"{p} not found")

    packages: list[Package] = []
    skipped: list[SkippedEntry] = []
    with p.open("rb") as fh:
        for raw_line in fh:
            if len(raw_line) > _MAX_LINE_BYTES:
                skipped.append(SkippedEntry(str(p), "<overlong line>", "line exceeds 10 KB"))
                continue
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line or line.startswith("#"):
                continue
            line = _strip_inline_comment(line).strip()
            if not line:
                continue
            # Option lines: -r, -c, --index-url, …
            if line.startswith("-"):
                skipped.append(SkippedEntry(str(p), line, "option line"))
                continue
            # Inline environment markers: "pkg==1.2; python_version > '3.8'"
            line = line.split(";", 1)[0].strip()
            if not line:
                continue
            # Extras: "pkg[extra]==1.2" -> "pkg==1.2"
            line = re.sub(r"\[[^\]]*\]", "", line).strip()

            name, version, original = _split_req_line(line)
            if name is None:
                skipped.append(SkippedEntry(str(p), line, "could not parse requirement"))
                continue
            if not _NAME_RE.match(name):
                skipped.append(SkippedEntry(str(p), line, "invalid package name"))
                continue
            if version is None:
                skipped.append(SkippedEntry(str(p), line, "no pinned version"))
                continue
            packages.append(
                Package(
                    name=name,
                    ecosystem="PyPI",
                    version=version,
                    original_spec=original,
                    source_file=str(p),
                )
            )
    return packages, skipped


def _split_req_line(line: str) -> tuple[str | None, str | None, str]:
    """Split a requirement line into (name, version|None, original_spec).

    version is None for bare names (skipped upstream). Only == and >=
    produce a queryable version; other operators are unsupported.
    """
    original = line
    for op in ("==", ">="):
        if op in line:
            name, _, ver = line.partition(op)
            name, ver = name.strip(), ver.strip()
            if not name or not ver:
                return None, None, original
            if not _CONCRETE_VERSION_RE.match(ver):
                return name, None, original  # unparseable version -> treated as unpinned
            return name, ver, original
    # Any other operator (<, >, ~=, !=, <=, ===) is unsupported.
    if re.search(r"[<>=!~]", line):
        return line.strip(), None, original  # placeholder name; caller skips as unpinned
    name = line.strip()
    if not name:
        return None, None, original
    return name, None, original
