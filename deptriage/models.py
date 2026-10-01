"""Core data model: Package, Finding, ScanResult, SkippedEntry, and errors."""

from dataclasses import dataclass, field


class ManifestError(Exception):
    """Raised when a manifest file is missing, unreadable, or malformed."""


class OsvError(Exception):
    """Raised when the OSV.dev API cannot be reached or returns an error."""


@dataclass
class Package:
    """A single dependency parsed from a manifest file."""

    name: str
    ecosystem: str  # "npm" or "PyPI"
    version: str  # normalized concrete version sent to OSV.dev
    original_spec: str  # version spec exactly as declared in the manifest
    source_file: str


@dataclass
class Finding:
    """One vulnerability instance for one installed package version."""

    package: Package
    osv_id: str
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    severity: str = "unknown"  # critical|high|medium|low|unknown
    score: float | None = None
    score_type: str | None = None  # e.g. "CVSS_V3"
    fixed_version: str | None = None  # None renders as "no fix available"


@dataclass
class SkippedEntry:
    """A manifest entry that could not be turned into a concrete query."""

    source_file: str
    raw: str
    reason: str


@dataclass
class ScanResult:
    """Aggregate outcome of one scan run."""

    findings: list[Finding] = field(default_factory=list)
    skipped: list[SkippedEntry] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    manifests: list[str] = field(default_factory=list)
