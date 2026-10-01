# DepTriage — Requirements

Spec-driven requirements for the DepTriage CLI (Lesson 1 evidence).
Written in EARS (Easy Approach to Requirements Syntax) notation.

---

## Functional Requirements

### REQ-1 — Manifest parsing: package.json

**WHEN** the user supplies a `package.json` path,
**THE SYSTEM SHALL** parse `dependencies` and `devDependencies` and produce one
`Package(name, ecosystem="npm", version)` record per resolvable concrete version,
skipping unpinned specs (e.g. `*`, `latest`, URL/git references) with a recorded
reason.

### REQ-2 — Manifest parsing: requirements.txt

**WHEN** the user supplies a `requirements.txt` path,
**THE SYSTEM SHALL** parse each non-comment, non-option line and produce one
`Package(name, ecosystem="PyPI", version)` record for every `==` or `>=` pinned
entry, skipping bare names, unsupported operators, and option lines (`-r`, `-c`,
`--*`) with a recorded reason.

### REQ-3 — OSV.dev batch query

**WHEN** at least one `Package` record exists after parsing,
**THE SYSTEM SHALL** POST all packages to `https://api.osv.dev/v1/query-batch` in
chunks of at most 1,000, with a connect/read timeout of 10 seconds, retrying up to
3 times with exponential back-off on 429 and 5xx responses, and raising `OsvError`
on persistent failure or non-retryable HTTP errors.

### REQ-4 — Severity ranking

**WHEN** a vulnerability response is received from OSV.dev,
**THE SYSTEM SHALL** assign severity from CVSS v3 score (preferred) or the first
numeric score entry: critical (≥9.0), high (≥7.0), medium (≥4.0), low (>0),
unknown (no numeric score); extract the first non-GIT `fixed` version from
`affected[].ranges[].events`; and return a `Finding` dataclass capturing all fields.

### REQ-5 — Report rendering

**WHEN** all findings have been ranked,
**THE SYSTEM SHALL** render the report in the format requested by `--format`:
- `table` (default): a human-readable aligned table sorted critical → high → medium
  → low → unknown, then by package name, followed by a skipped-entries footer.
- `json`: a JSON object with keys `generated_at`, `manifests`, `findings` (array,
  same sort order), `summary.counts`, `summary.total`, and `skipped`.

### REQ-6 — Exit-code policy [PBT]

**WHEN** the scan completes,
**THE SYSTEM SHALL** exit with code 0 if no finding's severity rank meets or exceeds
the `--threshold` rank, and with code 1 if at least one finding does; exit 2 for
manifest/usage errors; exit 3 for network failures.

**Property** (verified by hypothesis in `tests/test_properties.py`):
`exit_code_for(findings, threshold) == 1` **iff** `any(meets_threshold(f, threshold) for f in findings)`,
and `== 0` otherwise — for all non-empty and empty finding lists and all four threshold levels.

### REQ-7 — Finding completeness [PBT]

**WHEN** the ranker processes a list of findings,
**THE SYSTEM SHALL** return a list that is a pure permutation of the input — no
finding may be added, duplicated, or silently dropped during sorting.

**Property** (verified by hypothesis in `tests/test_properties.py`):
`rank(findings)` returns the same set of object identities as `findings`, with
`len(rank(findings)) == len(findings)`.

### REQ-8 — No dropped critical/high findings [PBT]

**WHEN** the ranker processes a list of findings that includes at least one finding
with severity `critical` or `high`,
**THE SYSTEM SHALL** preserve every such finding in the output, regardless of the
remaining findings in the list.

**Property** (verified by hypothesis in `tests/test_properties.py`):
For all finding lists, every finding with `severity in ("critical", "high")` present
in the input also appears in `rank(findings)` by object identity.

---

## Non-Functional Requirements

### REQ-9 — Standard-library only runtime

**THE SYSTEM SHALL** have zero runtime dependencies beyond the Python 3.10+ standard
library. Dev-only dependencies (`hypothesis`, `pytest`, `ruff`) are permitted in
`[project.optional-dependencies]`.

### REQ-10 — Error surface

**WHEN** any input file is missing, unreadable, or malformed,
**THE SYSTEM SHALL** write a human-readable error to stderr and exit with code 2.

### REQ-11 — Dual-manifest support

**WHEN** the user supplies both a `package.json` and a `requirements.txt`,
**THE SYSTEM SHALL** merge the resulting package lists before querying OSV.dev and
produce a unified, severity-ranked report across both ecosystems.

### REQ-12 — Threshold options

**THE SYSTEM SHALL** accept `--threshold` values of `critical`, `high` (default),
`medium`, and `low`, applying the chosen threshold consistently to the exit-code
decision and report labelling.
