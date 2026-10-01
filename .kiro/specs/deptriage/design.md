# DepTriage — Design

Technical architecture and sequence diagrams for the DepTriage CLI.

---

## 1. Architecture Overview

DepTriage is a single-process Python CLI with no runtime dependencies. It is
structured as a pipeline of four stages, each implemented as a dedicated module:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   parsers   │───▶│     osv     │───▶│   ranker    │───▶│   report    │
│             │    │             │    │             │    │             │
│ package.json│    │ querybatch  │    │ severity_of │    │ to_table()  │
│ requirements│    │ OSV.dev API │    │ rank()      │    │ to_json()   │
│    .txt     │    │ retry logic │    │ meets_      │    │ exit_code_  │
│             │    │             │    │ threshold() │    │ for()       │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       ▲                                                         │
       │                                                         ▼
  ┌─────────┐                                           ┌─────────────┐
  │   cli   │◀──────────────────────────────────────────│  exit code  │
  │argparse │                                           │  0/1/2/3    │
  └─────────┘                                           └─────────────┘
```

### Module responsibilities

| Module | Responsibility |
|---|---|
| `cli.py` | Argument parsing, orchestration, exit-code policy |
| `parsers.py` | `parse_package_json()`, `parse_requirements_txt()` |
| `osv.py` | `query_batch()` — HTTP client, chunking, retry |
| `ranker.py` | `severity_of()`, `fixed_version_of()`, `rank()`, `meets_threshold()` |
| `report.py` | `to_table()`, `to_json()`, `exit_code_for()` |
| `models.py` | `Package`, `Finding`, `ScanResult`, `SkippedEntry`, error types |

---

## 2. Data Model

```
Package
  name:          str          # e.g. "lodash"
  ecosystem:     str          # "npm" | "PyPI"
  version:       str          # concrete resolved version
  original_spec: str          # as declared in the manifest
  source_file:   str          # path to the originating manifest

Finding
  package:       Package
  osv_id:        str          # primary OSV identifier
  aliases:       list[str]    # CVE / GHSA aliases
  summary:       str
  severity:      str          # critical | high | medium | low | unknown
  score:         float | None # CVSS numeric score
  score_type:    str | None   # "CVSS_V3" | "CVSS_V2"
  fixed_version: str | None   # None → rendered as "no fix available"

ScanResult
  findings:  list[Finding]
  skipped:   list[SkippedEntry]
  summary:   dict[str, int]   # counts per severity
  manifests: list[str]        # paths that were scanned

SkippedEntry
  source_file: str
  raw:         str            # original line/entry
  reason:      str
```

---

## 3. Sequence Diagrams

### 3.1 Happy path — single manifest, table output

```
User          cli.py          parsers.py       osv.py          ranker.py       report.py
 │                │                │               │                │               │
 │─scan pkg.json─▶│                │               │                │               │
 │                │─parse_pkg_json─▶               │                │               │
 │                │                │──(packages)──▶│                │               │
 │                │                │               │─POST /querybatch│             │
 │                │                │               │◀──(vuln IDs)───│               │
 │                │                │               │─GET /vulns/{id}─▶              │
 │                │                │               │◀──(full records)│               │
 │                │                │               │─(pairs)────────────────────────▶│
 │                │                │               │                │─severity_of()  │
 │                │                │               │                │─fixed_ver..()  │
 │                │                │               │                │─rank()─────────▶
 │                │                │               │                │               │─to_table()
 │                │                │               │                │               │──stdout──▶User
 │                │                │               │                │               │
 │                │◀────────────────────────────────────────────────────────────────│
 │                │─exit_code_for()─────────────────────────────────────────────────▶
 │                │◀─────────────────────────────────────────────────────────────────
 │◀──exit(0|1)────│
```

### 3.2 Error paths

```
Trigger               Module        Action
─────────────────────────────────────────────────────────────
Missing file          cli.py        ManifestError → stderr, exit 2
Bad JSON              parsers.py    ManifestError → stderr, exit 2
Unsupported manifest  cli.py        ManifestError → stderr, exit 2
OSV 4xx (non-429)     osv.py        OsvError (no retry) → stderr, exit 3
OSV 5xx / 429         osv.py        Retry ×3 with backoff → OsvError → exit 3
Timeout               osv.py        OsvError → stderr, exit 3
```

### 3.3 Retry logic

```
Attempt 1 ──▶ OSV.dev ──▶ 5xx/429
                              │
                    wait 1 s (exponential backoff)
                              │
Attempt 2 ──▶ OSV.dev ──▶ 5xx/429
                              │
                    wait 2 s
                              │
Attempt 3 ──▶ OSV.dev ──▶ 5xx/429
                              │
                    OsvError raised, exit 3
```

---

## 4. Component Design Notes

### 4.1 Parser — version normalization

`_normalize_npm_spec()` strips `^`, `~`, `>=`, `<=`, `=` prefixes iteratively,
then validates the remainder against `_CONCRETE_VERSION_RE`. Any spec that cannot
be reduced to a concrete version is recorded as a `SkippedEntry` with a human-readable
reason.

For `requirements.txt`, only `==` and `>=` produce queryable versions. Lines with
other operators (`~=`, `!=`, `<`, `>`, `===`) are recorded as skipped with reason
"no pinned version".

### 4.2 OSV client — two-step fetch

The OSV querybatch endpoint (`POST /v1/querybatch`) accepts up to 1,000 queries per
request and returns shallow vuln stubs containing only the vulnerability ID and
`modified` date. `query_batch()` performs a second step: for each unique vuln ID in
the batch response it issues a `GET /v1/vulns/{id}` to retrieve the full record
(severity vector, summary, affected ranges, aliases). Full records are cached within
a chunk to avoid duplicate GETs for the same ID across multiple packages.

If a stub already contains `severity`, `affected`, or `summary` fields (e.g. in
test fixtures that pre-populate full records), the GET step is skipped for that
stub — preserving offline test behaviour.

`query_batch()` slices the package list into chunks of 1,000, POSTs each chunk, and
zips the full-record results back with the original packages in order.

### 4.3 Ranker — CVSS preference

`severity_of()` filters the `severity` array for entries with numeric scores,
prefers `CVSS_V3` type over any other, and falls back to the first numeric entry.
Boolean scores (`true`/`false`) and string scores are explicitly rejected.

### 4.4 Reporter — format independence

`to_table()` and `to_json()` both call `rank()` internally so the sort order is
always consistent regardless of which format is selected. `exit_code_for()` is
format-independent and operates on the raw finding list.

---

## 5. Testing Strategy

| Layer | Tool | Scope |
|---|---|---|
| Unit | pytest | parsers, ranker, report, osv (with recorded fixtures) |
| Property | hypothesis | REQ-6, REQ-7, REQ-8 (see `tests/test_properties.py`) |
| E2E | pytest | Full CLI invocation with fixture manifests and mocked OSV |

Property-based tests use `hypothesis` to generate arbitrary `Finding` lists and
threshold values, verifying the three invariants stated in requirements REQ-6, REQ-7,
and REQ-8 across hundreds of examples per property.
