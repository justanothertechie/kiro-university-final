# DepTriage — Implementation Tasks

Sequenced implementation plan. Tasks are numbered; each states its acceptance
criterion so progress can be verified by running `pytest`.

---

## Task 1 — Project scaffold and data model

**Goal**: Create the package layout, `pyproject.toml`, and `deptriage/models.py`.

- [ ] Create `deptriage/` package with `__init__.py` and `__main__.py`
- [ ] Define `Package`, `Finding`, `ScanResult`, `SkippedEntry` dataclasses
- [ ] Define `ManifestError` and `OsvError` exception classes
- [ ] Add `pyproject.toml` with `[project]`, `[build-system]`, and `[project.optional-dependencies]` dev group (`hypothesis`, `pytest`, `ruff`)

**Acceptance**: `python -c "from deptriage.models import Package, Finding"` succeeds.

---

## Task 2 — package.json parser

**Goal**: Implement `deptriage/parsers.py` — `parse_package_json()`.

- [ ] Parse `dependencies` and `devDependencies` sections
- [ ] Implement `_normalize_npm_spec()` to strip `^`, `~`, `>=`, `<=`, `=` prefixes
- [ ] Skip unpinned specs (`*`, `latest`, URL/git/file) with descriptive reason
- [ ] Raise `ManifestError` on missing file or malformed JSON

**Acceptance**: `tests/test_parsers.py::test_package_json_*` all pass.

---

## Task 3 — requirements.txt parser

**Goal**: Implement `parse_requirements_txt()` in `deptriage/parsers.py`.

- [ ] Handle `==` and `>=` pinned versions; skip bare names and unsupported operators
- [ ] Strip inline comments, environment markers (`;`), and extras (`[extra]`)
- [ ] Skip option lines (`-r`, `-c`, `--*`) with reason "option line"
- [ ] Guard against overlong lines (> 10 KB)
- [ ] Raise `ManifestError` on missing file

**Acceptance**: `tests/test_parsers.py::test_requirements_*` all pass.

---

## Task 4 — OSV.dev HTTP client

**Goal**: Implement `deptriage/osv.py` — `query_batch()`.

- [ ] POST to `https://api.osv.dev/v1/query-batch` using `urllib.request`
- [ ] Chunk packages into slices of at most 1,000
- [ ] Set connect/read timeout of 10 seconds
- [ ] Retry up to 3 times with exponential back-off on 429 and 5xx responses
- [ ] Raise `OsvError` on persistent failure, timeout, or non-retryable error
- [ ] Return `list[tuple[Package, dict]]` — one dict per package in input order

**Acceptance**: `tests/test_osv.py` all pass (uses recorded HTTP fixtures).

---

## Task 5 — Severity ranker

**Goal**: Implement `deptriage/ranker.py`.

- [ ] `severity_of(vuln)` — prefer CVSS_V3; map score to critical/high/medium/low/unknown
- [ ] `fixed_version_of(vuln, ecosystem)` — extract first non-GIT `fixed` event
- [ ] `rank(findings)` — sort by severity desc, then package name, then osv_id
- [ ] `meets_threshold(finding, threshold)` — severity rank ≥ threshold rank

**Acceptance**: `tests/test_ranker.py` all pass.

---

## Task 6 — Report renderers

**Goal**: Implement `deptriage/report.py` — `to_table()`, `to_json()`, `exit_code_for()`.

- [ ] `to_table()` — aligned columnar output: SEVERITY, PACKAGE, INSTALLED, IDS, SUMMARY, FIXED
- [ ] Truncate summary at 60 characters; render `None` fixed_version as `"no fix available"`
- [ ] `to_json()` — structured JSON with `generated_at`, `manifests`, `findings`, `summary`, `skipped`
- [ ] `exit_code_for(findings, threshold)` — return 1 if any finding meets threshold, else 0

**Acceptance**: `tests/test_report.py` all pass, including golden-file comparison.

---

## Task 7 — CLI wiring

**Goal**: Implement `deptriage/cli.py` — `main()` and `run_scan()`.

- [ ] `argparse` subcommand `scan` with positional `manifests`, `--format`, `--threshold`
- [ ] Dispatch to `parse_package_json` or `parse_requirements_txt` by filename
- [ ] Catch `ManifestError` → exit 2; catch `OsvError` → exit 3
- [ ] Call `report.to_table()` or `report.to_json()` based on `--format`
- [ ] Return `report.exit_code_for(result.findings, args.threshold)`

**Acceptance**: `tests/test_cli.py` all pass; `python -m deptriage scan --help` works.

---

## Task 8 — End-to-end tests

**Goal**: Add `tests/test_e2e.py` using fixture manifests and a recorded OSV response.

- [ ] Create `tests/fixtures/manifests/package.json` and `requirements.txt`
- [ ] Record `tests/fixtures/osv/batch_basic.json` OSV response
- [ ] Test: table output with `--threshold low` exits 1 and includes expected findings
- [ ] Test: `--threshold critical` exits 0 when no critical findings in fixture
- [ ] Test: `--format json` produces valid JSON

**Acceptance**: `tests/test_e2e.py` all pass.

---

## Task 9 — Property-based tests [PBT — Lesson 4]

**Goal**: Write `tests/test_properties.py` using `hypothesis` to prove REQ-6, REQ-7, REQ-8.

- [ ] **REQ-6**: `exit_code_for(findings, threshold) == 1 iff any(meets_threshold(f, t))`
      for all finding lists and all four threshold levels (300 examples)
- [ ] **REQ-7**: `rank(findings)` is a pure permutation — same object identities,
      same count, no additions or drops (300 examples)
- [ ] **REQ-8**: every `critical` or `high` finding in the input appears in
      `rank(findings)` by object identity (300 examples)
- [ ] Generate `Package` and `Finding` objects via `st.builds()`; use
      `st.sampled_from(ORDERED_SEVERITIES)` for severity

**Acceptance**: `pytest tests/test_properties.py` passes with hypothesis profile `default`.

---

## Task 10 — Packaging and entry point

**Goal**: Ensure the package is installable and the `deptriage` console script works.

- [ ] Verify `[project.scripts] deptriage = "deptriage.cli:main"` in `pyproject.toml`
- [ ] Confirm `pip install -e ".[dev]"` succeeds in a clean venv
- [ ] Confirm `deptriage scan --help` works after install

**Acceptance**: `deptriage scan package.json --format json` runs without error on the fixture.

---

## Task 11 — README and COVERAGE

**Goal**: Write `README.md` and `COVERAGE.md` for the submission.

- [ ] `README.md`: usage examples, exit code table, project layout, setup instructions
- [ ] `COVERAGE.md`: lesson-to-evidence matrix mapping all 7 lessons + Bonus 2 to files

**Acceptance**: Both files present and accurate at submission time.

---

## Task 12 — Final verification

**Goal**: Run the complete test suite and confirm all 43 tests pass.

- [ ] `python -m pytest` — all tests green
- [ ] `python -m deptriage scan tests/fixtures/manifests/package.json tests/fixtures/manifests/requirements.txt` — requires a live OSV.dev network connection; the real CLI calls the API directly (recorded fixtures are used only by the test suite)
- [ ] Confirm `.kiro/` directory is complete (specs, steering, hooks, agents, mcp.json)

**Acceptance**: Zero test failures; all `.kiro/` files present and valid JSON/Markdown.
