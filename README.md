# DepTriage

DepTriage is a dependency vulnerability triage assistant: it parses `package.json` and `requirements.txt`, batch-queries the free OSV.dev API, and emits a severity-ranked triage report with fix guidance, exiting non-zero when findings meet your severity threshold. Built with Kiro as a spec-driven, stdlib-only Python CLI.

## Setup

- Python 3.10+
- No runtime dependencies (standard library only)
- Dev only: `pip install -e ".[dev]"` (pytest, hypothesis, ruff)

## Usage

```bash
# Scan one or both manifest types (table output, high threshold by default)
python -m deptriage scan package.json requirements.txt

# JSON report, fail only on critical findings
python -m deptriage scan package.json --format json --threshold critical

# Exit codes: 0 clean/below threshold · 1 threshold met/exceeded · 2 usage error · 3 network failure
```

## How it works

1. **Parse** — manifests become `(name, ecosystem, version)` queries (`npm` / `PyPI`)
2. **Query** — batched POSTs to `https://api.osv.dev/v1/query-batch` (no API key), with timeout + retry
3. **Rank** — CVSS v3 score → critical/high/medium/low; fixed version extracted from OSV ranges or marked `no fix available`
4. **Report** — JSON or human-readable table, sorted by severity

## Kiro University challenge coverage

Every lesson is demonstrated in this repo — see [COVERAGE.md](COVERAGE.md) for the
lesson-to-evidence matrix (specs, steering, hooks, property-based tests, power,
MCP server, custom agent, plus the packaged Bonus 2 power).

## Project layout

```
.kiro/
  specs/deptriage/     # requirements.md (EARS), design.md, tasks.md
  steering/             # tech-stack.md, secure-coding.md
  hooks/               # on-manifest-save.json (PostFileSave → rescan)
  agents/              # triage-agent.json (Lesson 7 custom agent)
  mcp.json             # fetch MCP server for OSV.dev
power/deptriage-power/ # plugin.json + skills/triage/SKILL.md + mcp.json (Bonus 2)
deptriage/             # the CLI: cli, models, parsers, osv, ranker, report
tests/                 # unit + e2e tests (property-based tests via Kiro IDE, Task 9)
```
