# DepTriage

*Built by Sidd (@hackingSidd on X)*

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
```

## Exit codes

| Code | Meaning | What it means for you |
|:----:|---------|----------------------|
| 🟢 **0** | **Clean** | No findings at or above your threshold — you're good |
| 🔴 **1** | **Findings** | At least one vuln meets/exceeds `--threshold` — action required |
| 🟡 **2** | **Usage error** | Bad arguments or manifest not found — check your command |
| 🌐 **3** | **Network failure** | Couldn't reach OSV.dev after retries — check your connection |

## How it works

1. **Parse** — manifests become `(name, ecosystem, version)` queries (`npm` / `PyPI`)
2. **Batch query** — chunked POSTs to `https://api.osv.dev/v1/querybatch` (no API key), with timeout + retry
3. **Detail fetch** — per-vuln GET to `https://api.osv.dev/v1/vulns/{id}` for full severity + affected data
4. **Rank** — CVSS v3 score → critical/high/medium/low; fixed version extracted from OSV ranges or marked `no fix available`
5. **Report** — JSON or human-readable table, sorted by severity

## Kiro University challenge coverage

Every lesson is demonstrated in this repo — see [COVERAGE.md](COVERAGE.md) for the
lesson-to-evidence matrix (specs, steering, hooks, property-based tests, power,
MCP server, custom agent, plus the packaged Bonus 2 power).

## Power activation (Lesson 5 + Bonus 2)

The `deptriage` power lives in `power/deptriage-power/`. To activate it in Kiro IDE:

1. Open the **Powers** panel (sidebar icon or `Ctrl+Shift+P` → "Powers")
2. Click **Install from folder** and select `power/deptriage-power/`
3. The `triage` skill is now available to all agents in this workspace
4. The power's `mcp.json` wires in the `fetch` MCP server for OSV.dev queries

Evidence: `.kiro/agents/triage-agent.json` references the `triage` skill, and
`power/deptriage-power/plugin.json` declares it as a packaged, shareable power.

## Project layout

```
.kiro/
  specs/deptriage/     # requirements.md (EARS), design.md, tasks.md
  steering/             # tech-stack.md, secure-coding.md
  hooks/               # on-manifest-save.json (PostFileSave → rescan)
  agents/              # triage-agent.json (Lesson 7 custom agent)
  settings/mcp.json    # fetch MCP server for OSV.dev
power/deptriage-power/ # plugin.json + skills/triage/SKILL.md + mcp.json (Bonus 2)
deptriage/             # the CLI: cli, models, parsers, osv, ranker, report
tests/                 # unit + e2e tests (property-based tests via Kiro IDE, Task 9)
```
