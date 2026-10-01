# DepTriage — Lesson-to-evidence coverage matrix

Maps directly to the entry form's **"Lessons demonstrated"** section.
Paths are as they will appear in the final repo (`justanothertechie/kiro-university-final`).

| # | Lesson (credits) | Demonstrated by | Evidence file(s) |
|---|---|---|---|
| 1 | Spec-driven development (250) | EARS-notation requirements, architecture design, sequenced implementation tasks for the DepTriage CLI | `.kiro/specs/deptriage/requirements.md`, `.kiro/specs/deptriage/design.md`, `.kiro/specs/deptriage/tasks.md` |
| 2 | Steering documents (250) | Persistent project conventions: tech stack (Python 3.10+, stdlib-only, ruff-style) and secure-coding rules (input validation, timeouts/retries, no subprocess, no secrets) | `.kiro/steering/tech-stack.md`, `.kiro/steering/secure-coding.md` |
| 3 | Hooks (250) | `PostFileSave` hook re-runs `python -m deptriage scan` whenever `package.json` or `requirements.txt` is saved | `.kiro/hooks/on-manifest-save.json` |
| 4 | Property-based testing (500) | `hypothesis` properties proving the three [PBT] requirements: threshold exit-code equivalence (REQ-6), finding completeness (REQ-7), no dropped critical/high findings (REQ-8) | `tests/test_properties.py` (generated via Kiro IDE per `tasks.md` Task 9; properties stated in `.kiro/specs/deptriage/requirements.md`) |
| 5 | Powers (500) | The `deptriage` Kiro power (manifest + triage skill + MCP wiring) is installed from `power/deptriage-power/` via the Kiro IDE Powers panel; the `triage` skill is loaded into the workspace and used by the custom agent | `power/deptriage-power/plugin.json`, `power/deptriage-power/skills/triage/SKILL.md`, `power/deptriage-power/mcp.json`, `.kiro/agents/triage-agent.json` |
| 6 | Model Context Protocol (1000) | `fetch`-type MCP server registered at `.kiro/settings/mcp.json` so the Kiro agent can query the OSV.dev API during development | `.kiro/settings/mcp.json` |
| 7 | Custom agents (1000) | `triage-agent`: purpose-built agent with read/write/shell tools, shell limited to `python *` / `pytest *`, pre-loaded with the requirements spec and triage runbook skill, MCP + powers enabled | `.kiro/agents/triage-agent.json` |
| B2 | Package a Kiro power — bonus (250) | The same `deptriage` power is packaged in the repo as a complete, shareable power (manifest + skill + MCP config) | `power/deptriage-power/` (plugin.json URL + bundled resources) |

## Notes for the "Lessons demonstrated" write-up
- Lesson 4's evidence (`tests/test_properties.py`) was generated via Kiro IDE (tasks.md Task 9, Lesson 4) and is present in the repo. The properties it proves are specified in `requirements.md` (REQ-6/7/8).
- Lesson 5 and Bonus 2 share one power by design: the power is *used* by the build (Lesson 5) and *packaged* in the repo (Bonus 2). The entry form treats these as separate checkboxes — reference the same `power/deptriage-power/` directory for both, describing use vs. packaging.
- Lesson 5 activation evidence: open this project in Kiro IDE → Powers panel → Install from folder → select `power/deptriage-power/` → the `triage` skill becomes available. The `triage-agent.json` agent references this skill directly.
- Bonus 1 (Kiro Web / cloud sessions, 250) is **not pursued** — paid-plan only, out of reach on the free plan. Reachable max: **5,000 / 5,250**.
- Demo video must show: the scan running on a real manifest, the hook firing on save, and the `triage-agent` in action.
