---
name: triage
description: Run a DepTriage vulnerability triage and interpret the severity-ranked report
---

# DepTriage triage runbook

Use this skill when asked to triage dependency vulnerabilities in a repo.

## 1. Scan

```bash
python -m deptriage scan package.json requirements.txt --format table
```

- Omit manifests that do not exist; at least one is required.
- Default threshold is `high`. Override with `--threshold critical|high|medium|low`.
- Exit code 1 means findings met/exceeded the threshold — that is the signal, not an error.

## 2. Read the report

Each finding carries: severity (critical/high/medium/low/unknown), package, installed
version, OSV/CVE identifiers, summary, and a fixed version or the explicit marker
`no fix available`.

- Work top-down: critical first, then high. Medium/low are informational unless the
  threshold says otherwise.
- A finding with `no fix available` is not actionable via upgrade — suggest
  mitigations (remove the dependency, pin usage, monitor) instead of inventing a version.

## 3. Propose fixes

- Propose the **minimal** manifest change per finding: upgrade to the reported fixed
  version, preserving the project's existing version-spec style (`^`, `~`, `==`).
- Show the diff before applying it. Never rewrite a manifest silently.
- After applying, re-run the scan to confirm the finding is cleared.

## 4. Report back

Summarize: findings by severity, what was fixed, what has no fix, and the final
exit code. Keep it to the facts in the report — do not speculate about exploitability
beyond the CVSS score and summary text.
