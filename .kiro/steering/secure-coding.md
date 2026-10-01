---
inclusion: always
---

# DepTriage — Secure Coding Guidelines

This document is always-included steering. Apply these rules to every change.

## Input validation

- **File paths**: always resolve via `pathlib.Path`; verify `path.is_file()` before
  opening. Never open a path constructed from user input without validation.
- **Manifest size**: enforce a per-line limit of 10 KB in `requirements.txt` to
  prevent memory exhaustion from adversarially crafted files.
- **JSON parsing**: wrap `json.loads` / `json.load` in try/except for
  `json.JSONDecodeError` and `UnicodeDecodeError`; raise `ManifestError` with a
  safe message that does not echo raw file content.
- **Version strings**: validate against `_CONCRETE_VERSION_RE` before constructing
  OSV queries. Never pass unvalidated user-supplied version strings to external APIs.

## Network

- **Timeouts**: always set a connect/read timeout (10 s) on every `urlopen` call.
  A missing timeout can hang the process indefinitely.
- **Retries**: retry only on 429 (rate-limit) and 5xx (transient server error).
  Do not retry on 4xx client errors — they indicate a programmer bug, not a
  transient failure.
- **No secrets**: the OSV.dev API requires no API key. Do not add authentication
  headers, tokens, or credentials to the HTTP client. If future requirements need
  auth, load credentials from environment variables only — never hardcode them.
- **TLS**: use the default `urllib` HTTPS handling; do not disable SSL verification.

## Subprocess and shell

- **No subprocess**: do not use `subprocess`, `os.system`, `os.popen`, or `shlex`
  to invoke external commands at runtime. All work happens in-process.
- **No eval / exec**: do not use `eval()`, `exec()`, or `compile()` on any
  externally supplied data.

## Error messages

- Write error messages to `stderr`, not `stdout`.
- Error messages must describe the problem without echoing raw file content or
  internal stack traces to end users. Use `ManifestError` and `OsvError` to
  surface safe, human-readable messages.

## Dependency hygiene

- Pin dev dependency versions in `pyproject.toml` only as lower bounds
  (`hypothesis`, `pytest`, `ruff`) — the runtime section stays empty.
- Never commit `.env` files, API keys, or credentials.
