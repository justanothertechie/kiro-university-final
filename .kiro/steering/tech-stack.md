---
inclusion: always
---

# DepTriage — Technology Stack

This document is always-included steering. Follow these constraints in every
code-generation and modification task.

## Runtime

- **Language**: Python 3.10+ (use `match`, `X | Y` union types, `str | None`, etc.)
- **Runtime dependencies**: **zero** — standard library only.
  Do not add `requests`, `httpx`, `pydantic`, `click`, or any third-party package
  to `[project.dependencies]`.
- **Dev dependencies** (allowed only in `[project.optional-dependencies]`):
  `hypothesis`, `pytest`, `ruff`

## HTTP

Use `urllib.request.urlopen` with an `urllib.request.Request` object.
Set a combined connect/read timeout of 10 seconds.
Never use `subprocess` to shell out to `curl` or similar tools.

## CLI

Use `argparse` from the standard library. No `click`, `typer`, or `fire`.

## Code style

- Line length: 100 characters.
- Imports: stdlib first, then local package imports; no third-party runtime imports.
- Type hints on all public functions and dataclass fields.
- Prefer dataclasses (`@dataclass`) over plain dicts for structured data.
- Use `pathlib.Path` for all filesystem operations.
- All functions that read files must accept `str | Path`.

## Testing

- Test runner: `pytest`
- Property-based testing: `hypothesis` — use `@given` + `@settings` decorators.
- Unit tests live in `tests/`; fixtures in `tests/fixtures/`.
- Do not make real network calls in tests; use recorded fixtures or `unittest.mock`.

## Linting

- `ruff check` and `ruff format` — match the project's existing ruff configuration.
- No unused imports, no wildcard imports (`from x import *`).
