"""DepTriage — dependency vulnerability triage CLI.

Parses package.json / requirements.txt manifests, batch-queries the public
OSV.dev API, ranks findings by CVSS severity, and emits a triage report.
Stdlib-only at runtime.
"""

__version__ = "1.0.0"
