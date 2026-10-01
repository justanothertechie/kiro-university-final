"""OSV.dev client: chunked, retried batch queries over urllib (stdlib only).

Two-step fetch:
  1. POST /v1/querybatch  → returns {results: [{vulns: [{id, modified}]}, …]}
  2. GET  /v1/vulns/{id}  → returns the full vulnerability record (severity,
                             summary, affected ranges, aliases, etc.)
Both calls share the same timeout and retry behaviour.
"""

import json
import time
import urllib.error
import urllib.request

from .models import OsvError, Package

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
CHUNK_SIZE = 1000
TIMEOUT_SECONDS = 10
MAX_RETRIES = 3  # retries after the initial attempt
BACKOFF_SECONDS = (1, 2, 4)
MAX_RETRY_AFTER_SECONDS = 60

# Legacy alias so existing tests that reference osv.OSV_URL keep working.
OSV_URL = OSV_BATCH_URL


def _post_json(url: str, body: bytes, timeout: int = TIMEOUT_SECONDS) -> dict:
    """POST a JSON body and return the decoded JSON response dict."""
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _get_json(url: str, timeout: int = TIMEOUT_SECONDS) -> dict:
    """GET a URL and return the decoded JSON response dict."""
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _is_retryable_http(code: int | None) -> bool:
    return code is not None and 500 <= code < 600


def _call_with_retry(fn, *args, sleep, max_retries: int = MAX_RETRIES) -> dict:
    """Call fn(*args) with retries: timeouts/connection errors/5xx get exponential backoff.

    HTTP 429 is honored once via Retry-After, then fails. Other 4xx fail fast.
    Raises OsvError on persistent failure.
    """
    retried_429 = False
    for attempt in range(max_retries + 1):
        try:
            return fn(*args)
        except urllib.error.HTTPError as exc:
            code = exc.code
            if code == 429 and not retried_429:
                retried_429 = True
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                try:
                    delay = min(int(retry_after), MAX_RETRY_AFTER_SECONDS)
                except (TypeError, ValueError):
                    delay = 1
                sleep(delay)
                continue
            if _is_retryable_http(code) and attempt < max_retries:
                sleep(BACKOFF_SECONDS[attempt])
                continue
            raise OsvError(f"OSV.dev request failed: HTTP {code}") from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            if attempt < max_retries:
                sleep(BACKOFF_SECONDS[attempt])
                continue
            raise OsvError(f"OSV.dev is unreachable after retries: {exc}") from exc
    raise OsvError("OSV.dev request failed after retries")  # unreachable


# Keep the old name as an internal alias so test_osv.py's _request_with_retry
# reference paths continue to work (they call query_batch which uses _call_with_retry).
def _request_with_retry(post_json, body: bytes, sleep) -> dict:
    """Legacy shim: wraps _call_with_retry for the POST case."""
    return _call_with_retry(post_json, OSV_BATCH_URL, body, sleep=sleep)


def _chunked(packages: list[Package], size: int):
    for i in range(0, len(packages), size):
        yield packages[i : i + size]


def query_batch(
    packages: list[Package],
    post_json=None,
    get_json=None,
    sleep=None,
) -> list[tuple[Package, dict]]:
    """Query OSV.dev for each package, chunked at <=1000 queries per request.

    Two-step fetch:
      Step 1 – POST /v1/querybatch returns shallow vuln stubs (id + modified).
      Step 2 – GET  /v1/vulns/{id} fetches the full record for each unique ID.

    Returns [(Package, full_vuln_dict_or_empty)] in the original package order.
    A package with no vulnerabilities yields an empty dict.

    post_json / get_json / sleep are injectable for offline tests; defaults use
    urllib and time.sleep.
    """
    do_post = post_json or _post_json
    do_get = get_json or _get_json
    do_sleep = sleep or time.sleep

    pairs: list[tuple[Package, dict]] = []

    for chunk in _chunked(packages, CHUNK_SIZE):
        body = json.dumps(
            {
                "queries": [
                    {
                        "package": {"name": pkg.name, "ecosystem": pkg.ecosystem},
                        "version": pkg.version,
                    }
                    for pkg in chunk
                ]
            }
        ).encode("utf-8")

        data = _call_with_retry(do_post, OSV_BATCH_URL, body, sleep=do_sleep)
        results = data.get("results", [])
        if not isinstance(results, list):
            raise OsvError("OSV.dev returned a malformed response")

        # --- Step 2: fetch full records for every unique vuln ID in this chunk ---
        vuln_cache: dict[str, dict] = {}
        for result in results:
            if not isinstance(result, dict):
                continue
            for stub in result.get("vulns") or []:
                if not isinstance(stub, dict):
                    continue
                vid = stub.get("id")
                if not vid or vid in vuln_cache:
                    continue
                # If the stub already contains severity/affected it's a full
                # record (e.g. served by a fake transport in tests) — use it
                # directly without a network round-trip.
                if "severity" in stub or "affected" in stub or "summary" in stub:
                    vuln_cache[vid] = stub
                else:
                    url = OSV_VULN_URL.format(id=vid)
                    try:
                        full = _call_with_retry(do_get, url, sleep=do_sleep)
                        vuln_cache[vid] = full if isinstance(full, dict) else stub
                    except OsvError:
                        # Degrade gracefully: keep the stub if detail fetch fails.
                        vuln_cache[vid] = stub

        # --- Re-assemble results in original package order ---
        for index, pkg in enumerate(chunk):
            result = results[index] if index < len(results) else {}
            if not isinstance(result, dict):
                result = {}
            stubs = result.get("vulns") or []
            if not isinstance(stubs, list):
                stubs = []
            full_vulns = [
                vuln_cache.get(s.get("id", ""), s)
                for s in stubs
                if isinstance(s, dict) and s.get("id")
            ]
            pairs.append((pkg, {"vulns": full_vulns} if full_vulns else {}))

    return pairs
