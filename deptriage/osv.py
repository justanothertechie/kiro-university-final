"""OSV.dev client: chunked, retried batch queries over urllib (stdlib only)."""

import json
import time
import urllib.error
import urllib.request

from .models import OsvError, Package

OSV_URL = "https://api.osv.dev/v1/query-batch"
CHUNK_SIZE = 1000
TIMEOUT_SECONDS = 10
MAX_RETRIES = 3  # retries after the initial attempt
BACKOFF_SECONDS = (1, 2, 4)
MAX_RETRY_AFTER_SECONDS = 60


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


def _is_retryable_http(code: int | None) -> bool:
    return code is not None and 500 <= code < 600


def _request_with_retry(post_json, body: bytes, sleep) -> dict:
    """POST with retries: timeouts/connection errors/5xx get exponential backoff.

    HTTP 429 is honored once via Retry-After, then fails. Other 4xx fail fast.
    Raises OsvError on persistent failure.
    """
    retried_429 = False
    for attempt in range(MAX_RETRIES + 1):
        try:
            return post_json(OSV_URL, body)
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
            if _is_retryable_http(code) and attempt < MAX_RETRIES:
                sleep(BACKOFF_SECONDS[attempt])
                continue
            raise OsvError(f"OSV.dev request failed: HTTP {code}") from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            # URLError wraps timeouts and DNS/connection failures.
            if attempt < MAX_RETRIES:
                sleep(BACKOFF_SECONDS[attempt])
                continue
            raise OsvError(f"OSV.dev is unreachable after retries: {exc}") from exc
    raise OsvError("OSV.dev request failed after retries")  # unreachable


def _chunked(packages: list[Package], size: int):
    for i in range(0, len(packages), size):
        yield packages[i : i + size]


def query_batch(
    packages: list[Package],
    post_json=None,
    sleep=None,
) -> list[tuple[Package, dict]]:
    """Query OSV.dev for each package, chunked at <=1000 queries per request.

    Returns [(Package, response_dict)] in the original package order. A
    package with no vulnerabilities yields an empty dict. post_json/sleep are
    injectable for offline tests; defaults use urllib and time.sleep.
    """
    post = post_json or _post_json
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
        data = _request_with_retry(post, body, do_sleep)
        results = data.get("results", [])
        if not isinstance(results, list):
            raise OsvError("OSV.dev returned a malformed response")
        for index, pkg in enumerate(chunk):
            response = results[index] if index < len(results) else {}
            pairs.append((pkg, response if isinstance(response, dict) else {}))
    return pairs
