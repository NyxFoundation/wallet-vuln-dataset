#!/usr/bin/env python3
"""gh_rate.py — GitHub rate-limit aware retry for the `gh` CLI crawlers.

Why this module exists
----------------------
The Ethereum-client crawlers treated *any* HTTP 403 as an auth misconfiguration
and aborted the entire run. Across 11 repos that was survivable — the search
budget was never really strained. Across **157 repos** it is fatal: GitHub's
`search/*` endpoints allow 30 requests/minute, so a full crawl (≈35 terms ×
157 repos ≈ 5,500 search calls) *will* hit 403 repeatedly by design, and
aborting on the first one loses every repo after it.

But a 403 is genuinely ambiguous. GitHub returns it for:

  * primary rate limit    — "API rate limit exceeded"      -> wait for reset
  * secondary rate limit  — "secondary rate limit"          -> exponential backoff
  * real auth failure     — bad/absent token, missing scope -> abort, retrying
                                                               will never help

Conflating the third case with the first two would spin forever on a broken
token. So the message is inspected, and only the rate-limit cases are retried.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time

# A 403 whose body matches one of these is a throttle, not an auth problem.
_PRIMARY_RE = re.compile(r"API rate limit exceeded", re.IGNORECASE)
_SECONDARY_RE = re.compile(
    r"secondary rate limit|abuse detection|exceeded a secondary", re.IGNORECASE)

MAX_ATTEMPTS = 6
MAX_SLEEP = 900  # never block longer than 15 min on one call


def classify_403(message: str) -> str:
    """'primary' | 'secondary' | 'auth' for a 403 body."""
    if _SECONDARY_RE.search(message):
        return "secondary"
    if _PRIMARY_RE.search(message):
        return "primary"
    return "auth"


def seconds_until_reset(resource: str = "search") -> int:
    """Seconds until `resource`'s quota resets, per GitHub's own clock.

    Falls back to 60s when the rate_limit endpoint itself is unavailable —
    guessing short is safe because the caller retries.
    """
    try:
        r = subprocess.run(["gh", "api", "rate_limit"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return 60
        data = json.loads(r.stdout)
        res = data.get("resources", {}).get(resource, {})
        reset, remaining = res.get("reset"), res.get("remaining")
        if remaining and remaining > 0:
            return 0
        if reset:
            return max(0, int(reset - time.time())) + 2
    except Exception:
        pass
    return 60


def run_gh(argv: list[str], *, timeout: int = 120, resource: str = "search",
           label: str = "") -> subprocess.CompletedProcess:
    """Run a `gh` command, transparently waiting out rate limits.

    Returns the CompletedProcess of the first non-throttled attempt. Raises
    PermissionError when the 403 is a genuine auth failure, so callers keep
    their existing abort-the-run behaviour for that case only.
    """
    delay = 30
    proc: subprocess.CompletedProcess | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=timeout, encoding="utf-8", errors="replace")
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print(f"  [gh_rate] {label} transport error: {exc}", file=sys.stderr)
            raise

        if proc.returncode == 0:
            return proc

        stderr = (proc.stderr or "")
        if "403" not in stderr and "429" not in stderr:
            return proc                       # some other error; caller handles it

        kind = classify_403(stderr)
        if kind == "auth":
            raise PermissionError(stderr.strip()[:400])

        if kind == "primary":
            wait = min(seconds_until_reset(resource), MAX_SLEEP)
        else:                                  # secondary limit: exponential
            wait = min(delay, MAX_SLEEP)
            delay *= 2

        print(f"  [gh_rate] {label} {kind} rate limit "
              f"(attempt {attempt}/{MAX_ATTEMPTS}) — sleeping {wait}s",
              file=sys.stderr)
        time.sleep(max(1, wait))

    print(f"  [gh_rate] {label} gave up after {MAX_ATTEMPTS} attempts",
          file=sys.stderr)
    assert proc is not None  # MAX_ATTEMPTS >= 1, so the loop always ran once
    return proc


def throttle(resource: str = "search", floor: int = 0) -> None:
    """Pre-emptively sleep when a resource's quota is nearly spent.

    Cheaper than discovering exhaustion via a 403: one rate_limit call (which
    is itself unmetered) buys a precise wait instead of a blind retry.
    """
    wait = seconds_until_reset(resource)
    if wait > floor:
        print(f"  [gh_rate] {resource} quota spent — sleeping {wait}s", file=sys.stderr)
        time.sleep(wait)
