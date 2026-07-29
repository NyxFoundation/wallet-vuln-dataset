#!/usr/bin/env python3
"""Scrape security-related commits from in-scope Ethereum wallet repos via
`gh api search/commits`, producing CSVs that round-trip through
`scripts/datasets/build_derived.py`.

This script is Phase A's "commit-grep" slice — it pulls commit subjects that
match security-relevant terms but were never associated with a GHSA advisory,
PR, or CHANGELOG entry in the earlier slices (crawl_wallet_past_fixes.py).
Squash-merged commits, direct-push security patches, and backports often fall
into this category.

Output layout (mirrors the GHSA/PR slice):
    <out-dir>/<wallet>.commits.csv
    <out-dir>/<wallet>.commits_manifest.json

The CSV columns match what `scripts/datasets/build_derived.py` already
accepts (issue #2 schema):
    source, contest, issue_id, severity, title, description,
    source_url, introduced_in_commit

Usage:
    # Single wallet:
    uv run python3 benchmarks/scripts/grep_wallet_commits.py \\
        --wallet geth --out-dir benchmarks/data/ethereum_past_fixes

    # All 11 wallets (slow — respects 30 req/min rate limit with sleep):
    uv run python3 benchmarks/scripts/grep_wallet_commits.py \\
        --wallet all --out-dir benchmarks/data/ethereum_past_fixes

    # Smoke test — cap rows per wallet:
    uv run python3 benchmarks/scripts/grep_wallet_commits.py \\
        --wallet geth --out-dir /tmp/commits_smoke --max-records 100
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

# ---------------------------------------------------------------------------
# Import WALLET_CONFIG and CSV_FIELDS from the sibling crawl script.
# Using importlib keeps us dep-free (no package install needed) and avoids
# a circular import if this module is loaded by tests via the same helper.
# ---------------------------------------------------------------------------
_CRAWL_SCRIPT = Path(__file__).resolve().parent / "crawl_wallet_past_fixes.py"

def _load_crawl_module():
    spec = importlib.util.spec_from_file_location("_crawl_wallet_past_fixes", _CRAWL_SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {_CRAWL_SCRIPT}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod

_crawl = _load_crawl_module()

WALLET_CONFIG: dict[str, dict] = _crawl.WALLET_CONFIG
CSV_FIELDS: tuple[str, ...] = _crawl.CSV_FIELDS

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Search terms for `gh api search/commits`.  Each term is issued as a
# separate query (repo:<slug> <term>) so we stay under the 1,000-result cap
# per search API call and cast a wider net than a single compound query.
SECURITY_TERMS: tuple[str, ...] = (
    "security",
    "vulnerability",
    "CVE-",
    "DoS",
    "panic",
    "crash",
    "RCE",
    "memory leak",
    "integer overflow",
    "race condition",
)

# Regex to infer severity from a commit subject line.  Matches
# Critical/High/Medium/Low case-insensitively; defaults to "Info".
SEVERITY_RE = re.compile(r"\b(Critical|High|Medium|Low)\b", re.I)

# Cap collected commits per (repo, term) query to bound API spend.
# search/commits counts against the `core` rate limit (30 req/min for
# authenticated users).  Keeping this conservative lets an all-wallet run
# finish in one rate-limit window per wallet.
MAX_COMMITS_PER_TERM = 200


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class AuthError(Exception):
    """Raised when the GitHub API returns 401/403, indicating an auth
    misconfiguration that will affect every subsequent wallet.  The caller
    should abort the entire --wallet all run rather than skipping one wallet."""


# ---------------------------------------------------------------------------
# GitHub search helpers
# ---------------------------------------------------------------------------

def _extract_http_status(stderr_text: str) -> int | None:
    """Extract the HTTP status code from gh stderr output.

    gh stderr typically contains lines like:
        gh: Repository name not found (HTTP 422)
        gh: Must have push access to repository (HTTP 403)
    or raw JSON error bodies with a "status" field.
    Returns the integer status code, or None if not found.
    """
    import re as _re
    # Pattern: "HTTP <status>" or "status: <status>" in gh output
    m = _re.search(r"HTTP (\d{3})", stderr_text)
    if m:
        return int(m.group(1))
    # gh sometimes writes the status as part of a JSON error body on stderr
    m = _re.search(r'"status":\s*(\d{3})', stderr_text)
    if m:
        return int(m.group(1))
    return None


def search_commits(repo: str, term: str) -> list[dict]:
    """Return up to MAX_COMMITS_PER_TERM commit search-result dicts for the
    given repo + term.

    Shells out to `gh api -X GET search/commits` with
    `--paginate` so gh walks the Link header automatically.

    Rate-limit note: search/commits is on the `core` limit (30 req/min for
    authenticated users).  Callers are responsible for sleeping between calls;
    a 2-second sleep is baked into `fetch_security_commits`.

    Raises:
        AuthError: on HTTP 401/403 (auth misconfiguration — abort all wallets).
    Returns:
        Empty list on HTTP 422 (repo too large / unsupported) or other errors.
    """
    query = f"repo:{repo} {term}"
    try:
        result = subprocess.run(
            [
                "gh", "api", "-X", "GET", "search/commits",
                "-f", f"q={query}",
                "-f", "per_page=100",
                "--paginate",
                "-H", "Accept: application/vnd.github.cloak-preview+json",
            ],
            capture_output=True, text=True, timeout=120,
            encoding="utf-8", errors="replace",
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        print(f"  [warn] gh failed for term {term!r}: {exc}", file=sys.stderr)
        return []

    if result.returncode != 0:
        msg = (result.stderr or "").strip()[:300]
        status = _extract_http_status(result.stderr or "")

        if status in (401, 403):
            # Auth failure — raise so the caller can abort all subsequent wallets.
            raise AuthError(
                f"GitHub API returned HTTP {status} for term {term!r} on {repo}: {msg}"
            )
        if status == 422:
            # Repo too large for search/commits index — legitimate skip.
            print(
                f"  [warn] gh exit {result.returncode} (HTTP 422) for term {term!r} on {repo}: "
                f"repo too large for search/commits index — skipping term",
                file=sys.stderr,
            )
            return []

        # Other non-zero exit: warn and continue.
        print(
            f"  [warn] gh exit {result.returncode} for term {term!r}: {msg}",
            file=sys.stderr,
        )
        return []

    body = result.stdout.strip()
    if not body:
        return []

    # `--paginate` concatenates multiple JSON objects on separate lines when
    # the endpoint returns paginated results.  The search/commits endpoint
    # wraps each page in {"items": [...], "total_count": N} — we need to
    # flatten across pages.
    items: list[dict] = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            page = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(page, dict):
            items.extend(page.get("items") or [])
        elif isinstance(page, list):
            # gh --paginate sometimes emits a bare array; handle gracefully.
            items.extend(page)
        if len(items) >= MAX_COMMITS_PER_TERM:
            break

    return items[:MAX_COMMITS_PER_TERM]


def fetch_security_commits(repo: str) -> list[dict]:
    """Iterate SECURITY_TERMS, search commits for each, deduplicate by SHA.

    A 2-second sleep between terms keeps us well under the search/commits
    rate limit of 30 req/min for authenticated users (2s/call = 30 calls/min
    exactly at the limit; sleeping ensures we stay under it).
    """
    seen_sha: set[str] = set()
    all_commits: list[dict] = []

    for i, term in enumerate(SECURITY_TERMS, 1):
        print(
            f"  [{repo}] term {i}/{len(SECURITY_TERMS)}: {term!r} ...",
            file=sys.stderr,
        )
        commits = search_commits(repo, term)
        new_count = 0
        for c in commits:
            sha = c.get("sha", "")
            if sha and sha not in seen_sha:
                seen_sha.add(sha)
                all_commits.append(c)
                new_count += 1
        print(
            f"  [{repo}] term {i}/{len(SECURITY_TERMS)}: {term!r} -> "
            f"{len(commits)} hits, {new_count} new (total {len(all_commits)})",
            file=sys.stderr,
        )
        # Respect the search/commits rate limit: 30 req/min authenticated.
        time.sleep(2)

    return all_commits


# ---------------------------------------------------------------------------
# Row projection
# ---------------------------------------------------------------------------

def commit_to_row(commit: dict, wallet_slug: str, repo: str) -> dict | None:
    """Project one commit search-result dict onto the build_derived CSV schema.

    Returns None for:
    - empty subjects (unparseable commits)
    - merge commits: "Merge <anything>" — high volume, low security signal
    - revert commits: "Revert <anything>" — similarly noisy without extra context

    The issue_id prefix COMMIT# is chosen to never collide with the prefixes
    used by the other pipeline slices:
        GHSA-   — GitHub Security Advisories (crawl_wallet_past_fixes.py)
        PR#     — Pull-request titles (crawl_wallet_past_fixes.py)
        ISSUE#  — Issue bodies (crawl_wallet_past_fixes.py)
        CHANGELOG# — Changelog entries
        RELEASE#   — Release notes
    """
    sha = commit.get("sha", "")
    message = commit.get("commit", {}).get("message", "") or ""

    # Split subject (first line) from body (remainder after first blank line).
    if "\n\n" in message:
        subject, body = message.split("\n\n", 1)
    elif "\n" in message:
        subject, body = message.split("\n", 1)
    else:
        subject, body = message, ""

    subject = subject.strip()
    body = body.strip()

    if not subject:
        return None

    # Drop merge commits — they are usually auto-generated ("Merge pull
    # request #NNN from ...") and carry no unique security signal.
    # Drop revert commits — the original commit already covers the finding.
    if subject.startswith("Merge ") or subject.startswith("Revert "):
        return None

    # Infer severity from subject; default to Info.
    m = SEVERITY_RE.search(subject)
    if m:
        # Normalize to Title case so we get High / Medium / Low / Critical.
        raw = m.group(1).capitalize()
        # Collapse Critical to High (downstream enum doesn't distinguish).
        severity = "High" if raw == "Critical" else raw
    else:
        severity = "Info"

    return {
        "source": wallet_slug,
        "contest": repo,
        "issue_id": f"COMMIT#{sha[:12]}",
        "severity": severity,
        "title": subject[:120],
        "description": body,
        "source_url": commit.get("html_url", ""),
        # This IS the fix commit, not the introducing commit.
        "introduced_in_commit": "",
    }


# ---------------------------------------------------------------------------
# Per-wallet crawl
# ---------------------------------------------------------------------------

def crawl_commits(
    wallet_slug: str,
    *,
    fetcher: Callable[[str], list[dict]] = fetch_security_commits,
) -> list[dict]:
    """Crawl security commits for one wallet.  `fetcher` is injectable so
    tests can stub the GitHub round-trip without touching subprocess."""
    if wallet_slug not in WALLET_CONFIG:
        sys.exit(
            f"unknown wallet {wallet_slug!r}; known: {sorted(WALLET_CONFIG)}"
        )
    repo = WALLET_CONFIG[wallet_slug]["repo"]

    raw_commits = fetcher(repo)
    rows: list[dict] = []
    for c in raw_commits:
        row = commit_to_row(c, wallet_slug, repo)
        if row is not None:
            rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def write_csv(rows: Iterable[dict], out_path: Path) -> int:
    """Write rows to out_path in canonical column order.  Returns row count."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in CSV_FIELDS})
            n += 1
    return n


def write_manifest(
    out_path: Path,
    *,
    wallet: str,
    repo: str,
    n_search_terms: int,
    n_commits_searched: int,
    n_rows: int,
    crawled_at: str,
    gh_version: str,
) -> None:
    """Provenance snapshot for auditing / re-run comparisons."""
    manifest = {
        "wallet": wallet,
        "repo": repo,
        "n_search_terms": n_search_terms,
        "n_commits_searched": n_commits_searched,
        "n_rows": n_rows,
        "crawled_at": crawled_at,
        "gh_version": gh_version,
        "source_url": f"https://github.com/{repo}/commits",
    }
    out_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _gh_version() -> str:
    try:
        v = subprocess.run(
            ["gh", "--version"], capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
        if v.returncode == 0:
            return v.stdout.strip().splitlines()[0]
    except Exception:
        pass
    return ""


def crawl_and_write(
    wallet_slug: str,
    out_dir: Path,
    *,
    max_records: int | None = None,
) -> int:
    """Top-level: crawl, write CSV + manifest, return row count."""
    repo = WALLET_CONFIG[wallet_slug]["repo"]
    print(
        f"[{wallet_slug}] searching commits on {repo} "
        f"({len(SECURITY_TERMS)} terms) ...",
        file=sys.stderr,
    )

    rows: list[dict] = []
    raw_commits: list[dict] = []

    # We need raw commit count for the manifest; re-implement the crawl here
    # so we can capture the intermediate count before max_records truncation.
    def _capturing_fetcher(r: str) -> list[dict]:
        commits = fetch_security_commits(r)
        raw_commits.extend(commits)
        return commits

    rows = crawl_commits(wallet_slug, fetcher=_capturing_fetcher)
    if max_records:
        rows = rows[:max_records]

    csv_path = out_dir / f"{wallet_slug}.commits.csv"
    manifest_path = out_dir / f"{wallet_slug}.commits_manifest.json"

    n = write_csv(rows, csv_path)
    crawled_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_manifest(
        manifest_path,
        wallet=wallet_slug,
        repo=repo,
        n_search_terms=len(SECURITY_TERMS),
        n_commits_searched=len(raw_commits),
        n_rows=n,
        crawled_at=crawled_at,
        gh_version=_gh_version(),
    )
    print(f"[{wallet_slug}] wrote {n} rows -> {csv_path}", file=sys.stderr)
    return n


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--wallet", required=True,
        help=(
            "Wallet slug (one of: " + ", ".join(sorted(WALLET_CONFIG))
            + ") or 'all' for the full set."
        ),
    )
    p.add_argument(
        "--out-dir", default="benchmarks/data/ethereum_past_fixes",
        help="Output directory (default: benchmarks/data/ethereum_past_fixes).",
    )
    p.add_argument(
        "--max-records", type=int, default=0,
        help="Cap rows per wallet (0 = no cap).  Useful for smoke tests.",
    )
    args = p.parse_args()

    out_dir = Path(args.out_dir)
    if args.wallet == "all":
        wallets = sorted(WALLET_CONFIG)
    else:
        if args.wallet not in WALLET_CONFIG:
            sys.exit(
                f"unknown --wallet {args.wallet!r}; pass 'all' or one of: "
                f"{sorted(WALLET_CONFIG)}"
            )
        wallets = [args.wallet]

    cap = args.max_records or None
    total = 0
    per_client: dict[str, int] = {}
    for c in wallets:
        try:
            n = crawl_and_write(c, out_dir, max_records=cap)
        except AuthError as exc:
            # 401/403 is an auth misconfiguration that will affect every
            # subsequent wallet — abort the entire run with a loud message.
            print(
                f"\n[FATAL] GitHub auth failure while processing [{c}]: {exc}\n"
                f"This affects all subsequent wallets. Aborting --wallet all run.\n"
                f"Fix your gh auth (run `gh auth login` or check GITHUB_TOKEN).",
                file=sys.stderr,
            )
            return 1
        except Exception as exc:
            # 422 (repo too large for search/commits index) and other transient
            # errors are already handled inside search_commits; this catches any
            # remaining unexpected exceptions per wallet — warn and continue.
            print(
                f"[{c}] SKIP — unexpected error: {exc}",
                file=sys.stderr,
            )
            n = 0
        per_client[c] = n
        total += n

    print(
        f"\ndone — {total} rows across {len(wallets)} wallet(s)",
        file=sys.stderr,
    )
    for c, n in per_client.items():
        print(f"  {c}: {n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
