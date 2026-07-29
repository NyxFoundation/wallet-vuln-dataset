#!/usr/bin/env python3
"""mine_direct_pulls.py — Fetch PRs via direct REST pagination instead of GitHub Search.

Root cause of missing data: GitHub Search index does not catch up after repo
transfers (ConsenSys/teku ← PegaSysEng/teku). The search API returns only ~166
PRs when the actual count is ~10,792. This script bypasses the search index by
using the direct `repos/{owner}/{repo}/pulls` REST endpoint.

This script supplements crawl_wallet_past_fixes.py for wallets where Search fails:
  - teku  (ConsenSys/teku — post-transfer index gap)
  - besu  (hyperledger/besu — broad issue labelling, search misses body content)

Key differences from the search-based approach:
  - Uses `repos/{repo}/pulls?state=closed&per_page=100` — direct REST, not search.
  - Filters wallet-side: title OR first 1000 chars of body must contain a keyword.
  - Paginates with a configurable `--max-pages` cap to avoid rate-limit burn.

Output CSV schema (matches build_derived.py / merge_crawl_csvs.py):
    source, contest, issue_id, severity, title, description,
    source_url, introduced_in_commit

Usage:
    # Smoke test: first 5 pages of teku PRs
    uv run python3 benchmarks/scripts/mine_direct_pulls.py \\
        --wallet teku --out-dir C:\\tmp\\teku_direct --max-pages 5

    # Full crawl for both wallets
    uv run python3 benchmarks/scripts/mine_direct_pulls.py \\
        --wallet all --out-dir dataset/ethereum_past_fixes/direct_prs
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

# ---------------------------------------------------------------------------
# Wallet registry — only wallets where Search fails belong here.
# Full 11-wallet coverage lives in crawl_wallet_past_fixes.py.
# ---------------------------------------------------------------------------
import importlib.util as _ilu
from pathlib import Path as _P
_WSPEC = _ilu.spec_from_file_location("_wallets", _P(__file__).resolve().parent / "wallets.py")
_wallets_mod = _ilu.module_from_spec(_WSPEC); _WSPEC.loader.exec_module(_wallets_mod)  # type: ignore
WALLET_REPOS: dict[str, str] = {s: c["repo"] for s, c in _wallets_mod.WALLET_CONFIG.items()}

# ---------------------------------------------------------------------------
# Security keyword lists
# ---------------------------------------------------------------------------

import importlib.util as _ilu
from pathlib import Path as _P
_VSPEC = _ilu.spec_from_file_location("_wallet_vocab", _P(__file__).resolve().parent / "wallet_vocab.py")
_vocab = _ilu.module_from_spec(_VSPEC); _VSPEC.loader.exec_module(_vocab)  # type: ignore
_WSPEC2 = _ilu.spec_from_file_location("_wallets2", _P(__file__).resolve().parent / "wallets.py")
_wal = _ilu.module_from_spec(_WSPEC2); _WSPEC2.loader.exec_module(_wal)  # type: ignore


def _terms_for(slug: str) -> list[str]:
    cfg = _wal.WALLET_CONFIG.get(slug, {})
    return _vocab.search_terms(slug, cfg.get("category", ""), _wal.language_of(slug))

import importlib.util as _ilu3
from pathlib import Path as _P3
_GSPEC = _ilu3.spec_from_file_location("_gh_rate", _P3(__file__).resolve().parent / "gh_rate.py")
_ghr = _ilu3.module_from_spec(_GSPEC); _GSPEC.loader.exec_module(_ghr)  # type: ignore

SECURITY_KEYWORDS: list[str] = list(_vocab._CORE_SEARCH_TERMS)

# Java-specific terms that appear in teku/besu crash/bug PRs
JAVA_KEYWORDS: list[str] = _vocab._LANGUAGE_SEARCH_TERMS["java"]

# Combined and lowercased for efficient matching
_ALL_KEYWORDS: list[str] = list(dict.fromkeys(
    kw.lower() for kw in SECURITY_KEYWORDS + JAVA_KEYWORDS
))

# ---------------------------------------------------------------------------
# CSV schema
# ---------------------------------------------------------------------------
CSV_FIELDS = (
    "source", "contest", "issue_id", "severity", "title",
    "description", "source_url", "introduced_in_commit",
)

# Truncation limits to keep CSV rows sane
_TITLE_MAX = 300
_BODY_MAX = 2000


# ---------------------------------------------------------------------------
# Keyword filter
# ---------------------------------------------------------------------------

def is_security_relevant(pr: dict) -> bool:
    """Return True if PR title OR first 1000 chars of body contains any keyword.

    Case-insensitive. Checks both general security terms and Java-specific
    crash signatures (IllegalStateException, throws, assertion failed).
    """
    title = (pr.get("title") or "").lower()
    body = (pr.get("body") or "")[:1000].lower()
    text = title + " " + body
    return any(kw in text for kw in _ALL_KEYWORDS)


# ---------------------------------------------------------------------------
# gh CLI helpers
# ---------------------------------------------------------------------------

def _gh_available() -> bool:
    try:
        r = subprocess.run(
            ["gh", "--version"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _gh_version() -> str:
    try:
        r = subprocess.run(
            ["gh", "--version"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
        if r.returncode == 0:
            return r.stdout.strip().splitlines()[0]
    except Exception:
        pass
    return ""


def _fetch_pulls_page(repo: str, page: int) -> list[dict] | None:
    """Fetch one page of closed PRs from the direct REST endpoint.

    Returns:
        list of PR dicts on success,
        empty list when page is beyond the last page,
        None on hard error (caller should log and continue).
    """
    try:
        result = _ghr.run_gh(
            [
                "gh", "api",
                f"repos/{repo}/pulls",
                "-X", "GET",
                "-f", "state=closed",
                "-f", "per_page=100",
                "-f", f"page={page}",
            ],
            timeout=90, resource="core", label=f"{repo} pulls p{page}",
        )
    except subprocess.TimeoutExpired:
        print(
            f"  [warn] gh api timed out: repo={repo} page={page}",
            file=sys.stderr,
        )
        return None
    except FileNotFoundError:
        print("  [warn] gh CLI not found", file=sys.stderr)
        return None

    if result.returncode != 0:
        msg = (result.stderr or "").strip()[:300]
        print(
            f"  [warn] gh api exit {result.returncode} (repo={repo} page={page}): {msg}",
            file=sys.stderr,
        )
        return None

    body = result.stdout.strip()
    if not body:
        return []
    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        print(f"  [warn] JSON decode error page {page}: {e}", file=sys.stderr)
        return None

    if not isinstance(data, list):
        print(
            f"  [warn] unexpected response type {type(data).__name__} on page {page}",
            file=sys.stderr,
        )
        return None

    return data


# ---------------------------------------------------------------------------
# Per-wallet mining
# ---------------------------------------------------------------------------

def _pr_to_row(pr: dict, wallet_slug: str) -> dict | None:
    """Map a pulls-API PR object onto the build_derived CSV schema.

    Returns None when both title and body are absent.
    """
    title = (pr.get("title") or "").strip()
    body = (pr.get("body") or "").strip()
    if not title and not body:
        return None

    return {
        "source": wallet_slug,
        "contest": "direct_pr",
        "issue_id": f"PR#{pr['number']}",
        "severity": "Unrated",
        "title": title[:_TITLE_MAX],
        "description": body[:_BODY_MAX],
        "source_url": (pr.get("html_url") or "").strip(),
        "introduced_in_commit": "",
    }


def mine_client(
    wallet_slug: str,
    *,
    max_pages: int | None = None,
    sleep_between: float = 1.0,
) -> list[dict]:
    """Paginate all closed PRs for one wallet and return security-relevant rows.

    Args:
        wallet_slug:    Key in WALLET_REPOS.
        max_pages:      Stop after this many pages (None = paginate to end).
        sleep_between:  Seconds to sleep between page fetches (rate-limit guard).

    Returns:
        Deduplicated list of row dicts ready to write to CSV.
    """
    if wallet_slug not in WALLET_REPOS:
        sys.exit(f"unknown wallet {wallet_slug!r}; known: {sorted(WALLET_REPOS)}")

    repo = WALLET_REPOS[wallet_slug]
    print(
        f"[{wallet_slug}] paginating {repo} closed PRs "
        f"(max_pages={max_pages or 'unlimited'})...",
        file=sys.stderr,
    )

    seen: set[int] = set()
    rows: list[dict] = []
    page = 1
    total_fetched = 0
    total_relevant = 0

    while True:
        if max_pages and page > max_pages:
            print(
                f"  [{wallet_slug}] reached max_pages={max_pages}; stopping",
                file=sys.stderr,
            )
            break

        print(f"  [{wallet_slug}] page {page}...", file=sys.stderr)
        prs = _fetch_pulls_page(repo, page)

        if prs is None:
            # Hard error on this page — skip and stop to avoid thrashing
            print(f"  [{wallet_slug}] fetch error on page {page}; aborting", file=sys.stderr)
            break

        if not prs:
            # Empty page = past the last page
            print(f"  [{wallet_slug}] empty response on page {page}; done", file=sys.stderr)
            break

        total_fetched += len(prs)
        page_relevant = 0

        for pr in prs:
            num = pr.get("number")
            if num is None or num in seen:
                continue
            seen.add(num)

            if not is_security_relevant(pr):
                continue

            row = _pr_to_row(pr, wallet_slug)
            if row is None:
                continue

            rows.append(row)
            page_relevant += 1

        total_relevant += page_relevant
        print(
            f"  [{wallet_slug}] page {page}: {len(prs)} PRs, "
            f"{page_relevant} security-relevant (running total: {total_relevant})",
            file=sys.stderr,
        )

        if len(prs) < 100:
            # Partial page = last page
            print(f"  [{wallet_slug}] partial page ({len(prs)} < 100); done", file=sys.stderr)
            break

        page += 1
        time.sleep(sleep_between)

    print(
        f"[{wallet_slug}] done — {total_relevant} security-relevant PRs "
        f"from {total_fetched} total closed PRs ({page - 1} pages)",
        file=sys.stderr,
    )
    return rows


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def write_csv(rows: Iterable[dict], out_path: Path) -> int:
    """Write rows to CSV in canonical column order. Returns row count."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in CSV_FIELDS})
            n += 1
    return n


def write_manifest(
    out_path: Path,
    *,
    wallet_slug: str,
    repo: str,
    n_rows: int,
    max_pages: int | None,
) -> None:
    manifest = {
        "wallet": wallet_slug,
        "repo": repo,
        "n_rows": n_rows,
        "max_pages": max_pages,
        "security_keywords": _ALL_KEYWORDS,
        "method": "direct_rest_pagination",
        "crawled_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gh_version": _gh_version(),
        "note": (
            "Direct REST pagination of repos/{repo}/pulls?state=closed — bypasses "
            "GitHub Search index gap caused by repo transfer "
            "(ConsenSys/teku ← PegaSysEng/teku). Wallet-side keyword filter on "
            "title + first 1000 chars of body."
        ),
    }
    out_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def mine_and_write(
    wallet_slug: str,
    out_dir: Path,
    *,
    max_pages: int | None = None,
) -> int:
    """Top-level: mine, write CSV + manifest, return row count."""
    repo = WALLET_REPOS[wallet_slug]
    rows = mine_client(wallet_slug, max_pages=max_pages)

    csv_path = out_dir / f"{wallet_slug}.direct_prs.csv"
    manifest_path = out_dir / f"{wallet_slug}.direct_prs_manifest.json"

    n = write_csv(rows, csv_path)
    write_manifest(
        manifest_path,
        wallet_slug=wallet_slug,
        repo=repo,
        n_rows=n,
        max_pages=max_pages,
    )
    print(f"[{wallet_slug}] wrote {n} rows -> {csv_path}", file=sys.stderr)
    return n


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--wallet", required=True,
        help=(
            "Wallet slug ("
            + ", ".join(sorted(WALLET_REPOS))
            + ") or 'all'."
        ),
    )
    p.add_argument(
        "--out-dir",
        default="dataset/ethereum_past_fixes/direct_prs",
        help="Output directory for <wallet>.direct_prs.csv + manifest.",
    )
    p.add_argument(
        "--max-pages", type=int, default=0,
        help=(
            "Maximum pages to fetch per wallet (100 PRs/page). "
            "0 = no cap (full crawl). Use 5 for smoke tests."
        ),
    )
    args = p.parse_args()

    if not _gh_available():
        print(
            "ERROR: gh CLI not found or not authenticated. "
            "Install from https://cli.github.com/ and run `gh auth login`.",
            file=sys.stderr,
        )
        return 1

    out_dir = Path(args.out_dir)

    if args.wallet == "all":
        wallets = sorted(WALLET_REPOS)
    else:
        if args.wallet not in WALLET_REPOS:
            sys.exit(
                f"unknown --wallet {args.wallet!r}; "
                f"pass 'all' or one of: {sorted(WALLET_REPOS)}"
            )
        wallets = [args.wallet]

    max_pages = args.max_pages or None
    total = 0
    for c in wallets:
        total += mine_and_write(c, out_dir, max_pages=max_pages)

    print(
        f"done — {total} security-relevant PR rows across {len(wallets)} wallet(s)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
