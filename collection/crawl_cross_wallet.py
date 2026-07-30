#!/usr/bin/env python3
"""crawl_cross_wallet.py — Find PRs that mention multiple Ethereum wallets.

Cross-wallet integration bugs are a distinct failure class: a change in one
wallet exposes a divergence from another (e.g., a teku-nimbus state-transition
mismatch, or a lighthouse-prysm attestation-processing difference).  These PRs
rarely appear in per-wallet security-label searches because they are typically
labelled "interop" or "compatibility", not "security".

Strategy:
  For each of the 11 in-scope wallet repos, search merged PRs whose body/title
  mentions at least one OTHER wallet's name or alias.  The same PR can be found
  from multiple repos; we deduplicate globally on (repo, PR number).

Severity heuristic:
  - "High"   if body/title mentions "divergence", "consensus", "fork choice",
              or "state transition" alongside the cross-wallet mention.
  - "Medium" otherwise.

Output CSV (compatible with merge_crawl_csvs.py / build_derived.py schema):
    source, contest, issue_id, severity, title, description,
    source_url, introduced_in_commit

Usage:
    uv run python3 benchmarks/scripts/crawl_cross_wallet.py \\
        --out-dir dataset/ethereum_past_fixes/cross_client

    uv run python3 benchmarks/scripts/crawl_cross_wallet.py \\
        --out-dir C:\\tmp\\cross_client
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
# Wallet registry (all 11 in-scope + consensus-specs)
# ---------------------------------------------------------------------------
import importlib.util as _ilu7
from pathlib import Path as _P7
_WS7 = _ilu7.spec_from_file_location("_wallets", _P7(__file__).resolve().parent / "wallets.py")
_wal = _ilu7.module_from_spec(_WS7); _WS7.loader.exec_module(_wal)  # type: ignore

# Repos to SEARCH. This was its own hardcoded copy of the 11 Ethereum clients,
# separate from CLIENT_NAMES (what to search FOR) — which is why fixing only
# the latter left the stage emitting erigon/teku/lodestar rows.
WALLET_REPOS: dict[str, str] = {k: v["repo"] for k, v in _wal.WALLET_CONFIG.items()}

# Extra repos that reference multiple wallet names in integration context
# Standards repos: the wallet analogue of ethereum/consensus-specs.
EXTRA_REPOS: dict[str, str] = {
    "bips":  "bitcoin/bips",
    "slips": "satoshilabs/slips",
    "eips":  "ethereum/EIPs",
}

# Aliases per wallet slug — any of these appearing in a foreign PR body
# counts as a cross-wallet mention.
import importlib.util as _ilu6
from pathlib import Path as _P6
_WS6 = _ilu6.spec_from_file_location("_wallets", _P6(__file__).resolve().parent / "wallets.py")
_wal = _ilu6.module_from_spec(_WS6); _WS6.loader.exec_module(_wal)  # type: ignore
_VS6 = _ilu6.spec_from_file_location("_wallet_vocab", _P6(__file__).resolve().parent / "wallet_vocab.py")
_vocab = _ilu6.module_from_spec(_VS6); _VS6.loader.exec_module(_vocab)  # type: ignore

# Names a wallet is referred to by, derived from the registry: the slug, the
# repo name, and the owner org. Cross-WALLET variant hunting is the point —
# wallets copy each other's security fixes, so "same bug as Rabby had" in a
# MetaMask PR is a lead. The ported version searched for geth/nimbus/prysm.
def _names_for(slug: str) -> list[str]:
    cfg = _wal.WALLET_CONFIG[slug]
    owner, name = cfg["repo"].split("/", 1)
    out = {slug, slug.replace("-", " "), name.lower(), name.lower().replace("-", " "), owner.lower()}
    return sorted(n for n in out if len(n) > 3)


CLIENT_NAMES: dict[str, list[str]] = {s: _names_for(s) for s in _wal.WALLET_CONFIG}

# Search query patterns (appended to `gh search prs --repo <repo>` calls)
CROSS_CLIENT_QUERIES: list[str] = [
    "integration in:title",
    "interop in:title,body",
    "compatibility in:title",
]

# High-severity signals: if body/title contains any of these alongside a
# cross-wallet mention, severity is bumped to High.
# A cross-wallet mention is only interesting when it co-occurs with custody
# language. "consensus"/"fork choice"/"slashing" mean nothing to a wallet.
HIGH_SEVERITY_SIGNALS: list[str] = (
    _vocab.KEY_MATERIAL + _vocab.SIGNING + _vocab.MPC + _vocab.APPROVAL
)

# ---------------------------------------------------------------------------
# CSV schema
# ---------------------------------------------------------------------------
CSV_FIELDS = (
    "source", "contest", "issue_id", "severity", "title",
    "description", "source_url", "introduced_in_commit",
)

_TITLE_MAX = 300
_BODY_MAX = 2000


# ---------------------------------------------------------------------------
# Helpers
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


def _search_prs(repo: str, query: str, limit: int = 100) -> list[dict]:
    """Run `gh search prs --repo <repo> --merged` with a query string.

    Returns list of PR dicts with keys: number, title, body, url.
    """
    try:
        result = subprocess.run(
            [
                "gh", "search", "prs",
                "--repo", repo,
                "--merged",
                "--json", "number,title,body,url",
                "--limit", str(limit),
                query,
            ],
            capture_output=True, text=True, timeout=90,
            encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired:
        print(
            f"  [warn] gh search prs timed out: repo={repo} query={query!r}",
            file=sys.stderr,
        )
        return []
    except FileNotFoundError:
        print("  [warn] gh CLI not found", file=sys.stderr)
        return []

    if result.returncode != 0:
        msg = (result.stderr or "").strip()[:300]
        print(
            f"  [warn] gh search prs exit {result.returncode}: {msg}",
            file=sys.stderr,
        )
        return []

    body = result.stdout.strip()
    if not body:
        return []
    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        print(f"  [warn] JSON decode error: {e}", file=sys.stderr)
        return []

    if not isinstance(data, list):
        return []
    return data


# ---------------------------------------------------------------------------
# Cross-wallet detection
# ---------------------------------------------------------------------------

def _mentions_other_clients(
    pr: dict,
    source_slug: str,
) -> list[str]:
    """Return list of OTHER wallet slugs whose aliases appear in title+body.

    Only the first 2000 chars of body are scanned to keep it cheap.
    """
    title = (pr.get("title") or "").lower()
    body = (pr.get("body") or "")[:2000].lower()
    text = title + " " + body

    mentioned: list[str] = []
    for slug, aliases in CLIENT_NAMES.items():
        if slug == source_slug:
            continue
        if any(alias.lower() in text for alias in aliases):
            mentioned.append(slug)
    return mentioned


def _infer_severity(pr: dict) -> str:
    """High if body/title contains a high-severity signal; Medium otherwise."""
    title = (pr.get("title") or "").lower()
    body = (pr.get("body") or "")[:2000].lower()
    text = title + " " + body
    if any(sig.lower() in text for sig in HIGH_SEVERITY_SIGNALS):
        return "High"
    return "Medium"


def _pr_to_row(pr: dict, source_slug: str, mentioned_clients: list[str]) -> dict | None:
    title = (pr.get("title") or "").strip()
    body = (pr.get("body") or "").strip()
    if not title and not body:
        return None

    # Prepend cross-wallet context to description
    clients_str = ", ".join(sorted(mentioned_clients))
    extra = f"[cross-wallet: {clients_str}] "

    return {
        "source": source_slug,
        "contest": "cross_client",
        "issue_id": f"PR#{pr['number']}",
        "severity": _infer_severity(pr),
        "title": title[:_TITLE_MAX],
        "description": (extra + body)[:_BODY_MAX],
        "source_url": (pr.get("url") or "").strip(),
        "introduced_in_commit": "",
    }


# ---------------------------------------------------------------------------
# Per-repo crawl
# ---------------------------------------------------------------------------

def crawl_repo(
    source_slug: str,
    repo: str,
    *,
    seen_global: set[str],
    sleep_between: float = 2.0,
) -> list[dict]:
    """Crawl one repo for cross-wallet PRs.

    Args:
        source_slug:   Wallet slug (or extra-repo key) for the `source` column.
        repo:          GitHub repo slug (owner/name).
        seen_global:   Shared dedup set of "{repo}#{number}" strings across all repos.
        sleep_between: Seconds to sleep between query batches (search rate-limit).

    Returns:
        List of row dicts for security-relevant cross-wallet PRs.
    """
    print(f"[{source_slug}] searching {repo} for cross-wallet mentions...", file=sys.stderr)
    rows: list[dict] = []
    query_count = 0

    for i, query in enumerate(CROSS_CLIENT_QUERIES):
        if i > 0:
            time.sleep(sleep_between)

        prs = _search_prs(repo, query)
        query_count += 1
        new_count = 0

        for pr in prs:
            num = pr.get("number")
            if num is None:
                continue
            dedup_key = f"{repo}#{num}"
            if dedup_key in seen_global:
                continue

            mentioned = _mentions_other_clients(pr, source_slug)
            if not mentioned:
                # PR appeared in search but doesn't actually mention another wallet
                continue

            seen_global.add(dedup_key)
            row = _pr_to_row(pr, source_slug, mentioned)
            if row is None:
                continue
            rows.append(row)
            new_count += 1

        print(
            f"  [{source_slug}] query={query!r}: {len(prs)} hits, "
            f"{new_count} cross-wallet",
            file=sys.stderr,
        )

    print(
        f"[{source_slug}] done — {len(rows)} cross-wallet rows from {query_count} queries",
        file=sys.stderr,
    )
    return rows


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def write_csv(rows: Iterable[dict], out_path: Path) -> int:
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
    n_rows: int,
    clients_crawled: list[str],
) -> None:
    manifest = {
        "n_rows": n_rows,
        "clients_crawled": clients_crawled,
        "cross_client_queries": CROSS_CLIENT_QUERIES,
        "client_names": CLIENT_NAMES,
        "high_severity_signals": HIGH_SEVERITY_SIGNALS,
        "crawled_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gh_version": _gh_version(),
        "note": (
            "Cross-wallet integration PRs: merged PRs in any of the 11 in-scope "
            "repos whose title or body mentions at least one other wallet name. "
            "Severity=High when divergence/consensus/fork-choice signals present."
        ),
    }
    out_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--out-dir",
        default="dataset/ethereum_past_fixes/cross_client",
        help="Output directory for cross_client.csv + manifest.",
    )
    p.add_argument(
        "--sleep", type=float, default=2.0,
        help="Seconds to sleep between gh search queries (default: 2).",
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

    # Global dedup: "{repo}#{number}" to avoid counting the same PR twice
    # (e.g., if lighthouse mentions teku AND prysm, it only appears once).
    seen_global: set[str] = set()
    all_rows: list[dict] = []

    # Crawl all 11 wallets
    all_repos: dict[str, str] = {**WALLET_REPOS, **EXTRA_REPOS}
    clients_crawled: list[str] = []

    for slug, repo in sorted(all_repos.items()):
        rows = crawl_repo(
            slug, repo,
            seen_global=seen_global,
            sleep_between=args.sleep,
        )
        all_rows.extend(rows)
        clients_crawled.append(slug)
        # Pause between repos to stay well under the 30 req/min search limit
        time.sleep(args.sleep)

    csv_path = out_dir / "cross_client.csv"
    manifest_path = out_dir / "cross_client_manifest.json"

    n = write_csv(all_rows, csv_path)
    write_manifest(
        manifest_path,
        n_rows=n,
        clients_crawled=clients_crawled,
    )

    print(f"\ndone — {n} cross-wallet rows -> {csv_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
