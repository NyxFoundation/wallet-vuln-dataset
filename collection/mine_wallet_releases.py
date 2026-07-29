#!/usr/bin/env python3
"""Mine security-relevant lines from GitHub Releases bodies for the 11
in-scope Ethereum wallets.

Many wallets (geth, lighthouse, reth, lodestar, nethermind, grandine) ship
security-fix notes in their GitHub Releases rather than a CHANGELOG file.
This script extracts those lines and writes a CSV that round-trips through
`scripts/datasets/build_derived.py --domain ethereum --filter-platforms ''`.

Output layout:
    benchmarks/data/ethereum_past_fixes/<wallet>.releases.csv
    benchmarks/data/ethereum_past_fixes/<wallet>.releases_manifest.json

The `.releases.csv` suffix distinguishes these from:
  - `<wallet>.csv`           (GHSA crawler)
  - `<wallet>.changelog.csv` (CHANGELOG parser)

Usage:
    # Mine one wallet:
    uv run python3 benchmarks/scripts/mine_wallet_releases.py \\
        --wallet geth --out-dir benchmarks/data/ethereum_past_fixes

    # Mine all in-scope wallets:
    uv run python3 benchmarks/scripts/mine_wallet_releases.py \\
        --wallet all --out-dir benchmarks/data/ethereum_past_fixes
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Callable, Iterable

# ---------------------------------------------------------------------------
# Import WALLET_CONFIG and CSV_FIELDS from the sibling crawler script so we
# stay in sync without duplicating constants.  Both scripts live under
# benchmarks/scripts/ and are NOT in a package, so we use importlib.
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
_CRAWLER_PATH = _HERE / "crawl_wallet_past_fixes.py"

_spec = importlib.util.spec_from_file_location("_crawl_wallet_past_fixes", _CRAWLER_PATH)
assert _spec and _spec.loader, f"cannot locate sibling script: {_CRAWLER_PATH}"
_crawler_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_crawler_mod)  # type: ignore[union-attr]

WALLET_CONFIG: dict[str, dict] = _crawler_mod.WALLET_CONFIG
CSV_FIELDS = _crawler_mod.CSV_FIELDS

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Word-boundary-anchored security keyword regex.
# \b ensures "securitytoken" does NOT match while "security:" DOES.
SECURITY_LINE_RE = re.compile(
    r"\b("
    r"security"
    r"|vuln(erability)?"
    r"|CVE-\d{4}-\d+"
    r"|DoS"
    r"|panic"
    r"|crash"
    r"|RCE"
    r"|memory[ _-]?leak"
    r"|integer[ _-]?overflow"
    r"|race[ _-]?condition"
    r")\b",
    re.IGNORECASE,
)

# Markdown "chrome" at the start of a line: hashes, bullets, quotes, space.
_CHROME_RE = re.compile(r"^[#\-*>\s]+")

# Severity hint in the line text itself.
_SEVERITY_RE = re.compile(r"\b(Critical|High|Medium|Low)\b", re.IGNORECASE)

# T1 fix: nimbus "Urgency guidelines" template lines are false positives.
# Example: "high-urgency: ... critical update required for Nimbus"
# These match _SEVERITY_RE but are NOT security findings — they're urgency metadata.
# Skip any line that is part of the urgency template.
_URGENCY_FP_RE = re.compile(
    r"\b(urgency.{0,30}guidelines|critical update required|high-urgency|low-urgency|"
    r"medium-urgency|urgency-level)\b",
    re.IGNORECASE,
)

RELEASES_PER_PAGE = 100
RELEASES_MAX = 500


# ---------------------------------------------------------------------------
# GitHub Releases fetcher
# ---------------------------------------------------------------------------

def fetch_releases(repo: str) -> list[dict]:
    """Fetch non-draft releases from `<owner>/<repo>` via gh CLI.

    Pre-releases are KEPT — security fixes often ship there first.
    Only drafts are dropped.  Capped at RELEASES_MAX total.

    Uses `-X GET` to avoid gh's automatic POST promotion when `-f` is
    present (same gotcha as the GHSA advisory endpoint).
    """
    try:
        result = subprocess.run(
            [
                "gh", "api",
                f"repos/{repo}/releases",
                "-X", "GET",
                "--paginate",
                "-f", f"per_page={RELEASES_PER_PAGE}",
            ],
            capture_output=True, text=True, timeout=180,
            encoding="utf-8", errors="replace",
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        print(f"  [warn] gh failed for {repo}: {exc}", file=sys.stderr)
        return []

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        if "404" in stderr or "Not Found" in stderr:
            print(f"  [warn] [{repo}] releases endpoint 404 — skipping", file=sys.stderr)
        else:
            print(
                f"  [warn] gh exit {result.returncode} for {repo}/releases: "
                f"{stderr[:300]}",
                file=sys.stderr,
            )
        return []

    body = result.stdout.strip()
    if not body:
        return []

    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        print(f"  [warn] gh output not JSON for {repo}: {exc}", file=sys.stderr)
        return []

    if not isinstance(data, list):
        print(f"  [warn] unexpected gh response shape for {repo}: {type(data)}", file=sys.stderr)
        return []

    # Drop drafts only; keep pre-releases.
    releases = [r for r in data if not r.get("draft", False)]

    # Cap to avoid runaway on repos with thousands of releases.
    if len(releases) >= RELEASES_MAX:
        print(
            f"  [warn] [{repo}] release list truncated at {RELEASES_MAX} entries "
            f"(total before cap: {len(releases)})",
            file=sys.stderr,
        )
        releases = releases[:RELEASES_MAX]

    return releases


# ---------------------------------------------------------------------------
# Row extractor for a single release
# ---------------------------------------------------------------------------

def extract_security_lines_from_release(
    release: dict,
    wallet_slug: str,
    repo: str,
) -> list[dict]:
    """Scan one release body and return security-relevant rows.

    id scheme: ``RELEASE#<tag_name>#<sha256_hex8>`` — the tag makes the
    same line in different releases produce different ids, while the hash
    keeps rows within a single release unique.
    """
    body = release.get("body") or ""
    if not body:
        return []

    lines = body.splitlines()
    tag = release.get("tag_name", "unknown")
    html_url = release.get("html_url", "")

    seen_ids: set[str] = set()
    rows: list[dict] = []

    for i, line in enumerate(lines):
        if not line.strip():
            continue
        if not SECURITY_LINE_RE.search(line):
            continue

        title = _CHROME_RE.sub("", line).strip()
        if len(title) < 10:
            continue

        # Stable id: combines tag (unique per release) + hash of stripped line.
        line_hash = sha256(line.strip().encode("utf-8")).hexdigest()[:8]
        issue_id = f"RELEASE#{tag}#{line_hash}"

        # Per-release dedup: identical line text within the same tag → keep first.
        if issue_id in seen_ids:
            continue
        seen_ids.add(issue_id)

        # T1 fix: skip nimbus "Urgency guidelines" template lines (false positives).
        # These match SECURITY_LINE_RE via "critical"/"high" but are metadata, not findings.
        if _URGENCY_FP_RE.search(line):
            continue

        # Severity: scan line for explicit word.
        sev_match = _SEVERITY_RE.search(line)
        severity = sev_match.group(1).capitalize() if sev_match else "Info"
        if severity.lower() == "critical":
            severity = "High"

        # Context: up to 3 lines before + 3 lines after, prefixed with tag name.
        ctx_before = lines[max(0, i - 3):i]
        ctx_after = lines[i + 1:i + 4]
        description = f"[{tag}] " + "\n".join(ctx_before + [line] + ctx_after)

        rows.append({
            "source": wallet_slug,
            "contest": repo,
            "issue_id": issue_id,
            "severity": severity,
            "title": title,
            "description": description,
            "source_url": html_url,
            "introduced_in_commit": "",
        })

    return rows


# ---------------------------------------------------------------------------
# Wallet-level crawl with global dedup
# ---------------------------------------------------------------------------

def crawl_releases(
    wallet_slug: str,
    *,
    fetcher: Callable[[str], list[dict]] = fetch_releases,
) -> list[dict]:
    """Crawl GitHub Releases for one wallet and return deduplicated rows.

    Releases are processed in the order returned by the API (newest first),
    but global dedup keeps the row from the EARLIEST release (oldest
    `published_at`) because that's when the fix actually shipped.  This
    prevents geth-style "what's changed" sections that re-quote earlier
    security-fix bullets from inflating counts.
    """
    if wallet_slug not in WALLET_CONFIG:
        sys.exit(f"unknown wallet {wallet_slug!r}; known: {sorted(WALLET_CONFIG)}")
    repo = WALLET_CONFIG[wallet_slug]["repo"]

    releases = fetcher(repo)

    # Collect all rows, preserving each row's published_at for dedup sorting.
    all_rows: list[tuple[str, dict]] = []  # (published_at, row)
    for release in releases:
        published_at = release.get("published_at") or ""
        for row in extract_security_lines_from_release(release, wallet_slug, repo):
            all_rows.append((published_at, row))

    # Global dedup: key = (wallet_slug, contest, stripped_line_text).
    # We want to keep the row from the EARLIEST release (smallest published_at).
    # published_at is ISO-8601 so lexicographic sort works correctly.
    # Sort ascending by published_at so the first occurrence is from the oldest release.
    all_rows.sort(key=lambda t: t[0])

    seen_global: set[tuple[str, str, str]] = set()
    deduped: list[dict] = []
    for _pub, row in all_rows:
        # The title IS the stripped line text (same transform applied in extractor).
        dedup_key = (row["source"], row["contest"], row["title"])
        if dedup_key in seen_global:
            continue
        seen_global.add(dedup_key)
        deduped.append(row)

    return deduped


# ---------------------------------------------------------------------------
# CSV + manifest writers
# ---------------------------------------------------------------------------

def write_csv(rows: Iterable[dict], out_path: Path) -> int:
    """Write rows in canonical column order. Returns row count."""
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
    n_releases_scanned: int,
    n_rows: int,
    releases_truncated: bool = False,
    releases_returned: int | None = None,
) -> None:
    """Write a JSON provenance snapshot alongside the CSV."""
    gh_version = ""
    try:
        v = subprocess.run(
            ["gh", "--version"], capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
        if v.returncode == 0:
            gh_version = v.stdout.strip().splitlines()[0]
    except Exception:
        pass

    manifest = {
        "wallet": wallet,
        "repo": repo,
        "n_releases_scanned": n_releases_scanned,
        "n_rows": n_rows,
        "releases_truncated": releases_truncated,
        "crawled_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gh_version": gh_version,
        "source_url": f"https://github.com/{repo}/releases",
    }
    if releases_returned is not None:
        manifest["releases_returned"] = releases_returned
    out_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Top-level crawl + write
# ---------------------------------------------------------------------------

def crawl_and_write(
    wallet_slug: str,
    out_dir: Path,
    *,
    max_records: int | None = None,
    fetcher: Callable[[str], list[dict]] = fetch_releases,
) -> int:
    """Crawl one wallet, write CSV + manifest. Returns row count."""
    repo = WALLET_CONFIG[wallet_slug]["repo"]
    print(f"[{wallet_slug}] mining releases on {repo}...", file=sys.stderr)

    # Fetch all releases first (to know n_releases_scanned).
    # fetch_releases already applies the RELEASES_MAX cap internally.
    releases = fetcher(repo)
    n_releases_scanned = len(releases)
    # Detect whether the cap was hit: cap applies when we got exactly RELEASES_MAX
    # releases (the fetcher may have silently truncated a larger list).
    releases_truncated = n_releases_scanned >= RELEASES_MAX

    # Build rows using the same fetcher but pass pre-fetched data via lambda.
    rows = crawl_releases(wallet_slug, fetcher=lambda _repo: releases)

    if max_records:
        rows = rows[:max_records]

    csv_path = out_dir / f"{wallet_slug}.releases.csv"
    manifest_path = out_dir / f"{wallet_slug}.releases_manifest.json"

    n = write_csv(rows, csv_path)
    write_manifest(
        manifest_path,
        wallet=wallet_slug,
        repo=repo,
        n_releases_scanned=n_releases_scanned,
        n_rows=n,
        releases_truncated=releases_truncated,
        releases_returned=n_releases_scanned,
    )
    print(f"[{wallet_slug}] {n_releases_scanned} releases -> {n} rows -> {csv_path}", file=sys.stderr)
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
            "Wallet slug (one of: " + ", ".join(sorted(WALLET_CONFIG)) +
            ") or 'all' for the full set."
        ),
    )
    p.add_argument(
        "--out-dir", default="benchmarks/data/ethereum_past_fixes",
        help="Output directory for <wallet>.releases.csv + <wallet>.releases_manifest.json.",
    )
    p.add_argument(
        "--max-records", type=int, default=0,
        help="Cap rows per wallet (0 = no cap, useful for smoke tests).",
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
    breakdown: list[str] = []
    for c in wallets:
        n = crawl_and_write(c, out_dir, max_records=cap)
        total += n
        breakdown.append(f"  {c}: {n}")

    print(
        f"done — {total} rows across {len(wallets)} wallet(s)",
        file=sys.stderr,
    )
    for line in breakdown:
        print(line, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
