#!/usr/bin/env python3
"""Parse CHANGELOG files from 11 in-scope Ethereum wallets to extract
security-relevant lines as additional vulnerability records.

Many security fixes appear in CHANGELOG.md without ever receiving a GHSA,
making this an independent source from `crawl_wallet_past_fixes.py`.

Output layout:
    benchmarks/data/ethereum_past_fixes/<wallet>.changelog.csv
    benchmarks/data/ethereum_past_fixes/<wallet>.changelog_manifest.json

The `.changelog.csv` suffix distinguishes these from the GHSA crawler's
`<wallet>.csv` so both can coexist in the same directory.

Usage:
    # Crawl one wallet:
    uv run python3 benchmarks/scripts/parse_wallet_changelogs.py \\
        --wallet geth --out-dir benchmarks/data/ethereum_past_fixes

    # Crawl all in-scope wallets:
    uv run python3 benchmarks/scripts/parse_wallet_changelogs.py \\
        --wallet all --out-dir benchmarks/data/ethereum_past_fixes
"""

from __future__ import annotations

import argparse
import base64
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
# stay in sync with any future additions without duplicating the constants.
# Both scripts live under benchmarks/scripts/ and are NOT in a package, so
# we use importlib rather than a relative import.
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

# Paths to try, in priority order.  Some repos keep their history in a
# non-standard location (e.g. erigon uses ChangeLog.md, reth uses
# docs/release.md).  Extend this tuple rather than adding per-wallet
# special cases so the fallback list stays self-contained.
CHANGELOG_PATHS = (
    "CHANGELOG.md",
    "ChangeLog.md",
    "docs/CHANGELOG.md",
    "docs/release.md",
    "CHANGES.md",
    "HISTORY.md",
    "releases/CHANGELOG.md",
)

# Word-boundary-anchored regex for security-relevant lines.
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


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _gh_text(args: list[str], timeout: int = 60) -> str | None:
    """Run `gh` and return raw stdout text, or None on error."""
    try:
        result = subprocess.run(
            ["gh", *args],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        print(f"  [warn] gh failed: {exc}", file=sys.stderr)
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def default_branch_for(repo: str) -> str:
    """Return the default branch name for `repo` (fallback: 'main')."""
    out = _gh_text([
        "api", f"repos/{repo}",
        "-X", "GET",
        "--jq", ".default_branch",
    ])
    if out:
        branch = out.strip()
        if branch:
            return branch
    return "main"


def find_changelog(repo: str) -> tuple[str, str] | None:
    """Try each path in CHANGELOG_PATHS via the GitHub Contents API.

    Returns ``(path, decoded_text)`` for the first hit, or ``None`` if
    none of the candidate paths exist.
    """
    for path in CHANGELOG_PATHS:
        try:
            result = subprocess.run(
                ["gh", "api", f"repos/{repo}/contents/{path}", "-X", "GET"],
                capture_output=True, text=True, timeout=60,
                encoding="utf-8", errors="replace",
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print(f"  [warn] gh failed for {repo}/{path}: {exc}", file=sys.stderr)
            continue

        if result.returncode != 0:
            # 404 is expected; anything else is unusual but non-fatal.
            stderr = (result.stderr or "").lower()
            if "404" not in stderr and "not found" not in stderr and result.returncode != 1:
                print(
                    f"  [warn] gh exit {result.returncode} for {repo}/{path}: "
                    f"{(result.stderr or '').strip()[:200]}",
                    file=sys.stderr,
                )
            continue

        body = result.stdout.strip()
        if not body:
            continue
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            print(f"  [warn] non-JSON response for {repo}/{path}: {exc}", file=sys.stderr)
            continue

        encoded = data.get("content", "")
        if not encoded:
            continue
        try:
            decoded = base64.b64decode(encoded).decode("utf-8")
        except Exception as exc:
            print(f"  [warn] base64 decode failed for {repo}/{path}: {exc}", file=sys.stderr)
            continue

        return (path, decoded)

    return None


def extract_security_lines(
    changelog_text: str,
    path: str,
    repo: str,
    default_branch: str,
    wallet_slug: str,
) -> list[dict]:
    """Scan `changelog_text` and return one row per security-relevant line.

    Deduplication is by stable ``issue_id`` (sha256 of stripped line text)
    — the first occurrence wins if the same line appears multiple times.
    Lines whose title (after chrome stripping) is shorter than 10 characters
    are dropped as likely non-entries (e.g. bare section headings).
    """
    lines = changelog_text.splitlines()
    seen_ids: set[str] = set()
    rows: list[dict] = []

    for lineno_0based, line in enumerate(lines):
        line_number = lineno_0based + 1  # 1-indexed for GitHub anchor

        if not line.strip():
            continue
        if not SECURITY_LINE_RE.search(line):
            continue

        # Strip leading markdown chrome to get the "title".
        title = _CHROME_RE.sub("", line).strip()
        if len(title) < 10:
            continue

        # Stable, deterministic id — same stripped text → same id across runs.
        raw_id = sha256(line.strip().encode("utf-8")).hexdigest()[:16]
        issue_id = f"CHANGELOG#{raw_id}"

        if issue_id in seen_ids:
            continue
        seen_ids.add(issue_id)

        # Severity: scan the matched line for an explicit word.
        sev_match = _SEVERITY_RE.search(line)
        severity = sev_match.group(1).capitalize() if sev_match else "Info"
        # Normalise "critical" (not in our enum) → "High"
        if severity.lower() == "critical":
            severity = "High"

        # Context: up to 3 lines before + 3 lines after (skip out-of-range).
        ctx_before = lines[max(0, lineno_0based - 3):lineno_0based]
        ctx_after = lines[lineno_0based + 1:lineno_0based + 4]
        description = "\n".join(ctx_before + [line] + ctx_after)

        source_url = (
            f"https://github.com/{repo}/blob/{default_branch}/{path}"
            f"#L{line_number}"
        )

        rows.append({
            "source": wallet_slug,
            "contest": repo,
            "issue_id": issue_id,
            "severity": severity,
            "title": title,
            "description": description,
            "source_url": source_url,
            "introduced_in_commit": "",
        })

    return rows


# ---------------------------------------------------------------------------
# Public crawl entry point
# ---------------------------------------------------------------------------

def crawl_changelog(
    wallet_slug: str,
    *,
    finder: Callable[[str], tuple[str, str] | None] = find_changelog,
    branch_resolver: Callable[[str], str] = default_branch_for,
) -> list[dict]:
    """Crawl the CHANGELOG for one wallet and return rows.

    ``finder`` and ``branch_resolver`` are injectable for testing so we
    never hit the network in unit tests.
    """
    if wallet_slug not in WALLET_CONFIG:
        sys.exit(
            f"unknown wallet {wallet_slug!r}; known: {sorted(WALLET_CONFIG)}"
        )
    repo = WALLET_CONFIG[wallet_slug]["repo"]

    result = finder(repo)
    if result is None:
        print(
            f"  [warn] [{wallet_slug}] no CHANGELOG found at known paths in {repo}",
            file=sys.stderr,
        )
        return []

    changelog_path, changelog_text = result
    branch = branch_resolver(repo)
    rows = extract_security_lines(
        changelog_text, changelog_path, repo, branch, wallet_slug
    )
    return rows


# ---------------------------------------------------------------------------
# CSV + manifest writers
# ---------------------------------------------------------------------------

def write_csv(rows: Iterable[dict], out_path: Path) -> int:
    """Write rows to ``out_path`` in canonical column order.

    Returns the row count (excluding header).
    """
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
    changelog_path: str,
    n_rows: int,
    source_url: str,
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
        "changelog_path": changelog_path,
        "n_rows": n_rows,
        "crawled_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gh_version": gh_version,
        "source_url": source_url,
    }
    out_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def crawl_and_write(
    wallet_slug: str,
    out_dir: Path,
    *,
    max_records: int | None = None,
) -> tuple[int, str | None]:
    """Crawl one wallet, write CSV + manifest. Returns (row_count, changelog_path_or_None)."""
    repo = WALLET_CONFIG[wallet_slug]["repo"]
    print(f"[{wallet_slug}] scanning CHANGELOG in {repo}...", file=sys.stderr)

    rows = crawl_changelog(wallet_slug)
    if max_records:
        rows = rows[:max_records]

    changelog_path = ""
    if rows:
        # Derive the changelog path from the first row's source_url for manifest.
        # source_url pattern: https://github.com/{repo}/blob/{branch}/{path}#L{n}
        url = rows[0].get("source_url", "")
        # Extract the path portion (between branch and #L)
        try:
            after_blob = url.split("/blob/", 1)[1]
            branch_and_path = after_blob.split("#L")[0]
            changelog_path = "/".join(branch_and_path.split("/")[1:])
        except (IndexError, ValueError):
            changelog_path = ""

    csv_path = out_dir / f"{wallet_slug}.changelog.csv"
    manifest_path = out_dir / f"{wallet_slug}.changelog_manifest.json"
    n = write_csv(rows, csv_path)

    # For manifest source_url: point to the CHANGELOG file itself (no line anchor).
    if rows and changelog_path:
        branch = rows[0]["source_url"].split("/blob/")[1].split("/")[0]
        manifest_source_url = f"https://github.com/{repo}/blob/{branch}/{changelog_path}"
    else:
        manifest_source_url = f"https://github.com/{repo}"

    write_manifest(
        manifest_path,
        wallet=wallet_slug,
        repo=repo,
        changelog_path=changelog_path,
        n_rows=n,
        source_url=manifest_source_url,
    )
    print(f"[{wallet_slug}] wrote {n} rows -> {csv_path}", file=sys.stderr)
    return n, changelog_path or None


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
        help="Output directory for <wallet>.changelog.csv + <wallet>.changelog_manifest.json.",
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
    no_changelog: list[str] = []
    for c in wallets:
        n, cl_path = crawl_and_write(c, out_dir, max_records=cap)
        total += n
        if cl_path is None:
            no_changelog.append(c)

    print(
        f"done — {total} rows across {len(wallets)} wallet(s)"
        + (f"; no CHANGELOG: {no_changelog}" if no_changelog else ""),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
