#!/usr/bin/env python3
"""Mine "stealth" security PRs from the 11 in-scope Ethereum wallets.

Stealth PRs = merged PRs that were never labeled `security` but whose
bodies contain security-relevant keywords (panic, overflow, crash, DoS,
etc.).  Finding documented in issue #2 by grandchildrice: 98-100% of
Ethereum wallet security fixes are stealth.

Key improvements over the baseline crawl_wallet_past_fixes.py approach:
  - Searches PR *bodies* (not just titles) for security keywords.
  - Covers language-specific terms (Java: throws/IllegalStateException,
    Nim: defect/accessViolation, Rust: unwrap/RUSTSEC-/unsoundness).
  - Fixes the T16 fork_choice vs "fork choice" query-bug by trying all
    four variants of spec terms and deduplicating.
  - Uses `gh search prs` (not `gh api search/issues`) which handles the
    `in:body` qualifier directly.

Output per wallet:
    <out-dir>/<wallet>.stealth_prs.csv
    <out-dir>/<wallet>.stealth_prs_manifest.json

CSV columns match build_derived.py schema:
    source, contest, issue_id, severity, title, description,
    source_url, introduced_in_commit

Usage:
    # Mine all wallets:
    uv run python3 benchmarks/scripts/mine_stealth_prs.py \\
        --wallet all --out-dir dataset/ethereum_past_fixes/stealth_prs

    # Smoke test one wallet, cap at 50 rows:
    uv run python3 benchmarks/scripts/mine_stealth_prs.py \\
        --wallet geth --out-dir /tmp/test_stealth --max-per-wallet 50
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
# Wallet registry (issue #2 scope — do not add repos outside this list)
# ---------------------------------------------------------------------------
import importlib.util as _ilu
from pathlib import Path as _P
_WSPEC = _ilu.spec_from_file_location("_wallets", _P(__file__).resolve().parent / "wallets.py")
_wallets_mod = _ilu.module_from_spec(_WSPEC); _WSPEC.loader.exec_module(_wallets_mod)  # type: ignore
WALLET_REPOS: dict[str, str] = {s: c["repo"] for s, c in _wallets_mod.WALLET_CONFIG.items()}

# ---------------------------------------------------------------------------
# Security keyword lists
# ---------------------------------------------------------------------------

# General security keywords — searched in PR bodies for all wallets.
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

GENERAL_KEYWORDS: list[str] = list(_vocab._CORE_SEARCH_TERMS)

# Language-specific keywords by wallet group (T20).
# These are IN ADDITION to GENERAL_KEYWORDS for the matched wallets.
LANG_SPECIFIC: dict[str, list[str]] = {
    s: _vocab._LANGUAGE_SEARCH_TERMS.get(_wal.language_of(s), [])
    for s in _wal.WALLET_CONFIG
}

# Spec-term variants (T16 fix): each logical term maps to all surface forms
# that appear in PR bodies.  All variants are queried independently and then
# deduplicated.
# Wallet standards whose mis-implementation is itself the bug (BIP/SLIP/EIP).
SPEC_TERM_VARIANTS: dict[str, list[str]] = _vocab.STANDARD_TERMS

# Flattened: unique list of all spec surface forms.
_SPEC_KEYWORDS: list[str] = [
    variant
    for variants in SPEC_TERM_VARIANTS.values()
    for variant in variants
]

# ---------------------------------------------------------------------------
# Sensitive path patterns for path_hint metadata (T8)
# ---------------------------------------------------------------------------
SENSITIVE_PATHS: list[str] = _vocab.SENSITIVE_PATHS

# ---------------------------------------------------------------------------
# CSV schema
# ---------------------------------------------------------------------------
CSV_FIELDS = (
    "source", "contest", "issue_id", "severity", "title",
    "description", "source_url", "introduced_in_commit", "path_hint",
)

# Character caps for truncating free-text fields before writing to CSV.
_TITLE_MAX = 200
_BODY_MAX = 500


# ---------------------------------------------------------------------------
# gh CLI helpers
# ---------------------------------------------------------------------------

def _gh_available() -> bool:
    """Return True when the `gh` CLI is installed and reachable."""
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
    """Return the first line of `gh --version`, or empty string on failure."""
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


def _search_prs(repo: str, keyword: str, limit: int = 1000) -> list[dict]:
    """Run `gh search prs` for a single keyword in PR bodies.

    Returns a (possibly empty) list of PR objects with at least:
        number, title, body, url, closedAt, labels

    On any error (timeout, non-zero exit, bad JSON) returns an empty list
    and prints a warning to stderr.
    """
    try:
        result = _ghr.run_gh(
            [
                "gh", "search", "prs",
                "--repo", repo,
                "--merged",
                "--match", "body",
                "--json", "number,title,body,url,closedAt,labels",
                "--limit", str(limit),
                keyword,
            ],
            timeout=60, resource="search", label=f"{repo} {keyword!r}",
        )
    except subprocess.TimeoutExpired:
        print(
            f"  [warn] gh search prs timed out: repo={repo} keyword={keyword!r}",
            file=sys.stderr,
        )
        return []
    except FileNotFoundError:
        print("  [warn] gh CLI not found — skipping", file=sys.stderr)
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
        print(f"  [warn] gh search prs JSON decode error: {e}", file=sys.stderr)
        return []

    if not isinstance(data, list):
        print(
            f"  [warn] gh search prs returned non-list: {type(data).__name__}",
            file=sys.stderr,
        )
        return []
    return data


# ---------------------------------------------------------------------------
# Per-wallet mining
# ---------------------------------------------------------------------------

def _keywords_for_wallet(wallet_slug: str) -> list[str]:
    """Return the full ordered keyword list for a wallet (general + lang-specific
    + spec variants).  Preserves insertion order; caller deduplicates results."""
    kws: list[str] = list(GENERAL_KEYWORDS)
    kws.extend(LANG_SPECIFIC.get(wallet_slug, []))
    kws.extend(_SPEC_KEYWORDS)
    return kws


def _compute_path_hint(title: str, body: str) -> str:
    """Scan title + body for SENSITIVE_PATHS terms; return comma-separated matches."""
    # Word-boundary matched via the shared vocabulary. Bare `in` matching made
    # "se" fire on "Safe.sol" and "lock" on "package-lock.json", so a dependency
    # bump came back tagged "crypto,se,lock".
    text = title + " " + body
    matched = _vocab.matches(text, SENSITIVE_PATHS)
    # Deduplicate while preserving first-seen order
    seen: set[str] = set()
    unique: list[str] = []
    for m in matched:
        if m not in seen:
            seen.add(m)
            unique.append(m)
    return ",".join(unique)


def _pr_to_row(pr: dict, wallet_slug: str) -> dict | None:
    """Map a `gh search prs` JSON object onto the build_derived CSV schema.

    Returns None when both title and body are absent (carries no signal)."""
    title = (pr.get("title") or "").strip()
    body = (pr.get("body") or "").strip()
    if not title and not body:
        return None

    return {
        "source": wallet_slug,
        "contest": "stealth_pr",
        "issue_id": f"PR#{pr['number']}",
        # Severity is unknown — not yet classified (important for T2 downstream).
        "severity": "Unrated",
        "title": title[:_TITLE_MAX],
        "description": body[:_BODY_MAX],
        "source_url": (pr.get("url") or "").strip(),
        "introduced_in_commit": "",
        "path_hint": _compute_path_hint(title, body[:_BODY_MAX]),
    }


def mine_wallet(
    wallet_slug: str,
    *,
    max_per_wallet: int | None = None,
    sleep_between: float = 2.0,
) -> list[dict]:
    """Mine stealth PRs for one wallet.  Returns a deduplicated list of row
    dicts ready to be written to CSV.

    Deduplication key is (repo, PR number) — the same PR can hit multiple
    keywords, but only the first occurrence is kept.

    If max_per_wallet is set, collection stops once the cap is reached
    (across all keywords, after deduplication).
    """
    if wallet_slug not in WALLET_REPOS:
        sys.exit(f"unknown wallet {wallet_slug!r}; known: {sorted(WALLET_REPOS)}")

    repo = WALLET_REPOS[wallet_slug]
    keywords = _keywords_for_wallet(wallet_slug)
    print(
        f"[{wallet_slug}] mining {len(keywords)} keywords on {repo}…",
        file=sys.stderr,
    )

    seen: set[int] = set()
    rows: list[dict] = []

    for i, kw in enumerate(keywords):
        if i > 0:
            time.sleep(sleep_between)

        print(
            f"  [{wallet_slug}] keyword {i+1}/{len(keywords)}: {kw!r}",
            file=sys.stderr,
        )
        prs = _search_prs(repo, kw)
        new_count = 0
        for pr in prs:
            num = pr.get("number")
            if num is None or num in seen:
                continue
            seen.add(num)
            row = _pr_to_row(pr, wallet_slug)
            if row is None:
                continue
            rows.append(row)
            new_count += 1
            if max_per_wallet and len(rows) >= max_per_wallet:
                print(
                    f"  [{wallet_slug}] hit max-per-wallet cap ({max_per_wallet}); stopping",
                    file=sys.stderr,
                )
                return rows

        print(
            f"  [{wallet_slug}] keyword {kw!r}: {len(prs)} hits, {new_count} new"
            f" (total unique so far: {len(rows)})",
            file=sys.stderr,
        )

    print(
        f"[{wallet_slug}] done — {len(rows)} unique stealth PRs from {len(seen)} deduped numbers",
        file=sys.stderr,
    )
    return rows


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def write_csv(rows: Iterable[dict], out_path: Path) -> int:
    """Write rows to `out_path` in canonical column order. Returns row count
    (excluding the header line)."""
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
    keywords: list[str],
) -> None:
    """Write a provenance JSON alongside the CSV so re-runs are auditable."""
    manifest = {
        "wallet": wallet_slug,
        "repo": repo,
        "n_rows": n_rows,
        "keywords_searched": keywords,
        "spec_term_variants": SPEC_TERM_VARIANTS,
        "crawled_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gh_version": _gh_version(),
        "note": (
            "Stealth PRs: merged PRs whose bodies match security keywords "
            "but that were never labeled 'security'. Severity='Unrated' "
            "pending downstream classification (T2)."
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
    max_per_wallet: int | None = None,
) -> int:
    """Top-level: mine, write CSV + manifest, return row count."""
    repo = WALLET_REPOS[wallet_slug]
    keywords = _keywords_for_wallet(wallet_slug)
    rows = mine_wallet(wallet_slug, max_per_wallet=max_per_wallet)

    csv_path = out_dir / f"{wallet_slug}.stealth_prs.csv"
    manifest_path = out_dir / f"{wallet_slug}.stealth_prs_manifest.json"

    n = write_csv(rows, csv_path)
    write_manifest(
        manifest_path,
        wallet_slug=wallet_slug,
        repo=repo,
        n_rows=n,
        keywords=keywords,
    )
    print(
        f"[{wallet_slug}] wrote {n} rows → {csv_path}",
        file=sys.stderr,
    )
    return n


# ---------------------------------------------------------------------------
# Retroactive path-hint application (T8)
# ---------------------------------------------------------------------------

def apply_path_hints(csv_in: Path, csv_out: Path) -> int:
    """Reprocess an existing stealth-PR CSV and add/update the ``path_hint`` column.

    Reads *csv_in*, computes ``path_hint`` for every row from its ``title`` and
    ``description`` fields, then writes the result to *csv_out* (which may be the
    same path as *csv_in* for in-place updates).

    Returns the number of rows that received a non-empty path_hint.
    """
    import tempfile

    rows_in: list[dict] = []
    with csv_in.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows_in.append(row)

    # Determine output fields: preserve original order, append path_hint if absent
    if rows_in:
        orig_fields = list(rows_in[0].keys())
    else:
        orig_fields = list(CSV_FIELDS)

    out_fields = list(orig_fields)
    if "path_hint" not in out_fields:
        out_fields.append("path_hint")

    n_with_hint = 0
    out_rows: list[dict] = []
    for row in rows_in:
        title = row.get("title", "") or ""
        desc = row.get("description", "") or ""
        hint = _compute_path_hint(title, desc)
        row["path_hint"] = hint
        if hint:
            n_with_hint += 1
        out_rows.append(row)

    # Write to a temp file first, then replace — safe against mid-write crash
    csv_out.parent.mkdir(parents=True, exist_ok=True)
    tmp = csv_out.parent / (csv_out.name + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=out_fields, extrasaction="ignore")
        w.writeheader()
        for row in out_rows:
            w.writerow({k: row.get(k, "") for k in out_fields})
    tmp.replace(csv_out)

    return n_with_hint


def apply_hints_to_dir(src_dir: Path) -> dict[str, int]:
    """Apply path hints in-place to all ``*.stealth_prs.csv`` files in *src_dir*.

    Returns a mapping of filename → n_rows_with_hint.
    """
    results: dict[str, int] = {}
    csv_files = sorted(src_dir.glob("*.stealth_prs.csv"))
    if not csv_files:
        print(f"[apply-hints] No *.stealth_prs.csv files found in {src_dir}", file=sys.stderr)
        return results

    total_rows = 0
    total_with_hint = 0
    for csv_path in csv_files:
        n = apply_path_hints(csv_path, csv_path)
        results[csv_path.name] = n

        # Count total rows for reporting
        with csv_path.open(encoding="utf-8", newline="") as fh:
            row_count = sum(1 for _ in csv.DictReader(fh))

        total_rows += row_count
        total_with_hint += n
        print(
            f"  [apply-hints] {csv_path.name}: {n}/{row_count} rows have path_hint",
            file=sys.stderr,
        )

    print(
        f"[apply-hints] done — {total_with_hint}/{total_rows} rows have path_hint "
        f"across {len(csv_files)} CSV files",
        file=sys.stderr,
    )
    return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # --apply-hints mode — mutually exclusive with --wallet
    p.add_argument(
        "--apply-hints", action="store_true",
        help=(
            "Retroactively add path_hint column to all existing "
            "*.stealth_prs.csv files in --src-dir (does not crawl GitHub)."
        ),
    )
    p.add_argument(
        "--src-dir",
        default="dataset/ethereum_past_fixes/stealth_prs",
        help="Source directory for --apply-hints mode (default: dataset/ethereum_past_fixes/stealth_prs).",
    )
    p.add_argument(
        "--wallet",
        help=(
            "Wallet slug ("
            + ", ".join(sorted(WALLET_REPOS))
            + ") or 'all'. Required unless --apply-hints is set."
        ),
    )
    p.add_argument(
        "--out-dir",
        default="dataset/ethereum_past_fixes/stealth_prs",
        help="Output directory for <wallet>.stealth_prs.csv + manifest.",
    )
    p.add_argument(
        "--max-per-wallet", type=int, default=500,
        help="Cap results per wallet (default: 500; 0 = no cap).",
    )
    args = p.parse_args()

    # ------------------------------------------------------------------
    # --apply-hints: retroactive path_hint update, no GitHub crawl
    # ------------------------------------------------------------------
    if args.apply_hints:
        src_dir = Path(args.src_dir)
        if not src_dir.exists():
            print(f"ERROR: --src-dir does not exist: {src_dir}", file=sys.stderr)
            return 1
        apply_hints_to_dir(src_dir)
        return 0

    # ------------------------------------------------------------------
    # Normal mining mode
    # ------------------------------------------------------------------
    if not args.wallet:
        p.error("--wallet is required unless --apply-hints is set")

    # Fail fast when gh is not available — avoids writing empty CSVs.
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

    cap = args.max_per_wallet or None
    total = 0
    for c in wallets:
        total += mine_and_write(c, out_dir, max_per_wallet=cap)

    print(
        f"done — {total} stealth PR rows across {len(wallets)} wallet(s)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
