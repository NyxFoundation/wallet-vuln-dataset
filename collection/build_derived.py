"""build_derived.py — normalize raw scraper / curated CSVs into a unified
parquet table per domain, plus a JSON manifest.

Output layout (per --domain) — mirrors the on-HF folder-per-config layout
under NyxFoundation/vulnerability-reports:
    <out-dir>/<domain>/train.parquet
    <out-dir>/<domain>/manifest.json

Unified schema (one row per audit finding):
    id                     str   '<platform>:<contest>:<issue_id>' (hash fallback)
    source_platform        str   defi: 'code4rena' | 'sherlock' | 'codehawks'
                                 ethereum: '<wallet>' (geth, nethermind, ...)
    contest                str   contest identifier (defi) / repo slug (ethereum)
    issue_id               str   platform-local issue / PR id, '#'-stripped
    severity               str   'High' | 'Medium' | 'Low' | 'Info'
    title                  str   verbatim
    description            str   verbatim
    source_url             str   row's `source_url` if present, else best-effort synth
    introduced_in_commit   str   vulnerable-state commit = parent of the fix commit
                                 (populated downstream by scripts/datasets/blame_walk.py;
                                  '' for defi rows and for ethereum rows not yet enriched).
                                 v1 semantic: NOT the commit that first introduced the bug
                                 (true git-log -G search is deferred to a follow-up PR);
                                 instead stores the parent of the fix commit, i.e. the last
                                 state in which the bug was present. For Phase B replay this
                                 is functionally equivalent: auditing the pre-fix state asks
                                 "would the prompt catch this bug in the broken codebase?"
    domain                 str   passed via --domain
    scraped_at             str   ISO 8601 UTC, --scraped-at or now()

Sources accepted:
    1. csv/similar_audit_findings.csv shape:
         source, contest, issue_id, severity, title, description
    2. benchmarks/data/defi_audit_reports/*_all_issues.csv shape (Code4rena):
         contest_repo, contest_name, issue_id, severity, title, description,
         source_url, is_primary, is_duplicate, duplicate_of, quality, labels
    3. Sherlock scraper:
         contest_id, contest_title, issue_id, severity, title, description,
         source_url, found_by, judge_comment
    4. CodeHawks scraper:
         contest_slug, contest_name, contest_reward, finding_id, severity,
         title, description, source_url, submitter, num_duplicates
    5. Ethereum past-fix crawler (benchmarks/data/ethereum_past_fixes/*.csv):
         source, contest, issue_id, severity, title, description, source_url,
         introduced_in_commit
       `source` is the wallet slug (geth, nethermind, besu, erigon, reth,
       lighthouse, lodestar, nimbus, prysm, teku, grandine); `contest` is
       typically the upstream repo slug; `introduced_in_commit` is the
       vulnerable-state commit (parent of the fix commit — see
       scripts/datasets/blame_walk.py for the resolver). Used by Phase B to
       slice the corpus to the pre-fix state for held-out replay.

Pass `--platform-hint <p>` if a CSV lacks a `source` column.

Pass `--filter-platforms ''` (empty) to disable platform filtering when
unioning a domain whose platforms aren't pre-enumerated here (e.g.
ethereum's 11 wallets).

Downstream enrichment (NOT produced here — classification is a separate step
so re-builds do not re-trigger Haiku):
    stride      str   STRIDE threat category assigned by classify_stride_cwe.py
    cwe_top25   str   CWE-Top-25 (2024) id or "N/A", assigned by classify_stride_cwe.py
    Run: python -m scripts.datasets.classify_stride_cwe --in <train.parquet> --out <out.parquet>

Example:
    python scripts/datasets/build_derived.py \\
        --domain defi \\
        --source csv/similar_audit_findings.csv \\
        --out-dir dist/datasets
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

# 8 MiB per CSV cell — well above any legitimate audit description we've
# seen (~15 KiB max in csv/similar_audit_findings.csv) but bounded enough
# that a corrupt input can't OOM the runner.
_CSV_FIELD_LIMIT_BYTES = 8 * 1024 * 1024

PLATFORMS = ("code4rena", "sherlock", "codehawks")

# Ethereum bug-bounty in-scope wallets (issue #2). Used as the default
# platform allow-list when --domain=ethereum and --filter-platforms is
# not given explicitly.
ETH_CLIENTS = (
    "geth", "nethermind", "besu", "erigon", "reth",
    "lighthouse", "lodestar", "nimbus", "prysm", "teku", "grandine",
)

# CSV column aliases — first key found wins. Per-platform scraper outputs
# populate different keys for the same logical contest (e.g. Code4rena's
# scraper writes `contest_repo`; the curated csv/similar_audit_findings.csv
# writes `contest`). slugify_contest() collapses these to a stable form so
# the same finding gets the same `id` regardless of which CSV it came from.
CONTEST_KEYS = ("contest", "contest_repo", "contest_name", "contest_id", "contest_slug")
ISSUE_KEYS = ("issue_id", "finding_id")
PLATFORM_KEYS = ("source_platform", "source", "platform")

_SLUG_RE = re.compile(r"[^a-z0-9.-]+")


def first_present(row: dict, keys: Iterable[str], default: str = "") -> str:
    """First non-empty value among `keys`, coerced to str. None-safe — the
    caller may pass dicts whose values are pandas NaN / None (e.g. from a
    parquet round-trip) without tripping a TypeError."""
    for k in keys:
        v = row.get(k)
        if v is None:
            continue
        s = str(v).strip()
        # pandas/numpy NaN floats stringify as 'nan' — treat as missing.
        if not s or s.lower() == "nan":
            continue
        return s
    return default


def slugify_contest(s: str) -> str:
    """Stable, URL-safe contest identifier. Lowercases, replaces runs of
    non-`[a-z0-9.-]` with a single `-`, and trims leading/trailing dashes.
    Idempotent on already-slugged inputs.
    """
    s = (s or "").lower().strip()
    s = _SLUG_RE.sub("-", s)
    return s.strip("-")


def synth_source_url(platform: str, contest_slug: str, issue_id: str) -> str:
    """Best-effort URL for platforms whose URL shape is mostly deterministic.

    Code4rena: `code-423n4/<contest>` GitHub repo, issue numbers map 1:1.
    May 404 for contests whose findings live in a sibling `<contest>-findings`
    repo — populate `source_url` from the scraper directly to avoid this.

    Sherlock / CodeHawks: URL shapes vary per contest; we don't synthesize.
    The scraper's `source_url` column, when present, is preferred.
    """
    iid = issue_id.lstrip("#").strip()
    if not iid:
        return ""
    if platform == "code4rena" and contest_slug:
        return f"https://github.com/code-423n4/{contest_slug}/issues/{iid}"
    return ""


def normalize_row(row: dict, domain: str, scraped_at: str, platform_hint: str = "") -> dict | None:
    """Project a CSV row onto the unified schema. Returns None if the row is
    too sparse to keep (e.g. blank title and description)."""
    platform = (platform_hint or first_present(row, PLATFORM_KEYS)).lower()
    contest_raw = first_present(row, CONTEST_KEYS)
    contest = slugify_contest(contest_raw)
    issue_id = first_present(row, ISSUE_KEYS)
    severity = first_present(row, ("severity",)).capitalize()
    title = first_present(row, ("title",))
    # `description_excerpt` is the truncated form used by the
    # past_defi_patterns / chainlink_v2 CSVs; treat it as the description
    # so those sources can be unioned into the same parquet without losing
    # the body text.
    description = first_present(row, ("description", "description_excerpt"))
    source_url = first_present(row, ("source_url",)) or synth_source_url(
        platform, contest, issue_id
    )
    # Provenance commit for Phase B replay (ethereum past-fixes). Empty
    # for defi / curated CSVs that don't carry this column.
    introduced_in_commit = first_present(row, ("introduced_in_commit",))

    if not title and not description:
        return None

    iid = issue_id.lstrip("#").strip()
    if platform and contest and iid:
        record_id = f"{platform}:{contest}:{iid}"
    else:
        h = hashlib.sha256(f"{title}\n{description}".encode("utf-8")).hexdigest()[:16]
        record_id = f"unknown:{h}"

    return {
        "id": record_id,
        "source_platform": platform,
        "contest": contest,
        "issue_id": issue_id,
        "severity": severity,
        "title": title,
        "description": description,
        "source_url": source_url,
        "introduced_in_commit": introduced_in_commit,
        "domain": domain,
        "scraped_at": scraped_at,
    }


def speca_commit() -> str:
    """`git rev-parse HEAD` rooted at this script's repo, regardless of the
    caller's cwd — so a wrapper script that runs build_derived from /tmp
    still records the correct speca commit.
    """
    repo_root = Path(__file__).resolve().parents[2]
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
            cwd=str(repo_root),
        ).strip()
    except Exception:
        return ""


def load_rows(
    sources: list[str],
    domain: str,
    scraped_at: str,
    platform_hint: str,
    allowed_platforms: set[str] | None,
    allowed_severities: set[str],
    max_rows: int,
) -> list[dict]:
    """Load + normalize. `allowed_platforms=None` disables platform
    filtering — used when the domain's platform universe isn't
    pre-enumerated (e.g. ethereum's 11 wallets passed in via the CSV)."""
    csv.field_size_limit(_CSV_FIELD_LIMIT_BYTES)
    out: list[dict] = []
    for src in sources:
        path = Path(src)
        if not path.exists():
            sys.exit(f"source not found: {path}")
        # Force utf-8 — scraper outputs are utf-8 (GHSA bodies often
        # carry curly quotes / non-ASCII names) and Python's default
        # falls back to the system locale (cp932 on Japanese Windows),
        # which decode-errors on those characters.
        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for raw in reader:
                norm = normalize_row(raw, domain, scraped_at, platform_hint)
                if norm is None:
                    continue
                if allowed_platforms is not None and norm["source_platform"] not in allowed_platforms:
                    continue
                if allowed_severities and norm["severity"] not in allowed_severities:
                    continue
                out.append(norm)
                if max_rows and len(out) >= max_rows:
                    return out
    return out


def build(
    domain: str,
    sources: list[str],
    out_dir: Path,
    scraped_at: str = "",
    platform_hint: str = "",
    filter_platforms: str = ",".join(PLATFORMS),
    severity_filter: str = "",
    max_rows: int = 0,
) -> dict:
    """Library entry point. Returns the manifest dict.

    `filter_platforms` semantics:
        - non-empty CSV string  → keep only those platforms (e.g. defi default).
        - empty string ('')     → no platform filter (e.g. ethereum, where
                                  the CSV carries arbitrary wallet slugs).
    """
    scraped_at = scraped_at or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    raw_filter = (filter_platforms or "").strip()
    if raw_filter:
        allowed_platforms: set[str] | None = {
            p.strip().lower() for p in raw_filter.split(",") if p.strip()
        }
    else:
        # No filter — accept whatever `source_platform` the CSV carries.
        allowed_platforms = None
    allowed_severities = {
        s.strip().capitalize() for s in severity_filter.split(",") if s.strip()
    }

    rows = load_rows(
        sources, domain, scraped_at, platform_hint,
        allowed_platforms, allowed_severities, max_rows,
    )
    if not rows:
        sys.exit("no rows after filtering")

    df = pd.DataFrame(rows)
    df = df.drop_duplicates(subset=["id"], keep="first").reset_index(drop=True)

    domain_dir = out_dir / domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    parquet_path = domain_dir / "train.parquet"

    table = pa.Table.from_pandas(df, preserve_index=False)
    pq.write_table(table, parquet_path, compression="zstd")

    rows_by_platform = {k: int(v) for k, v in df.groupby("source_platform").size().items()}
    rows_by_severity = {k: int(v) for k, v in df.groupby("severity").size().items()}

    # Always a list (empty == no severity filter applied) so consumers
    # don't need an isinstance() branch.
    severities_included = sorted(allowed_severities)
    # platforms_included: explicit allow-list when --filter-platforms is
    # set; empty list when filtering is disabled. Consumers can grep
    # rows_by_platform for the platforms that actually landed in the
    # parquet either way.
    platforms_included = sorted(allowed_platforms) if allowed_platforms is not None else []

    manifest = {
        "domain": domain,
        "n_rows": int(len(df)),
        "sources": list(sources),
        "scraped_at": scraped_at,
        "speca_commit": speca_commit(),
        "platforms_included": platforms_included,
        "severities_included": severities_included,
        "rows_by_platform": rows_by_platform,
        "rows_by_severity": rows_by_severity,
        "parquet_path": str(parquet_path.relative_to(domain_dir)),
        "parquet_bytes": parquet_path.stat().st_size,
    }
    (domain_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--domain", required=True,
                   help="Domain label (e.g. defi, lending, oracle).")
    p.add_argument("--source", action="append", required=True,
                   help="CSV path; pass --source multiple times to merge.")
    p.add_argument("--out-dir", default="dist/datasets",
                   help="Output root (default dist/datasets).")
    p.add_argument("--scraped-at", default="",
                   help="ISO 8601 UTC; default = now.")
    p.add_argument("--platform-hint", default="",
                   help="Override platform when CSV lacks a source column.")
    p.add_argument("--filter-platforms", default=",".join(PLATFORMS),
                   help="Comma-separated platforms to include. "
                        "Pass '' (empty) to disable filtering — needed for "
                        "domains like ethereum whose source_platform values "
                        "(wallet slugs) aren't pre-enumerated.")
    p.add_argument("--severity-filter", default="",
                   help="Comma-separated severities to include (default: all).")
    p.add_argument("--max-rows", type=int, default=0,
                   help="Cap row count after filtering (0 = no cap).")
    args = p.parse_args()

    manifest = build(
        domain=args.domain,
        sources=args.source,
        out_dir=Path(args.out_dir),
        scraped_at=args.scraped_at,
        platform_hint=args.platform_hint,
        filter_platforms=args.filter_platforms,
        severity_filter=args.severity_filter,
        max_rows=args.max_rows,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
