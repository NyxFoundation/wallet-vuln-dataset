#!/usr/bin/env python3
"""merge_crawl_csvs.py — Merge any new-format crawl CSVs into train.parquet.

Reads *.csv from one or more source directories, normalizes column names to
train.parquet schema, deduplicates on (source_platform, issue_id), and
appends new rows.

Handles both old-schema (source, contest, issue_id, ...) and new-schema
(source_platform, ...) CSVs.

Usage:
    uv run python3 scripts/datasets/merge_crawl_csvs.py \
        --src-dirs dataset/ethereum_past_fixes/stealth_prs \
                   dataset/ethereum_past_fixes/spec_divergence \
        --parquet dataset/ethereum_past_fixes/train.parquet \
        --out dataset/ethereum_past_fixes/train.parquet
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    sys.exit("Run: uv add pandas pyarrow")

REQUIRED_COLS = [
    "id", "source_platform", "contest", "issue_id", "severity",
    "title", "description", "source_url", "introduced_in_commit",
    "domain", "scraped_at", "stride", "cwe_top25",
]

ALLOWED_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info", "Unrated"}


def make_id(source_platform: str, issue_id: str) -> str:
    return hashlib.md5(f"{source_platform}:{issue_id}".encode()).hexdigest()[:16]


def normalize_severity(s: str) -> str:
    s = s.strip()
    if s in ALLOWED_SEVERITIES:
        return s
    sl = s.lower()
    if sl == "critical":
        return "High"
    if sl in ("unrated", ""):
        return "Unrated"
    return "Info"


def load_csv(csv_path: Path, now: str) -> list[dict]:
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        for row in reader:
            # Normalize: old schema uses 'source', new uses 'source_platform'
            source = row.get("source_platform") or row.get("source", "")
            issue_id = row.get("issue_id", "").strip()
            if not source or not issue_id:
                continue
            rows.append({
                "id": make_id(source, issue_id),
                "source_platform": source.strip(),
                "contest": row.get("contest", "unknown").strip(),
                "issue_id": issue_id,
                "severity": normalize_severity(row.get("severity", "Unrated")),
                "title": (row.get("title") or "")[:500].strip(),
                "description": (row.get("description") or "")[:2000].strip(),
                "source_url": (row.get("source_url") or "").strip(),
                "introduced_in_commit": (row.get("introduced_in_commit") or "").strip(),
                "domain": row.get("domain", "ethereum").strip() or "ethereum",
                "scraped_at": row.get("scraped_at", now).strip() or now,
                "stride": row.get("stride", "Other").strip() or "Other",
                "cwe_top25": row.get("cwe_top25", "N/A").strip() or "N/A",
            })
    return rows


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--src-dirs", nargs="+", required=True, type=Path,
                   help="Directories containing *.csv files to merge")
    p.add_argument("--parquet", default="dataset/ethereum_past_fixes/train.parquet", type=Path)
    p.add_argument("--out", default="dataset/ethereum_past_fixes/train.parquet", type=Path)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    now = datetime.now(timezone.utc).isoformat()
    all_rows: list[dict] = []
    for src_dir in args.src_dirs:
        if not src_dir.exists():
            print(f"[merge_crawl_csvs] skipping {src_dir} (not found)", file=sys.stderr)
            continue
        for csv_path in sorted(src_dir.glob("*.csv")):
            rows = load_csv(csv_path, now)
            print(f"[merge_crawl_csvs] {csv_path.name}: {len(rows)} rows", file=sys.stderr)
            all_rows.extend(rows)

    print(f"[merge_crawl_csvs] total loaded: {len(all_rows)} rows", file=sys.stderr)

    df = pd.read_parquet(args.parquet)
    print(f"[merge_crawl_csvs] existing parquet: {len(df)} rows", file=sys.stderr)

    existing_ids = set(df["id"].tolist())
    new_rows = [r for r in all_rows if r["id"] not in existing_ids]
    print(f"[merge_crawl_csvs] new (deduplicated): {len(new_rows)} rows", file=sys.stderr)

    if not new_rows:
        print("[merge_crawl_csvs] nothing to add — parquet unchanged", file=sys.stderr)
        return 0

    if args.dry_run:
        print(f"[dry-run] would add {len(new_rows)} rows; skipping write", file=sys.stderr)
        return 0

    new_df = pd.DataFrame(new_rows)[REQUIRED_COLS]
    merged = pd.concat([df, new_df], ignore_index=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    merged.to_parquet(args.out, index=False)
    print(f"[merge_crawl_csvs] wrote {args.out} ({len(merged)} rows, +{len(new_rows)})",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
