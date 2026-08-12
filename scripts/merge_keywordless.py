#!/usr/bin/env python3
"""Fold a keyword-free sweep into the corpus inputs.

`keywordless_sweep.sh` leaves one enumerated parquet and one verdict CSV per
repository under `scratchpad_crawl/allcommits/`. Nothing downstream reads those,
so a finished sweep sits outside the dataset until this runs. It was previously
done by hand — the sweep's closing line named this script and the script did not
exist, so wave 2's fixes had no committed path in.

Two destinations, because they answer different questions:

  data/silent_fix_llm.csv        EVERY verdict, negatives included. The negatives
                                are what make the positives meaningful, and
                                dropping them would silently redefine the
                                denominator of every rate in the README.
  data/raw/train.classified.parquet
                                the rows that cleared the admission threshold,
                                as candidates. The gate re-scores them; this only
                                puts them in front of it.

Idempotent: keyed on source_url, re-running adds nothing. Run the gate afterwards
to actually admit the rows.

    uv run python scripts/merge_keywordless.py            # report only
    uv run python scripts/merge_keywordless.py --write
"""
from __future__ import annotations

import argparse
import glob
import pathlib
import sys

import pandas as pd

ROOT = pathlib.Path(__file__).resolve().parent.parent
THRESHOLD = 0.70
# The gate reads these; a missing one becomes a NaN column that fails T0/T1
# checks far downstream, so assemble them here where the source is obvious.
RAW_COLS = ["id", "source_platform", "contest", "issue_id", "severity", "title",
            "description", "source_url", "introduced_in_commit", "domain",
            "scraped_at", "stride", "cwe_top25", "evidence"]


def collect() -> tuple[pd.DataFrame, pd.DataFrame]:
    """(all verdicts, admitted candidate rows) across every swept repository."""
    verdicts, cands = [], []
    for f in sorted(glob.glob(str(ROOT / "scratchpad_crawl/allcommits/*.parquet"))):
        p = pathlib.Path(f)
        vf = p.with_suffix(".verdict.csv")
        if not vf.exists():
            print(f"[skip] {p.stem}: no verdict csv", file=sys.stderr)
            continue
        enum = pd.read_parquet(f)
        v = pd.read_csv(vf)
        verdicts.append(v)
        hits = v[v.silent_fix_prob >= THRESHOLD][["source_url"]]
        rows = enum.merge(hits, on="source_url")
        for c in RAW_COLS:
            if c not in rows.columns:
                rows[c] = pd.NA
        # scraped_at is left NA rather than stamped with "now": these commits were
        # read whenever the sweep ran, and inventing a timestamp at merge time
        # would misdate them.
        cands.append(rows[RAW_COLS])
        print(f"[read] {p.stem:<18} {len(v):>6,} verdicts  {len(rows):>5,} above {THRESHOLD}")
    if not verdicts:
        raise SystemExit("no swept repositories found")
    return (pd.concat(verdicts, ignore_index=True),
            pd.concat(cands, ignore_index=True))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true",
                    help="apply the merge; without it, only report what would change")
    ap.add_argument("--silent-fix-csv", type=pathlib.Path,
                    default=ROOT / "data/silent_fix_llm.csv")
    ap.add_argument("--raw", type=pathlib.Path,
                    default=ROOT / "data/raw/train.classified.parquet")
    a = ap.parse_args()

    verdicts, cands = collect()

    sf = pd.read_csv(a.silent_fix_csv)
    new_v = verdicts[~verdicts.source_url.isin(set(sf.source_url))]
    raw = pd.read_parquet(a.raw)
    new_c = cands[~cands.source_url.isin(set(raw.source_url))].drop_duplicates("source_url")

    print(f"\nverdicts   {len(sf):>7,} -> {len(sf) + len(new_v):>7,}  (+{len(new_v):,})")
    print(f"candidates {len(raw):>7,} -> {len(raw) + len(new_c):>7,}  (+{len(new_c):,})")
    if not a.write:
        print("\nreport only; pass --write to apply", file=sys.stderr)
        return 0

    if len(new_v):
        pd.concat([sf, new_v], ignore_index=True).to_csv(a.silent_fix_csv, index=False)
    if len(new_c):
        pd.concat([raw, new_c], ignore_index=True).to_parquet(a.raw, index=False)
    print(f"\nwrote {a.silent_fix_csv} and {a.raw}\n"
          f"now rebuild: uv run python pipeline/build_security_dataset.py "
          f"--in {a.raw.relative_to(ROOT)} --out data/wallet_vulns.parquet "
          f"--manifest data/manifest.json --silent-fix-csv "
          f"{a.silent_fix_csv.relative_to(ROOT)} --labels-csv data/labels.csv "
          f"--mechanisms-csv data/mechanisms.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
