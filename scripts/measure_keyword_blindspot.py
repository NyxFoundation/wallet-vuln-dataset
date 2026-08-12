#!/usr/bin/env python3
"""What the keyword crawl would have missed, measured on the same repositories.

The keyword-free sweep exists on the claim that authors do not label their
security fixes. This quantifies it: for every fix the sweep recovered, does the
commit message contain any of the crawler's own search terms?

The test is deliberately generous to keywords. GitHub's commit search indexes
the message; this matches subject AND body, so a term buried in a paragraph
counts as found. The real miss rate is therefore at least what this reports.

    uv run python scripts/measure_keyword_blindspot.py
"""
from __future__ import annotations

import glob
import importlib.util as ilu
import pathlib
import re
import sys

import pandas as pd

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _vocab():
    sp = ilu.spec_from_file_location("v", ROOT / "collection/wallet_vocab.py")
    m = ilu.module_from_spec(sp); sp.loader.exec_module(m)  # type: ignore
    return list(m._CORE_SEARCH_TERMS)


def main() -> int:
    terms = _vocab()
    pat = re.compile("|".join(re.escape(t) for t in terms), re.I)
    rows, tot, seen = [], 0, 0
    for f in sorted(glob.glob(str(ROOT / "scratchpad_crawl/allcommits/*.parquet"))):
        p = pathlib.Path(f)
        vf = p.with_suffix(".verdict.csv")
        if not vf.exists():
            continue
        e = pd.read_parquet(f, columns=["source_url", "title", "description"])
        d = pd.read_csv(vf, usecols=["source_url", "silent_fix_prob"])
        h = d[d.silent_fix_prob >= 0.70].merge(e, on="source_url")
        if not len(h):
            continue
        m = (h.title.fillna("") + " " + h.description.fillna("")).str.contains(pat, na=False)
        rows.append((p.stem, len(h), int((~m).sum()), float((~m).mean())))
        tot += len(h); seen += int(m.sum())
    if not rows:
        print("no verdict files yet", file=sys.stderr)
        return 1
    print(f"{len(terms)} crawler search terms\n")
    print(f"{'repo':<18}{'silent fixes':>13}{'keyword invisible':>19}{'share':>8}")
    for s, n, miss, sh in sorted(rows, key=lambda r: -r[3]):
        print(f"{s:<18}{n:>13,}{miss:>19,}{sh:>7.0%}")
    print(f"\n{'TOTAL':<18}{tot:>13,}{tot - seen:>19,}{(tot - seen) / tot:>7.0%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
