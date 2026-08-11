#!/usr/bin/env python3
"""repo_priority.py — the order to sweep repos in, and the evidence for it.

Stars say how many people a defect would reach. They say nothing about how many
defects are there, and the two diverge sharply: measured silent-fix rate across
repos with >=150 judged commits runs from 25.3% (LedgerHQ/app-ethereum) to 0.3%
(solana-foundation/solana-web3.js) — an 25x spread. Sorting on stars alone sends
the most expensive repos (large app monorepos, tens of thousands of commits) to
the front of a queue where they yield ~2%.

So this prints both, and leaves the decision explicit. A repo is skipped on
evidence — "2,016 commits judged, 41 hits" — not because it looked big.

`cost` is the count of commits that would actually be sent to the model.
enumerate_commits keeps 63-84% of history (pooled 77%, measured over seven
repos) after dropping merges, source-free commits and oversized diffs — so this
is an estimate, and a repo already enumerated reports its true count instead.

    uv run python scripts/repo_priority.py                  # the table
    uv run python scripts/repo_priority.py --top 10 --slugs # feed the sweep
"""
from __future__ import annotations

import argparse
import importlib.util as ilu
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
# Measured across seven fully-enumerated repos: 63%-84%, pooled 77%.
#
# The first estimate was 54%, from multiplying two rates sampled on one repo
# (80% non-merge x 67% touching source). They are not independent — a non-merge
# commit is far more likely to touch source — so the product understated the
# real keep rate by a third, and every cost in this table with it. The spread
# tracks language mix: electrum is almost entirely Python and keeps 84%, while
# a JS monorepo full of lockfiles and configs keeps 63%.
KEEP_SHARE = 0.77


def _load(name: str, rel: str):
    spec = ilu.spec_from_file_location(name, ROOT / rel)
    mod = ilu.module_from_spec(spec); spec.loader.exec_module(mod)  # type: ignore
    return mod


def measured_yield() -> dict[str, tuple[int, int]]:
    """repo -> (judged, hits) from every prediction made so far."""
    csv = ROOT / "data" / "silent_fix_llm.csv"
    if not csv.exists():
        return {}
    df = pd.read_csv(csv, usecols=["source_url", "silent_fix_prob"])
    slug = df.source_url.map(
        lambda u: (re.search(r"github\.com/([^/]+/[^/]+)", str(u)) or [None, None])[1])
    df = df.assign(repo=slug).dropna(subset=["repo"])
    g = df.groupby("repo").agg(n=("silent_fix_prob", "size"),
                               hit=("silent_fix_prob", lambda s: int((s >= 0.70).sum())))
    return {r: (int(v.n), int(v.hit)) for r, v in g.iterrows()}


def commit_count(wallet: str) -> int:
    p = ROOT / "scratchpad_crawl" / "repos" / f"{wallet}.git"
    if not (p / "HEAD").exists():
        return -1
    r = subprocess.run(["git", "-C", str(p), "rev-list", "--count", "--no-merges", "--all"],
                       capture_output=True, text=True, timeout=300)
    try:
        return int(r.stdout.strip())
    except ValueError:
        return -1


def stars(repo: str) -> int:
    r = subprocess.run(["gh", "api", f"/repos/{repo}", "--jq", ".stargazers_count"],
                       capture_output=True, text=True, timeout=30)
    try:
        return int(r.stdout.strip())
    except ValueError:
        return -1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--top", type=int, default=0, help="only the first N repos")
    ap.add_argument("--slugs", action="store_true", help="print bare slugs for the sweep")
    ap.add_argument("--stars-cache", type=Path,
                    default=ROOT / "scratchpad_crawl" / "stars.json")
    a = ap.parse_args()

    wallets = _load("wallets", "collection/wallets.py").WALLET_CONFIG
    if a.stars_cache.exists():
        star_map = json.loads(a.stars_cache.read_text())
    else:
        with ThreadPoolExecutor(max_workers=8) as ex:
            star_map = dict(zip(wallets, ex.map(stars, (c["repo"] for c in wallets.values()))))
        a.stars_cache.parent.mkdir(parents=True, exist_ok=True)
        a.stars_cache.write_text(json.dumps(star_map))

    yields = measured_yield()
    rows = []
    for slug, cfg in wallets.items():
        n, hit = yields.get(cfg["repo"], (0, 0))
        rows.append({
            "slug": slug, "repo": cfg["repo"], "stars": int(star_map.get(slug, -1)),
            "judged": n, "hits": hit,
            "rate": (hit / n) if n >= 150 else float("nan"),
            "commits": commit_count(slug),
        })
    df = pd.DataFrame(rows).sort_values("stars", ascending=False)
    # A repo that has actually been enumerated knows its own cost; only guess
    # for the rest.
    import glob as _glob
    known = {}
    for pq in _glob.glob(str(ROOT / "scratchpad_crawl/allcommits/*.parquet")):
        slug = Path(pq).stem
        try:
            known[slug] = len(pd.read_parquet(pq, columns=["id"]))
        except Exception:
            pass
    df["cost"] = (df.commits * KEEP_SHARE).round().astype("Int64").where(df.commits > 0)
    df["cost"] = df.apply(lambda r: known.get(r.slug, r["cost"]), axis=1).astype("Int64")
    if a.top:
        df = df.head(a.top)

    if a.slugs:
        print(" ".join(df.slug.tolist()))
        return 0

    print(f"{'stars':>8} {'commits':>8} {'to judge':>9} {'measured':>9}  repo")
    for _, r in df.iterrows():
        rate = "     —" if pd.isna(r["rate"]) else f"{r['rate']:>6.1%}"
        cost = "     —" if pd.isna(r["cost"]) else f"{int(r['cost']):>9,}"
        print(f"{r.stars:>8,} {max(r.commits,0):>8,} {cost} {rate}    {r.repo}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
