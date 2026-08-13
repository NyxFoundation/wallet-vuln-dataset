#!/usr/bin/env python3
"""Flag rows whose commit never reached the product, and rows that count a fix twice.

Enumeration walks `git log --all`, which is deliberate — a fix on a maintenance
branch is still a fix. But it also admits commits from branches that were never
merged, and commits from pull requests that were squash-merged, whose change is
then counted a second time under the squashed SHA. Neither is visible in the row.

Three columns are added; no row is deleted, because a row that did not ship is
still evidence about how the project works:

  on_default   the commit is an ancestor of HEAD
  in_release   a tag contains the commit (so users got it even if it is off-trunk)
  dup_subject  its subject, ignoring a trailing "(#123)", matches a DIFFERENT row
               in this table that IS on the default branch — i.e. the same fix,
               counted once as the PR commit and once as the squash

The population to analyse is then `on_default | in_release`, minus `dup_subject`.

    uv run python scripts/mark_reachable.py data/silent_mechanisms.csv
    uv run python scripts/mark_reachable.py data/advisory_mechanisms.csv
"""
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

import pandas as pd

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPOS = ROOT / "scratchpad_crawl" / "repos"


def _norm(subject: str) -> str:
    s = re.sub(r"\s*\(#\d+\)\s*$", "", str(subject)).strip().lower()
    return re.sub(r"\s+", " ", s)


def _reachable(repo: str) -> tuple[set[str], dict[str, str]]:
    """(SHAs reachable from HEAD, SHA -> normalised subject) for the whole repo."""
    out = subprocess.run(
        ["git", "-C", str(REPOS / f"{repo}.git"), "rev-list",
         "--format=%H %s", "--no-commit-header", "HEAD"],
        capture_output=True, text=True, errors="replace", timeout=1800).stdout
    reach, subj = set(), {}
    for line in out.splitlines():
        if not line.strip():
            continue
        sha, _, s = line.partition(" ")
        reach.add(sha)
        subj[sha] = _norm(s)
    return reach, subj


def _tagged(repo: str, shas: list[str]) -> set[str]:
    """Which of these SHAs any tag contains. One call per SHA, so only off-trunk
    rows are asked — on-trunk rows do not need it."""
    got = set()
    for sha in shas:
        r = subprocess.run(["git", "-C", str(REPOS / f"{repo}.git"), "tag",
                            "--contains", sha], capture_output=True, text=True,
                           timeout=180)
        if r.stdout.strip():
            got.add(sha)
    return got


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("table", type=pathlib.Path)
    ap.add_argument("--out", type=pathlib.Path, help="default: overwrite in place")
    a = ap.parse_args()

    df = pd.read_csv(a.table)
    # Only a /commit/<sha> URL can be tested. A /pull/<n> URL has no SHA in it,
    # and the first version of this script fed the PR NUMBER to `merge-base`,
    # which fails for every row — so 1,132 advisory rows were recorded as
    # "never reached the product" when the truth is "not testable this way".
    df["sha"] = df.source_url.map(
        lambda u: str(u).rsplit("/", 1)[-1] if "/commit/" in str(u) else None)
    df["on_default"] = pd.Series([pd.NA] * len(df), dtype="boolean")
    df["in_release"] = pd.Series([pd.NA] * len(df), dtype="boolean")
    df["dup_subject"] = pd.Series([pd.NA] * len(df), dtype="boolean")
    testable = df.sha.notna()
    print(f"{int(testable.sum()):,} of {len(df):,} rows carry a commit SHA and can "
          f"be tested; the rest stay NA", file=sys.stderr)

    for repo, g in df[testable].groupby("wallet"):
        if not (REPOS / f"{repo}.git" / "HEAD").exists():
            print(f"[skip] {repo}: no clone; rows left unflagged", file=sys.stderr)
            continue
        reach, subj = _reachable(repo)
        on = g.sha.isin(reach)
        # Assign the whole series, not just its True positions. Writing only the
        # Trues left every tested-but-unreachable row at NA, making "not testable"
        # and "tested, never shipped" the same value — the exact confusion these
        # columns exist to remove.
        df.loc[g.index, "on_default"] = on.values
        df.loc[g.index, "in_release"] = False
        df.loc[g.index, "dup_subject"] = False
        off = g[~on]
        if len(off):
            tagged = _tagged(repo, off.sha.tolist())
            df.loc[off.index, "in_release"] = off.sha.isin(tagged).values
            # A duplicate only if the twin is the default-branch row of the same fix.
            on_subjects = {_norm(t) for t in g.loc[g.index[on], "title"]}
            df.loc[off.index, "dup_subject"] = off.title.map(_norm).isin(on_subjects).values
        print(f"[{repo:<18}] {len(g):>5} rows  on_default {int(on.sum()):>5}  "
              f"off-trunk {len(off):>4}", flush=True)

    reached = (df.on_default.fillna(False) | df.in_release.fillna(False))
    dup = df.dup_subject.fillna(False)
    print(f"\n{a.table.name}: {len(df):,} rows")
    print(f"  not testable (no commit SHA): {int((~testable).sum()):,}")
    print(f"  reached a product           : {int((reached & testable).sum()):,}")
    print(f"  never reached it            : {int((~reached & testable).sum()):,}")
    print(f"  duplicate of a counted fix  : {int((dup & testable).sum()):,}")
    (a.out or a.table).parent.mkdir(parents=True, exist_ok=True)
    df.drop(columns=["sha"]).to_csv(a.out or a.table, index=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
