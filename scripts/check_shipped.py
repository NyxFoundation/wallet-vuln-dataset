#!/usr/bin/env python3
"""Did the flaw this commit fixes ever reach a released version?

A "fix commit" is not evidence of a shipped vulnerability. It can be a developer
cleaning up their own branch, or a fix that landed before the product's first
release. Both appear in the corpus, because enumeration walks `git log --all`.

Two conditions, both from git alone:

  on_default  the commit is an ancestor of HEAD. A commit reachable only from a
              feature branch never became the product.
  shipped_in  a tag contains the commit's PARENT but not the commit itself. Such
              a tag is a released version carrying the pre-fix code — direct
              evidence that users ran the flaw.

Neither condition is about severity. They only separate "this was in a release"
from "this was in a working copy".

    uv run python scripts/check_shipped.py trezor-firmware d800fcb…
    uv run python scripts/check_shipped.py --mechanism authorization-check --want 5
"""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

import pandas as pd

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPOS = ROOT / "scratchpad_crawl" / "repos"


def _git(repo: str, *args: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(REPOS / f"{repo}.git")] + list(args),
                          capture_output=True, text=True, errors="replace",
                          timeout=timeout)


def check(repo: str, sha: str) -> tuple[bool, str | None]:
    """(is on the default branch, name of a release that shipped the flaw)."""
    if _git(repo, "merge-base", "--is-ancestor", sha, "HEAD").returncode != 0:
        return False, None
    parent = _git(repo, "rev-parse", f"{sha}^").stdout.strip()
    if not parent:
        return True, None
    # Two calls, not one per tag: `--contains` walks the graph once, and the
    # per-tag version took minutes on a repo with 849 tags.
    has_fix = set(_git(repo, "tag", "--contains", sha).stdout.split())
    has_parent = set(_git(repo, "tag", "--contains", parent).stdout.split())
    shipped = sorted(has_parent - has_fix)
    return True, (shipped[0] if shipped else None)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", nargs="?")
    ap.add_argument("sha", nargs="?")
    ap.add_argument("--mechanism", help="scan candidates with this defect mechanism")
    ap.add_argument("--want", type=int, default=5, help="stop after N that pass")
    ap.add_argument("--table", type=pathlib.Path,
                    default=ROOT / "data" / "silent_mechanisms.csv")
    a = ap.parse_args()

    if a.repo and a.sha:
        on, tag = check(a.repo, a.sha)
        print(f"on default branch : {'yes' if on else 'NO'}")
        print(f"shipped the flaw  : {tag or 'no release found carrying it'}")
        return 0 if (on and tag) else 1

    if not a.mechanism:
        ap.error("give either <repo> <sha>, or --mechanism")
    df = pd.read_csv(a.table)
    pool = df[(df.mechanism == a.mechanism) & (df.silent_fix_prob >= 0.9)]
    found = 0
    for _, row in pool.iterrows():
        repo = row.wallet
        if not (REPOS / f"{repo}.git" / "HEAD").exists():
            continue
        try:
            on, tag = check(repo, str(row.source_url).rsplit("/", 1)[-1])
        except subprocess.TimeoutExpired:
            continue
        if on and tag:
            print(f"[{repo}] shipped in {tag}\n  {row.title}\n  {row.source_url}",
                  flush=True)
            found += 1
            if found >= a.want:
                break
    if not found:
        print("nothing in this mechanism passed both conditions", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
