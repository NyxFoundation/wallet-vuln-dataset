#!/usr/bin/env python3
"""enumerate_commits.py — every commit in a repo, with no keyword filter at all.

The keyword crawl (`grep_wallet_commits.py`) decides what to look at from the
words an author chose, which is exactly the assumption a silent fix breaks: the
commit that says "cleanup" is the one worth reading. This walks the whole
history from a local bare clone instead and lets the LLM pass be the only judge
of meaning.

What is filtered here is STRUCTURAL only — facts about the commit, never a guess
at what it means:

  * merge commits carry no diff of their own
  * commits touching no source file cannot contain a code defect
  * commits above --max-files are vendored drops, generated output or
    reformatting sweeps; their diffs do not fit a prompt and are not a fix

Two DETERMINISTIC signals are recorded per commit, both computed from git rather
than from text:

  is_backport   the same patch (by `git patch-id`, which hashes the diff and so
                survives a cherry-pick's new SHA) appears on more than one
                branch. Backporting a change to a maintenance branch is extra
                work a team only does when users on the old release cannot wait
                — the developers' own statement of urgency, made by action
                rather than in words, which is why it survives where a keyword
                does not.
  n_branches    how many refs contain the commit.

Usage:
    uv run python collection/enumerate_commits.py --wallet bitcoinjs-lib \
        --out scratchpad_crawl/allcommits/bitcoinjs-lib.parquet
"""
from __future__ import annotations

import argparse
import hashlib
import os
import signal
import subprocess
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import local_diffs as ld  # noqa: E402

SOURCE_EXT = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go", ".rs", ".py", ".c",
    ".cc", ".cpp", ".cxx", ".h", ".hpp", ".java", ".kt", ".kts", ".swift",
    ".m", ".mm", ".sol", ".nim", ".dart", ".rb", ".cs", ".scala", ".ex",
    ".exs", ".hs", ".ml", ".zig", ".vy", ".move", ".cairo", ".S", ".asm",
}
# Above this, the commit is a vendored drop, generated output or a formatting
# sweep. Such a diff neither fits a prompt nor describes a single defect.
MAX_FILES = 60
# `git log --all -p` renders the whole history's diffs; on a many-ref repo that
# runs for tens of minutes for one optional column. Cap it well under the time a
# repo's own judging pass takes.
PATCH_ID_TIMEOUT = 420


def _run(args: list[str], cwd: Path) -> str:
    r = subprocess.run(["git", "-C", str(cwd)] + args, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=600)
    return r.stdout


def touches_source(files: list[str]) -> bool:
    return any(Path(f).suffix in SOURCE_EXT for f in files)


def _patch_ids(p: Path, timeout: float) -> str:
    """`git log -p | git patch-id`, killed as a GROUP when it overruns.

    subprocess.run(shell=True, timeout=…) terminates the shell and returns, but
    the pipeline's children survive it: a `git patch-id` orphaned this way was
    still burning a core 30 minutes after its 420s deadline, invisible to the
    run that had already moved on. Own the process group so the timeout actually
    stops the work it claims to stop.
    """
    proc = subprocess.Popen(
        f"git -C {p} log --all --no-merges --format=%H -p | git patch-id --stable",
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, errors="replace", start_new_session=True)
    try:
        out, _ = proc.communicate(timeout=timeout)
        return out or ""
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait(timeout=30)
        raise


def collect(wallet: str, limit: int = 0) -> pd.DataFrame:
    p = ld.ensure_clone(wallet)
    repo = ld.WALLET_REPOS[wallet]

    # Which commits sit on more than one ref. `--all` walks every branch and tag;
    # a patch-id seen under two different SHAs is the same change applied twice,
    # which is what a cherry-pick to a maintenance branch looks like.
    patch_ids: dict[str, list[str]] = {}
    log = _run(["log", "--all", "--no-merges", "--format=%H"], p)
    shas = [s for s in log.split() if s]
    if limit:
        shas = shas[:limit]

    # ONE `git log` for the whole history, not two `git show`s per commit: the
    # per-commit version spent all its time on process spawn and could not walk
    # a 1,000-commit repo inside two minutes.
    wanted = set(shas)
    SEP = "\x01COMMIT\x01"
    stream = _run(["log", "--all", "--no-merges", "--name-only",
                   f"--format={SEP}%H%x00%s%x00%b%x00"], p)

    rows = []
    for chunk in stream.split(SEP):
        if not chunk.strip():
            continue
        head, _, tail = chunk.partition("\x00")
        sha = head.strip()
        if sha not in wanted:
            continue
        subject, _, rest = tail.partition("\x00")
        body, _, filepart = rest.partition("\x00")
        files = [f for f in filepart.split("\n") if f.strip()]
        if not files or len(files) > MAX_FILES or not touches_source(files):
            continue
        rows.append({
            "id": hashlib.sha1(f"{wallet}:{sha}".encode()).hexdigest()[:16],
            "source_platform": wallet,
            "issue_id": sha[:12],
            "contest": "all-commits",
            "severity": "Unrated",
            "title": subject[:500],
            "description": body[:2000],
            "source_url": f"https://github.com/{repo}/commit/{sha}",
            "domain": "wallet",
            "stride": "Other",
            "cwe_top25": "N/A",
            "n_files": len(files),
        })
    df = pd.DataFrame(rows)

    # Backport detection is ADDITIVE metadata. It must never decide whether the
    # repo gets enumerated at all: `git log --all -p` renders every diff in the
    # history, which on wallet-core (107 refs) blew a 1800s timeout, killed the
    # enumerator, and the sweep's `|| continue` skipped the repo in silence. An
    # optional column is not worth a lost repo, so a failure here costs the
    # column and nothing else.
    df["is_backport"] = False
    if len(df):
        try:
            pid_out = _patch_ids(p, PATCH_ID_TIMEOUT)
            for line in pid_out.splitlines():
                bits = line.split()
                if len(bits) == 2:
                    patch_ids.setdefault(bits[0], []).append(bits[1])
            dup = {sha for shas_ in patch_ids.values() if len(shas_) > 1 for sha in shas_}
            full = df["source_url"].str.rsplit("/", n=1).str[-1]
            df["is_backport"] = full.isin(dup)
        except (subprocess.TimeoutExpired, OSError) as exc:
            print(f"[enumerate] {wallet}: backport detection skipped "
                  f"({type(exc).__name__}); commits are unaffected", file=sys.stderr)
    return df


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--wallet", required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=0, help="cap commits walked (smoke runs)")
    a = ap.parse_args()

    df = collect(a.wallet, a.limit)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(a.out, index=False)
    nb = int(df["is_backport"].sum()) if "is_backport" in df.columns else 0
    print(f"[enumerate] {a.wallet}: {len(df)} commits kept "
          f"({nb} backported) -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
