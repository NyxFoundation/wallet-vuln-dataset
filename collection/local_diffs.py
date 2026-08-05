#!/usr/bin/env python3
"""local_diffs.py — serve PR/commit diffs from a local git clone.

Drop-in replacement for the per-item `gh pr diff` / `gh api /commits` calls used
by the classifiers. Git transport (clone/fetch) is NOT subject to the REST API's
5,000/hr or the secondary-rate-limit 403s we fought with — so this removes the
rate-limit ceiling and turns each diff fetch from a ~0.3-1s network call into a
~1-5ms local `git` read.

Design:
  * One bare, blobless clone per wallet (`--filter=blob:none`): fast to create,
    full commit/tree graph, blobs fetched lazily on first access (still git
    transport, no REST limit). Cached under scratchpad_crawl/repos/<wallet>.git.
  * commit SHA  -> `git show` (fetch the object on demand if absent).
  * PR number   -> ensure refs/pull/N/head, then diff merge-base(default,head)
    ..head — the same 3-dot semantics as `gh pr diff`, so diffs match the cache.

CLI:
  warm  --wallet geth                 # create/refresh the local clone
  diff  --wallet geth --url <github url>
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import importlib.util as _ilu
_WSPEC = _ilu.spec_from_file_location("_wallets", Path(__file__).resolve().parent / "wallets.py")
_wallets_mod = _ilu.module_from_spec(_WSPEC); _WSPEC.loader.exec_module(_wallets_mod)  # type: ignore
WALLET_REPOS: dict[str, str] = {s: c["repo"] for s, c in _wallets_mod.WALLET_CONFIG.items()}
REPO_DIR = Path("scratchpad_crawl/repos")
PR_RE = re.compile(r"github\.com/[^/]+/[^/]+/pull/(\d+)")
SHA_RE = re.compile(r"github\.com/[^/]+/[^/]+/commit/([0-9a-f]{7,40})", re.I)


def _run(args, timeout=600):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace")


def repo_path(wallet: str) -> Path:
    return REPO_DIR / f"{wallet}.git"


_CLONE_DEAD: dict[str, str] = {}
_CLONE_DEAD_LOCK = threading.Lock()


def ensure_clone(wallet: str, blobless: bool = True) -> Path:
    """Return the bare clone path, cloning it once even under concurrency.

    Callers are thread pools, and two workers reaching the same cold repo both
    saw "no clone" and both ran `git clone` into the same path: the loser died
    with "destination path already exists and is not an empty directory", which
    the caller records as a permanently failed diff. Clone into a private
    directory and rename it into place, so the loser simply adopts the winner's
    clone. The rename is also what makes the path safe to read from ANOTHER
    process — a half-written clone is never visible under the final name.
    """
    p = repo_path(wallet)
    if (p / "HEAD").exists():
        return p
    # A repo that cannot be cloned cannot be cloned for the next row either.
    # `chainapsis/keplr-wallet` went private after it was crawled, and every one
    # of its 263 curated rows re-attempted a full clone against a 404 — the
    # failure is a property of the REPO, not of the row that happened to hit it.
    with _CLONE_DEAD_LOCK:
        if wallet in _CLONE_DEAD:
            raise RuntimeError(f"clone unavailable for {wallet}: {_CLONE_DEAD[wallet]}")
    p.parent.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/{WALLET_REPOS[wallet]}.git"
    staging = p.with_name(f"{p.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    args = (["git", "clone", "--bare"] + (["--filter=blob:none"] if blobless else [])
            + [url, str(staging)])
    print(f"[local_diffs] cloning {url} (bare{'/blobless' if blobless else ''})…", file=sys.stderr)
    try:
        r = _run(args, timeout=1800)
        if r.returncode != 0:
            err = r.stderr[:300]
            # Only a permanent answer is remembered; a timeout or transport blip
            # must stay retryable, or one bad minute writes off a whole repo.
            if re.search(r"not found|does not exist|Access denied|401|403|"
                         r"could not read Username|Authentication failed", err, re.I):
                with _CLONE_DEAD_LOCK:
                    _CLONE_DEAD[wallet] = err.strip().splitlines()[-1][:160]
            raise RuntimeError(f"clone failed for {wallet}: {err}")
        try:
            os.rename(staging, p)
        except OSError:
            # Another worker got there first; its clone is as good as ours.
            if not (p / "HEAD").exists():
                raise
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    return p


def _default_ref(p: Path) -> str:
    r = _run(["git", "-C", str(p), "symbolic-ref", "--short", "HEAD"])
    return f"refs/heads/{r.stdout.strip()}" if r.returncode == 0 and r.stdout.strip() else "HEAD"


def get_commit_diff(wallet: str, sha: str) -> str | None:
    p = ensure_clone(wallet)
    if _run(["git", "-C", str(p), "cat-file", "-e", sha]).returncode != 0:
        _run(["git", "-C", str(p), "fetch", "--quiet", "origin", sha], timeout=300)
    r = _run(["git", "-C", str(p), "show", "--format=", "--unified=3", sha])
    return r.stdout if r.returncode == 0 and r.stdout.strip() else None


def warm_prs(wallet: str) -> None:
    """Bulk-fetch every PR head ref so all PR diffs are served locally/instantly.
    One fetch per repo (~+120 MB blobless for geth) instead of a network call per
    PR — turns the 17k-row classification into an LLM-bound-only job."""
    p = ensure_clone(wallet)
    r = _run(["git", "-C", str(p), "fetch", "--filter=blob:none", "--quiet",
              "origin", "+refs/pull/*/head:refs/pull/*/head"], timeout=1200)
    n = _run(["git", "-C", str(p), "for-each-ref", "refs/pull/", "--format=x"]).stdout.count("x")
    print(f"[local_diffs] {wallet}: {n} PR refs local"
          + ("" if r.returncode == 0 else " (some conflicts skipped)"), file=sys.stderr)


def _resolve_pr_ref(p: Path, n: str, fetch: bool = True) -> str | None:
    """PR head ref, tolerating both layouts (refs/pull/N/head and refs/pull/N).

    A plain clone has no `refs/pull/*` — GitHub does not advertise them — so on a
    clone that has not been through `warm-prs` this returned None for every PR
    and every caller read that as "no such fix commit", silently. `get_pr_diff`
    already fetched the ref on demand; this did not, and the two disagreeing is
    what left 327 rows with no `fix_commit` and therefore un-de-duplicated.
    """
    for ref in (f"refs/pull/{n}/head", f"refs/pull/{n}"):
        if _run(["git", "-C", str(p), "rev-parse", "--verify", "--quiet", ref]).returncode == 0:
            return ref
    if not fetch:
        return None
    target = f"refs/pull/{n}/head"
    if _run(["git", "-C", str(p), "fetch", "--quiet", "origin", f"{target}:{target}"],
            timeout=300).returncode == 0:
        return target
    return None


def get_pr_diff(wallet: str, n: str) -> str | None:
    p = ensure_clone(wallet)
    ref = _resolve_pr_ref(p, n)
    if ref is None:
        target = f"refs/pull/{n}/head"
        if _run(["git", "-C", str(p), "fetch", "--quiet", "origin",
                 f"{target}:{target}"], timeout=300).returncode != 0:
            return None
        ref = target
    head = _run(["git", "-C", str(p), "rev-parse", ref]).stdout.strip()
    if not head:
        return None
    base = _run(["git", "-C", str(p), "merge-base", _default_ref(p), head]).stdout.strip()
    # No common ancestor (e.g. an unrelated-history fork) -> we cannot reproduce
    # GitHub's diff locally; signal miss so the caller falls back to `gh`.
    if not base:
        return None
    r = _run(["git", "-C", str(p), "diff", "--unified=3", f"{base}..{head}"])
    return r.stdout if r.returncode == 0 and r.stdout.strip() else None


def diff_for_url(url: str, wallet: str) -> str | None:
    m = SHA_RE.search(url)
    if m:
        return get_commit_diff(wallet, m.group(1))
    m = PR_RE.search(url)
    if m:
        return get_pr_diff(wallet, m.group(1))
    return None


def refresh(wallet: str) -> None:
    """Delta fetch: pull only new objects into an existing clone (cheap)."""
    p = repo_path(wallet)
    if not (p / "HEAD").exists():
        ensure_clone(wallet)
        return
    r = _run(["git", "-C", str(p), "fetch", "--filter=blob:none", "--quiet",
              "--prune", "origin", "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"],
             timeout=900)
    print(f"[local_diffs] {wallet} refreshed" + ("" if r.returncode == 0 else f" (warn: {r.stderr[:120]})"),
          file=sys.stderr)


def _gh_fallback(url: str, wallet: str) -> str | None:
    """Rare fork-PR cases where the local 3-dot diff is unreliable -> use gh."""
    repo = WALLET_REPOS[wallet]
    m = PR_RE.search(url)
    if m:
        r = _run(["gh", "pr", "diff", m.group(1), "--repo", repo], timeout=60)
    else:
        m = SHA_RE.search(url)
        if not m:
            return None
        r = _run(["gh", "api", f"/repos/{repo}/commits/{m.group(1)}",
                  "--jq", ".files[] | .patch // empty"], timeout=60)
    return r.stdout if r.returncode == 0 and r.stdout.strip() else None


# Diffs above this size are NOT cached. A monorepo commit touching thousands of
# files yields a multi-megabyte diff; caching those grew the JSON cache to 23 GB
# after 4,200 rows, and the caller re-serialises the whole cache every
# checkpoint, which is what killed the labelling run. Nothing is lost by
# skipping them: enrich_labels truncates every file to FILE_CAP_CHARS anyway,
# and a local bare clone re-reads a diff in milliseconds. The cache exists to
# avoid REMOTE fetches, not local ones.
MAX_CACHED_DIFF_CHARS = 200_000


def get_diff_cached(url: str, wallet: str, cache: dict, allow_gh: bool = True) -> str | None:
    """Canonical diff provider: persistent JSON cache -> local git -> gh fallback.

    Re-runs pay nothing for already-seen URLs; new rows fetch only their own
    objects (git transport, no REST rate limit). `cache` is mutated in place;
    the caller persists it. An empty-string cache entry means "known-missing".
    """
    if url in cache:
        return cache[url] or None
    d = diff_for_url(url, wallet)
    if d is None and allow_gh:
        d = _gh_fallback(url, wallet)
    if d is None or len(d) <= MAX_CACHED_DIFF_CHARS:
        cache[url] = d or ""      # oversized diffs re-read from git each time
    return d


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("warm"); w.add_argument("--wallet", required=True)
    wp = sub.add_parser("warm-prs"); wp.add_argument("--wallet", required=True)
    rf = sub.add_parser("refresh"); rf.add_argument("--wallet", required=True)
    d = sub.add_parser("diff")
    d.add_argument("--wallet", required=True); d.add_argument("--url", required=True)
    a = ap.parse_args()
    wallets = sorted(WALLET_REPOS) if a.wallet == "all" else [a.wallet]
    if a.cmd == "warm":
        for c in wallets:
            ensure_clone(c)
            print(f"[local_diffs] {c} ready at {repo_path(c)}")
        return 0
    if a.cmd == "warm-prs":
        for c in wallets:
            warm_prs(c)
        return 0
    if a.cmd == "refresh":
        for c in wallets:
            refresh(c)
        return 0
    if a.cmd == "diff":
        diff = diff_for_url(a.url, a.wallet)
        if diff is None:
            print("NO DIFF", file=sys.stderr); return 1
        sys.stdout.write(diff)
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
