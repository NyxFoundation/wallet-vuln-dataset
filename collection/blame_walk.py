"""blame_walk.py — enrich `introduced_in_commit` for ethereum past-fix rows.

v1 semantic: `introduced_in_commit` stores the **vulnerable-state commit**,
which is the parent of the fix commit (not the commit that first introduced
the bug). For Phase B replay this is functionally equivalent: auditing the
pre-fix state asks "would the prompt catch this bug in the broken codebase?"
— exactly the replay semantic Phase B requires.

True introducing-commit search via `git log -G` (walking back to the first
commit that added the vulnerable code) is deferred to a follow-up PR.

Column name `introduced_in_commit` is kept as-is for schema stability.

Per-source-type coverage in v1:
    PR#<n>         → resolved via merge commit's first parent         (resolvable)
    RELEASE#<t>#<h>→ resolved via tag's commit's first parent         (resolvable)
    COMMIT#<12hex> → resolved via commit's first parent               (resolvable)
    GHSA-*         → resolved via advisory's patched_version tag       (resolvable)
    ISSUE#<n>      → "" always (no canonical fix commit in schema)     (TODO)
    CHANGELOG#<h>  → "" always (no version anchor in unified schema)   (TODO)

Usage:
    python -m scripts.datasets.blame_walk \
        --in  dist/datasets/ethereum/train.parquet \
        --out dist/datasets/ethereum/train.parquet \
        [--max-rows N] \
        [--manifest dist/datasets/ethereum/blame_walk_manifest.json]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import quote

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Injectable gh fetcher (mirrors crawl_wallet_past_fixes.py pattern)
# ---------------------------------------------------------------------------

def gh_json(path: str, timeout: int = 30):
    """Call `gh api <path>` and return parsed JSON, or None on error.

    Uses simple GET (no -f flags) so no -X GET workaround needed here.
    For list endpoints called by callers that add -f fields, the caller
    should wrap with their own subprocess call."""
    try:
        result = subprocess.run(
            ["gh", "api", path],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.warning("gh failed: %s", e)
        return None
    if result.returncode != 0:
        msg = (result.stderr or "").strip()[:300]
        logger.warning("gh exit %d: %s", result.returncode, msg)
        return None
    body = result.stdout.strip()
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError as e:
        logger.warning("gh output not JSON: %s", e)
        return None


# ---------------------------------------------------------------------------
# Import WALLET_CONFIG from the crawler (importlib, no sys.path mutation)
# ---------------------------------------------------------------------------

def _load_client_config() -> dict:
    import importlib.util
    crawler_path = Path(__file__).resolve().parents[2] / "benchmarks" / "scripts" / "crawl_wallet_past_fixes.py"
    spec = importlib.util.spec_from_file_location("_crawl_wallet_past_fixes", crawler_path)
    if spec is None or spec.loader is None:
        return {}
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return getattr(mod, "WALLET_CONFIG", {})


WALLET_CONFIG: dict = _load_client_config()

# ---------------------------------------------------------------------------
# Shared helper: resolve a tag to the parent of the tag commit
# ---------------------------------------------------------------------------

def resolve_release_by_tag(repo: str, tag: str, gh: Callable) -> str:
    """Given a repo slug and a tag name, return the SHA of the commit
    immediately *before* the tagged commit (i.e. the first parent of the
    tag's commit). This is the vulnerable-state commit for a release fix.

    If the tag object is an annotated tag, it is dereferenced first.
    Returns "" on any failure (404, missing parents, parse error)."""
    encoded_tag = quote(tag, safe="")
    ref_path = f"repos/{repo}/git/ref/tags/{encoded_tag}"
    ref = gh(ref_path)
    if ref is None:
        # Retry with "v" prefix if original didn't start with "v"
        if not tag.startswith("v"):
            vtag = f"v{tag}"
            encoded_vtag = quote(vtag, safe="")
            ref = gh(f"repos/{repo}/git/ref/tags/{encoded_vtag}")
    if ref is None:
        return ""

    obj = ref.get("object", {})
    obj_sha = obj.get("sha", "")
    obj_type = obj.get("type", "")
    if not obj_sha:
        return ""

    # Dereference annotated tags
    if obj_type == "tag":
        tag_obj = gh(f"repos/{repo}/git/tags/{obj_sha}")
        if tag_obj is None:
            return ""
        obj_sha = tag_obj.get("object", {}).get("sha", "")
        if not obj_sha:
            return ""

    # Now obj_sha should be a commit SHA
    commit = gh(f"repos/{repo}/commits/{obj_sha}")
    if commit is None:
        return ""
    parents = commit.get("parents", [])
    if not parents:
        return ""  # initial commit
    return parents[0].get("sha", "")


# ---------------------------------------------------------------------------
# Per-source-type resolvers
# ---------------------------------------------------------------------------

def resolve_pr(row: dict, gh: Callable) -> str:
    """Resolve PR#<n> rows.

    Returns the first parent of the merge commit (= the target branch tip
    just before the merge landed = the last vulnerable state)."""
    issue_id: str = row.get("issue_id", "")
    m = re.match(r"^PR#(\d+)$", issue_id)
    if not m:
        return ""
    n = m.group(1)
    platform = row.get("source_platform", "")
    cfg = WALLET_CONFIG.get(platform, {})
    repo = cfg.get("repo", "")
    if not repo:
        return ""

    pr = gh(f"repos/{repo}/pulls/{n}")
    if pr is None:
        return ""
    merge_sha = pr.get("merge_commit_sha") or ""
    if not merge_sha:
        # PR closed without merge
        return ""

    commit = gh(f"repos/{repo}/commits/{merge_sha}")
    if commit is None:
        return ""
    parents = commit.get("parents", [])
    if not parents:
        return ""
    return parents[0].get("sha", "")


def resolve_release(row: dict, gh: Callable) -> str:
    """Resolve RELEASE#<tag>#<hex> rows.

    Parses the tag from the issue_id and delegates to resolve_release_by_tag."""
    issue_id: str = row.get("issue_id", "")
    # Format: RELEASE#<tag>#<8hex>
    # tag is everything between first and second '#'
    parts = issue_id.split("#", 2)
    if len(parts) < 3 or parts[0] != "RELEASE":
        return ""
    tag = parts[1]
    if not tag:
        return ""

    platform = row.get("source_platform", "")
    cfg = WALLET_CONFIG.get(platform, {})
    repo = cfg.get("repo", "")
    if not repo:
        return ""

    return resolve_release_by_tag(repo, tag, gh)


def resolve_commit(row: dict, gh: Callable) -> str:
    """Resolve COMMIT#<12hex> rows.

    Prefers the full 40-char SHA extracted from source_url; falls back to
    the 12-char short SHA from issue_id."""
    issue_id: str = row.get("issue_id", "")
    m = re.match(r"^COMMIT#([a-f0-9]{12})$", issue_id)
    if not m:
        return ""
    short_sha = m.group(1)

    # Try to get full SHA from source_url
    source_url: str = row.get("source_url", "")
    full_sha_m = re.search(r"/commit/([a-f0-9]{40})", source_url)
    sha = full_sha_m.group(1) if full_sha_m else short_sha

    platform = row.get("source_platform", "")
    cfg = WALLET_CONFIG.get(platform, {})
    repo = cfg.get("repo", "")
    if not repo:
        return ""

    commit = gh(f"repos/{repo}/commits/{sha}")
    if commit is None:
        return ""
    parents = commit.get("parents", [])
    if not parents:
        return ""
    return parents[0].get("sha", "")


def resolve_advisory(row: dict, gh: Callable) -> str:
    """Resolve GHSA-* rows.

    Re-fetches the advisory, parses patched_versions, and resolves the
    patched tag back to the vulnerable-state commit via resolve_release_by_tag."""
    ghsa_id: str = row.get("issue_id", "")
    if not ghsa_id.startswith("GHSA-"):
        return ""

    platform = row.get("source_platform", "")
    cfg = WALLET_CONFIG.get(platform, {})
    repo = cfg.get("repo", "")
    if not repo:
        return ""

    adv = gh(f"repos/{repo}/security-advisories/{ghsa_id}")
    if adv is None:
        return ""

    vulns = adv.get("vulnerabilities") or []
    if not vulns:
        return ""
    patched_versions: str = vulns[0].get("patched_versions") or ""
    if not patched_versions:
        return ""

    # Parse the first semver-looking token from patched_versions
    # e.g. ">= 1.16.9" → "1.16.9"; "^1.2.3 || ~2.0.0" → "1.2.3"
    # Strip operators: >=, <=, >, <, ^, ~, = and whitespace
    semver_token = _parse_first_semver(patched_versions)
    if not semver_token:
        return ""

    return resolve_release_by_tag(repo, semver_token, gh)


def _parse_first_semver(version_str: str) -> str:
    """Extract the first semver-like token from a version constraint string.

    Examples:
        ">= 1.16.9"   → "1.16.9"
        "^1.2.3"      → "1.2.3"
        "~1.0 || ^2"  → "1.0"
        "< 2.0.0, >= 1.5.0" → "2.0.0"  (first token encountered)
    """
    # Split on common separators (space, comma, ||, &&)
    tokens = re.split(r"[\s,|&]+", version_str.strip())
    for tok in tokens:
        # Strip leading operators
        cleaned = re.sub(r"^[><=^~!]+", "", tok).strip()
        # Must look like a version (starts with digit)
        if cleaned and re.match(r"^\d+[\d.]*", cleaned):
            return cleaned
    return ""


def resolve_issue(row: dict, gh: Callable) -> str:  # noqa: ARG001
    """Resolve ISSUE#<n> rows.

    TODO(phase-b-deeper): Issues link to no canonical fix commit in the
    unified schema. Would require crawling linked PRs per issue and
    identifying which one fixed it — deferred to a follow-up PR when
    issue-source rows justify the API spend."""
    return ""


def resolve_changelog(row: dict, gh: Callable) -> str:  # noqa: ARG001
    """Resolve CHANGELOG#<16hex> rows.

    TODO(phase-b-deeper): Changelog rows lack a version anchor in the
    unified schema. Would require parsing changelog format per-wallet and
    matching each entry to a release tag — deferred until changelog-source
    rows are numerous enough to justify the complexity."""
    return ""


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def dispatch(row: dict, gh: Callable) -> str:
    """Route a row to the appropriate resolver based on issue_id prefix.

    On any unhandled exception (404, malformed payload, missing key),
    logs a warning and returns "" — never lets one bad row tank the batch."""
    issue_id: str = row.get("issue_id", "")
    try:
        if issue_id.startswith("GHSA-"):
            return resolve_advisory(row, gh)
        if issue_id.startswith("PR#"):
            return resolve_pr(row, gh)
        if issue_id.startswith("ISSUE#"):
            return resolve_issue(row, gh)
        if issue_id.startswith("CHANGELOG#"):
            return resolve_changelog(row, gh)
        if issue_id.startswith("RELEASE#"):
            return resolve_release(row, gh)
        if issue_id.startswith("COMMIT#"):
            return resolve_commit(row, gh)
        # Unknown prefix
        logger.debug("unknown issue_id prefix: %r", issue_id)
        return ""
    except Exception as exc:  # noqa: BLE001
        logger.warning("dispatch error for row %r: %s", issue_id, exc)
        return ""


# ---------------------------------------------------------------------------
# Rate limiter (token-bucket, 30 calls / 60s)
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Simple sliding-window rate limiter: at most `max_calls` per `window_s`."""

    def __init__(self, max_calls: int = 30, window_s: float = 60.0) -> None:
        self._max_calls = max_calls
        self._window_s = window_s
        self._call_times: list[float] = []

    def acquire(self) -> None:
        now = time.monotonic()
        # Drop timestamps older than the window
        self._call_times = [t for t in self._call_times if now - t < self._window_s]
        if len(self._call_times) >= self._max_calls:
            sleep_s = self._window_s - (now - self._call_times[0])
            if sleep_s > 0:
                logger.debug("rate limit: sleeping %.1fs", sleep_s)
                time.sleep(sleep_s)
        self._call_times.append(time.monotonic())


# ---------------------------------------------------------------------------
# Main walk function
# ---------------------------------------------------------------------------

def walk(
    parquet_in: Path,
    parquet_out: Path,
    *,
    max_rows: int = 0,
    fetcher: Callable = gh_json,
) -> dict:
    """Enrich `introduced_in_commit` in the parquet.

    Reads `parquet_in`, calls `dispatch` for each row, writes `parquet_out`
    with the same schema (no new columns), and returns a manifest dict.

    `fetcher` is injectable — pass a mock for tests.
    `max_rows` caps the number of rows processed (0 = no cap).
    """
    try:
        import pandas as pd
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as e:
        sys.exit(f"missing dep: {e}; install with `uv sync --group datasets`")

    started_at = datetime.now(timezone.utc).isoformat()

    df = pd.read_parquet(parquet_in)
    if max_rows:
        df = df.head(max_rows).copy()
    else:
        df = df.copy()

    # Cache: (repo, sha) → parent sha, so repeated PR/commit lookups
    # don't re-hit the API.
    _cache: dict[tuple[str, str], str] = {}

    rate_limiter = _RateLimiter(max_calls=30, window_s=60.0)
    call_count = 0

    def cached_gh(path: str):
        nonlocal call_count
        # Use path as cache key (includes repo+sha)
        if path in _cache:
            return _cache[path]
        rate_limiter.acquire()
        result = fetcher(path)
        call_count += 1
        # Only cache successful (non-None) results.  A transient 5xx must not
        # become a permanent cache miss for the rest of the run.
        if result is not None:
            _cache[path] = result
        return result

    by_source: dict[str, int] = defaultdict(int)
    failed_samples: list[str] = []
    n_resolved = 0

    results: list[str] = []
    for _, row in df.iterrows():
        row_dict = row.to_dict()
        sha = dispatch(row_dict, cached_gh)
        results.append(sha)

        # Tally by prefix
        issue_id: str = row_dict.get("issue_id", "")
        prefix = _issue_prefix(issue_id)
        by_source[prefix] += 1

        if sha:
            n_resolved += 1
        else:
            if len(failed_samples) < 10:
                failed_samples.append(issue_id)

    df["introduced_in_commit"] = results

    # Atomic write: write to <out>.tmp then os.replace to avoid a partial
    # file on crash (walk() defaults --out to --in, so in-place updates must
    # be atomic to preserve the original if the process is interrupted).
    parquet_out.parent.mkdir(parents=True, exist_ok=True)
    tmp_out = parquet_out.with_suffix(".tmp.parquet")
    table = pa.Table.from_pandas(df, preserve_index=False)
    pq.write_table(table, tmp_out, compression="zstd")
    os.replace(tmp_out, parquet_out)

    ended_at = datetime.now(timezone.utc).isoformat()
    n_rows = len(df)
    coverage_pct = (n_resolved / n_rows * 100) if n_rows else 0.0

    return {
        "n_rows": n_rows,
        "n_resolved": n_resolved,
        "coverage_pct": round(coverage_pct, 2),
        "by_source": dict(by_source),
        "failed_samples": failed_samples,
        "gh_calls": call_count,
        "started_at": started_at,
        "ended_at": ended_at,
    }


def _issue_prefix(issue_id: str) -> str:
    """Return a short prefix label for the issue_id (used in by_source tallying)."""
    for prefix in ("GHSA-", "PR#", "ISSUE#", "CHANGELOG#", "RELEASE#", "COMMIT#"):
        if issue_id.startswith(prefix):
            return prefix.rstrip("#-")
    return "unknown"


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--in", dest="parquet_in",
        default="dist/datasets/ethereum/train.parquet",
        help="Input parquet path (default: dist/datasets/ethereum/train.parquet).",
    )
    p.add_argument(
        "--out", dest="parquet_out",
        default="dist/datasets/ethereum/train.parquet",
        help="Output parquet path (default: same as --in, in-place update).",
    )
    p.add_argument(
        "--max-rows", type=int, default=0,
        help="Cap number of rows processed (0 = no cap; useful for smoke runs).",
    )
    p.add_argument(
        "--manifest", default="dist/datasets/ethereum/blame_walk_manifest.json",
        help="Path to write the manifest JSON.",
    )
    args = p.parse_args()

    parquet_in = Path(args.parquet_in)
    parquet_out = Path(args.parquet_out)
    manifest_path = Path(args.manifest)

    if not parquet_in.exists():
        sys.exit(f"input parquet not found: {parquet_in}")

    logger.info("blame-walk: %s → %s", parquet_in, parquet_out)
    manifest = walk(parquet_in, parquet_out, max_rows=args.max_rows)

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    logger.info(
        "done: %d/%d rows resolved (%.1f%%)",
        manifest["n_resolved"], manifest["n_rows"], manifest["coverage_pct"],
    )


if __name__ == "__main__":
    main()
