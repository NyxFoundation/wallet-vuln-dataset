#!/usr/bin/env python3
"""Crawl past security fixes from the 11 in-scope Ethereum wallets into a
CSV that round-trips through `scripts/datasets/build_derived.py`.

Sources:
    - GitHub Security Advisories (GHSA): the cleanest data source —
      structured, severity-labeled, deduplicated by upstream. Pulled via
      `gh api repos/<repo>/security-advisories`.
    - Security-relevant merged PRs: title-matched against SECURITY_TITLE_RE.
      Capped at ~2000 closed PRs per repo to avoid runaway API spend (geth
      alone has ~30k closed PRs; the title filter is cheap but pagination
      over that volume burns rate-limit).
    - Closed issues labelled `security` (fallback: `vulnerability`). Legacy
      PR objects returned by the issues endpoint are stripped by checking
      the `pull_request` key.

Out of scope (tracked as TODOs, planned for follow-up slices):
    - CHANGELOG / audit-report mining.
    - `introduced_in_commit` blame-walk (defaults to "" — Phase B replay
      can fall back to the advisory's `published_at` minus a fixed
      window until the blame walk lands).

Why `gh` subprocess instead of `requests`?  The repo's other scrapers
(`scripts/scrape_*.py`) all shell out to `gh`. Reusing the same auth
(`gh auth login`) avoids a parallel `GITHUB_TOKEN` env-var dance.

Output layout (mirrors `defi_audit_reports/`):
    benchmarks/data/ethereum_past_fixes/<wallet>.csv
    benchmarks/data/ethereum_past_fixes/<wallet>.crawl_manifest.json

The CSV columns match what `scripts/datasets/build_derived.py` already
accepts (issue #2 schema):
    source, contest, issue_id, severity, title, description,
    source_url, introduced_in_commit

Usage:
    # Crawl one wallet (geth is the v1 vertical):
    uv run python3 benchmarks/scripts/crawl_wallet_past_fixes.py \\
        --wallet geth --out-dir benchmarks/data/ethereum_past_fixes

    # Crawl every in-scope wallet (skip on a 404 — the per-wallet gh
    # output writes alongside, so re-run is idempotent):
    uv run python3 benchmarks/scripts/crawl_wallet_past_fixes.py \\
        --wallet all --out-dir benchmarks/data/ethereum_past_fixes
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

# The wallet registry lives in wallets.py — the single source of truth for
# which repositories the corpus covers (see its module docstring for the
# in-scope rule and the field meanings). Nothing here hard-codes a repo slug.
import importlib.util as _ilu
_WSPEC = _ilu.spec_from_file_location("_wallets", Path(__file__).resolve().parent / "wallets.py")
_wallets_mod = _ilu.module_from_spec(_WSPEC); _WSPEC.loader.exec_module(_wallets_mod)  # type: ignore
WALLET_CONFIG: dict[str, dict] = _wallets_mod.WALLET_CONFIG

import importlib.util as _ilu3
from pathlib import Path as _P3
_GSPEC = _ilu3.spec_from_file_location("_gh_rate", _P3(__file__).resolve().parent / "gh_rate.py")
_ghr = _ilu3.module_from_spec(_GSPEC); _GSPEC.loader.exec_module(_ghr)  # type: ignore

# GHSA `severity` is one of low/medium/high/critical. Map onto the
# unified schema's `severity` (High/Medium/Low/Info). `critical`
# collapses to `High` because the downstream parquet's enum doesn't
# distinguish — the CVSS score on the advisory itself is preserved via
# `description`, so no information is lost.
SEVERITY_MAP = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

# Per-page when listing advisories. The list-repository-security-advisories
# endpoint uses CURSOR pagination (before/after), not page numbers — so we
# rely on `gh api --paginate` to walk the Link header for us instead of
# rolling our own page loop.
ADVISORIES_PER_PAGE = 100

# Maximum number of closed PRs to examine when using the page-loop fallback.
# geth has ~30k closed PRs; paginating the full list would burn rate-limit.
# 2000 PRs = 20 pages of 100 — used only if search/issues is unavailable.
PR_PAGE_CAP = 2000

# T9: Repos where GitHub search/issues returns HTTP 422 (not indexed or
# ACL-restricted).  fetch_security_prs falls back to label-based PR crawl
# for these repos instead of the search endpoint.
_SEARCH_UNSUPPORTED_REPOS: frozenset[str] = frozenset()  # populated on HTTP-422 fallback

# Security keyword terms used in GitHub search queries (must map to the
# same concepts as SECURITY_TITLE_RE).  Splitting into short terms keeps
# each query under GitHub's character limit and avoids double-quoting of
# multi-word phrases across different shell environments.
_SEARCH_TERMS = [
    "security",
    "vulnerability",
    "CVE",
    "DoS",
    "panic",
    "crash",
    "RCE",
    "memory+leak",
    "integer+overflow",
    "race+condition",
]

CSV_FIELDS = (
    "source", "contest", "issue_id", "severity", "title",
    "description", "source_url", "introduced_in_commit",
)

# Compiled regex for detecting security-relevant PR / issue titles.
# Word-boundary anchored so partial matches like "securitytoken" are not hits.
# CVE pattern does not need \b on the right because the digit sequence already
# acts as a natural boundary.
SECURITY_TITLE_RE = re.compile(
    r"\b(?:"
    r"security"
    r"|vuln(?:erability)?"
    r"|CVE-\d{4}-\d+"
    r"|DoS"
    r"|panic"
    r"|crash"
    r"|RCE"
    r"|memory\s+leak"
    r"|integer\s+overflow"
    r"|race\s+condition"
    r")\b",
    re.IGNORECASE,
)

# _SEVERITY_LABEL_RE removed (T10): title-based severity inference is unreliable.
# PRs and issues without an explicit label now get severity="Unrated".

# Per-wallet label strategy. The Ethereum-client build hand-tuned 11 repos;
# with 157 wallet repos that does not scale, so the strategy is *derived* from
# the registry (category + language) with a small override table for the repos
# whose label taxonomy is unusual and high-volume enough to be worth tuning.
#
# Every repo additionally gets the body-keyword pass — wallet fixes are far more
# often unlabelled than client fixes, because most wallet repos ship an app and
# never file an advisory.

# Bug/security label names that are near-universal across GitHub repos. A repo
# that uses none of them simply falls through to the body-keyword pass.
_GENERIC_BUG_LABELS = ["bug", "type:bug", "type: bug", "kind/bug", "C-bug",
                       "Bug", "bug-fix", "defect", "regression"]
_GENERIC_SEC_LABELS = ["security", "Security", "C-security", "A-security",
                       "type:security", "sec", "vulnerability"]
_GENERIC_SKIP_LABELS = ["documentation", "docs", "dependencies", "chore",
                        "enhancement", "feature", "question"]

# Area labels worth crawling, by registry category — these mark the subsystems
# where a wallet bug becomes a fund-loss bug.
_AREA_BY_CATEGORY: dict[str, list[str]] = {
    "browser_extension": ["signing", "transaction", "permissions", "phishing",
                          "connect", "provider", "keyring", "network"],
    "mobile":            ["signing", "transaction", "keychain", "biometrics",
                          "deeplink", "webview", "backup"],
    "desktop":           ["signing", "transaction", "storage", "rpc", "backup"],
    "hardware_firmware": ["crypto", "signing", "bootloader", "secure-element",
                          "u2f", "display", "pin", "seed"],
    "smart_account":     ["validation", "signature", "module", "upgrade",
                          "guard", "audit"],
    "mpc_tss":           ["crypto", "protocol", "share", "signing", "audit"],
    "wallet_sdk":        ["crypto", "signing", "encoding", "abi", "provider"],
    "node_wallet":       ["wallet", "rpc", "consensus", "p2p"],
    "infra":             ["protocol", "session", "pairing", "relay", "crypto"],
}

# Repos whose taxonomy is distinctive enough to hand-tune (all tier 1 / high
# PR volume — verified against the GitHub labels API on 2026-07-29).
_LABEL_OVERRIDES: dict[str, dict] = {
    "metamask":        {"bug_labels": ["type-bug", "regression-prod"],
                        "sec_labels": ["type-security", "Sev0-urgent", "Sev1-high"],
                        "area_labels": ["area-confirmations", "area-signatures",
                                        "area-tokens", "area-phishing", "area-network"]},
    "metamask-mobile": {"bug_labels": ["type-bug"], "sec_labels": ["type-security"],
                        "area_labels": ["area-signatures", "area-confirmations"]},
    "brave-wallet":    {"bug_labels": ["bug"], "sec_labels": ["security"],
                        "area_labels": ["OS/Android", "feature/web3/wallet"],
                        "strategy": "body_keyword_primary"},
    "bitcoin-core":    {"bug_labels": ["Bug"], "sec_labels": [],
                        "area_labels": ["Wallet", "Descriptors", "P2P", "RPC/REST/ZMQ"],
                        "strategy": "body_keyword_primary"},
    "trezor-firmware": {"bug_labels": ["bug"], "sec_labels": ["security"],
                        "area_labels": ["core", "crypto", "bootloader", "T1B1", "T2T1"]},
    "electrum":        {"bug_labels": ["bug"], "sec_labels": ["security"],
                        "area_labels": ["wallet", "crypto", "network"],
                        "strategy": "body_keyword_primary"},
    "monero":          {"bug_labels": ["bug"], "sec_labels": ["security"],
                        "area_labels": ["wallet", "crypto", "ringct"],
                        "strategy": "body_keyword_primary"},
    "ledger-live":     {"bug_labels": ["bug"], "sec_labels": ["security"],
                        "area_labels": ["team: live", "coin integration"]},
    "safe-contracts":  {"bug_labels": ["bug"], "sec_labels": ["security"],
                        "area_labels": ["audit", "contracts"]},
    "walletconnect":   {"bug_labels": ["bug"], "sec_labels": ["security"],
                        "area_labels": ["sign", "auth", "core"]},
}


def label_strategy(wallet_slug: str) -> dict:
    """Derive the crawl strategy for a repo from the registry + overrides."""
    cfg = WALLET_CONFIG.get(wallet_slug, {})
    category = cfg.get("category", "wallet_sdk")
    out = {
        "bug_labels":  list(_GENERIC_BUG_LABELS),
        "sec_labels":  list(_GENERIC_SEC_LABELS),
        "area_labels": list(_AREA_BY_CATEGORY.get(category, [])),
        "skip_labels": list(_GENERIC_SKIP_LABELS),
        # key-custody repos rarely label at all -> lead with the body keywords
        "strategy": ("body_keyword_primary"
                     if category in {"hardware_firmware", "mpc_tss", "smart_account"}
                     else "labels_primary"),
        "extra_labels": [],
    }
    out.update(_LABEL_OVERRIDES.get(wallet_slug, {}))
    return out


# Back-compat alias: the crawl functions look this map up by slug.
class _LabelMap(dict):
    def get(self, k, default=None):           # noqa: D102
        return label_strategy(k) if k in WALLET_CONFIG else (default or {})
    def __getitem__(self, k):                 # noqa: D105
        return label_strategy(k)
    def __contains__(self, k):                # noqa: D105
        return k in WALLET_CONFIG

CL_LABEL_MAP = _LabelMap()

# Language-specific body keywords for the body-keyword strategies. Keyed by
# the repo *language* (wallets.py::language_of) rather than by slug, so a new
# repo inherits them for free.
_LANG_KEYWORDS_BY_LANG: dict[str, list[str]] = {
    "rust":     ["unwrap", "panic", "RUSTSEC-", "unsoundness", "unsafe"],
    "go":       ["panic", "nil pointer", "govulncheck", "data race"],
    "c":        ["buffer overflow", "memcpy", "out of bounds", "stack smashing",
                 "uninitialized", "CVE-"],
    "cpp":      ["buffer overflow", "out of bounds", "use after free",
                 "uninitialized", "UBSan", "ASan"],
    "java":     ["throws", "IllegalStateException", "NullPointerException"],
    "csharp":   ["NullReferenceException", "unhandled exception"],
    "python":   ["traceback", "assertion failed", "unhandled exception"],
    "solidity": ["reentrancy", "delegatecall", "unchecked", "audit finding",
                 "invariant", "signature replay"],
    "cairo":    ["assert", "signature replay", "audit finding"],
    "swift":    ["crash", "fatalError", "keychain"],
    "kotlin":   ["crash", "NullPointerException", "keystore"],
    "dart":     ["exception", "crash"],
    "js":       ["prototype pollution", "XSS", "sanitiz", "unsafe-eval",
                 "postMessage", "origin check"],
}


class _LangKeywords(dict):
    """Slug -> body keywords, resolved through the repo's language."""
    def get(self, slug, default=None):        # noqa: D102
        return _LANG_KEYWORDS_BY_LANG.get(_wallets_mod.language_of(slug), default or [])
    def __getitem__(self, slug):              # noqa: D105
        return self.get(slug, [])
    def __contains__(self, slug):             # noqa: D105
        return _wallets_mod.language_of(slug) in _LANG_KEYWORDS_BY_LANG

LANG_KEYWORDS = _LangKeywords()


def apply_prysm_stratification(
    rows: list[dict],
    all_cl_rows: list[dict],
    max_pct: float = 0.30,
) -> list[dict]:
    """Cap prysm rows at `max_pct` of the total CL row count (T18).

    Rationale: prysm's bug + bug-fix labels are very broad (the repo has
    thousands of labelled PRs) so without a cap prysm would dominate the
    CL portion of the training set and skew per-wallet analysis.

    Args:
        rows:        Prysm-only rows to potentially downsample.
        all_cl_rows: ALL consensus-layer rows (all 6 CL wallets combined),
                     used to compute the cap threshold.
        max_pct:     Maximum fraction of all_cl_rows that prysm may occupy
                     (default 0.30 = 30 %).

    Returns:
        The original `rows` list if already within limit, otherwise a
        deterministic random sample (seed=42) capped at the threshold.
    """
    import random as _random

    cap = int(len(all_cl_rows) * max_pct)
    if len(rows) <= cap:
        return rows
    print(
        f"  [T18] prysm stratification: {len(rows)} rows -> {cap} "
        f"(cap={max_pct:.0%} of {len(all_cl_rows)} CL rows)",
        file=sys.stderr,
    )
    rng = _random.Random(42)
    return rng.sample(rows, cap)


def crawl_teku_jira_references(
    gh_token: str,
    out_dir: Path,
    max_results: int = 200,
) -> list[dict]:
    """Extract merged Teku PRs that reference a Jira ticket (T19).

    Runs two gh search queries against Consensys/teku:
      1. PRs with 'TEKU-' anywhere in title or body (Jira issue key pattern).
      2. PRs with 'security' in title.

    Both queries are deduplicated by PR number before returning rows in the
    standard CSV schema with contest='jira_reference'.

    Args:
        gh_token:    GitHub token (currently unused — auth comes from
                     `gh auth login` / GH_TOKEN env, same as rest of file).
        out_dir:     Output directory (unused here, caller writes CSV).
        max_results: Per-query --limit passed to `gh search prs`.

    Returns:
        List of row dicts in the canonical CSV schema.
    """
    repo = WALLET_CONFIG["teku"]["repo"]
    seen: set[int] = set()
    rows: list[dict] = []

    _queries = [
        ("TEKU- in:title,body", max_results),
        ('"security" in:title', max_results),
    ]

    _json_fields = "number,title,body,url,closedAt"

    for query_str, limit in _queries:
        chunk = gh_json([
            "search", "prs",
            "--repo", repo,
            "--state", "merged",
            "--json", _json_fields,
            "--limit", str(limit),
            query_str,
        ])
        if not isinstance(chunk, list):
            print(
                f"  [T19] teku jira query {query_str!r} returned no results",
                file=sys.stderr,
            )
            continue
        for item in chunk:
            num = item.get("number")
            if num is None or num in seen:
                continue
            seen.add(num)
            title = (item.get("title") or "").strip()
            body = (item.get("body") or "").strip()
            if not title and not body:
                continue
            rows.append({
                "source": "teku",
                "contest": "jira_reference",
                "issue_id": f"PR#{num}",
                "severity": _severity_from_title(title),
                "title": title,
                "description": body,
                "source_url": (item.get("url") or "").strip(),
                "introduced_in_commit": "",
            })
        time.sleep(2)  # search API rate-limit guard

    print(
        f"  [T19] teku jira references: {len(rows)} unique PRs from {len(_queries)} queries",
        file=sys.stderr,
    )
    return rows


def gh_json(args: list[str], timeout: int = 120):
    """Run `gh` and return parsed JSON, or None on error.

    Mirrors the shape used by `scripts/scrape_code4rena.py` so the
    failure modes (and how they're logged) match the repo's existing
    scrapers."""
    try:
        # `search` when the call is a search endpoint, else `core` — the two
        # have independent quotas and very different reset windows.
        _res = "search" if any("search" in str(a) for a in args) else "core"
        result = _ghr.run_gh(["gh", *args], timeout=timeout, resource=_res,
                             label=" ".join(str(a) for a in args[:3]))
    except PermissionError as e:
        print(f"  [fatal] gh auth failure: {e}", file=sys.stderr)
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"  [warn] gh failed: {e}", file=sys.stderr)
        return None
    if result.returncode != 0:
        # 404 on security-advisories means the repo has none published —
        # surfaced loudly to operators since the alternative would be a
        # silently-empty CSV.
        msg = (result.stderr or "").strip()[:300]
        print(f"  [warn] gh exit {result.returncode}: {msg}", file=sys.stderr)
        return None
    body = result.stdout.strip()
    if not body:
        return []
    try:
        return json.loads(body)
    except json.JSONDecodeError as e:
        print(f"  [warn] gh output not JSON: {e}", file=sys.stderr)
        return None


def fetch_advisories(repo: str) -> list[dict]:
    """List published GHSA advisories on `<owner>/<repo>`. `gh api
    --paginate` walks the Link-header cursor automatically — works
    whether the upstream uses page numbers or before/after cursors
    (GHSA's endpoint is the latter).

    Two `gh api` gotchas baked in here:
      1. `-X GET` is REQUIRED. Without it, gh sees a `-f` field and
         flips the method to POST — and POST /security-advisories means
         "create advisory", which 403s for any token without the
         `repository_security_advisories` admin scope.
      2. Do NOT pass `state=published`. Same admin scope requirement;
         the default already returns only published rows for non-admin
         tokens.
    Both pitfalls verified by smoke-testing ethereum/go-ethereum on
    2026-05-09 with a `repo` + `read:org` token (sururu-k)."""
    chunk = gh_json([
        "api", f"repos/{repo}/security-advisories",
        "-X", "GET",
        "--paginate",
        "-f", f"per_page={ADVISORIES_PER_PAGE}",
    ])
    return chunk if isinstance(chunk, list) else []


def normalize_severity(advisory: dict) -> str:
    raw = (advisory.get("severity") or "").strip().lower()
    return SEVERITY_MAP.get(raw, "Info")


def advisory_to_row(advisory: dict, wallet_slug: str, repo: str) -> dict | None:
    """Project one GHSA advisory onto the build_derived CSV schema.

    Returns None if the advisory is too sparse to keep — e.g. a
    placeholder draft where summary + description are both blank."""
    ghsa_id = (advisory.get("ghsa_id") or "").strip()
    summary = (advisory.get("summary") or "").strip()
    description = (advisory.get("description") or "").strip()

    if not (summary or description):
        return None
    if not ghsa_id:
        # No id → no stable record key. Skip rather than synthesize one,
        # so build_derived doesn't dedupe genuinely-distinct advisories
        # by collision on a hash fallback.
        return None

    return {
        "source": wallet_slug,
        "contest": repo,
        "issue_id": ghsa_id,
        "severity": normalize_severity(advisory),
        "title": summary,
        "description": description,
        "source_url": (advisory.get("html_url") or "").strip(),
        # TODO(phase-b-replay): walk the advisory's `vulnerabilities[].patched_versions`
        # back to the introducing commit via `git log -G` on patched
        # files. Empty for v1 — Phase B's per-wallet time slicer can
        # fall back to advisory.published_at - 90 days as a coarse
        # bucket until this lands.
        "introduced_in_commit": "",
    }


def _fetch_security_prs_label_fallback(repo: str) -> list[dict]:
    """T9 fallback: fetch merged PRs via label API when search/issues is
    unavailable (HTTP 422).  Used for prysmaticlabs/prysm and
    hyperledger/besu which are not indexed by GitHub code-search.

    Queries the pulls REST endpoint with the labels that each repo uses for
    security-relevant work.  Filters to merged PRs only; applies
    SECURITY_TITLE_RE as a second-pass title filter so that broad labels
    (e.g. "bug") do not flood the dataset with unrelated rows.
    """
    # Label sets derived from CL_LABEL_MAP / EL knowledge
    _FALLBACK_LABELS: dict[str, list[str]] = {
        "prysmaticlabs/prysm": ["bug", "security"],
        "hyperledger/besu": ["bug", "consensus", "EVM"],
    }
    labels = _FALLBACK_LABELS.get(repo, ["bug", "security"])
    seen: set[int] = set()
    results: list[dict] = []

    for label in labels:
        print(
            f"  [T9] label fallback for {repo}: querying label={label!r}",
            file=sys.stderr,
        )
        chunk = gh_json([
            "api", f"repos/{repo}/pulls",
            "-X", "GET",
            "--paginate",
            "-f", "state=closed",
            "-f", f"labels={label}",
            "-f", "per_page=100",
        ])
        if not isinstance(chunk, list):
            print(f"  [T9] no data for label={label!r}", file=sys.stderr)
            time.sleep(1)
            continue
        for pr in chunk:
            if not pr.get("merged_at"):
                continue
            num = pr.get("number")
            if num is None or num in seen:
                continue
            title = (pr.get("title") or "").strip()
            # Second-pass title filter: only keep security-relevant hits
            if not SECURITY_TITLE_RE.search(title):
                continue
            seen.add(num)
            pr.setdefault("merged_at", pr.get("merged_at"))
            results.append(pr)
            if len(results) >= PR_PAGE_CAP:
                break
        time.sleep(1)
        if len(results) >= PR_PAGE_CAP:
            break

    print(
        f"  [T9] label fallback for {repo}: {len(results)} security PRs",
        file=sys.stderr,
    )
    return results


def fetch_security_prs(repo: str) -> list[dict]:
    """Return merged PRs whose titles contain a security keyword.

    Uses GitHub's search/issues endpoint (which covers PRs too) to query
    each keyword in _SEARCH_TERMS against PR titles in the given repo.
    This is far more targeted than paginating all closed PRs — geth has
    ~30k closed PRs but only ~150 security-keyword matches, so the page
    loop would spend 300 API calls to find what search finds in ~10.

    Deduplication: multiple keyword queries may return the same PR number.
    We deduplicate on `number` and keep the first occurrence.

    T9: For repos in _SEARCH_UNSUPPORTED_REPOS (prysm, besu) where the
    search/issues endpoint returns HTTP 422, falls back to label-based
    PR crawl via _fetch_security_prs_label_fallback.

    Search API returns a simplified issue object, not the full PR object.
    We need `merged_at` to confirm the PR is merged; that field is absent
    from search results, so we check `pull_request.merged_at` if present,
    or fall back to `state == 'closed'` + absence of `pull_request.merged_at`
    being null. GitHub search `is:merged` qualifier guarantees the item is
    merged, so we trust the search filter rather than rechecking field-level.

    `-X GET` is required when passing `-f` fields (without it gh flips to
    POST and 403s — same gotcha as fetch_advisories).
    """
    # T9: repos not indexed by GitHub search → label fallback
    if repo in _SEARCH_UNSUPPORTED_REPOS:
        return _fetch_security_prs_label_fallback(repo)

    seen: set[int] = set()
    results: list[dict] = []

    for i, term in enumerate(_SEARCH_TERMS):
        # Rate-limit guard: search/issues counts against the core limit
        # (30 req/min authenticated). With up to 10 terms x 10 pages = 100
        # calls per wallet, sleeping 2s between terms keeps us well under
        # the limit (other crawlers follow the same convention).
        if i > 0:
            time.sleep(2)

        # Use `in:title` to restrict to title matches (same semantics as
        # SECURITY_TITLE_RE on the title field). `is:merged` guarantees only
        # merged PRs are returned, eliminating the merged_at null-check.
        query = f"repo:{repo} is:pr is:merged {term} in:title"
        page = 1
        while True:
            chunk = gh_json([
                "api", "search/issues",
                "-X", "GET",
                "-f", f"q={query}",
                "-f", "per_page=100",
                "-f", f"page={page}",
            ])
            if not isinstance(chunk, dict):
                break
            items = chunk.get("items") or []
            if not items:
                break
            for item in items:
                num = item.get("number")
                if num is not None and num not in seen:
                    seen.add(num)
                    # Normalize the search result to look like a pulls API
                    # object so pr_to_row works without branching.
                    item.setdefault("merged_at", "search-confirmed-merged")
                    results.append(item)
            if len(items) < 100:
                break
            # GitHub search caps at 1000 results per query; stop at page 10.
            if page >= 10:
                break
            page += 1

    # Guard against runaway: cap deduplicated PR count.
    # geth alone has ~30k closed PRs; without this cap a rogue term could
    # accumulate many thousands of results across all pages and blow the
    # rate limit and downstream processing time.
    if len(results) > PR_PAGE_CAP:
        print(
            f"  [warn] fetch_security_prs: deduped PR count {len(results)} exceeds "
            f"PR_PAGE_CAP={PR_PAGE_CAP}; truncating",
            file=sys.stderr,
        )
        results = results[:PR_PAGE_CAP]

    return results


def fetch_security_issues(repo: str) -> list[dict]:
    """Return closed issues labelled `security` (or `vulnerability` as
    fallback). Filters out legacy PR objects that GitHub's issues endpoint
    returns (items with a `pull_request` key are PRs, not issues).

    Two label attempts:
      1. label=security
      2. label=vulnerability  (only if attempt 1 returns nothing)
    """
    def _fetch_label(label: str) -> list[dict]:
        chunk = gh_json([
            "api", f"repos/{repo}/issues",
            "-X", "GET",
            "--paginate",
            "-f", "state=closed",
            "-f", f"labels={label}",
            "-f", "per_page=100",
        ])
        if not isinstance(chunk, list):
            return []
        # Strip PR objects that the legacy endpoint returns alongside real issues.
        return [item for item in chunk if "pull_request" not in item]

    results = _fetch_label("security")
    if not results:
        results = _fetch_label("vulnerability")
    return results


def _severity_from_title(title: str) -> str:
    """Severity for PRs/issues without an explicit label.

    T10: title-regex inference removed — was unreliable and produced
    low-quality labels. All PRs/issues without a structured severity
    label now return 'Unrated'. GHSA advisories use normalize_severity()
    directly and never call this function.
    """
    return "Unrated"


def pr_to_row(pr: dict, wallet_slug: str, repo: str) -> dict | None:
    """Map a GitHub PR object onto the build_derived CSV schema.

    Returns None if both title and body are empty — such rows carry no
    useful signal for downstream analysis."""
    title = (pr.get("title") or "").strip()
    body = (pr.get("body") or "").strip()
    if not title and not body:
        return None
    return {
        "source": wallet_slug,
        "contest": repo,
        "issue_id": f"PR#{pr['number']}",
        "severity": _severity_from_title(title),
        "title": title,
        "description": body,
        "source_url": (pr.get("html_url") or "").strip(),
        "introduced_in_commit": "",
    }


def issue_to_row(issue: dict, wallet_slug: str, repo: str) -> dict | None:
    """Map a GitHub issue object onto the build_derived CSV schema.

    Returns None if both title and body are empty."""
    title = (issue.get("title") or "").strip()
    body = (issue.get("body") or "").strip()
    if not title and not body:
        return None
    return {
        "source": wallet_slug,
        "contest": repo,
        "issue_id": f"ISSUE#{issue['number']}",
        "severity": _severity_from_title(title),
        "title": title,
        "description": body,
        "source_url": (issue.get("html_url") or "").strip(),
        "introduced_in_commit": "",
    }


# CL wallets that benefit from extra-label crawling.  EL wallets (geth,
# nethermind, besu, erigon, reth) are already well-covered by their GHSA
# advisories and the security PR search.
# Repos whose fixes are key-custody-critical (firmware / MPC / smart account):
# their commit vocabulary is cryptographic rather than UI-level, so the
# crawler widens the keyword net for them.
_KEY_CUSTODY_SLUGS = frozenset(
    s for s, c in WALLET_CONFIG.items()
    if c.get("category") in {"hardware_firmware", "mpc_tss", "smart_account"}
)


def crawl_extra_labels(
    wallet_slug: str,
    config: dict,
    label_map: dict,
    max_records: int | None = None,
) -> list[dict]:
    """Fetch merged PRs for area_labels listed in CL_LABEL_MAP[wallet_slug].

    For each label in ``area_labels`` (skipping anything in ``skip_labels``),
    paginates closed PRs via:

        gh api "repos/{repo}/pulls?state=closed&labels={label}&per_page=100" \\
            --paginate

    For ``strategy="body_keyword_primary"`` wallets (nimbus), also runs
    ``gh search prs`` body-keyword queries using ``LANG_KEYWORDS[wallet_slug]``
    so Nim-specific crash patterns are captured even when labels are sparse.

    All rows are deduplicated by PR number across every label query.

    Args:
        wallet_slug:  One of the 11 in-scope wallet slugs.
        config:       WALLET_CONFIG entry for this wallet (must contain "repo").
        label_map:    CL_LABEL_MAP — keyed by wallet slug.
        max_records:  Optional cap on returned rows (None = no cap).

    Returns:
        List of row dicts in the canonical CSV schema.  ``contest`` is set to
        the label string that matched, so downstream analysis can group by
        label without losing the source.
    """
    cl_cfg = label_map.get(wallet_slug)
    if cl_cfg is None:
        return []

    repo = config["repo"]
    area_labels: list[str] = cl_cfg.get("area_labels") or []
    skip_labels: set[str] = set(cl_cfg.get("skip_labels") or [])
    strategy: str = cl_cfg.get("strategy", "labels_primary")

    seen_nums: set[int] = set()
    rows: list[dict] = []

    def _add_pr(pr: dict, contest_label: str) -> bool:
        """Convert one PR dict and append to rows. Returns True when max hit."""
        num = pr.get("number")
        if num is None or num in seen_nums:
            return False
        seen_nums.add(num)
        title = (pr.get("title") or "").strip()
        body = (pr.get("body") or "").strip()
        if not title and not body:
            return False
        rows.append({
            "source": wallet_slug,
            "contest": contest_label,
            "issue_id": f"PR#{num}",
            "severity": _severity_from_title(title),
            "title": title,
            "description": body,
            "source_url": (pr.get("html_url") or pr.get("url") or "").strip(),
            "introduced_in_commit": "",
        })
        if max_records and len(rows) >= max_records:
            return True
        return False

    # --- Label-based crawl ---
    for label in area_labels:
        if label in skip_labels:
            continue

        print(
            f"  [{wallet_slug}] extra_labels: fetching PRs with label={label!r}",
            file=sys.stderr,
        )
        chunk = gh_json([
            "api",
            f"repos/{repo}/pulls",
            "-X", "GET",
            "--paginate",
            "-f", "state=closed",
            "-f", f"labels={label}",
            "-f", "per_page=100",
        ])
        if not isinstance(chunk, list):
            print(
                f"  [{wallet_slug}] extra_labels: no data for label={label!r}",
                file=sys.stderr,
            )
            time.sleep(1)
            continue

        # Only keep merged PRs (merged_at non-null)
        merged = [pr for pr in chunk if pr.get("merged_at")]
        print(
            f"  [{wallet_slug}] extra_labels: label={label!r} => "
            f"{len(merged)} merged PR(s)",
            file=sys.stderr,
        )
        for pr in merged:
            if _add_pr(pr, label):
                return rows

        time.sleep(1)

    # --- Body-keyword crawl for body_keyword_primary wallets (e.g. nimbus) ---
    if strategy == "body_keyword_primary":
        lang_kws = LANG_KEYWORDS.get(wallet_slug) or []
        for kw in lang_kws:
            if max_records and len(rows) >= max_records:
                break
            print(
                f"  [{wallet_slug}] extra_labels: body-keyword search {kw!r}",
                file=sys.stderr,
            )
            query = f"repo:{repo} is:pr is:merged {kw} in:body"
            chunk = gh_json([
                "api", "search/issues",
                "-X", "GET",
                "-f", f"q={query}",
                "-f", "per_page=100",
                "-f", "page=1",
            ])
            items: list[dict] = []
            if isinstance(chunk, dict):
                items = chunk.get("items") or []
            elif isinstance(chunk, list):
                items = chunk
            print(
                f"  [{wallet_slug}] extra_labels: body-keyword {kw!r} => "
                f"{len(items)} PR(s)",
                file=sys.stderr,
            )
            for item in items:
                # Normalise search result to look like a pulls API object
                item.setdefault("merged_at", "search-confirmed-merged")
                if _add_pr(item, f"body_kw:{kw}"):
                    return rows
            time.sleep(2)  # search API rate-limit guard

    print(
        f"  [{wallet_slug}] extra_labels: total {len(rows)} extra row(s)",
        file=sys.stderr,
    )
    return rows


def crawl_wallet(
    wallet_slug: str,
    *,
    max_records: int | None = None,
    fetcher=fetch_advisories,
    pr_fetcher=fetch_security_prs,
    issue_fetcher=fetch_security_issues,
) -> list[dict]:
    """Crawl one in-scope wallet. All three fetchers are injectable so
    tests can stub the GitHub round-trip without monkeypatching subprocess.

    Row ordering: advisory rows first, then PR rows, then issue rows,
    then extra-label rows (CL wallets only).
    max_records caps the COMBINED row count."""
    if wallet_slug not in WALLET_CONFIG:
        sys.exit(f"unknown wallet {wallet_slug!r}; known: {sorted(WALLET_CONFIG)}")
    repo = WALLET_CONFIG[wallet_slug]["repo"]

    rows: list[dict] = []

    for adv in fetcher(repo):
        row = advisory_to_row(adv, wallet_slug, repo)
        if row is None:
            continue
        rows.append(row)
        if max_records and len(rows) >= max_records:
            return rows

    for pr in pr_fetcher(repo):
        row = pr_to_row(pr, wallet_slug, repo)
        if row is None:
            continue
        rows.append(row)
        if max_records and len(rows) >= max_records:
            return rows

    for issue in issue_fetcher(repo):
        row = issue_to_row(issue, wallet_slug, repo)
        if row is None:
            continue
        rows.append(row)
        if max_records and len(rows) >= max_records:
            return rows

    # Extra-label crawl for CL wallets only.
    # EL wallets (geth, nethermind, besu, erigon, reth) are already
    # well-covered by their GHSA advisories and security PR search.
    if wallet_slug in _KEY_CUSTODY_SLUGS:
        remaining = (max_records - len(rows)) if max_records else None
        config = WALLET_CONFIG[wallet_slug]
        extra = crawl_extra_labels(
            wallet_slug, config, CL_LABEL_MAP, max_records=remaining
        )
        rows.extend(extra)
        if max_records and len(rows) >= max_records:
            return rows[:max_records]

    return rows


def write_csv(rows: Iterable[dict], out_path: Path) -> int:
    """Write rows to `out_path` in the canonical column order. Returns
    the row count (excluding header)."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in CSV_FIELDS})
            n += 1
    return n


def write_manifest(
    out_path: Path,
    *,
    wallet_slug: str,
    repo: str,
    n_rows: int,
    sources: list[str],
) -> None:
    """Provenance snapshot — when the crawl ran, what gh version, what
    sources were tapped. Lives next to the CSV so a re-run is auditable."""
    gh_version = ""
    try:
        v = subprocess.run(
            ["gh", "--version"], capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
        if v.returncode == 0:
            gh_version = v.stdout.strip().splitlines()[0]
    except Exception:
        pass

    manifest = {
        "wallet": wallet_slug,
        "repo": repo,
        "n_rows": n_rows,
        "sources": sources,
        "crawled_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gh_version": gh_version,
    }
    out_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def crawl_and_write(wallet_slug: str, out_dir: Path, *, max_records: int | None = None) -> int:
    """Top-level: crawl, write CSV + manifest, return row count."""
    repo = WALLET_CONFIG[wallet_slug]["repo"]
    print(f"[{wallet_slug}] crawling advisories + PRs + issues on {repo}...", file=sys.stderr)
    rows = crawl_wallet(wallet_slug, max_records=max_records)
    csv_path = out_dir / f"{wallet_slug}.csv"
    manifest_path = out_dir / f"{wallet_slug}.crawl_manifest.json"
    n = write_csv(rows, csv_path)
    write_manifest(
        manifest_path,
        wallet_slug=wallet_slug,
        repo=repo,
        n_rows=n,
        sources=[
            f"https://github.com/{repo}/security/advisories",
            f"https://github.com/{repo}/pulls?q=is:pr+is:closed",
            f"https://github.com/{repo}/issues?q=is:issue+is:closed+label:security",
        ],
    )
    print(f"[{wallet_slug}] wrote {n} rows -> {csv_path}", file=sys.stderr)
    return n


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--wallet", required=True,
        help="Wallet slug (one of: " + ", ".join(sorted(WALLET_CONFIG))
             + ") or 'all' for the full set.",
    )
    p.add_argument(
        "--out-dir", default="benchmarks/data/ethereum_past_fixes",
        help="Output directory for <wallet>.csv + <wallet>.crawl_manifest.json.",
    )
    p.add_argument(
        "--max-records", type=int, default=0,
        help="Cap rows per wallet (0 = no cap, useful for smoke tests).",
    )
    args = p.parse_args()

    out_dir = Path(args.out_dir)
    if args.wallet == "all":
        wallets = sorted(WALLET_CONFIG)
    else:
        if args.wallet not in WALLET_CONFIG:
            sys.exit(f"unknown --wallet {args.wallet!r}; pass 'all' or one of: {sorted(WALLET_CONFIG)}")
        wallets = [args.wallet]

    cap = args.max_records or None
    total = 0
    for c in wallets:
        total += crawl_and_write(c, out_dir, max_records=cap)
    print(f"done — {total} rows across {len(wallets)} wallet(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
