#!/usr/bin/env python3
"""Mine PRs and issues from Ethereum spec repos for security-relevant
spec-divergence issues.

Critical insight: searching "fork_choice" (underscore) returns 13x fewer
results than "fork choice" (space).  For every logical term we therefore
search ALL variant forms (underscore, space-separated, camelCase,
PascalCase) and deduplicate by (repo, type, number).

Sources:
    - ethereum/consensus-specs  — PRs (merged) + closed issues
    - ethereum/execution-specs  — PRs (merged)
    - ethereum/EIPs             — PRs (merged)
    - ethereum/execution-apis   — PRs (merged)

Output (mirrors train.parquet schema from crawl_wallet_past_fixes.py):
    <out-dir>/specs_divergence.csv
    <out-dir>/specs_divergence_manifest.json

Usage:
    uv run python3 benchmarks/scripts/crawl_standards_divergence.py \\
        --out-dir dataset/ethereum_past_fixes/spec_divergence

    uv run python3 benchmarks/scripts/crawl_standards_divergence.py \\
        --out-dir /tmp/test_specs --max-per-term 20
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

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SPEC_REPOS = [
    "ethereum/consensus-specs",
    "ethereum/execution-specs",
    "ethereum/EIPs",
    "ethereum/execution-apis",
]

# For ethereum/consensus-specs we also search issues (not just PRs).
ISSUES_REPO = "ethereum/consensus-specs"

# Each logical term maps to 3-4 surface variants.  We query each variant
# separately and deduplicate afterwards — this is the key insight from the
# contributor note (underscore vs space yields 13x different result counts).
SPEC_TERMS: dict[str, list[str]] = {
    "fork_choice":       ["fork_choice", "fork choice", "forkChoice", "ForkChoice"],
    "sync_committee":    ["sync_committee", "sync committee", "syncCommittee", "SyncCommittee"],
    "state_transition":  ["state_transition", "state transition", "stateTransition", "process_slot"],
    "epoch_processing":  ["epoch_processing", "epoch processing", "processEpoch", "process_epoch"],
    "fork_choice_store": ["ProtoArray", "fc_store", "ForkChoiceStore"],
    "attestation":       ["attestation"],
    "slashing":          ["slashing", "slashable"],
    "bls_verify":        ["bls_verify", "bls.Verify", "BLSVerify"],
    "client_divergence": [
        "wallet divergence", "consensus divergence",
        "consensus split", "implementation divergence",
    ],
}

# Patterns for detecting which wallet a PR/issue is about.
CLIENT_PATTERNS: dict[str, list[str]] = {
    "geth":        ["go-ethereum", "geth"],
    "prysm":       ["prysm", "prysmatic"],
    "lighthouse":  ["lighthouse", "sigma prime", "sigp"],
    "lodestar":    ["lodestar", "chainsafe"],
    "nimbus":      ["nimbus"],
    "teku":        ["teku", "consensys"],
    "besu":        ["besu", "hyperledger"],
    "erigon":      ["erigon"],
    "reth":        ["reth", "paradigm"],
    "nethermind":  ["nethermind"],
    "grandine":    ["grandine"],
}

CSV_FIELDS = (
    "source", "contest", "issue_id", "severity",
    "title", "description", "source_url", "introduced_in_commit",
)

# Severity elevation trigger: if title or body contains any of these phrases
# the row gets "High", otherwise "Medium".
HIGH_SEVERITY_PATTERNS = re.compile(
    r"wallet\s+divergence|consensus\s+divergence|consensus\s+split"
    r"|implementation\s+divergence",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detect_client(text: str) -> str:
    """Return the first matching wallet name, or 'ethereum_specs' as fallback."""
    lower = text.lower()
    for wallet, patterns in CLIENT_PATTERNS.items():
        for pat in patterns:
            if pat.lower() in lower:
                return wallet
    return "ethereum_specs"


def _severity(text: str) -> str:
    if HIGH_SEVERITY_PATTERNS.search(text):
        return "High"
    return "Medium"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def gh_search(
    kind: str,          # "prs" or "issues"
    repo: str,
    state: str,         # "merged" / "closed"
    term: str,
    limit: int,
    timeout: int = 60,
) -> list[dict] | None:
    """Run `gh search <kind>` and return parsed JSON or None on error.

    Note on flags:
      - `gh search prs`    uses `--merged` (boolean) not `--state merged`
      - `gh search issues` uses `--state closed`
    """
    if kind == "prs" and state == "merged":
        state_flags = ["--merged"]
    else:
        state_flags = ["--state", state]

    cmd = [
        "gh", "search", kind,
        "--repo", repo,
        *state_flags,
        "--json", "number,title,body,url,closedAt,labels",
        "--limit", str(limit),
        f'"{term}" in:title,body',
    ]
    print(
        f"  [fetch] gh search {kind} --repo {repo} --limit {limit} \"{term}\"",
        file=sys.stderr,
    )
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        print(f"  [warn] timeout: {exc}", file=sys.stderr)
        return None
    except FileNotFoundError:
        print("  [error] `gh` not found on PATH", file=sys.stderr)
        sys.exit(1)

    if result.returncode != 0:
        msg = (result.stderr or "").strip()[:300]
        print(f"  [warn] gh exit {result.returncode}: {msg}", file=sys.stderr)
        return None

    body = result.stdout.strip()
    if not body:
        return []
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        print(f"  [warn] JSON parse error: {exc}", file=sys.stderr)
        return None


def _to_row(item: dict, repo: str, kind: str) -> dict:
    """Convert a raw gh JSON item to a CSV row dict."""
    number = item.get("number", 0)
    title = (item.get("title") or "")[:200]
    body  = (item.get("body") or "")[:500]
    url   = item.get("url") or ""
    text  = f"{title} {body}"

    prefix = "PR" if kind == "prs" else "ISSUE"
    issue_id = f"{prefix}#{number}"

    return {
        "source":             _detect_client(text),
        "contest":            "spec_divergence",
        "issue_id":           issue_id,
        "severity":           _severity(text),
        "title":              title,
        "description":        body,
        "source_url":         url,
        "introduced_in_commit": "",
    }


# ---------------------------------------------------------------------------
# Core crawl
# ---------------------------------------------------------------------------


def crawl(
    out_dir: Path,
    max_per_term: int,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Dedup key: (repo, kind, number)
    seen: set[tuple[str, str, int]] = set()
    rows: list[dict] = []

    stats: dict[str, int] = {}
    total_api_calls = 0

    def _collect(kind: str, repo: str, term: str, state: str) -> int:
        nonlocal total_api_calls
        items = gh_search(kind, repo, state, term, limit=max_per_term)
        total_api_calls += 1
        time.sleep(1)  # rate-limit courtesy delay

        if items is None:
            return 0

        added = 0
        for item in items:
            number = item.get("number", 0)
            key = (repo, kind, number)
            if key in seen:
                continue
            seen.add(key)
            rows.append(_to_row(item, repo, kind))
            added += 1
        return added

    # --- PRs: all 4 repos × all term variants ---------------------------------
    for group_name, variants in SPEC_TERMS.items():
        group_total = 0
        for repo in SPEC_REPOS:
            for term in variants:
                added = _collect("prs", repo, term, "merged")
                group_total += added
                label = f"prs:{repo}:{term}"
                stats[label] = stats.get(label, 0) + added

        print(
            f"[group] {group_name}: +{group_total} new rows "
            f"(running total: {len(rows)})",
            file=sys.stderr,
        )

    # --- Issues: consensus-specs only, all term variants ----------------------
    print("\n[phase] Searching closed issues on ethereum/consensus-specs …",
          file=sys.stderr)
    for group_name, variants in SPEC_TERMS.items():
        group_total = 0
        for term in variants:
            added = _collect("issues", ISSUES_REPO, term, "closed")
            group_total += added
            label = f"issues:{ISSUES_REPO}:{term}"
            stats[label] = stats.get(label, 0) + added

        print(
            f"[group/issues] {group_name}: +{group_total} new rows "
            f"(running total: {len(rows)})",
            file=sys.stderr,
        )

    # --- Write CSV ------------------------------------------------------------
    csv_path = out_dir / "specs_divergence.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(CSV_FIELDS))
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n[done] {len(rows)} rows → {csv_path}", file=sys.stderr)

    # --- Write manifest -------------------------------------------------------
    manifest = {
        "generated_at":    _now_iso(),
        "total_rows":      len(rows),
        "total_api_calls": total_api_calls,
        "max_per_term":    max_per_term,
        "repos_searched":  SPEC_REPOS,
        "issues_repo":     ISSUES_REPO,
        "term_groups":     list(SPEC_TERMS.keys()),
        "stats_by_query":  stats,
        "severity_counts": {
            "High":   sum(1 for r in rows if r["severity"] == "High"),
            "Medium": sum(1 for r in rows if r["severity"] == "Medium"),
        },
        "client_counts": _count_by_field(rows, "source"),
    }
    manifest_path = out_dir / "specs_divergence_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"[done] manifest → {manifest_path}", file=sys.stderr)


def _count_by_field(rows: list[dict], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        val = row.get(field, "")
        counts[val] = counts.get(val, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Mine Ethereum spec repos for security-relevant spec-divergence "
            "PRs and issues."
        ),
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Directory to write specs_divergence.csv and manifest.json",
    )
    parser.add_argument(
        "--max-per-term",
        type=int,
        default=200,
        metavar="N",
        help=(
            "Maximum results per (repo, term) search call (default: 200). "
            "GitHub caps `gh search` at 1000; use a lower value for quick tests."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print(
        f"[start] crawl_standards_divergence  out={args.out_dir}  "
        f"max_per_term={args.max_per_term}",
        file=sys.stderr,
    )
    crawl(out_dir=args.out_dir, max_per_term=args.max_per_term)


if __name__ == "__main__":
    main()
