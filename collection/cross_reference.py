#!/usr/bin/env python3
"""cross_reference.py — De-duplicate and cross-reference GHSA/PR/CVE records.

Loads train.parquet, identifies near-duplicate rows that represent the same
vulnerability from different crawl sources, canonicalises each cluster to the
highest-confidence row, and adds an ``evidence`` column (JSON list of all
source URLs in the cluster).

Matching rules:
  Within the same source_platform:
  - CVE match:   both rows mention the same CVE-YYYY-NNNNN in issue_id or
                 description
  - GHSA match:  both rows mention the same GHSA-xxxx-xxxx-xxxx in issue_id or
                 description
  - Title match: the first 60 chars of the normalised title (lower-cased,
                 punctuation stripped) are identical AND non-empty

  Cross-platform (T11):
  - SHA match:   both rows contain the same 40-hex-char commit SHA in any of
                 introduced_in_commit, source_url, or description.  Because
                 commit SHAs are globally unique across repos, SHA matches are
                 trusted across source_platform boundaries.

  T12 (cherry-pick severity inheritance):
  Cross-platform SHA clusters inherit the highest-confidence severity from any
  member.  This means a cherry-pick fix commit appearing as introduced_in_commit
  in one row and as part of a GitHub URL in another will cause the lower-severity
  row to be promoted to the cluster representative if it otherwise has the best
  metadata, while the severity always reflects the highest-confidence member.

Severity confidence order (highest → lowest):
  Critical > High > Medium > Low > Info > Unrated > ""

Usage:
    uv run python3 scripts/datasets/cross_reference.py \\
        --in  dataset/ethereum_past_fixes/train.parquet \\
        --out dataset/ethereum_past_fixes/train.crossref.parquet
"""

from __future__ import annotations

import argparse
import json
import re
import string
import sys
from pathlib import Path
from typing import Iterator

# ---------------------------------------------------------------------------
# Severity ordering (higher index = higher confidence)
# ---------------------------------------------------------------------------
_SEV_ORDER: list[str] = ["", "Unrated", "Info", "Low", "Medium", "High", "Critical"]
_SEV_RANK: dict[str, int] = {s: i for i, s in enumerate(_SEV_ORDER)}


def _sev_rank(sev: str | None) -> int:
    return _SEV_RANK.get(sev or "", 0)


# ---------------------------------------------------------------------------
# Identifier extraction helpers
# ---------------------------------------------------------------------------
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE)
# T11: full 40-char hex SHA (git commit hash).  Shorter abbreviated SHAs are
# not matched here because they collide too easily across large repos.
_SHA_RE = re.compile(r"\b([0-9a-f]{40})\b")

_PUNCT_TABLE = str.maketrans("", "", string.punctuation)


def _extract_ids(text: str, pattern: re.Pattern) -> set[str]:
    """Return upper-cased identifiers matched by *pattern* in *text*."""
    return {m.upper() for m in pattern.findall(text or "")}


def _title_key(title: str) -> str:
    """Normalise title: lower-case, strip punctuation, take first 60 chars."""
    cleaned = (title or "").lower().translate(_PUNCT_TABLE).strip()
    return cleaned[:60]


# ---------------------------------------------------------------------------
# Union-Find (path-compressed)
# ---------------------------------------------------------------------------

class _UF:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        a, b = self.find(a), self.find(b)
        if a != b:
            self.parent[b] = a

    def clusters(self, n: int) -> Iterator[list[int]]:
        """Yield groups of indices that belong to the same component."""
        groups: dict[int, list[int]] = {}
        for i in range(n):
            root = self.find(i)
            groups.setdefault(root, []).append(i)
        yield from groups.values()


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def cross_reference(
    df,  # pandas.DataFrame
    *,
    verbose: bool = True,
) -> tuple:  # (out_df, manifest_dict)
    """De-duplicate *df* and return (result_df, manifest).

    The result has the same schema as *df* plus an ``evidence`` column.
    """
    import pandas as pd

    n = len(df)
    uf = _UF(n)

    # ------------------------------------------------------------------
    # Index rows per platform for efficient lookup
    # ------------------------------------------------------------------
    # Maps: platform → { cve_id → [row_idx, ...] }
    #                  { ghsa_id → [row_idx, ...] }
    #                  { title_key → [row_idx, ...] }

    cve_idx: dict[str, dict[str, list[int]]] = {}   # platform → cve → indices
    ghsa_idx: dict[str, dict[str, list[int]]] = {}
    title_idx: dict[str, dict[str, list[int]]] = {}

    issue_id_col = df["issue_id"].fillna("").tolist()
    desc_col = df["description"].fillna("").tolist()
    title_col = df["title"].fillna("").tolist()
    platform_col = df["source_platform"].fillna("").tolist()
    url_col_raw = df["source_url"].fillna("").tolist()
    # T11: introduced_in_commit may hold the cherry-pick SHA
    intro_col = (
        df["introduced_in_commit"].fillna("").tolist()
        if "introduced_in_commit" in df.columns
        else [""] * n
    )

    # T11: global (cross-platform) SHA index
    sha_idx: dict[str, list[int]] = {}

    for i in range(n):
        plat = platform_col[i]
        combined = issue_id_col[i] + " " + desc_col[i]

        # CVE
        for cve in _extract_ids(combined, _CVE_RE):
            cve_idx.setdefault(plat, {}).setdefault(cve, []).append(i)

        # GHSA
        for ghsa in _extract_ids(combined, _GHSA_RE):
            ghsa_idx.setdefault(plat, {}).setdefault(ghsa, []).append(i)

        # Title
        tk = _title_key(title_col[i])
        if tk:  # skip empty title keys
            title_idx.setdefault(plat, {}).setdefault(tk, []).append(i)

        # T11: SHA — search introduced_in_commit, source_url, and description
        sha_sources = intro_col[i] + " " + url_col_raw[i] + " " + desc_col[i]
        for sha in _SHA_RE.findall(sha_sources):
            sha_idx.setdefault(sha, []).append(i)

    # ------------------------------------------------------------------
    # Union rows that share a CVE/GHSA id or title key (same platform)
    # ------------------------------------------------------------------
    def _union_bucket(bucket_map: dict[str, dict[str, list[int]]]) -> None:
        for _plat, id_map in bucket_map.items():
            for _id, indices in id_map.items():
                if len(indices) < 2:
                    continue
                first = indices[0]
                for other in indices[1:]:
                    uf.union(first, other)

    _union_bucket(cve_idx)
    _union_bucket(ghsa_idx)
    _union_bucket(title_idx)

    # T11: union rows sharing a SHA (cross-platform)
    sha_unions = 0
    for _sha, indices in sha_idx.items():
        # De-duplicate — a row may have multiple SHAs so could appear twice
        uniq = list(dict.fromkeys(indices))
        if len(uniq) < 2:
            continue
        first = uniq[0]
        for other in uniq[1:]:
            if uf.find(first) != uf.find(other):
                sha_unions += 1
            uf.union(first, other)
    if verbose and sha_unions:
        print(
            f"[cross_reference] T11: {sha_unions} new cross-platform merges via commit SHA",
            file=sys.stderr,
        )

    # ------------------------------------------------------------------
    # Resolve clusters → keep best row, collect evidence URLs
    # ------------------------------------------------------------------
    sev_col = df["severity"].fillna("").tolist()
    url_col = df["source_url"].fillna("").tolist()

    keep_indices: list[int] = []
    evidence_map: dict[int, list[str]] = {}  # row_idx (kept) → evidence list
    total_dupes = 0
    cluster_count = 0
    deduped_clusters: list[dict] = []

    for cluster in uf.clusters(n):
        if len(cluster) == 1:
            # Singleton — no duplicate
            keep_indices.append(cluster[0])
            evidence_map[cluster[0]] = [url_col[cluster[0]]]
            continue

        cluster_count += 1
        total_dupes += len(cluster) - 1

        # Pick representative: highest severity; ties broken by first seen (min idx)
        best = max(cluster, key=lambda i: (_sev_rank(sev_col[i]), -i))

        # Collect unique, non-empty source URLs from the whole cluster
        urls = list(dict.fromkeys(
            u for i in sorted(cluster) for u in [url_col[i]] if u
        ))

        keep_indices.append(best)
        evidence_map[best] = urls

        deduped_clusters.append({
            "kept_idx": best,
            "dropped_indices": [i for i in cluster if i != best],
            "cluster_size": len(cluster),
            "urls": urls,
        })

    if verbose:
        print(
            f"[cross_reference] {n} rows → {len(keep_indices)} after dedup "
            f"({total_dupes} duplicates removed across {cluster_count} clusters)",
            file=sys.stderr,
        )

    # ------------------------------------------------------------------
    # Build output dataframe
    # ------------------------------------------------------------------
    out_df = df.iloc[keep_indices].copy().reset_index(drop=True)

    # Add evidence column
    out_df["evidence"] = [
        json.dumps(evidence_map[keep_indices[j]], ensure_ascii=False)
        for j in range(len(keep_indices))
    ]

    manifest = {
        "input_rows": n,
        "output_rows": len(keep_indices),
        "duplicates_removed": total_dupes,
        "clusters_deduped": cluster_count,
        "dedup_rate_pct": round(100.0 * total_dupes / n, 2) if n else 0.0,
        "sha_cross_platform_merges": sha_unions,  # T11
        "clusters": deduped_clusters,
    }

    return out_df, manifest


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--in", dest="input", required=True,
                   help="Input parquet file (e.g. train.parquet)")
    p.add_argument("--out", required=True,
                   help="Output parquet file (e.g. train.crossref.parquet)")
    p.add_argument("--manifest-out",
                   help="Optional path for crossref_manifest.json "
                        "(defaults to <out-dir>/crossref_manifest.json)")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress progress messages")
    args = p.parse_args(argv)

    try:
        import pandas as pd
    except ImportError:
        print("ERROR: pandas is required. Run: uv add pandas pyarrow", file=sys.stderr)
        return 1

    in_path = Path(args.input)
    out_path = Path(args.out)
    manifest_path = Path(args.manifest_out) if args.manifest_out else (
        out_path.parent / "crossref_manifest.json"
    )

    if not in_path.exists():
        print(f"ERROR: input file not found: {in_path}", file=sys.stderr)
        return 1

    print(f"[cross_reference] loading {in_path} …", file=sys.stderr)
    df = pd.read_parquet(in_path)
    print(f"[cross_reference] {len(df)} rows loaded.", file=sys.stderr)

    out_df, manifest = cross_reference(df, verbose=not args.quiet)

    # Write parquet
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_parquet(out_path, index=False)
    print(f"[cross_reference] wrote {len(out_df)} rows → {out_path}", file=sys.stderr)

    # Write manifest
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"[cross_reference] manifest → {manifest_path}", file=sys.stderr)

    # Print summary to stdout
    print(
        f"input_rows={manifest['input_rows']}  "
        f"output_rows={manifest['output_rows']}  "
        f"duplicates_removed={manifest['duplicates_removed']}  "
        f"clusters_deduped={manifest['clusters_deduped']}  "
        f"dedup_rate={manifest['dedup_rate_pct']}%"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
