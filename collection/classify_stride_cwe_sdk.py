#!/usr/bin/env python3
"""classify_stride_cwe_sdk.py — STRIDE/CWE classification using Anthropic SDK directly.

Alternative to classify_stride_cwe.py (which uses `claude -p` subprocess).
Uses the `anthropic` Python package directly — works inside Claude Code sessions.

Usage:
    uv run python3 benchmarks/scripts/classify_stride_cwe_sdk.py \
        --in dataset/ethereum_past_fixes/train.parquet \
        --out dataset/ethereum_past_fixes/train.classified.parquet \
        --max-rows 50 \
        --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

try:
    import pandas as pd
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError:
    sys.exit("Run: uv add pandas pyarrow")

try:
    import anthropic
except ImportError:
    sys.exit("Run: uv add anthropic")

STRIDE_VALUES = [
    "Spoofing", "Tampering", "Repudiation",
    "Information Disclosure", "Denial of Service",
    "Elevation of Privilege", "Other",
]

CWE_TOP25 = [
    "CWE-79", "CWE-89", "CWE-20", "CWE-125", "CWE-78",
    "CWE-416", "CWE-22", "CWE-352", "CWE-434", "CWE-862",
    "CWE-476", "CWE-787", "CWE-119", "CWE-190", "CWE-502",
    "CWE-77", "CWE-269", "CWE-200", "CWE-306", "CWE-918",
    "CWE-362", "CWE-400", "CWE-611", "CWE-94", "CWE-798",
    "N/A",
]

BATCH_SIZE = 20
MODEL = "claude-haiku-4-5-20251001"

SYSTEM_PROMPT = f"""You are a software defect taxonomy expert.
For each item given, output ONLY a JSON array with one object per item:
{{"id": "<item id>", "stride": "<category>", "cwe": "<id or N/A>"}}

STRIDE categories (pick exactly one): {", ".join(STRIDE_VALUES)}
CWE Top-25 (2024) IDs (pick closest or N/A): {", ".join(CWE_TOP25)}

Base the classification on the title and description.
Output JSON only, no explanation."""


def classify_batch(wallet: anthropic.Anthropic, batch: list[dict], dry_run: bool) -> list[dict]:
    if dry_run:
        return [{"id": r["id"], "stride": "Other", "cwe": "N/A"} for r in batch]

    items_text = "\n".join(
        f'ID: {r["id"]}\nTitle: {r["title"]}\nDescription: {r["description"][:300]}'
        for r in batch
    )
    msg = wallet.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": items_text}],
    )
    text = msg.content[0].text.strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        text = "\n".join(text.split("\n")[1:])
        if text.endswith("```"):
            text = text[:-3].strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        print(f"  [warn] JSON parse failed, marking batch as Other/N/A", file=sys.stderr)
        return [{"id": r["id"], "stride": "Other", "cwe": "N/A"} for r in batch]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--in", dest="in_path", default="dataset/ethereum_past_fixes/train.parquet")
    p.add_argument("--out", dest="out_path", default="dataset/ethereum_past_fixes/train.classified.parquet")
    p.add_argument("--checkpoint", default="",
                   help="JSON checkpoint file for resume (default: <out>.checkpoint.json)")
    p.add_argument("--max-rows", type=int, default=0)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--workers", type=int, default=1, help="Unused; kept for CLI compat")
    args = p.parse_args()

    in_path = Path(args.in_path)
    out_path = Path(args.out_path)
    checkpoint_path = Path(args.checkpoint) if args.checkpoint else Path(str(out_path) + ".checkpoint.json")

    df = pd.read_parquet(in_path)
    if args.max_rows:
        df = df.head(args.max_rows)

    # Load checkpoint
    done: dict[str, dict] = {}
    if checkpoint_path.exists():
        done = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        print(f"[resume] {len(done)} rows already classified", file=sys.stderr)

    remaining = df[~df["id"].isin(done)].to_dict("records")
    print(f"[info] {len(remaining)} rows to classify (dry_run={args.dry_run})", file=sys.stderr)

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    wallet = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()

    for i in range(0, len(remaining), BATCH_SIZE):
        batch = remaining[i:i + BATCH_SIZE]
        results = classify_batch(wallet, batch, args.dry_run)
        for r in results:
            done[r["id"]] = r
        # Save checkpoint
        checkpoint_path.write_text(json.dumps(done, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"  classified {min(i + BATCH_SIZE, len(remaining))}/{len(remaining)}", file=sys.stderr)
        if not args.dry_run:
            time.sleep(0.5)

    # Merge back
    stride_map = {r["id"]: r.get("stride", "Other") for r in done.values()}
    cwe_map    = {r["id"]: r.get("cwe", "N/A")    for r in done.values()}
    df["stride"]    = df["id"].map(stride_map).fillna("Other")
    df["cwe_top25"] = df["id"].map(cwe_map).fillna("N/A")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out_path, index=False)

    manifest = {
        "n_rows": len(df),
        "n_classified": len(done),
        "model": MODEL if not args.dry_run else "dry-run",
        "dry_run": args.dry_run,
        "ended_at": datetime.now(timezone.utc).isoformat(),
    }
    mf_path = out_path.with_suffix(".classify_manifest.json")
    mf_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # Update manifest.json with post-classify stats
    main_manifest_path = out_path.parent / "manifest.json"
    if main_manifest_path.exists():
        main_manifest = json.loads(main_manifest_path.read_text(encoding="utf-8"))
        main_manifest["n_rows"] = len(df)
        if "source_platform" in df.columns:
            main_manifest["rows_by_platform"] = (
                df.groupby("source_platform").size().to_dict()
            )
        if "severity" in df.columns:
            main_manifest["rows_by_severity"] = (
                df.groupby("severity").size().to_dict()
            )
        if "stride" in df.columns:
            main_manifest["rows_by_stride"] = (
                {k: int(v) for k, v in df.groupby("stride").size().items()}
            )
        if "stride" in df.columns:
            main_manifest["stride_complete"] = bool(df["stride"].notna().mean() >= 0.99)
        else:
            main_manifest["stride_complete"] = False
        if "cwe_top25" in df.columns:
            main_manifest["cwe_complete"] = bool(df["cwe_top25"].notna().mean() >= 0.80)
        else:
            main_manifest["cwe_complete"] = False
        main_manifest_path.write_text(
            json.dumps(main_manifest, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"[done] updated {main_manifest_path} (n_rows={len(df)})", file=sys.stderr)
    else:
        print(f"[warn] {main_manifest_path} not found — skipping manifest update", file=sys.stderr)

    print(f"[done] wrote {out_path} ({len(df)} rows)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
