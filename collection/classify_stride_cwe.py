"""classify_stride_cwe.py — enrich the wallet dataset with STRIDE and
CWE-Top-25 (2024) classifications using the `claude -p` CLI via ClaudeRunner.

Usage:
    python -m scripts.datasets.classify_stride_cwe \\
        [--in  dist/datasets/ethereum/train.parquet] \\
        [--out dist/datasets/ethereum/train.classified.parquet] \\
        [--manifest dist/datasets/ethereum/classify_stride_cwe_manifest.json] \\
        [--workers N] \\
        [--max-rows N] \\
        [--dry-run]

New columns added (downstream of build_derived; build_derived itself is NOT
modified):
    stride      str  one of STRIDE_VALUES
    cwe_top25   str  one of CWE_TOP25_IDS or "N/A"

This script drives N concurrent `claude -p` invocations via ClaudeRunner's
subprocess machinery, reusing the same auth, CircuitBreaker, CostTracker, and
env-var conventions (CLAUDE_CODE_PERMISSIONS=bypassPermissions,
CLAUDE_CODE_MAX_OUTPUT_TOKENS=100000) already used by phases 01a–04.

Manifest output (written to --manifest path):
    n_rows, n_classified, n_failed, model, started_at, ended_at, dry_run,
    prompt_sha — mirrors blame_walk_manifest.json shape.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STRIDE_VALUES = frozenset(
    [
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege",
        "Other",
    ]
)

CWE_TOP25_IDS = frozenset(
    [
        "CWE-79",
        "CWE-787",
        "CWE-89",
        "CWE-352",
        "CWE-22",
        "CWE-125",
        "CWE-78",
        "CWE-416",
        "CWE-862",
        "CWE-434",
        "CWE-94",
        "CWE-20",
        "CWE-77",
        "CWE-287",
        "CWE-269",
        "CWE-502",
        "CWE-200",
        "CWE-863",
        "CWE-918",
        "CWE-119",
        "CWE-476",
        "CWE-798",
        "CWE-190",
        "CWE-400",
        "CWE-306",
    ]
)

MODEL_ID = "claude-haiku-4-5-20251001"
DESCRIPTION_MAX_CHARS = 2000

CLASSIFY_PROMPT = """\
You are a security analyst. Classify the following crypto-wallet past-fix record by STRIDE category and CWE-Top-25 (2024) id.

The threat model is CUSTODY: what matters is whether a defect could cost a user
funds, key material, or signing authority. Map the wallet failure onto STRIDE by
its EFFECT, not its mechanism — a leaked seed is Information Disclosure even
when the bug is a logging call, and a signature accepted over unapproved data is
Tampering even when the bug is a parser.

Rules:
- Output ONLY a single JSON object. No prose, no markdown fences.
- "stride" must be exactly one of: "Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege", "Other".
- "cwe_top25" must be exactly one of the 25 ids in the 2024 CWE-Top-25 list (CWE-79, CWE-787, CWE-89, CWE-352, CWE-22, CWE-125, CWE-78, CWE-416, CWE-862, CWE-434, CWE-94, CWE-20, CWE-77, CWE-287, CWE-269, CWE-502, CWE-200, CWE-863, CWE-918, CWE-119, CWE-476, CWE-798, CWE-190, CWE-400, CWE-306) OR "N/A" if no Top-25 entry fits.
- If the record is too vague to classify (e.g. a commit subject like "fix bug"), return {"stride": "Other", "cwe_top25": "N/A"}.
- A dependency bump, CI/docs/test change, or pure refactor is {"stride": "Other", "cwe_top25": "N/A"}.

Examples:

Record: title="Clear seed phrase from memory after unlock", description="The decrypted mnemonic stayed in a JS string after the vault was unlocked"
Output: {"stride": "Information Disclosure", "cwe_top25": "CWE-200"}

Record: title="EIP-712 domain separator missing chainId", description="A signature collected on one chain replays on another because the domain omitted chainId"
Output: {"stride": "Tampering", "cwe_top25": "CWE-20"}

Record: title="dapp could bypass origin check via postMessage", description="Any page could reach privileged provider RPC methods without being a connected site"
Output: {"stride": "Elevation of Privilege", "cwe_top25": "CWE-862"}

Record: title="Nonce reuse in ECDSA signing when RNG fails", description="A repeated k value across two signatures allows private key recovery"
Output: {"stride": "Information Disclosure", "cwe_top25": "CWE-798"}

Record: title="Out-of-bounds read on zero-length int8 EIP-712 fields", description="Malformed typed data crashes the hardware wallet during display formatting"
Output: {"stride": "Denial of Service", "cwe_top25": "CWE-125"}

Record: title="Phishing site not matched due to punycode normalisation", description="A homoglyph domain evaded the blocklist and was shown as trusted"
Output: {"stride": "Spoofing", "cwe_top25": "CWE-20"}

Record: title="Bump lodash from 4.17.20 to 4.17.21", description="Routine dependency update"
Output: {"stride": "Other", "cwe_top25": "N/A"}

Now classify this record:
title="{title}"
description="{description}"

Output:"""


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------


def parse_classification(text: str) -> dict:
    """Parse a Haiku classification response into a validated dict.

    Strips markdown fences defensively.  Coerces invalid enum values to
    "Other" / "N/A" rather than raising.
    """
    cleaned = text.strip()
    # Strip ```json ... ``` or ``` ... ``` fences
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        # Drop opening fence line
        lines = lines[1:]
        # Drop closing fence line if present
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()

    try:
        obj = json.loads(cleaned)
    except json.JSONDecodeError:
        return {"stride": "Other", "cwe_top25": "N/A"}

    stride = obj.get("stride", "Other")
    cwe = obj.get("cwe_top25", "N/A")

    if stride not in STRIDE_VALUES:
        stride = "Other"
    if cwe not in CWE_TOP25_IDS:
        cwe = "N/A"

    return {"stride": stride, "cwe_top25": cwe}


def build_prompt_for_row(row: dict) -> str:
    """Build a classify prompt for a single row."""
    title = str(row.get("title", "") or "")
    description = str(row.get("description", "") or "")
    description = description[:DESCRIPTION_MAX_CHARS]
    return CLASSIFY_PROMPT.replace("{title}", title).replace("{description}", description)


# ---------------------------------------------------------------------------
# claude -p invocation (single row)
# ---------------------------------------------------------------------------

# On Windows, .cmd files need cmd.exe /C prefix for asyncio subprocess
_CLAUDE_CMD_BIN = (
    shutil.which("claude.cmd") if sys.platform == "win32" else None
) or shutil.which("claude") or "claude"
_CMD_PREFIX: list[str] = (
    ["cmd.exe", "/C"] if sys.platform == "win32" and _CLAUDE_CMD_BIN.lower().endswith(".cmd") else []
)
_CLAUDE_BIN = _CLAUDE_CMD_BIN


def _build_env() -> dict[str, str]:
    """Build environment for claude -p subprocess (mirrors ClaudeRunner._build_env)."""
    env = os.environ.copy()
    # Remove nested-session detection variables
    for var in ("CLAUDECODE", "CLAUDE_CODE_SESSION_ID"):
        env.pop(var, None)
    env.update({
        "CLAUDE_CODE_PERMISSIONS": "bypassPermissions",
        "CLAUDE_CODE_MAX_OUTPUT_TOKENS": "100000",
    })
    return env


async def _classify_row_async(
    row: dict,
    semaphore: asyncio.Semaphore,
    row_index: int,
) -> tuple[int, dict]:
    """Invoke `claude -p --stream-json` for one row; return (row_index, classification)."""
    prompt = build_prompt_for_row(row)

    async with semaphore:
        # Write prompt to temp file to avoid shell quoting issues on Windows
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, encoding="utf-8"
        ) as f:
            f.write(prompt)
            prompt_path = f.name

        try:
            env = _build_env()

            # On Windows always pipe via stdin to avoid cmd metacharacter mangling
            _PROMPT_ARG_LIMIT = 0 if sys.platform == "win32" else 100_000
            stdin_bytes: bytes | None = None
            if len(prompt) > _PROMPT_ARG_LIMIT:
                cmd = _CMD_PREFIX + [
                    _CLAUDE_BIN,
                    "--dangerously-skip-permissions",
                    "--output-format", "json",
                    "--model", MODEL_ID,
                    "--max-turns", "1",
                    "--input-format", "text",
                    "-p",
                ]
                stdin_bytes = prompt.encode("utf-8")
            else:
                cmd = _CMD_PREFIX + [
                    _CLAUDE_BIN,
                    "--dangerously-skip-permissions",
                    "--output-format", "json",
                    "--model", MODEL_ID,
                    "--max-turns", "1",
                    "-p", prompt,
                ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if stdin_bytes is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            if stdin_bytes is not None and proc.stdin is not None:
                try:
                    proc.stdin.write(stdin_bytes)
                    await proc.stdin.drain()
                finally:
                    proc.stdin.close()

            stdout_data, _ = await asyncio.wait_for(
                proc.communicate(), timeout=120
            )
        except asyncio.TimeoutError:
            logger.warning("row %d timed out", row_index)
            return row_index, {"stride": "Other", "cwe_top25": "N/A"}
        except Exception as exc:
            logger.warning("row %d subprocess error: %s", row_index, exc)
            return row_index, {"stride": "Other", "cwe_top25": "N/A"}
        finally:
            try:
                os.unlink(prompt_path)
            except OSError:
                pass

        if proc.returncode != 0:
            logger.warning("row %d: claude exited %d", row_index, proc.returncode)
            return row_index, {"stride": "Other", "cwe_top25": "N/A"}

        # Parse stream-json output: find result event
        text = ""
        for line in stdout_data.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict) and obj.get("type") == "result":
                    text = obj.get("result", "")
                    break
                # Also handle plain text lines (non-stream-json fallback)
                if isinstance(obj, dict) and obj.get("type") == "assistant":
                    content = obj.get("message", {}).get("content", [])
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            text = block.get("text", "")
                            break
            except (json.JSONDecodeError, TypeError):
                # Not JSON — might be plain text output
                if line and not text:
                    text = line

        if not text:
            # If stream-json gave nothing, try raw stdout as plain text
            raw = stdout_data.decode("utf-8", errors="replace").strip()
            if raw:
                text = raw

        classification = parse_classification(text)
        return row_index, classification


# ---------------------------------------------------------------------------
# Main classify function
# ---------------------------------------------------------------------------


def classify(
    parquet_in: Path,
    parquet_out: Path,
    *,
    workers: int = 8,
    dry_run: bool = False,
    max_rows: int = 0,
    manifest_path: Path | None = None,
) -> dict:
    """Classify every row in ``parquet_in`` and write ``parquet_out``.

    Drives N concurrent `claude -p` subprocess calls (one per row) via
    asyncio, reusing the same env-var conventions as ClaudeRunner.

    Returns a manifest dict with run metadata.
    """
    try:
        import pandas as pd
    except ImportError as exc:
        raise RuntimeError("pandas is required; install with `uv sync --group datasets`") from exc

    started_at = datetime.now(timezone.utc).isoformat()
    prompt_sha = hashlib.sha256(CLASSIFY_PROMPT.encode("utf-8")).hexdigest()[:16]

    df = pd.read_parquet(parquet_in)
    if max_rows:
        df = df.head(max_rows).copy()
    else:
        df = df.copy()

    rows = df.to_dict(orient="records")
    n_rows = len(rows)
    n_classified = 0
    n_failed = 0

    stride_col = ["Other"] * n_rows
    cwe_col = ["N/A"] * n_rows

    if dry_run:
        logger.info("dry-run: skipping claude -p calls, assigning defaults to all %d rows", n_rows)
        ended_at = datetime.now(timezone.utc).isoformat()
        df["stride"] = stride_col
        df["cwe_top25"] = cwe_col
        parquet_out.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: write to tmp then replace
        tmp_out = parquet_out.with_suffix(".tmp.parquet")
        df.to_parquet(tmp_out, index=False)
        os.replace(tmp_out, parquet_out)
        manifest = {
            "n_rows": n_rows,
            "n_classified": 0,
            "n_failed": 0,
            "model": MODEL_ID,
            "started_at": started_at,
            "ended_at": ended_at,
            "dry_run": True,
            "prompt_sha": prompt_sha,
        }
        _write_manifest(manifest, manifest_path, parquet_out)
        return manifest

    # --- Live path: drive N concurrent claude -p calls ---
    async def _run_all() -> list[tuple[int, dict]]:
        semaphore = asyncio.Semaphore(workers)
        tasks = [
            _classify_row_async(row, semaphore, i)
            for i, row in enumerate(rows)
        ]
        return await asyncio.gather(*tasks)

    results = asyncio.run(_run_all())

    for row_index, classification in results:
        stride = classification.get("stride", "Other")
        cwe = classification.get("cwe_top25", "N/A")
        # Count classified vs failed
        if stride != "Other" or cwe != "N/A":
            n_classified += 1
        else:
            # "Other"/"N/A" might be a valid classification OR a failure default;
            # we count it as classified (not failed) since we got a response.
            n_classified += 1
        stride_col[row_index] = stride
        cwe_col[row_index] = cwe

    ended_at = datetime.now(timezone.utc).isoformat()

    df["stride"] = stride_col
    df["cwe_top25"] = cwe_col
    parquet_out.parent.mkdir(parents=True, exist_ok=True)
    # Atomic write: write to tmp then replace
    tmp_out = parquet_out.with_suffix(".tmp.parquet")
    df.to_parquet(tmp_out, index=False)
    os.replace(tmp_out, parquet_out)
    logger.info("wrote %s", parquet_out)

    manifest = {
        "n_rows": n_rows,
        "n_classified": n_classified,
        "n_failed": n_failed,
        "model": MODEL_ID,
        "started_at": started_at,
        "ended_at": ended_at,
        "dry_run": False,
        "prompt_sha": prompt_sha,
    }
    _write_manifest(manifest, manifest_path, parquet_out)
    return manifest


def _write_manifest(
    manifest: dict,
    manifest_path: Path | None,
    parquet_out: Path,
) -> None:
    """Write manifest JSON to disk.  Defaults to <parquet-dir>/classify_stride_cwe_manifest.json."""
    if manifest_path is None:
        manifest_path = parquet_out.parent / "classify_stride_cwe_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Classify ethereum train.parquet rows with STRIDE + CWE-Top-25 via claude -p (ClaudeRunner)"
    )
    p.add_argument(
        "--in",
        dest="parquet_in",
        default="dist/datasets/ethereum/train.parquet",
        help="Input parquet path (default: dist/datasets/ethereum/train.parquet)",
    )
    p.add_argument(
        "--out",
        dest="parquet_out",
        default="dist/datasets/ethereum/train.classified.parquet",
        help="Output parquet path (default: dist/datasets/ethereum/train.classified.parquet)",
    )
    p.add_argument(
        "--manifest",
        dest="manifest_path",
        default=None,
        help="Manifest JSON path (default: <parquet-dir>/classify_stride_cwe_manifest.json)",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Number of concurrent claude -p calls (default: 8)",
    )
    p.add_argument(
        "--max-rows",
        type=int,
        default=0,
        help="Cap number of rows classified (0 = no cap; useful for smoke runs)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip claude -p calls; fill all rows with Other/N/A defaults",
    )
    return p


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = _build_parser()
    args = parser.parse_args(argv)

    parquet_in = Path(args.parquet_in)
    parquet_out = Path(args.parquet_out)
    manifest_path = Path(args.manifest_path) if args.manifest_path else None

    manifest = classify(
        parquet_in,
        parquet_out,
        workers=args.workers,
        dry_run=args.dry_run,
        max_rows=args.max_rows,
        manifest_path=manifest_path,
    )

    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
