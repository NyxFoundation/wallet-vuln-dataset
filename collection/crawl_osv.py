#!/usr/bin/env python3
"""Crawl OSV.dev for all 11 Ethereum wallets across multiple ecosystems.

OSV.dev (https://osv.dev) is a free, open vulnerability database that
aggregates advisories from many upstream sources (GitHub, Go, npm, PyPI,
RustSec, etc.) and exposes them through a unified REST API.

Ecosystems covered:
    Go      — geth, nethermind (partial), erigon, prysm
    npm     — lodestar
    PyPI    — (currently none, reserved for future tools)
    crates.io — reth, lighthouse, grandine  (primary coverage in crawl_rustsec.py;
                duplicated here with a lighter package list to give a single
                entry-point for all 11 wallets)
    Maven   — besu, teku  (Java/Kotlin; best-effort — many deps are Gradle-only)

Note: nimbus-eth2 is written in Nim.  Nim has no OSV ecosystem entry;
advisories are covered by GitHub GHSA (crawl_wallet_past_fixes.py).

Output:
    <out-dir>/<wallet>.osv.csv
    <out-dir>/<wallet>.osv_manifest.json

CSV columns (identical schema to crawl_wallet_past_fixes.py / crawl_cve.py):
    source, contest, issue_id, severity, title, description,
    source_url, introduced_in_commit

Usage:
    uv run python3 benchmarks/scripts/crawl_osv.py --out-dir /tmp/osv_out
    uv run python3 benchmarks/scripts/crawl_osv.py --wallet geth --out-dir /tmp/osv_out
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# Package registry → wallet mapping
# ---------------------------------------------------------------------------

# Each entry is (ecosystem, package_name).  A single wallet may have multiple
# entries because it publishes packages in more than one ecosystem or under
# multiple names.
#
# Design note: OSV uses the module path for Go packages (not just the repo),
# which is why "github.com/ethereum/go-ethereum" and not "go-ethereum".

CLIENT_PACKAGES: dict[str, list[tuple[str, str]]] = {
    "geth": [
        ("Go", "github.com/ethereum/go-ethereum"),
    ],
    "nethermind": [
        # Nethermind is primarily C#; no Go/npm packages.  Coverage via NVD
        # (crawl_cve.py) and GHSA (crawl_wallet_past_fixes.py).
    ],
    "besu": [
        # Besu publishes to Maven Central.
        ("Maven", "org.hyperledger.besu:besu"),
        ("Maven", "org.hyperledger.besu:ethereum"),
    ],
    "erigon": [
        ("Go", "github.com/ledgerwatch/erigon"),
        # erigontech organisation fork
        ("Go", "github.com/erigontech/erigon"),
    ],
    "reth": [
        ("crates.io", "reth"),
        ("crates.io", "reth-primitives"),
    ],
    "lighthouse": [
        ("crates.io", "lighthouse"),
        ("crates.io", "eth2_libp2p"),
    ],
    "lodestar": [
        ("npm", "@chainsafe/lodestar"),
        ("npm", "@chainsafe/ssz"),
        ("npm", "@chainsafe/lodestar-beacon-state-transition"),
    ],
    "nimbus": [
        # Nim has no OSV ecosystem.  Placeholder keeps the slug reachable via
        # --wallet all without erroring; returns 0 rows.
    ],
    "prysm": [
        ("Go", "github.com/prysmaticlabs/prysm"),
        ("Go", "github.com/prysmaticlabs/prysm/v3"),
        ("Go", "github.com/prysmaticlabs/prysm/v4"),
        ("Go", "github.com/prysmaticlabs/prysm/v5"),
    ],
    "teku": [
        ("Maven", "tech.pegasys.teku:teku"),
    ],
    "grandine": [
        ("crates.io", "grandine"),
    ],
}

ALL_CLIENTS = list(CLIENT_PACKAGES)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "High",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "NONE": "Info",
}

ALLOWED_SEVERITIES = {"High", "Medium", "Low", "Info", "Unrated"}

CSV_FIELDS = (
    "source", "contest", "issue_id", "severity", "title",
    "description", "source_url", "introduced_in_commit",
)

SLEEP_BETWEEN_CALLS = 1.0


# ---------------------------------------------------------------------------
# OSV API helpers
# ---------------------------------------------------------------------------

def query_osv(ecosystem: str, package: str, retries: int = 3) -> list[dict]:
    """POST a package query to OSV.dev and return the vuln list (may be empty).

    OSV responds with {"vulns": [...]} or {} when no vulns are found.
    Retries with exponential back-off on network errors.
    """
    payload = json.dumps(
        {"package": {"name": package, "ecosystem": ecosystem}}
    ).encode("utf-8")
    req = Request(
        OSV_QUERY_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "speca-osv-crawler/1.0",
        },
    )
    for attempt in range(retries):
        try:
            with urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode("utf-8"))
                return data.get("vulns") or []
        except URLError as e:
            wait = 5 * (2 ** attempt)
            print(
                f"  [warn] OSV request failed (attempt {attempt + 1}): {e} "
                f"— retrying in {wait}s",
                file=sys.stderr,
            )
            time.sleep(wait)
        except json.JSONDecodeError as e:
            print(f"  [warn] OSV JSON decode error: {e}", file=sys.stderr)
            return []
    print(
        f"  [warn] OSV request failed after {retries} retries "
        f"for {ecosystem}/{package}",
        file=sys.stderr,
    )
    return []


# ---------------------------------------------------------------------------
# Advisory normalisation
# ---------------------------------------------------------------------------

def _extract_severity(vuln: dict) -> str:
    """Derive a unified severity string from OSV data.

    Priority order:
    1. database_specific.severity  (plain string, e.g. "HIGH")
    2. database_specific.cvss      (same)
    3. severity[].score CVSS vector keyword scan
    Returns "Unrated" when no usable data is present.
    """
    db_specific = vuln.get("database_specific") or {}
    for key in ("severity", "cvss"):
        raw = db_specific.get(key)
        if raw:
            mapped = SEVERITY_MAP.get(str(raw).upper())
            if mapped:
                return mapped

    for entry in (vuln.get("severity") or []):
        score_str = (entry.get("score") or "").upper()
        for keyword, level in [
            ("CRITICAL", "High"),
            ("HIGH", "High"),
            ("MEDIUM", "Medium"),
            ("LOW", "Low"),
        ]:
            if keyword in score_str:
                return level

    return "Unrated"


def _best_id(vuln: dict) -> str:
    """Return a stable, human-readable advisory ID.

    Preference order: CVE > GHSA > RUSTSEC > OSV ID.
    """
    osv_id = vuln.get("id", "")
    aliases = vuln.get("aliases") or []
    all_ids = [osv_id] + aliases

    for prefix in ("CVE-", "GHSA-", "RUSTSEC-"):
        for candidate in all_ids:
            if candidate.startswith(prefix):
                return candidate
    return osv_id


def _source_url(issue_id: str, vuln: dict) -> str:
    """Construct a human-readable advisory URL for the canonical ID."""
    if issue_id.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{issue_id}"
    if issue_id.startswith("GHSA-"):
        return f"https://github.com/advisories/{issue_id}"
    if issue_id.startswith("RUSTSEC-"):
        return f"https://rustsec.org/advisories/{issue_id}.html"
    return f"https://osv.dev/vulnerability/{issue_id}"


def _extract_fix(vuln: dict) -> tuple[str, str]:
    """Deterministic patch backlink from OSV's structured ranges.

    OSV records the fix as a machine-readable event: a GIT range yields the
    exact ``introduced`` / ``fixed`` commit SHAs; a SEMVER range yields the
    fixed version. This is the working, high-precision branch of silent-fix
    recovery (cf. VCMatch / PatchScout) — the advisory confirms the vuln and
    points at the commit that silently fixed it.

    Returns ``(introduced_commit, fix_ref)`` where fix_ref is a commit SHA
    (GIT) or a version string (SEMVER); either may be empty.
    """
    introduced, fix = "", ""
    for a in vuln.get("affected", []):
        for rng in a.get("ranges", []):
            git = rng.get("type") == "GIT"
            for ev in rng.get("events", []):
                iv = ev.get("introduced")
                if git and iv and iv not in ("0",) and not introduced:
                    introduced = iv
                fv = ev.get("fixed")
                if fv and not fix:
                    fix = fv
    return introduced, fix


def osv_vuln_to_row(vuln: dict, wallet_slug: str, ecosystem: str) -> dict | None:
    """Project one OSV vulnerability record onto the canonical CSV schema.

    Returns None if the record lacks a usable ID or any descriptive text.
    """
    issue_id = _best_id(vuln)
    if not issue_id:
        return None

    summary = (vuln.get("summary") or "").strip()
    details = (vuln.get("details") or "").strip()
    description = (details or summary)[:500]

    if not summary and not description:
        return None

    severity = _extract_severity(vuln)
    if severity not in ALLOWED_SEVERITIES:
        severity = "Unrated"

    introduced, fix = _extract_fix(vuln)
    if fix:
        # Record the backlink in-schema (no shared-schema column churn).
        tag = "fix_commit" if len(fix) >= 7 and all(c in "0123456789abcdef" for c in fix.lower()) else "fixed_version"
        description = f"{description}\n\n[{tag}: {fix}]"[:600]

    return {
        "source": wallet_slug,
        "contest": f"osv_{ecosystem.lower()}",
        "issue_id": issue_id,
        "severity": severity,
        "title": summary or issue_id,
        "description": description,
        "source_url": _source_url(issue_id, vuln),
        "introduced_in_commit": introduced,
    }


# ---------------------------------------------------------------------------
# Per-wallet crawl
# ---------------------------------------------------------------------------

def crawl_wallet(wallet_slug: str) -> list[dict]:
    """Query OSV.dev for all packages associated with `wallet_slug`.

    Deduplicates by issue_id so the same advisory surfaced via multiple
    package queries (e.g. prysm v3 and v4) appears only once.
    """
    packages = CLIENT_PACKAGES.get(wallet_slug, [])
    if not packages:
        print(
            f"  [{wallet_slug}] no OSV packages configured — skipping "
            f"(coverage via GHSA / NVD)",
            file=sys.stderr,
        )
        return []

    seen_ids: set[str] = set()
    rows: list[dict] = []

    for i, (ecosystem, package) in enumerate(packages):
        print(
            f"  [{wallet_slug}] querying OSV {ecosystem}/{package}...",
            file=sys.stderr,
        )
        vulns = query_osv(ecosystem, package)
        print(f"  [{wallet_slug}]   {len(vulns)} vuln(s) returned", file=sys.stderr)

        for vuln in vulns:
            row = osv_vuln_to_row(vuln, wallet_slug, ecosystem)
            if row is None:
                continue
            if row["issue_id"] in seen_ids:
                continue
            seen_ids.add(row["issue_id"])
            rows.append(row)

        if i < len(packages) - 1:
            time.sleep(SLEEP_BETWEEN_CALLS)

    return rows


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def write_csv(rows: list[dict], out_path: Path) -> int:
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
    wallet_slug: str,
    n_rows: int,
    packages: list[tuple[str, str]],
) -> None:
    manifest = {
        "wallet": wallet_slug,
        "source": "osv_dev",
        "packages_queried": [
            {"ecosystem": eco, "package": pkg} for eco, pkg in packages
        ],
        "n_rows": n_rows,
        "crawled_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "osv_endpoint": OSV_QUERY_URL,
    }
    out_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--wallet", default="all",
        help=(
            "Wallet slug ("
            + " | ".join(ALL_CLIENTS)
            + ") or 'all'."
        ),
    )
    p.add_argument(
        "--out-dir", default="/tmp/osv_out",
        help="Output directory for <wallet>.osv.csv + manifest.",
    )
    args = p.parse_args()

    out_dir = Path(args.out_dir)

    if args.wallet == "all":
        wallets = ALL_CLIENTS
    else:
        if args.wallet not in CLIENT_PACKAGES:
            sys.exit(
                f"unknown --wallet {args.wallet!r}; "
                f"valid: {ALL_CLIENTS} or 'all'"
            )
        wallets = [args.wallet]

    total = 0
    for slug in wallets:
        print(f"[{slug}] crawling OSV.dev advisories...", file=sys.stderr)
        rows = crawl_wallet(slug)
        csv_path = out_dir / f"{slug}.osv.csv"
        mf_path = out_dir / f"{slug}.osv_manifest.json"
        n = write_csv(rows, csv_path)
        write_manifest(mf_path, slug, n, CLIENT_PACKAGES.get(slug, []))
        print(f"[{slug}] wrote {n} OSV rows -> {csv_path}", file=sys.stderr)
        total += n
        time.sleep(SLEEP_BETWEEN_CALLS)

    print(
        f"done — {total} OSV rows across {len(wallets)} wallet(s)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
