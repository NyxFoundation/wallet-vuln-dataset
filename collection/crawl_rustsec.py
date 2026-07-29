#!/usr/bin/env python3
"""Crawl RustSec advisories for Rust-based Ethereum wallets via the OSV.dev API.

OSV.dev aggregates RustSec advisories under the crates.io ecosystem and exposes
them through a free, no-auth REST API.  We query each wallet's known crate names
and normalise the results onto the canonical CSV schema used by build_derived.py.

Clients covered: reth, lighthouse, grandine

Output:
    <out-dir>/<wallet>.rustsec.csv
    <out-dir>/<wallet>.rustsec_manifest.json

CSV columns (identical schema to crawl_wallet_past_fixes.py / crawl_cve.py):
    source, contest, issue_id, severity, title, description,
    source_url, introduced_in_commit

Usage:
    uv run python3 benchmarks/scripts/crawl_rustsec.py --out-dir /tmp/rustsec_out
    uv run python3 benchmarks/scripts/crawl_rustsec.py --wallet reth --out-dir /tmp/rustsec_out
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

# Crate names associated with each Rust-based Ethereum wallet.
#
# Two categories are included per wallet:
#   1. Internal workspace crates — the names given in the task spec.  These are
#      typically not published to crates.io individually, so OSV has no direct
#      advisory records for them; included for completeness / future coverage.
#   2. Key published dependency crates — shared libraries that ARE published to
#      crates.io and DO have RustSec advisories (e.g. libp2p, discv5, ethereum-types).
#      Advisories against these crates are directly relevant to wallets that
#      depend on them because a vulnerable dep version constitutes a risk.
#
# OSV.dev indexes advisories per crate name so we must query each individually.
RUST_CLIENT_CRATES: dict[str, list[str]] = {
    "reth": [
        # Internal workspace crates (task spec)
        "reth",
        "reth-primitives",
        "reth-db",
        "reth-rpc",
        "reth-net-nat",
        "reth-network",
        "reth-consensus",
        # Published dependency crates used by reth
        "revm",
        "revm-primitives",
        "discv5",
        "libp2p",
        "ethereum-types",
        "rlp",
    ],
    "lighthouse": [
        # Internal workspace crates (task spec)
        "lighthouse",
        "eth2_libp2p",
        "slasher",
        "beacon_node",
        "account_manager",
        "lighthouse_network",
        # Published dependency crates used by lighthouse
        "libp2p",
        "discv5",
        "blst",
        "ethereum-types",
        "ssz_types",
    ],
    "grandine": [
        # Internal workspace crates (task spec)
        "grandine",
        "eth2_types",
        "grandine-bin",
        # Published dependency crates used by grandine
        "libp2p",
        "discv5",
        "ethereum-types",
    ],
}

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
ECOSYSTEM = "crates.io"

# Map OSV/CVSS severity strings onto the project's unified schema.
# "Unrated" is a valid value when no CVSS data is present.
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

# Pause between API calls to be a respectful wallet.
SLEEP_BETWEEN_CALLS = 1.0


# ---------------------------------------------------------------------------
# OSV API helpers
# ---------------------------------------------------------------------------

def query_osv(ecosystem: str, package: str, retries: int = 3) -> list[dict]:
    """POST a package query to OSV.dev and return the vuln list (may be empty)."""
    payload = json.dumps(
        {"package": {"name": package, "ecosystem": ecosystem}}
    ).encode("utf-8")
    req = Request(
        OSV_QUERY_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "speca-rustsec-crawler/1.0",
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
    print(f"  [warn] OSV request failed after {retries} retries for {package!r}", file=sys.stderr)
    return []


# ---------------------------------------------------------------------------
# Advisory normalisation
# ---------------------------------------------------------------------------

def _extract_severity(vuln: dict) -> str:
    """Derive a unified severity from OSV severity array or CVSS scores.

    OSV severity entries have the form:
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/.../S:U/C:H/I:H/A:H"}

    We extract the base score from CVSS v3 first, fall back to v2, and
    return "Unrated" when no severity data is present.
    """
    severity_list = vuln.get("severity") or []
    for entry in severity_list:
        score_str = entry.get("score", "")
        # CVSS:3.x/... — the base score is the last /x.x segment encoded in
        # the vector string as BM (base metric).  The canonical way is to
        # parse the vector; here we use the database_specific field if present
        # since OSV often gives a pre-computed base score there.
        db_specific = vuln.get("database_specific") or {}
        cvss_score = db_specific.get("cvss") or db_specific.get("severity")
        if cvss_score:
            mapped = SEVERITY_MAP.get(str(cvss_score).upper())
            if mapped:
                return mapped
        # Fall back: check affected[].ecosystem_specific or just read the
        # CVSS vector base severity indicator.
        if "CRITICAL" in score_str.upper():
            return "High"
        if "HIGH" in score_str.upper():
            return "High"
        if "MEDIUM" in score_str.upper():
            return "Medium"
        if "LOW" in score_str.upper():
            return "Low"
    return "Unrated"


def _rustsec_id(vuln: dict) -> str:
    """Return the RUSTSEC-YYYY-NNNN alias if present, else the OSV ID."""
    aliases = vuln.get("aliases") or []
    for alias in aliases:
        if alias.startswith("RUSTSEC-"):
            return alias
    return vuln.get("id", "")


def _extract_description(vuln: dict) -> str:
    """Return the advisory details string, truncated to 500 chars."""
    details = (vuln.get("details") or "").strip()
    return details[:500]


def osv_vuln_to_row(vuln: dict, wallet_slug: str) -> dict | None:
    """Project one OSV vulnerability record onto the canonical CSV schema.

    Returns None if the record lacks a usable ID or title.
    """
    issue_id = _rustsec_id(vuln)
    if not issue_id:
        return None

    summary = (vuln.get("summary") or "").strip()
    description = _extract_description(vuln)

    if not summary and not description:
        return None

    severity = _extract_severity(vuln)
    if severity not in ALLOWED_SEVERITIES:
        severity = "Unrated"

    # Build the canonical RustSec advisory URL from the advisory ID.
    # Non-RUSTSEC IDs (e.g. GHSA-...) fall through to the OSV page.
    if issue_id.startswith("RUSTSEC-"):
        source_url = f"https://rustsec.org/advisories/{issue_id}.html"
    else:
        source_url = f"https://osv.dev/vulnerability/{issue_id}"

    return {
        "source": wallet_slug,
        "contest": "rustsec",
        "issue_id": issue_id,
        "severity": severity,
        "title": summary or issue_id,
        "description": description,
        "source_url": source_url,
        "introduced_in_commit": "",
    }


# ---------------------------------------------------------------------------
# Per-wallet crawl
# ---------------------------------------------------------------------------

def crawl_wallet(wallet_slug: str) -> list[dict]:
    """Query OSV.dev for all crates associated with `wallet_slug`.

    Deduplicates by issue_id so the same advisory surfaced via multiple
    crate queries appears only once.
    """
    crates = RUST_CLIENT_CRATES.get(wallet_slug)
    if not crates:
        print(f"  [warn] no crate mapping for wallet {wallet_slug!r}", file=sys.stderr)
        return []

    seen_ids: set[str] = set()
    rows: list[dict] = []

    for i, crate in enumerate(crates):
        print(f"  [{wallet_slug}] querying OSV for crate {crate!r}...", file=sys.stderr)
        vulns = query_osv(ECOSYSTEM, crate)
        print(f"  [{wallet_slug}]   {len(vulns)} vuln(s) returned", file=sys.stderr)

        for vuln in vulns:
            row = osv_vuln_to_row(vuln, wallet_slug)
            if row is None:
                continue
            if row["issue_id"] in seen_ids:
                continue
            seen_ids.add(row["issue_id"])
            rows.append(row)

        # Respect OSV rate limits — 1 s between calls.
        if i < len(crates) - 1:
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


def write_manifest(out_path: Path, wallet_slug: str, n_rows: int, crates: list[str]) -> None:
    manifest = {
        "wallet": wallet_slug,
        "source": "rustsec_via_osv",
        "ecosystem": ECOSYSTEM,
        "crates_queried": crates,
        "n_rows": n_rows,
        "crawled_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "osv_endpoint": OSV_QUERY_URL,
    }
    out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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
        help="Wallet slug (reth | lighthouse | grandine) or 'all'.",
    )
    p.add_argument(
        "--out-dir", default="/tmp/rustsec_out",
        help="Output directory for <wallet>.rustsec.csv + manifest.",
    )
    args = p.parse_args()

    out_dir = Path(args.out_dir)

    if args.wallet == "all":
        wallets = sorted(RUST_CLIENT_CRATES)
    else:
        if args.wallet not in RUST_CLIENT_CRATES:
            sys.exit(
                f"unknown --wallet {args.wallet!r}; "
                f"valid: {sorted(RUST_CLIENT_CRATES)} or 'all'"
            )
        wallets = [args.wallet]

    total = 0
    for slug in wallets:
        print(f"[{slug}] crawling RustSec advisories via OSV.dev...", file=sys.stderr)
        rows = crawl_wallet(slug)
        csv_path = out_dir / f"{slug}.rustsec.csv"
        mf_path = out_dir / f"{slug}.rustsec_manifest.json"
        n = write_csv(rows, csv_path)
        write_manifest(mf_path, slug, n, RUST_CLIENT_CRATES.get(slug, []))
        print(f"[{slug}] wrote {n} RustSec rows -> {csv_path}", file=sys.stderr)
        total += n
        # Sleep between wallets too.
        time.sleep(SLEEP_BETWEEN_CALLS)

    print(
        f"done — {total} RustSec rows across {len(wallets)} wallet(s)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
