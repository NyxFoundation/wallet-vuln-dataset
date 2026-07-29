#!/usr/bin/env python3
"""Crawl OSV.dev for Go module vulnerabilities using the querybatch endpoint.

Covers geth, prysm, and erigon — the three Go-based Ethereum wallets — plus
their known transitive dependencies. Uses the OSV.dev batch query API
(POST /v1/querybatch) to amortise round-trips.

Ecosystems: Go only (govulncheck-style). Java/Nim/TypeScript wallets are
covered by crawl_osv.py or crawl_wallet_past_fixes.py.

Output:
    <out-dir>/<wallet>.govulncheck.csv
    <out-dir>/<wallet>.govulncheck_manifest.json

CSV columns (identical schema to crawl_osv.py / crawl_wallet_past_fixes.py):
    source, contest, issue_id, severity, title, description,
    source_url, introduced_in_commit

Usage:
    uv run python3 benchmarks/scripts/crawl_govulncheck.py \\
        --wallet all \\
        --out-dir dataset/ethereum_past_fixes/govulncheck
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
# Go module → wallet mapping
# ---------------------------------------------------------------------------
# Each value is a list of Go module paths to query on behalf of that wallet.
# `None` means the wallet is not a Go project — skip it gracefully.

GO_MODULES: dict[str, list[str] | None] = {
    "geth": [
        "github.com/ethereum/go-ethereum",
        "golang.org/x/crypto",
        "github.com/gorilla/websocket",
    ],
    "prysm": [
        "github.com/prysmaticlabs/prysm",
        "github.com/prysmaticlabs/prysm/v3",
        "github.com/prysmaticlabs/prysm/v4",
        "github.com/prysmaticlabs/prysm/v5",
        "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4",
    ],
    "erigon": [
        "github.com/ledgerwatch/erigon",
        "github.com/erigontech/erigon",
    ],
    "lodestar": None,   # TypeScript
    "nimbus": None,     # Nim
    "teku": None,       # Java, covered by crawl_osv.py
}

ALL_CLIENTS = list(GO_MODULES)

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

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

# Sleep between batch requests (polite rate-limit behaviour)
SLEEP_BETWEEN_BATCHES = 1.0

# How many module queries to pack into one querybatch request
BATCH_SIZE = 10


# ---------------------------------------------------------------------------
# OSV API helpers
# ---------------------------------------------------------------------------

def _post_json(url: str, payload: bytes, retries: int = 3) -> dict | None:
    """POST JSON payload to `url` and return parsed response dict.

    Returns None on unrecoverable error.
    """
    req = Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "speca-govulncheck-crawler/1.0",
        },
    )
    for attempt in range(retries):
        try:
            with urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode("utf-8"))
        except URLError as e:
            wait = 5 * (2 ** attempt)
            print(
                f"  [warn] OSV POST failed (attempt {attempt + 1}): {e} "
                f"— retrying in {wait}s",
                file=sys.stderr,
            )
            time.sleep(wait)
        except json.JSONDecodeError as e:
            print(f"  [warn] OSV JSON decode error: {e}", file=sys.stderr)
            return None
    return None


def querybatch_ids(modules: list[str], retries: int = 3) -> list[list[str]]:
    """POST a querybatch request and return a parallel list of vuln-ID lists.

    The querybatch endpoint returns minimal stubs (id + modified only).
    We use it purely to discover which vuln IDs affect each module, then
    hydrate the full records via fetch_vuln_detail().

    OSV querybatch spec:
        POST https://api.osv.dev/v1/querybatch
        body: {"queries": [{"package": {"name": "...", "ecosystem": "Go"}}, ...]}
        response: {"results": [{"vulns": [{"id": "...", "modified": "..."}, ...]}, ...]}
    """
    queries = [
        {"package": {"name": m, "ecosystem": "Go"}} for m in modules
    ]
    payload = json.dumps({"queries": queries}).encode("utf-8")
    data = _post_json(OSV_QUERYBATCH_URL, payload, retries=retries)
    if data is None:
        return [[] for _ in modules]

    results = data.get("results") or []
    out: list[list[str]] = []
    for entry in results:
        if isinstance(entry, dict):
            stubs = entry.get("vulns") or []
            out.append([s["id"] for s in stubs if isinstance(s, dict) and s.get("id")])
        else:
            out.append([])
    # Pad if OSV returns fewer results than queries (shouldn't happen)
    while len(out) < len(modules):
        out.append([])
    return out


def fetch_vuln_detail(vuln_id: str, retries: int = 3) -> dict | None:
    """Fetch full OSV vuln record by ID via GET /v1/vulns/{id}.

    Returns the parsed dict, or None on error.
    """
    from urllib.request import urlopen
    url = f"{OSV_VULN_URL}/{vuln_id}"
    req = Request(
        url,
        headers={"User-Agent": "speca-govulncheck-crawler/1.0"},
    )
    for attempt in range(retries):
        try:
            with urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode("utf-8"))
        except URLError as e:
            wait = 5 * (2 ** attempt)
            print(
                f"  [warn] fetch_vuln_detail({vuln_id}) failed "
                f"(attempt {attempt + 1}): {e} — retrying in {wait}s",
                file=sys.stderr,
            )
            time.sleep(wait)
        except json.JSONDecodeError as e:
            print(f"  [warn] fetch_vuln_detail JSON decode error: {e}", file=sys.stderr)
            return None
    return None


def query_osv_module(module: str, retries: int = 3) -> list[dict]:
    """POST a single /v1/query for one Go module. Returns full vuln records."""
    payload = json.dumps(
        {"package": {"name": module, "ecosystem": "Go"}}
    ).encode("utf-8")
    data = _post_json(OSV_QUERY_URL, payload, retries=retries)
    if data is None:
        return []
    return data.get("vulns") or []


# ---------------------------------------------------------------------------
# Advisory normalisation
# ---------------------------------------------------------------------------

def _extract_severity(vuln: dict) -> str:
    """Derive a unified severity string from an OSV vuln record.

    Priority order:
    1. database_specific.severity  (plain string, e.g. "HIGH")
    2. database_specific.cvss      (same)
    3. severity[].score CVSS vector keyword scan
    Returns "Unrated" when no usable data is found.
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
    """Return the most human-readable advisory ID.

    Preference: CVE > GHSA > GO- (Go advisory DB) > OSV native ID.
    """
    osv_id = vuln.get("id") or ""
    aliases = vuln.get("aliases") or []
    all_ids = [osv_id] + list(aliases)

    for prefix in ("CVE-", "GHSA-", "GO-"):
        for candidate in all_ids:
            if candidate.startswith(prefix):
                return candidate
    return osv_id


def _source_url(issue_id: str) -> str:
    if issue_id.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{issue_id}"
    if issue_id.startswith("GHSA-"):
        return f"https://github.com/advisories/{issue_id}"
    if issue_id.startswith("GO-"):
        return f"https://pkg.go.dev/vuln/{issue_id}"
    return f"https://osv.dev/vulnerability/{issue_id}"


def vuln_to_row(vuln: dict, wallet_slug: str) -> dict | None:
    """Project one OSV vuln record onto the canonical CSV schema.

    Returns None if the record lacks a usable ID or any descriptive text.
    contest is always "govulncheck" to distinguish this source from the
    generic OSV crawl.
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

    return {
        "source": wallet_slug,
        "contest": "govulncheck",
        "issue_id": issue_id,
        "severity": severity,
        "title": summary or issue_id,
        "description": description,
        "source_url": _source_url(issue_id),
        "introduced_in_commit": "",
    }


# ---------------------------------------------------------------------------
# Per-wallet crawl
# ---------------------------------------------------------------------------

def crawl_wallet(wallet_slug: str) -> list[dict]:
    """Query OSV.dev govulncheck for all Go modules of `wallet_slug`.

    Strategy:
    1. Use querybatch to discover vuln IDs for each batch of modules
       (querybatch returns minimal stubs — id + modified only).
    2. For each new vuln ID, fetch the full record via /v1/vulns/{id}.
    3. Dedup by issue_id across all modules (same advisory may affect
       multiple module paths, e.g. prysm v3, v4, v5).

    Returns an empty list for non-Go wallets (modules == None).
    """
    modules = GO_MODULES.get(wallet_slug)
    if modules is None:
        print(
            f"  [{wallet_slug}] not a Go wallet — skipping govulncheck "
            f"(coverage via GHSA / NVD or other crawlers)",
            file=sys.stderr,
        )
        return []

    seen_ids: set[str] = set()
    rows: list[dict] = []

    # Split module list into batches of BATCH_SIZE
    batches = [modules[i:i + BATCH_SIZE] for i in range(0, len(modules), BATCH_SIZE)]

    for batch_idx, batch in enumerate(batches):
        if batch_idx > 0:
            time.sleep(SLEEP_BETWEEN_BATCHES)

        print(
            f"  [{wallet_slug}] querybatch {batch_idx + 1}/{len(batches)}: "
            f"{len(batch)} module(s)",
            file=sys.stderr,
        )
        id_lists = querybatch_ids(batch)

        for module, vuln_ids in zip(batch, id_lists):
            print(
                f"  [{wallet_slug}]   {module}: {len(vuln_ids)} vuln ID(s)",
                file=sys.stderr,
            )
            for vuln_id in vuln_ids:
                if vuln_id in seen_ids:
                    continue
                # Fetch full vuln record to get summary, details, aliases
                detail = fetch_vuln_detail(vuln_id)
                if detail is None:
                    continue
                row = vuln_to_row(detail, wallet_slug)
                if row is None:
                    continue
                canonical_id = row["issue_id"]
                if canonical_id in seen_ids:
                    # The detail resolved to an alias already seen
                    seen_ids.add(vuln_id)
                    continue
                seen_ids.add(vuln_id)
                seen_ids.add(canonical_id)
                rows.append(row)
                # Be polite — sleep between individual detail fetches
                time.sleep(0.2)

    print(
        f"  [{wallet_slug}] govulncheck total: {len(rows)} unique advisory rows",
        file=sys.stderr,
    )
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
    modules: list[str] | None,
) -> None:
    manifest = {
        "wallet": wallet_slug,
        "source": "osv_dev_govulncheck",
        "ecosystem": "Go",
        "modules_queried": modules or [],
        "n_rows": n_rows,
        "crawled_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "osv_endpoint": OSV_QUERYBATCH_URL,
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
        "--out-dir", default="dataset/ethereum_past_fixes/govulncheck",
        help="Output directory for <wallet>.govulncheck.csv + manifest.",
    )
    args = p.parse_args()

    out_dir = Path(args.out_dir)

    if args.wallet == "all":
        wallets = ALL_CLIENTS
    else:
        if args.wallet not in GO_MODULES:
            sys.exit(
                f"unknown --wallet {args.wallet!r}; "
                f"valid: {ALL_CLIENTS} or 'all'"
            )
        wallets = [args.wallet]

    total = 0
    for slug in wallets:
        print(f"[{slug}] crawling OSV.dev govulncheck (Go modules)...", file=sys.stderr)
        rows = crawl_wallet(slug)
        csv_path = out_dir / f"{slug}.govulncheck.csv"
        mf_path = out_dir / f"{slug}.govulncheck_manifest.json"
        n = write_csv(rows, csv_path)
        write_manifest(mf_path, slug, n, GO_MODULES.get(slug))
        print(f"[{slug}] wrote {n} govulncheck rows -> {csv_path}", file=sys.stderr)
        total += n

    print(
        f"done — {total} govulncheck rows across {len(wallets)} wallet(s)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
