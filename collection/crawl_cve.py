#!/usr/bin/env python3
"""Crawl CVE records for the 11 Ethereum wallets from NVD (NIST) API v2.

NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0
Rate limit: 5 req/30s without API key, 50 req/30s with NVID_API_KEY env var.

Output:
    <out-dir>/<wallet>.cve.csv
    <out-dir>/<wallet>.cve_manifest.json

CSV columns (same schema as crawl_wallet_past_fixes.py):
    source, contest, issue_id, severity, title, description, source_url, introduced_in_commit

Usage:
    python3 crawl_cve.py --out-dir /tmp/eth_crawl_out
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError
from urllib.parse import urlencode

CLIENT_KEYWORDS: dict[str, list[str]] = {
    "geth":       ["go-ethereum", "go ethereum", "geth"],
    "nethermind": ["nethermind"],
    "besu":       ["hyperledger besu", "besu"],
    "erigon":     ["erigon"],
    "reth":       ["reth paradigm", "reth ethereum"],
    "lighthouse": ["lighthouse sigma prime", "sigp lighthouse"],
    "lodestar":   ["lodestar chainsafe", "chainsafe lodestar"],
    "nimbus":     ["nimbus-eth2", "nimbus eth2", "status nimbus"],
    "prysm":      ["prysm prysmatic", "prysmatic prysm"],
    "teku":       ["teku consensys", "consensys teku"],
    "grandine":   ["grandine"],
}

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_MAP = {
    "CRITICAL": "High",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "NONE": "Info",
}

CSV_FIELDS = (
    "source", "contest", "issue_id", "severity", "title",
    "description", "source_url", "introduced_in_commit",
)


def nvd_request(params: dict, api_key: str | None = None, retries: int = 4) -> dict | None:
    url = NVD_BASE + "?" + urlencode(params)
    headers = {"User-Agent": "speca-cve-crawler/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    req = Request(url, headers=headers)
    for attempt in range(retries):
        try:
            with urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())
        except URLError as e:
            # 429 Too Many Requests — back off exponentially
            wait = 15 * (2 ** attempt)
            print(f"  [warn] NVD request failed (attempt {attempt+1}): {e} — retrying in {wait}s", file=sys.stderr)
            time.sleep(wait)
        except json.JSONDecodeError as e:
            print(f"  [warn] NVD JSON decode error: {e}", file=sys.stderr)
            return None
    print(f"  [warn] NVD request failed after {retries} retries", file=sys.stderr)
    return None


def fetch_cves_for_keyword(keyword: str, api_key: str | None) -> list[dict]:
    results = []
    start = 0
    page_size = 2000
    while True:
        params = {
            "keywordSearch": keyword,
            "keywordExactMatch": "",
            "startIndex": start,
            "resultsPerPage": page_size,
        }
        data = nvd_request(params, api_key)
        if not data:
            break
        vulns = data.get("vulnerabilities") or []
        results.extend(vulns)
        total = data.get("totalResults", 0)
        start += len(vulns)
        if start >= total or not vulns:
            break
        # NVD rate limit: 5 req/30s without key
        sleep_sec = 0.7 if api_key else 6.5
        time.sleep(sleep_sec)
    return results


def extract_severity(cve_item: dict) -> str:
    metrics = cve_item.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            base = (entries[0].get("cvssData") or {}).get("baseSeverity", "")
            return SEVERITY_MAP.get(base.upper(), "Info")
    return "Info"


def extract_description(cve_item: dict) -> str:
    descs = (cve_item.get("descriptions") or [])
    for d in descs:
        if d.get("lang") == "en":
            return d.get("value", "").strip()
    return ""


# NVD keywordSearch matches the wallet name as a *substring* ("geth" in
# "gethostbyaddr" / "GetHost", "Gether Technology", Linux "usb: g…" gadgets),
# returning unrelated CVEs (glibc, X.Org, Samba). A returned CVE is only kept
# when its description actually names the wallet via a distinctive identifier.
import re as _re

import importlib.util as _ilu
from pathlib import Path as _P
_ISPEC = _ilu.spec_from_file_location("_wallet_ident", _P(__file__).resolve().parent / "wallet_ident.py")
_ident = _ilu.module_from_spec(_ISPEC); _ISPEC.loader.exec_module(_ident)  # type: ignore
CLIENT_IDENT: dict[str, str] = _ident.CVE_IDENT


def _names_wallet(description: str, wallet_slug: str) -> bool:
    # Fails CLOSED for unknown slugs (see wallet_ident.names_wallet): a
    # mislabelled CVE in the authoritative tier costs more than a miss.
    return _ident.names_wallet(description, wallet_slug)


def cve_to_row(vuln: dict, wallet_slug: str) -> dict | None:
    cve_item = vuln.get("cve") or {}
    cve_id = cve_item.get("id", "").strip()
    if not cve_id:
        return None
    description = extract_description(cve_item)
    if not description:
        return None
    # Reject NVD substring-match false positives (see CLIENT_IDENT note above).
    if not _names_wallet(description, wallet_slug):
        return None
    return {
        "source": wallet_slug,
        "contest": "nvd",
        "issue_id": cve_id,
        "severity": extract_severity(cve_item),
        "title": cve_id,
        "description": description,
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "introduced_in_commit": "",
    }


def crawl_client_cves(wallet_slug: str, api_key: str | None) -> list[dict]:
    keywords = CLIENT_KEYWORDS.get(wallet_slug, [wallet_slug])
    seen_ids: set[str] = set()
    rows: list[dict] = []
    for kw in keywords:
        print(f"  [{wallet_slug}] keyword: {kw!r}", file=sys.stderr)
        vulns = fetch_cves_for_keyword(kw, api_key)
        for v in vulns:
            row = cve_to_row(v, wallet_slug)
            if row and row["issue_id"] not in seen_ids:
                seen_ids.add(row["issue_id"])
                rows.append(row)
        time.sleep(2)
    return rows


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


def write_manifest(out_path: Path, wallet_slug: str, n_rows: int) -> None:
    manifest = {
        "wallet": wallet_slug,
        "source": "nvd",
        "n_rows": n_rows,
        "crawled_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "keywords": CLIENT_KEYWORDS.get(wallet_slug, []),
    }
    out_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out-dir", default="/tmp/eth_crawl_out")
    p.add_argument("--wallet", default="all",
                   help="Wallet slug or 'all'")
    args = p.parse_args()

    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        print("[info] Using NVD API key (higher rate limit)", file=sys.stderr)
    else:
        print("[info] No NVD_API_KEY — using anonymous rate limit (6.5s/req)", file=sys.stderr)

    out_dir = Path(args.out_dir)
    wallets = list(CLIENT_KEYWORDS) if args.wallet == "all" else [args.wallet]

    total = 0
    for slug in wallets:
        print(f"[{slug}] crawling CVEs from NVD...", file=sys.stderr)
        rows = crawl_client_cves(slug, api_key)
        csv_path = out_dir / f"{slug}.cve.csv"
        mf_path = out_dir / f"{slug}.cve_manifest.json"
        n = write_csv(rows, csv_path)
        write_manifest(mf_path, slug, n)
        print(f"[{slug}] wrote {n} CVE rows -> {csv_path}", file=sys.stderr)
        total += n

    print(f"done — {total} CVE rows across {len(wallets)} wallet(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
