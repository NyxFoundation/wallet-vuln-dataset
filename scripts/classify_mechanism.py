#!/usr/bin/env python3
"""classify_mechanism.py — what KIND of defect each recovered fix actually is.

`vuln_class` says which part of the custody chain broke (signing, key_material,
transport). It does not say what went wrong there, and that is the question a
corpus of wallet fixes is uniquely able to answer: nobody has characterised the
mechanisms because nobody has had the fixes.

Regex over the classifier's own reasoning covered 22% of rows and is the same
method this project rejected for collection — a mechanism the author phrased
unusually is invisible to it. So the labelling is done by reading, in batches,
against a fixed taxonomy derived from the corpus rather than from a standard.

    uv run python scripts/classify_mechanism.py \
        --in data/keywordless_sweep_wave1.csv \
        --out data/wave1_mechanisms.csv
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

MECHANISMS = [
    "nonce-or-randomness",       # nonce bias/reuse/hardcoded, RNG failure ignored, weak entropy
    "signature-verification-gap",# verification missing, stubbed, short-circuited, result discarded
    "signed-differs-from-shown", # trusted display, tx preview, the user approved something else
    "encoding-canonicalization", # RLP/DER/bech32/typed-data/punycode/normalisation
    "input-bounds-parsing",      # length, bounds, malformed input, OOB, integer overflow
    "curve-point-validation",    # on-curve, low-order, subgroup, malleability, r/s bounds
    "key-lifetime-in-memory",    # key/seed left in memory, logged, swapped, not zeroed
    "key-derivation-storage",    # derivation path, KDF params, at-rest encryption, backup
    "authorization-check",       # handler/endpoint/plugin reachable without the right caller
    "origin-session-auth",       # dapp origin, pairing, session binding, permission scope
    "side-channel-fault",        # timing, power, fault injection, constant-time
    "replay-scope",              # cross-chain, cross-domain, cross-session reuse of a signature
    "uri-deeplink-handling",     # deeplink, QR, custom scheme, in-app browser target
    "state-race-concurrency",    # request mutated after review, TOCTOU, races
    "dependency-supply-chain",   # vulnerable dep, build/release integrity
    "other",
]

PROMPT = """You label crypto-wallet security fixes by MECHANISM — what technically went
wrong — using only this list:

""" + "\n".join(f"- {m}" for m in MECHANISMS) + """

Rules:
- Pick the single mechanism that best describes the DEFECT, not the component.
- "signed-differs-from-shown" is for cases where signing/verification worked but the
  user was shown something other than what was authorised.
- "signature-verification-gap" is for verification that was absent, stubbed, or whose
  result was ignored.
- If the text does not describe a specific mechanism, answer "other".
- Output ONLY a JSON array of {"i": <index>, "m": "<mechanism>"} for all records, in
  order. No prose, no fences.

Records:
"""

ENDPOINT = "https://ollama.com/v1/chat/completions"


def call(prompt: str, model: str, key: str, timeout: float = 300) -> str:
    body = json.dumps({"model": model, "temperature": 0,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request(ENDPOINT, data=body, headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {key}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())["choices"][0]["message"]["content"]


def parse(text: str, n: int) -> list[str]:
    out = ["other"] * n
    a, b = text.find("["), text.rfind("]")
    if a < 0 or b <= a:
        return out
    try:
        arr = json.loads(text[a:b + 1])
    except json.JSONDecodeError:
        return out
    for pos, o in enumerate(arr if isinstance(arr, list) else []):
        if not isinstance(o, dict):
            continue
        try:
            i = int(o.get("i", pos))
        except (TypeError, ValueError):
            i = pos
        if 0 <= i < n and o.get("m") in MECHANISMS:
            out[i] = o["m"]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="data/keywordless_sweep_wave1.csv")
    ap.add_argument("--text-cols", default="reason",
                    help="comma-separated columns to read the defect from. Advisory rows "
                         "carry title+description instead of a classifier reason, and both "
                         "sides must be labelled by the same taxonomy for the comparison "
                         "between what gets disclosed and what gets fixed silently to mean "
                         "anything.")
    ap.add_argument("--out", default="data/wave1_mechanisms.csv")
    ap.add_argument("--cache", default="scratchpad_crawl/mechanism_cache.json", type=Path)
    ap.add_argument("--model", default="glm-5.2")
    ap.add_argument("--batch", type=int, default=12)
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()

    key = os.environ.get("OLLAMA_API_KEY", "")
    if not key:
        return print("FATAL: $OLLAMA_API_KEY not set", file=sys.stderr) or 1
    if not os.environ.get("SSL_CERT_FILE"):
        os.environ["SSL_CERT_FILE"] = "/etc/ssl/certs/ca-certificates.crt"

    df = pd.read_parquet(a.inp) if str(a.inp).endswith(".parquet") else pd.read_csv(a.inp)
    tcols = [c for c in a.text_cols.split(",") if c in df.columns]
    if not tcols:
        return print(f"FATAL: none of {a.text_cols} in {a.inp}", file=sys.stderr) or 1
    df["_text"] = df[tcols].fillna("").agg(" ".join, axis=1).str.strip()
    if "vuln_class" not in df.columns:
        df["vuln_class"] = ""
    cache = json.loads(a.cache.read_text()) if a.cache.exists() else {}
    todo = [i for i, u in enumerate(df.source_url) if u not in cache]
    print(f"{len(df)} rows, {len(df) - len(todo)} cached, {len(todo)} to label", file=sys.stderr)

    chunks = [todo[i:i + a.batch] for i in range(0, len(todo), a.batch)]

    def work(idxs):
        recs = "\n".join(
            f'{k}. class={df.vuln_class.iloc[i]} | {df._text.iloc[i][:420]}'
            for k, i in enumerate(idxs))
        try:
            return idxs, parse(call(PROMPT + recs, a.model, key), len(idxs))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            print(f"  batch failed: {type(e).__name__}", file=sys.stderr)
            return idxs, None

    done = 0
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        for idxs, labs in ex.map(work, chunks):
            if labs is not None:                    # a failure stays uncached, so a
                for i, lab in zip(idxs, labs):      # re-run retries it
                    cache[df.source_url.iloc[i]] = lab
            done += 1
            if done % 20 == 0:
                a.cache.parent.mkdir(parents=True, exist_ok=True)
                a.cache.write_text(json.dumps(cache))
                print(f"  {done}/{len(chunks)} batches ({len(cache)} labelled)", file=sys.stderr)
    a.cache.parent.mkdir(parents=True, exist_ok=True)
    a.cache.write_text(json.dumps(cache))

    df["mechanism"] = df.source_url.map(cache).fillna("other")
    df.to_csv(a.out, index=False)
    print(f"wrote {a.out}")
    print(df.mechanism.value_counts().to_string())
    return 0


if __name__ == "__main__":
    sys.exit(main())
