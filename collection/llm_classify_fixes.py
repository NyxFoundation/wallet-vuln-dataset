#!/usr/bin/env python3
"""llm_classify_fixes.py — training-free LLM silent-fix classifier (PoC).

Implements the LLM4VFD recipe (Code Change Intention + Development Artifacts +
light structural context) with a Chain-of-Thought prompt driven by `claude -p`
— no fine-tuning, no torch. This is the research-backed replacement for the
TF-IDF classifier that failed deployment validation.

  paper anchors:
    LLM4VFD (arXiv 2501.14983): CoT over diff + issue/PR artifacts + history-RAG,
      prompting-only, +68–145% F1 over PLM baselines.
    From LLMs to Agents (arXiv 2511.08060): zero-shot LLM/agents reach graph-level
      precision; LLM×graph is unexplored. We add "graph-lite" context (the
      security-sensitive subsystem touched) as a cheap structural signal.

Evaluation discipline (learned the hard way): report precision/recall/F1 AND the
applied ranking (highest/lowest confidence) — a good CV metric that ranks
features above real fixes is worthless.

Modes:
  --build-eval   sample a fixed, labelled eval set -> llm_eval_set.json
  --run          classify the eval set with claude -p, write predictions+metrics
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

# --- LLM engine (set from CLI in main) -------------------------------------
# Backends: Anthropic `claude -p` (default); a native local Ollama model; or any
# OpenAI-compatible /v1/chat/completions endpoint (Ollama Cloud, vLLM, LM Studio,
# local ollama's /v1). The last keeps the heavy classification phase off Claude.
ENGINE = {"engine": "claude", "model": "", "host": "http://localhost:11434",
          "base_url": "", "api_key": ""}

# urllib ignores the system CA store in this env -> HTTPS calls fail with
# CERTIFICATE_VERIFY_FAILED. Point it at the system bundle if not already set.
if not os.environ.get("SSL_CERT_FILE"):
    for _ca in ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"):
        if os.path.exists(_ca):
            os.environ["SSL_CERT_FILE"] = _ca
            break


def _call_llm(prompt: str) -> str:
    """Return the raw model text for a prompt via the configured engine."""
    eng = ENGINE["engine"]
    if eng == "openai":  # OpenAI-compatible /v1/chat/completions
        body = json.dumps({
            "model": ENGINE["model"], "temperature": 0,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()
        headers = {"Content-Type": "application/json"}
        if ENGINE["api_key"]:
            headers["Authorization"] = f"Bearer {ENGINE['api_key']}"
        req = urllib.request.Request(ENGINE["base_url"].rstrip("/") + "/chat/completions",
                                     data=body, headers=headers)
        with urllib.request.urlopen(req, timeout=300) as r:
            return json.loads(r.read())["choices"][0]["message"]["content"]
    if eng == "ollama":  # native local Ollama
        body = json.dumps({
            "model": ENGINE["model"] or "qwen2.5-coder:7b",
            "prompt": prompt, "stream": False, "format": "json",
            "options": {"temperature": 0},
        }).encode()
        req = urllib.request.Request(f"{ENGINE['host']}/api/generate", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=300) as r:
            return json.loads(r.read()).get("response", "")
    # default: claude CLI
    cmd = ["claude", "-p"] + (["--model", ENGINE["model"]] if ENGINE["model"] else []) + [prompt]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                       encoding="utf-8", errors="replace")
    return r.stdout.strip()

DEPBUMP_RE = re.compile(r"\bbump\b|chore\(deps|dependabot|renovate", re.I)
NONFIX_TITLE_RE = re.compile(
    r"\b(?:feat|feature|refactor|perf|rename|cleanup|clean up|implement"
    r"|add support|introduce|improve|optimi[sz]e|simplify|migrate|style|move)\b", re.I)
ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}|GHSA-", re.I)
SRC_EXT_RE = re.compile(r"\.(go|rs|java|nim|ts|js|py|c|cpp|h|sol)\b")
SENSITIVE_RE = re.compile(
    r"fork.?choice|state.?transition|epoch|consensus|finality|reorg|slashing"
    r"|attestation|sync.?committee|blob|kzg|bls|discv5|gossip|p2p|rlpx|evm"
    r"|opcode|precompile|trie|tx.?pool|mempool|signature|merkle|ssz|rlp|secp256",
    re.I)
PR_RE = re.compile(r"/pull/(\d+)")
SHA_RE = re.compile(r"/commit/([0-9a-f]{7,40})", re.I)


def _diff_doc(diff: str, cap: int = 6000) -> str:
    keep = []
    for ln in diff.splitlines():
        if ln.startswith(("diff --git", "@@")) or (ln[:1] in "+-" and not ln.startswith(("+++", "---"))):
            keep.append(ln)
    return "\n".join(keep)[:cap]


# Clean ground truth from the TITLE (unambiguous), not from leaky severity/id
# signals. Positive = title explicitly states a vuln-class fix; negative =
# title is clearly a feature/refactor with no vuln language. The LLM is scored
# on whether it can reach the same verdict from the diff + artifacts.
FIXVULN_TITLE_RE = re.compile(
    r"\b(?:fix|fixes|fixed|prevent|guard|avoid|patch|resolve)\w*\b[^.\n]{0,45}"
    r"\b(?:crash|panic|segfault|deadlock|hang|oom|out.of.memory|overflow"
    r"|underflow|use.after.free|nil (?:pointer|deref)|null (?:pointer|deref)"
    r"|data race|race condition|reorg|consensus|invalid block|dos"
    r"|denial.of.service|memory leak|infinite loop|out.of.bounds)\b", re.I)


# Exclude label-noise from positives: vendored-dep updates, reverts, and
# test-only "fix test panic" changes are not clean wallet-code vuln fixes even
# when the title says "fix … crash".
# Not clean wallet-vuln positives even when titled "fix … crash": vendored deps,
# reverts, and changes confined to tests / offline CLI / diagnostic tooling
# (not reachable by untrusted network input — the LLM's own FN reasons flagged
# these, and it was right).
POS_EXCLUDE_RE = re.compile(
    r"^\s*(?:vendor|revert|ci)\b|vendored|third.party|\btest(?:s|ing)?\b|\bsim\b"
    r"|simulator|evmtool|\binspect\b|pprof|\bflak", re.I)


def build_eval(cur, raw, cache, per_class, seed):
    ptitle = cur["title"].fillna("")
    pos = cur[ptitle.str.contains(FIXVULN_TITLE_RE)
              & cur["source_url"].str.contains(r"/pull/|/commit/", na=False)
              & ~ptitle.str.contains(DEPBUMP_RE)
              & ~ptitle.str.contains(POS_EXCLUDE_RE)]
    rtitle = raw["title"].fillna("")
    neg = raw[rtitle.str.contains(NONFIX_TITLE_RE)
              & ~rtitle.str.contains(FIXVULN_TITLE_RE)
              & ~rtitle.str.contains(DEPBUMP_RE)
              & raw["source_url"].str.contains(r"/pull/|/commit/", na=False)
              & ~(raw["title"].fillna("") + " " + raw["description"].fillna("")).str.contains(ID_RE)]

    def take(df, label, n):
        out = []
        df = df.sample(frac=1.0, random_state=seed)
        for _, r in df.iterrows():
            diff = cache.get(str(r["source_url"]))
            if not diff or not SRC_EXT_RE.search(diff):
                continue
            out.append({
                "url": str(r["source_url"]), "label": label,
                "platform": r["source_platform"], "title": str(r["title"])[:200],
                "desc": str(r["description"])[:600], "diff": _diff_doc(diff),
            })
            if len(out) >= n:
                break
        return out

    items = take(pos, 1, per_class) + take(neg, 0, per_class)
    return items


PROMPT_VERSION = "v2"


def build_prompt(it: dict) -> str:
    sens = sorted(set(m.group(0).lower() for m in SENSITIVE_RE.finditer(
        it["title"] + " " + it["desc"] + " " + it["diff"])))
    graph_ctx = (f"Security-sensitive subsystems touched: {', '.join(sens[:6])}"
                 if sens else "No obviously security-sensitive subsystem in the paths.")
    return f"""You are a security engineer triaging a code change in an Ethereum wallet.
Decide whether it is a SECURITY / vulnerability fix versus an ORDINARY change
(feature, refactor, performance, test, docs, style, dependency bump).

A SECURITY fix repairs an exploitable or availability-affecting defect, e.g.:
crash / panic / segfault, DoS / OOM / unbounded resource use, memory-safety
(use-after-free, OOB), integer overflow/underflow, auth / validation bypass — OR,
CRUCIALLY for a blockchain wallet, a CONSENSUS-class defect: fork-choice /
finality / reorg / state-transition / invalid-block-acceptance / non-determinism.
Treat a consensus-class fix as security-relevant EVEN IF no external attacker is
named — the pre-fix code can split the chain or accept invalid blocks. Nodes
process untrusted network input (blocks, txs, attestations, p2p messages, peers),
so weigh the WORST-CASE trigger, not the common case.

NOT security: adding a feature/flag/metric, renaming, refactoring, perf tuning,
test-only or CI/docs changes, or bumping a third-party/vendored dependency (even
if that dep fixed a crash) — the wallet's own code has no defect there.

Reason step by step (Chain-of-Thought):
1. What does the diff actually change (wallet source, or test/vendor/config)?
2. Does it ADD a guard/validation/bounds/nil/overflow check or error handling,
   or REMOVE an exploitable condition (panic/unwrap/unchecked path)?
3. Is the touched subsystem security- or consensus-relevant?
4. Could malformed/untrusted input or a peer trigger the pre-fix path (worst case)?

Calibrate: confidence >0.7 only when the diff concretely shows a defect being
repaired; <0.4 when it is a feature/refactor/vendor/test change.

Output ONLY a single JSON object on the last line, no prose after it:
{{"is_security_fix": true|false, "confidence": 0.0-1.0, "vuln_class": "<dos|memory|overflow|consensus|auth|validation|other|none>", "reason": "<one sentence>"}}

## Development artifacts
title: {it['title']}
description: {it['desc']}

## Structural context (graph-lite)
{graph_ctx}

## Code change (unified diff, truncated)
{it['diff']}
"""


def classify(it: dict) -> dict:
    prompt = build_prompt(it)
    try:
        out = _call_llm(prompt)
        m = re.search(r"\{[^{}]*\"is_security_fix\"[^{}]*\}", out, re.S)
        obj = json.loads(m.group(0)) if m else {}
    except Exception as e:
        obj = {"error": str(e)}
    return {**it, "pred": obj}


def evaluate(preds):
    tp = fp = tn = fn = 0
    scored = []
    for p in preds:
        pr = p.get("pred", {})
        yhat = 1 if pr.get("is_security_fix") else 0
        conf = float(pr.get("confidence") or 0)
        y = p["label"]
        scored.append((conf if yhat else 1 - conf, y, yhat, p["title"], pr.get("vuln_class")))
        if yhat and y: tp += 1
        elif yhat and not y: fp += 1
        elif not yhat and not y: tn += 1
        else: fn += 1
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    print(f"\n===== LLM classifier {PROMPT_VERSION} (n={len(preds)}) =====")
    print(f"  TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"  precision={prec:.3f} recall={rec:.3f} F1={f1:.3f} acc={(tp+tn)/len(preds):.3f}")
    scored.sort(key=lambda x: -x[0])
    print("\n  -- most-confident SECURITY-FIX predictions (should be real fixes) --")
    for s, y, yh, t, vc in [x for x in scored if x[2] == 1][:8]:
        print(f"    conf={s:.2f} label={'POS' if y else 'NEG'} [{vc}] {t[:52]}")
    print("  -- most-confident ORDINARY predictions (should be non-fixes) --")
    for s, y, yh, t, vc in [x for x in scored if x[2] == 0][:8]:
        print(f"    conf={s:.2f} label={'POS' if y else 'NEG'} {t[:52]}")
    return {"precision": prec, "recall": rec, "f1": f1, "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def apply_to_dataset(a) -> int:
    """Classify real dataset rows and emit source_url -> silent_fix_prob.

    Diffs come from local_diffs (bare clone + persistent cache, rate-limit-free);
    LLM predictions are cached per URL so re-runs are resumable ("差分だけ").
    """
    import csv
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import local_diffs

    df = pd.read_parquet(a.inp)
    if a.tier != "all" and "authority_tier" in df.columns:
        df = df[df["authority_tier"] == a.tier]
    df = df[df["source_url"].str.contains(r"/pull/|/commit/", na=False)].copy()
    if a.limit:
        df = df.head(a.limit)
    diff_cache = json.loads(a.cache.read_text()) if a.cache.exists() else {}
    pred_cache = json.loads(a.pred_cache.read_text()) if a.pred_cache.exists() else {}
    rows = df.to_dict("records")
    print(f"[apply] {len(rows)} rows (tier={a.tier}); "
          f"{sum(1 for r in rows if str(r['source_url']) in pred_cache)} already predicted",
          file=sys.stderr)

    def work(r):
        url = str(r["source_url"])
        if url in pred_cache:
            return url, pred_cache[url]
        diff = local_diffs.get_diff_cached(url, r["source_platform"], diff_cache)
        if not diff:
            return url, {"skip": "nodiff"}
        it = {"title": str(r.get("title") or "")[:200],
              "desc": str(r.get("description") or "")[:600], "diff": _diff_doc(diff)}
        return url, classify(it)["pred"]

    done = 0
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        for url, pred in ex.map(work, rows):
            pred_cache[url] = pred
            done += 1
            if done % 40 == 0:
                a.pred_cache.write_text(json.dumps(pred_cache))
                a.cache.write_text(json.dumps(diff_cache))
                print(f"  [apply] {done}/{len(rows)}", file=sys.stderr)
    a.pred_cache.write_text(json.dumps(pred_cache))
    a.cache.write_text(json.dumps(diff_cache))

    a.apply_out.parent.mkdir(parents=True, exist_ok=True)
    n_fix = 0
    with a.apply_out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["source_url", "silent_fix_prob", "is_security_fix", "vuln_class", "reason"])
        for r in rows:
            url = str(r["source_url"]); pr = pred_cache.get(url, {})
            if not isinstance(pr, dict) or "is_security_fix" not in pr:
                continue
            isfix = bool(pr.get("is_security_fix"))
            conf = float(pr.get("confidence") or 0)
            prob = conf if isfix else 1 - conf          # p(security fix)
            if prob >= 0.70:
                n_fix += 1
            w.writerow([url, f"{prob:.3f}", int(isfix), pr.get("vuln_class", ""),
                        str(pr.get("reason", ""))[:200]])
    print(f"[apply] wrote {a.apply_out} — {n_fix} rows with silent_fix_prob>=0.70", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-eval", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--apply", action="store_true", help="classify dataset rows -> silent_fix csv")
    ap.add_argument("--tier", default="C_candidate", help="authority_tier to classify (or 'all')")
    ap.add_argument("--apply-out", default=Path("scratchpad_crawl/supp/llm_silent_fix.csv"), type=Path)
    ap.add_argument("--pred-cache", default=Path("scratchpad_crawl/llm_pred_cache.json"), type=Path)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--eval-set", default=Path("scratchpad_crawl/llm_eval_set.json"), type=Path)
    ap.add_argument("--out", default=Path("scratchpad_crawl/llm_preds.json"), type=Path)
    ap.add_argument("--in", dest="inp", default=Path("data/wallet_vulns.parquet"), type=Path)
    ap.add_argument("--raw", default=Path("data/raw/train.classified.parquet"), type=Path)
    ap.add_argument("--cache", default=Path("scratchpad_crawl/diff_cache.json"), type=Path)
    ap.add_argument("--per-class", type=int, default=25)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--engine", choices=["claude", "ollama", "openai"], default="claude",
                    help="LLM backend for classification")
    ap.add_argument("--model", default="",
                    help="model id; empty picks the engine default (openai -> devstral-2:123b)")
    ap.add_argument("--ollama-host", default="http://localhost:11434")
    ap.add_argument("--base-url", default="", help="OpenAI-compatible base url (openai engine)")
    ap.add_argument("--api-key-env", default="", help="env var holding the API key (openai engine)")
    a = ap.parse_args()
    # Best default for the openai/Ollama-Cloud engine, chosen by an 80-item eval
    # sweep (see docs/model_evaluation.md): gemma4:31b — F1 0.872, precision 0.895
    # (near claude's 0.93) AND recall 0.85, two clean runs identical, 0 errors.
    # --model qwen3-coder:480b for a precision-leaning variant; multi-agent
    # consensus did NOT beat this single model (correlated errors).
    model = a.model or ("gemma4:31b" if a.engine == "openai" else "")
    ENGINE.update(engine=a.engine, model=model, host=a.ollama_host,
                  base_url=a.base_url, api_key=os.environ.get(a.api_key_env, "") if a.api_key_env else "")
    if a.engine == "ollama" and a.workers > 2:
        a.workers = 2  # a single local model serializes; avoid thrashing

    if a.apply:
        return apply_to_dataset(a)

    if a.build_eval:
        cache = json.loads(a.cache.read_text())
        items = build_eval(pd.read_parquet(a.inp), pd.read_parquet(a.raw), cache, a.per_class, a.seed)
        a.eval_set.write_text(json.dumps(items, indent=1))
        print(f"wrote {len(items)} eval items ({sum(i['label'] for i in items)} pos) -> {a.eval_set}")
        return 0

    if a.run:
        items = json.loads(a.eval_set.read_text())
        print(f"classifying {len(items)} items with claude -p ({a.workers} workers)…", file=sys.stderr)
        with ThreadPoolExecutor(max_workers=a.workers) as ex:
            preds = list(ex.map(classify, items))
        a.out.write_text(json.dumps(preds, indent=1))
        evaluate(preds)
        n_err = sum(1 for p in preds if "error" in p.get("pred", {}))
        if n_err:
            print(f"  ({n_err} classification errors)", file=sys.stderr)
        return 0

    ap.error("pass --build-eval or --run")


if __name__ == "__main__":
    raise SystemExit(main())
