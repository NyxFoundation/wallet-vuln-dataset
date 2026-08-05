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
import threading
import time
import urllib.error
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


# A hosted endpoint answers 429 when the caller is over its quota. That is not a
# verdict about the row — it is "ask again later" — and treating it as a failed
# row torched 7,641 rows of a 62,882-row pass before anyone noticed. This is the
# lesson gh_rate.py already encodes for GitHub ("403 is ambiguous; wait on the
# rate limit, abort on real auth failure"), which never reached the LLM path.
#
# The wait is process-global: when the quota is exhausted, every worker is over
# it, so backing off one thread while fifteen others keep hammering just refreshes
# the limit. The first thread to see a 429 parks the whole pool.
_RATE_GATE = threading.Event()
_RATE_GATE.set()                      # set == clear to send
_RATE_LOCK = threading.Lock()
RATE_MAX_TRIES = 6
RATE_BASE_SLEEP = 20.0                # doubled per attempt, capped
RATE_MAX_SLEEP = 600.0


def _rate_backoff(attempt: int, retry_after: str | None) -> None:
    """Park every worker for one backoff interval, then release them together."""
    delay = min(RATE_BASE_SLEEP * (2 ** attempt), RATE_MAX_SLEEP)
    if retry_after:
        try:
            delay = max(delay, min(float(retry_after), RATE_MAX_SLEEP))
        except ValueError:
            pass
    with _RATE_LOCK:
        if not _RATE_GATE.is_set():
            return                     # another thread is already serving the wait
        _RATE_GATE.clear()
    try:
        print(f"  [rate] over quota — pausing all workers {delay:.0f}s", file=sys.stderr)
        time.sleep(delay)
    finally:
        _RATE_GATE.set()


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
        last: Exception | None = None
        for attempt in range(RATE_MAX_TRIES):
            _RATE_GATE.wait()
            req = urllib.request.Request(
                ENGINE["base_url"].rstrip("/") + "/chat/completions",
                data=body, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=300) as r:
                    return json.loads(r.read())["choices"][0]["message"]["content"]
            except urllib.error.HTTPError as e:
                last = e
                # 429 = over quota, 5xx = the server's problem. Both are worth
                # retrying; 401/403/404 are answers and must not be retried.
                if e.code != 429 and e.code < 500:
                    raise
                _rate_backoff(attempt, e.headers.get("Retry-After") if e.headers else None)
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                last = e
                _rate_backoff(attempt, None)
        raise last if last else RuntimeError("exhausted retries")
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

DIFF_FLUSH_SECONDS = 600  # the diff cache is an optimisation, not the result

DEPBUMP_RE = re.compile(r"\bbump\b|chore\(deps|dependabot|renovate", re.I)
NONFIX_TITLE_RE = re.compile(
    r"\b(?:feat|feature|refactor|perf|rename|cleanup|clean up|implement"
    r"|add support|introduce|improve|optimi[sz]e|simplify|migrate|style|move)\b", re.I)
ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}|GHSA-", re.I)
SRC_EXT_RE = re.compile(r"\.(go|rs|java|nim|ts|js|py|c|cpp|h|sol)\b")
import importlib.util as _ilu4
from pathlib import Path as _P4
_VS = _ilu4.spec_from_file_location("_wallet_vocab", _P4(__file__).resolve().parent / "wallet_vocab.py")
_vocab = _ilu4.module_from_spec(_VS); _VS.loader.exec_module(_vocab)  # type: ignore
SENSITIVE_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(p) for p in _vocab.SENSITIVE_PATHS) + r")\b", re.I)
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


PROMPT_VERSION = "wallet-v1"


def build_prompt(it: dict) -> str:
    sens = sorted(set(m.group(0).lower() for m in SENSITIVE_RE.finditer(
        it["title"] + " " + it["desc"] + " " + it["diff"])))
    graph_ctx = (f"Security-sensitive subsystems touched: {', '.join(sens[:6])}"
                 if sens else "No obviously security-sensitive subsystem in the paths.")
    return f"""You are a security engineer triaging a code change in crypto
wallet software. Decide whether it is a SECURITY / vulnerability fix versus an
ORDINARY change (feature, refactor, performance, test, docs, style, dep bump).

The threat model is CUSTODY, not protocol. A SECURITY fix here is one that stops
a user losing FUNDS, KEY MATERIAL, or SIGNING AUTHORITY. Concretely:

- key material: seed/mnemonic/private key leaked, logged, left in memory, weakly
  generated (bad entropy/RNG), wrongly derived (BIP-32/39/44, SLIP-0010), or
  stored unprotected (keystore/keychain/vault/secure element)
- signing: a signature valid over something the user never saw or approved —
  missing EIP-712 domain/chainId, replay across chains, nonce/k reuse, signature
  malleability, blind signing, sighash or PSBT errors, verification that accepts
  an invalid signature
- approval: spend authority obtained WITHOUT any key compromise — unlimited
  approvals, permit/permit2 abuse, delegation or session-key scope errors
- transport: the dapp<->wallet channel admitting an unauthorized caller —
  missing origin checks, postMessage/CORS flaws, WalletConnect pairing or
  session hijack, deeplink/QR handling, exposed RPC methods, WebView bridges
- ui deception: the user approved the wrong thing because the UI lied —
  address spoofing/homoglyphs, clipboard hijack, wrong amount or recipient,
  broken transaction preview, phishing-list failures
- platform: an OS/browser escape reaching the key store — XSS, prototype
  pollution, CSP bypass, path traversal, insecure deserialization, backup or
  screenshot exposure, lock/biometric bypass
- smart accounts: reentrancy, uninitialized proxy, upgrade/module/guard bypass,
  ERC-1271 or ERC-4337 validation flaws
- MPC/seedless: share leakage, biased nonce, DKG/resharing flaws, or anything
  letting an attacker assemble a quorum of shares
- passkey/WebAuthn: mis-parsed clientDataJSON, unchecked user-presence or
  user-verification flags, missing origin/rpId binding, P-256 verification bugs
  — note these are SIGNING BYPASSES WITH NO KEY LEAK AT ALL
- firmware: bootloader/secure-boot verification, PIN/passphrase handling,
  trusted-display bypass, fault-injection and side-channel hardening
- supply chain: malicious dependency, compromised build or update channel

Weigh the WORST-CASE trigger, not the common case: a wallet processes untrusted
input from web pages, QR codes, deeplinks, hostile RPC nodes, malicious tokens
and contracts, and sometimes an attacker holding the device.

IMPORTANT — do not over-fire. A crash or panic in wallet UI code is usually just
a crash; it is a security fix only when it is reachable from untrusted input OR
touches key/signing paths. NOT security: adding a feature/flag/metric, renaming,
refactoring, perf tuning, test-only or CI/docs changes, or bumping a third-party
dependency (even if that dep fixed a CVE) — the wallet's own code has no defect
there.

Reason step by step (Chain-of-Thought):
1. What does the diff actually change (wallet source, or test/vendor/config)?
2. Does it ADD a guard/validation/bounds/origin/signature check, or REMOVE an
   exploitable condition?
3. Is the touched subsystem custody-relevant (keys, signing, approvals,
   transport, firmware, contract validation)?
4. Could a malicious dapp, signing request, deeplink/QR, hostile RPC, malicious
   local app, or physical device access trigger the pre-fix path (worst case)?
5. If funds/keys/signing authority are NOT reachable, say so and answer false.

`confidence` is NOT your confidence in your own answer. It is
**p(this change is a security fix)** on a 0.0-1.0 scale, and it must agree with
`is_security_fix` (>0.5 means true, <0.5 means false). Calibrate: >0.7 only when
the diff concretely shows a defect being repaired; <0.4 when it is a
feature/refactor/vendor/test change; ~0.5 when genuinely unsure.

Output ONLY a single JSON object on the last line, no prose after it:
{{"is_security_fix": true|false, "confidence": 0.0-1.0, "vuln_class": "<key_material|signing|approval|transport|ui_deception|platform|contract|mpc|firmware|supply_chain|dos|memory|other|none>", "reason": "<one sentence>"}}

## Development artifacts
title: {it['title']}
description: {it['desc']}

## Structural context (graph-lite)
{graph_ctx}

## Code change (unified diff, truncated)
{it['diff']}
"""


def _extract_json_object(text: str) -> dict:
    """Pull the JSON object carrying `is_security_fix` out of a model response.

    The old pattern was r'\\{[^{}]*"is_security_fix"[^{}]*\\}', and [^{}]* cannot
    span a NESTED object. A model that answers with any nested field — or wraps
    the object in a fenced block with an example — produced no match, and the
    caller stored the empty dict as the row's answer. On a 4,000-row Opus run
    that silently discarded 3,328 of them (83%); the rate looked like a finding
    about wallets, and was a finding about a regex.
    """
    for i, ch in enumerate(text):
        if ch != "{":
            continue
        depth = 0
        for j in range(i, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[i:j + 1])
                    except json.JSONDecodeError:
                        break
                    if isinstance(obj, dict) and "is_security_fix" in obj:
                        return obj
                    break
    return {}


def classify(it: dict) -> dict:
    prompt = build_prompt(it)
    try:
        out = _call_llm(prompt)
        obj = _extract_json_object(out)
        if obj:
            # Provenance belongs to the PREDICTION, not to whichever run happens
            # to write the csv later. Reading it off the live ENGINE stamped
            # 23,777 glm-5.2 answers as "claude-cli-default" when a quota-
            # interrupted pass was exported with --csv-only.
            obj["_model"] = ENGINE["model"] or (
                "claude-cli-default" if ENGINE["engine"] == "claude" else "unknown")
        if not obj:
            # An unparseable answer is a FAILED call, not a negative verdict.
            # Marking it lets the caller refuse to cache it, so a re-run retries.
            obj = {"parse_error": (out or "")[:200]}
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
        # One unresolvable row must not kill the batch. The corpus contains rows
        # sourced from the standards repos (bips/slips/eips) — legitimate search
        # targets but not wallets, so they have no local clone. Seven such rows
        # aborted a 25,472-row run at 9,840 with KeyError.
        try:
            diff = local_diffs.get_diff_cached(url, r["source_platform"], diff_cache)
        except KeyError:
            return url, {"skip": "noclone"}
        except Exception as exc:
            print(f"  [apply] diff failed for {url}: {exc}", file=sys.stderr)
            return url, {"skip": "differror"}
        if not diff:
            return url, {"skip": "nodiff"}
        it = {"title": str(r.get("title") or "")[:200],
              "desc": str(r.get("description") or "")[:600], "diff": _diff_doc(diff)}
        return url, classify(it)["pred"]

    done = n_bad = 0
    last_diff_flush = time.monotonic()
    if getattr(a, "csv_only", False):
        print(f"[apply] --csv-only: writing from {len(pred_cache)} cached predictions, "
              f"no model calls", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=1 if getattr(a, "csv_only", False) else a.workers) as ex:
        for url, pred in ex.map(work, [] if getattr(a, 'csv_only', False) else rows):
            # Cache answers and permanent skips; never cache a call that failed
            # or came back unparseable, or the next run treats it as settled.
            if isinstance(pred, dict) and ("parse_error" in pred or "error" in pred):
                n_bad += 1
                # Not caching a failure is only half the job: a run can fail
                # every single call and still print an advancing row counter.
                # 34,000 consecutive failures went unremarked exactly this way.
                if n_bad <= 5 or n_bad % 200 == 0:
                    why = pred.get("error") or f"unparseable: {pred.get('parse_error')}"
                    print(f"  [apply] FAILED ({n_bad} so far): {str(why)[:160]}",
                          file=sys.stderr)
            else:
                pred_cache[url] = pred
            done += 1
            if done % 40 == 0:
                # pred_cache is the work product (megabytes) — checkpoint it often.
                # diff_cache is only an optimisation and reaches ~700MB, so
                # re-serialising it every 40 rows costs more than every diff it
                # saves: throughput collapsed from 379 rows/min to 7. This is the
                # same defect c56f6a0 fixed in enrich_labels ("it reached 23 GB
                # and was the real cause of the stage-10 death") — that fix
                # landed in the sibling script only. Time-based here, because
                # within one pass each URL is fetched once and the cache only
                # pays off across runs.
                a.pred_cache.write_text(json.dumps(pred_cache))
                now = time.monotonic()
                if now - last_diff_flush >= DIFF_FLUSH_SECONDS:
                    a.cache.write_text(json.dumps(diff_cache))
                    last_diff_flush = now
                print(f"  [apply] {done}/{len(rows)} "
                      f"({len(pred_cache)} cached, {n_bad} failed)", file=sys.stderr)
    a.pred_cache.write_text(json.dumps(pred_cache))
    a.cache.write_text(json.dumps(diff_cache))

    a.apply_out.parent.mkdir(parents=True, exist_ok=True)
    n_fix = 0
    with a.apply_out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        # `model` is not decoration. Measured on the same 4,000 gate-dropped rows,
        # Opus and glm-5.2 agree on is_security_fix 96% of the time, but every
        # disagreement runs one way: glm flags rows Opus does not, never the
        # reverse, and at the 0.70 admission threshold it admits 4.5x as many.
        # silent_fix_prob is therefore NOT comparable across models — a corpus
        # built from a mix of them has a gate whose strictness varies by row.
        w.writerow(["source_url", "silent_fix_prob", "is_security_fix", "vuln_class",
                    "model", "prompt_version", "reason"])
        fallback_model = ENGINE["model"] or ("claude-cli-default"
                                            if ENGINE["engine"] == "claude" else "unknown")
        for r in rows:
            url = str(r["source_url"]); pr = pred_cache.get(url, {})
            if not isinstance(pr, dict) or "is_security_fix" not in pr:
                continue
            isfix = bool(pr.get("is_security_fix"))
            conf = float(pr.get("confidence") or 0)
            # `confidence` IS p(security fix) — see build_prompt. It is not a
            # self-certainty score, so it must NOT be inverted for negatives.
            #
            # The old `1 - conf` inversion was catastrophic here: the prompt
            # tells the model to emit LOW confidence for refactors, so a
            # CI-only change came back is_security_fix=0, confidence=0.03 and
            # was recorded as silent_fix_prob=0.97. Verified on a real sample:
            # "CI coverage configuration and test-function renames only; no
            # wallet source" scored 0.97. Left in place it would have promoted
            # thousands of refactors into the corroborated tier.
            prob = conf
            # Cross-check the two fields; disagreement means an unusable answer.
            if isfix != (conf > 0.5):
                continue
            if prob >= 0.70:
                n_fix += 1
            w.writerow([url, f"{prob:.3f}", int(isfix), pr.get("vuln_class", ""),
                        pr.get("_model") or fallback_model, PROMPT_VERSION,
                        str(pr.get("reason", ""))[:200]])
    print(f"[apply] wrote {a.apply_out} — {n_fix} rows with silent_fix_prob>=0.70", file=sys.stderr)
    if n_bad:
        print(f"[apply] {n_bad}/{len(rows)} calls failed or were unparseable and were "
              f"NOT cached — re-run to retry", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-eval", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--apply", action="store_true", help="classify dataset rows -> silent_fix csv")
    ap.add_argument("--csv-only", action="store_true",
                    help="write the csv from the existing --pred-cache and make no model "
                         "calls: a pass stopped by a quota still yields its artifact")
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
