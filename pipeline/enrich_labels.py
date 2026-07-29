#!/usr/bin/env python3
"""enrich_labels.py — add the label columns from docs/label_design.md.

For every curated row (that has a diff) this derives, deterministically from the
local git diff:
  label            protocol area of the bug (controlled vocabulary)
  root_cause       why it was a bug            (enum, from keywords + classifier)
  attack_path      how it's triggered          (enum)
  files_changed    JSON list of changed paths
  pre_fix_code     JSON [{file, hunks:[{start_line, code}]}]  (removed+context)
  post_fix_code    JSON same shape             (added+context)
  fix_commit       fixing commit SHA           (/commit/ or PR head)
  introduced_in_commit  parent of the fix commit = last pre-fix state

Diffs come from local_diffs (rate-limit-free). Writes data/labels.csv keyed by
`id`; build_security_dataset joins it (--labels-csv). LLM classifier reasons in
the prediction cache are reused to sharpen root_cause / attack_path.

Usage:
    uv run python pipeline/enrich_labels.py --in data/wallet_vulns.parquet \
        --out data/labels.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "collection"))
import local_diffs as ld  # noqa: E402
import llm_classify_fixes as llm  # noqa: E402  (reuse the pluggable LLM engine)

CONSENSUS = {"lighthouse", "lodestar", "nimbus", "prysm", "teku", "grandine"}
PR_RE = re.compile(r"/pull/(\d+)")
SHA_RE = re.compile(r"/commit/([0-9a-f]{7,40})", re.I)
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
FILE_CAP_LINES = 400
FILE_CAP_CHARS = 16000


def layer(wallet: str) -> str:
    return "consensus" if wallet in CONSENSUS else "execution"


# --- advisory -> fix commit (dedicated security patch releases only) ---------
GHSA_URL_RE = re.compile(r"/security/advisories/(GHSA-[0-9a-z-]+)", re.I)
SKIP_COMMIT = re.compile(
    r"^(params: (?:release|begin)|version:|build:|ci:|Merge branch .*release"
    r"|.*\bPPA\b|chore(?:\(release\))?: release|Prepare(?: for)? release)", re.I)
_TAGS: dict = {}
_ADV: dict = {}


def _tags(wallet):
    if wallet not in _TAGS:
        out = ld._run(["git", "-C", str(ld.repo_path(wallet)), "tag", "--sort=v:refname"]).stdout
        _TAGS[wallet] = [t for t in out.split() if re.match(r"^v?\d+\.\d+\.\d+$", t)]
    return _TAGS[wallet]


def _advisories(wallet):
    if wallet not in _ADV:
        repo = ld.WALLET_REPOS.get(wallet); _ADV[wallet] = {}
        if repo:
            try:
                for a in json.loads(ld._run(["gh", "api",
                        f"/repos/{repo}/security-advisories?per_page=100"]).stdout):
                    pv = next((v.get("patched_versions") for v in a.get("vulnerabilities", [])
                               if v.get("patched_versions")), "")
                    _ADV[wallet][a["ghsa_id"]] = (pv, a.get("summary", ""))
            except Exception:
                pass
    return _ADV[wallet]


def resolve_inline_ref(wallet, text):
    """A fix commit/PR the changelog/release text explicitly links (high
    precision — the author wrote the reference). commit hash > PR number."""
    rp = str(ld.repo_path(wallet))
    mc = re.search(r"/commit/([0-9a-f]{7,40})", text)
    if mc and ld._run(["git", "-C", rp, "cat-file", "-e", mc.group(1)]).returncode == 0:
        return mc.group(1)
    mp = re.search(r"/pull/(\d+)|\(#(\d+)\)|\[#?(\d{2,})\]|(?:^|\s)#(\d{2,})\b", text)
    if mp:
        pr = next(g for g in mp.groups() if g)
        ref = ld._resolve_pr_ref(ld.repo_path(wallet), pr)
        if ref:
            sha = ld._run(["git", "-C", rp, "rev-parse", ref]).stdout.strip()
            return sha or None
    return None


def resolve_advisory(wallet, ghsa, summary):
    """Fix commit for a GHSA advisory row, only when the patched version is a
    small dedicated security patch release (range ≤ 6 non-release commits)."""
    adv = _advisories(wallet).get(ghsa)
    if not adv:
        return None
    m = re.search(r"(\d+\.\d+\.\d+)", adv[0] or "")
    if not m:
        return None
    tags = _tags(wallet); ver = m.group(1)
    tag = next((c for c in (f"v{ver}", ver) if c in tags), None)
    if not tag:
        return None
    i = tags.index(tag)
    if i == 0:
        return None
    prev = tags[i - 1]
    log = ld._run(["git", "-C", str(ld.repo_path(wallet)), "log", f"{prev}..{tag}",
                   "--pretty=%H\t%s", "--name-only"]).stdout
    commits, cur = [], None
    for ln in log.splitlines():
        if re.match(r"^[0-9a-f]{40}\t", ln):
            sha, subj = ln.split("\t", 1); cur = [sha, subj, []]; commits.append(cur)
        elif ln.strip() and cur is not None:
            cur[2].append(ln.strip())
    fixes = [c for c in commits if not SKIP_COMMIT.match(c[1])]
    if not (1 <= len(fixes) <= 6):
        return None
    toks = set(re.findall(r"[a-z]{3,}", (adv[1] or summary or "").lower()))
    fixes.sort(key=lambda c: len(toks & set(re.findall(r"[a-z]{3,}",
                                    (c[1] + " " + " ".join(c[2])).lower()))), reverse=True)
    return fixes[0][0]


# --- label rules: (regex, label). Ordered specific -> general; first match wins.
# Matched against "changed file paths + title + description".
_C = [  # consensus
    (r"das[-_/]|data[-_]?column|peer[-_]?das|column[-_]?sidecar|sampling", "data-availability-sampling"),
    (r"kzg|blob[-_]?sidecar|polynomial[-_]?commit|4844|c-kzg", "kzg-commitments"),
    (r"\bepbs\b|payload[-_]?attestation|builder[-_]?(?:bid|api|payload)|blinded[-_]?(?:block|beacon)|mev[-_]?boost|\bptc\b|execution[-_]?payload[-_]?envelope", "builder"),
    (r"light[-_]?wallet", "light-wallet"),
    (r"weak[-_]?subjectivity", "weak-subjectivity"),
    (r"deposit[-_]?contract", "deposit-contract"),
    (r"fork[-_]?choice|forkchoice|on_block|proposer[-_]?boost|lmd|ghost", "fork-choice"),
    (r"sync[-_]?committee|synccommittee", "beacon-chain:sync-committee"),
    (r"execution[-_]?payload|execpayload|process_execution", "beacon-chain:execution-payload"),
    (r"attest", "beacon-chain:attestation"),
    (r"slash", "beacon-chain:slashing"),
    (r"withdraw|bls[-_]?to[-_]?execution|bls_change", "beacon-chain:withdrawal"),
    (r"voluntary[-_]?exit|consolidat|\bexit\b", "beacon-chain:exit-consolidation"),
    (r"\bdeposit", "beacon-chain:deposit"),
    # epoch processing, split by the process_epoch sub-stages (spec fn names)
    (r"justif|finali[sz]ation|\bffg\b|process_justif", "beacon-chain:justification-and-finality"),
    (r"rewards?[-_]?and[-_]?penal|\breward|penalt|inactivity", "beacon-chain:rewards-and-penalties"),
    (r"registry[-_]?update|activation[-_]?queue|exit[-_]?queue|\bchurn|activation_eligibility", "beacon-chain:registry-updates"),
    (r"effective[-_]?balance", "beacon-chain:effective-balance-updates"),
    (r"epoch[-_]?process|process_epoch|historical_summar|historical_root|participation_flag|randao_mix|slashings_reset|eth1_data_reset", "beacon-chain:epoch-processing"),
    (r"block[-_]?process|process_block|block_header|randao|eth1[-_]?data", "beacon-chain:block-processing"),
    (r"gossip|req[-_]?resp|reqresp|discv5|/enr|network|/p2p|libp2p", "p2p-interface"),
    (r"\bbls\b|signature[-_]?verif", "bls"),
    (r"/fork\b|fork\.py|upgrade_to|state_upgrade", "fork-transition"),
    (r"validator|duties|proposer|attester", "validator"),
    (r"beacon[-_]?chain|state[-_]?transition|beaconstate", "beacon-chain:block-processing"),
]
_E = [  # execution
    (r"precompil", "precompiles"),
    (r"instruction|opcode|/ops?/", "opcodes"),
    (r"eof\b|evm[-_]?object", "eof"),
    (r"blob[-_]?pool|blobpool|4844|blob[-_]?tx", "blobs"),
    (r"engine[-_]?api|newpayload|forkchoiceupdated|getpayload|payload[-_]?builder", "engine-api"),
    (r"txpool|tx[-_]?pool|mempool|legacypool", "txpool"),
    (r"downloader|snap[-_]?sync|/sync|beacon[-_]?sync|skeleton", "sync"),
    (r"\brpc\b|jsonrpc|json[-_]?rpc|/rpc/|eth_api|web3", "rpc"),
    (r"\bgas\b|gaspool|eip[-_]?1559|fee[-_]?market|basefee", "gas"),
    (r"/vm/|/evm|interpreter|opcodes", "evm"),
    (r"transaction|/tx\b|signer|/types/tx", "transactions"),
    (r"\btrie\b|mpt|patricia|/state|stateobject|snapshot|storage", "state-trie"),
    (r"\brlp\b", "rlp"),
    (r"devp2p|/p2p|discover|/eth/protocol|/eth/handler|snap[-_]?protocol|wire", "p2p"),
    (r"block[-_]?process|/core/blockchain|verifyheader|process(?:block|_block)|state_transition", "block-processing"),
]
_X = [  # cross-cutting (checked after protocol rules; most-informative first)
    (r"crypto|secp256|ecrecover|keccak|\bhash\b|blst|bn256|bls12|schnorr", "crypto"),
    (r"\bssz\b|serial|encode|decode|marshal|unmarshal|codec", "serialization"),
    (r"leveldb|rocksdb|pebble|/db\b|database|/ethdb|/storage/kv", "database"),
    # non-protocol but real areas (keeps 'other' honest instead of forced)
    (r"\.github|\.circleci|dockerfile|docker-compose|\.gradle\b|gradle/|makefile\b"
     r"|/build/|verification-metadata|renovate|/vendor/|docs/vulnerab|go\.mod\b|go\.sum"
     r"|package-lock|yarn\.lock|Cargo\.(?:toml|lock)|\.ya?ml\b", "build-ci"),
    (r"metric|diagnostic|prometheus|grafana|observ|telemetr|tracing|\botel\b", "metrics-observability"),
    (r"\bcmd/|/cli/|main\.(?:go|rs)\b|BesuCommand|/flags?/|command\.java", "cli"),
    (r"_test\.(?:go|rs|py|ts|js)|/tests?/|testhelper|mock_|spec\.(?:ts|js)|\bfuzz", "test"),
]
_C = [(re.compile(p, re.I), l) for p, l in _C]
_E = [(re.compile(p, re.I), l) for p, l in _E]
_X = [(re.compile(p, re.I), l) for p, l in _X]


def assign_label(hay: str, lyr: str) -> str:
    rules = (_C if lyr == "consensus" else _E) + _X
    for rx, lab in rules:
        if rx.search(hay):
            return lab
    return "other"


# --- root_cause / attack_path (keyword + classifier vuln_class) --------------
_RC = [
    (r"out.of.bounds|bounds check|index out|slice bounds|oob\b", "missing_bounds_check"),
    (r"overflow|underflow|wrapping", "integer_overflow_underflow"),
    (r"nil pointer|null pointer|nil deref|npe|unwrap|nil map|none type", "unhandled_error_or_nil"),
    (r"validat|verify|sanitiz|malformed|invalid input|check that", "missing_input_validation"),
    (r"gas|refund|out of gas|gas cost", "incorrect_gas_accounting"),
    (r"consensus|divergen|chain split|invalid block|non.?determin|fork", "consensus_divergence"),
    (r"oom|out of memory|unbounded|exhaust|memory leak|resource|dos|denial", "resource_exhaustion"),
    (r"race|toctou|concurren|deadlock|data race", "race_condition"),
    (r"deserial|serializ|decode|ssz|rlp", "serialization_bug"),
    (r"state|storage|trie|balance|corrupt", "improper_state_update"),
    (r"signature|crypto|kzg|bls|curve|point", "crypto_misuse"),
    (r"reentran", "reentrancy"),
]
_AP = [
    (r"malicious (?:block|payload)|invalid block|crafted block", "malicious_block"),
    (r"malicious (?:tx|transaction)|crafted (?:tx|transaction)", "malicious_tx"),
    (r"attestation|attester", "malicious_attestation"),
    (r"p2p|gossip|peer message|network message|req.?resp|rpc request", "malicious_p2p_message"),
    (r"malformed|invalid input|crafted input|bad input|parse", "malformed_input"),
    (r"crafted state|state|database", "crafted_state"),
    (r"large|oversized|huge|unbounded", "large_input"),
    (r"\bpeer\b|connection", "peer"),
]
_RC = [(re.compile(p, re.I), v) for p, v in _RC]
_AP = [(re.compile(p, re.I), v) for p, v in _AP]

_VCLASS_RC = {"dos": "resource_exhaustion", "memory": "missing_bounds_check",
              "overflow": "integer_overflow_underflow", "consensus": "consensus_divergence",
              "validation": "missing_input_validation", "auth": "missing_input_validation"}


def derive(rules, hay, default=""):
    for rx, v in rules:
        if rx.search(hay):
            return v
    return default


# --- diff parsing ------------------------------------------------------------
def parse_diff(diff: str):
    files, pre, post = [], [], []
    cur = None
    for ln in diff.splitlines():
        if ln.startswith("diff --git"):
            m = re.search(r" b/(\S+)$", ln)
            cur = m.group(1) if m else None
            if cur:
                files.append(cur)
            continue
        if cur is None:
            continue
        m = HUNK_RE.match(ln)
        if m:
            pre.append((cur, int(m.group(1)), []))
            post.append((cur, int(m.group(2)), []))
            continue
        if not pre:
            continue
        if ln.startswith("+") and not ln.startswith("+++"):
            post[-1][2].append(ln[1:])
        elif ln.startswith("-") and not ln.startswith("---"):
            pre[-1][2].append(ln[1:])
        elif ln.startswith(" "):
            pre[-1][2].append(ln[1:]); post[-1][2].append(ln[1:])
    return files, _group(pre), _group(post)


def _group(hunks):
    by_file: dict[str, list] = {}
    for f, start, lines in hunks:
        if not lines:
            continue
        by_file.setdefault(f, []).append({"start_line": start, "code": "\n".join(lines)})
    out, used = [], 0
    for f, hs in by_file.items():
        kept, n = [], 0
        for h in hs:
            if n >= FILE_CAP_LINES:
                kept.append({"start_line": h["start_line"], "code": "… [truncated]"}); break
            code = h["code"]
            if len(code) > FILE_CAP_CHARS:
                code = code[:FILE_CAP_CHARS] + "\n… [truncated]"
            kept.append({"start_line": h["start_line"], "code": code})
            n += code.count("\n") + 1
        out.append({"file": f, "hunks": kept})
    return out


# --- LLM fallback for rows the deterministic rules leave as "other" ----------
CONSENSUS_LABELS = [
    "beacon-chain:justification-and-finality", "beacon-chain:rewards-and-penalties",
    "beacon-chain:registry-updates", "beacon-chain:effective-balance-updates",
    "beacon-chain:epoch-processing", "beacon-chain:block-processing",
    "beacon-chain:attestation", "beacon-chain:slashing", "beacon-chain:deposit",
    "beacon-chain:withdrawal", "beacon-chain:exit-consolidation",
    "beacon-chain:sync-committee", "beacon-chain:execution-payload", "fork-choice",
    "p2p-interface", "validator", "weak-subjectivity", "deposit-contract", "bls",
    "light-wallet", "fork-transition", "kzg-commitments",
    "data-availability-sampling", "builder"]
EXECUTION_LABELS = [
    "evm", "opcodes", "precompiles", "gas", "transactions", "txpool",
    "block-processing", "state-trie", "rlp", "p2p", "sync", "engine-api",
    "blobs", "eof", "rpc"]
CROSS = ["crypto", "serialization", "database", "build-ci", "cli",
         "metrics-observability", "test", "other"]
RC_ENUM = [v for _, v in _RC] + ["improper_state_update", "other"]
AP_ENUM = [v for _, v in _AP] + ["internal_only"]


def llm_label(row, diff, lyr) -> dict:
    labels = (CONSENSUS_LABELS if lyr == "consensus" else EXECUTION_LABELS) + CROSS
    prompt = f"""Label this security fix in an Ethereum {lyr} wallet.

Pick the ONE best AREA label from this list (use "other" only if truly none fit):
{', '.join(labels)}

Also pick root_cause from: {', '.join(sorted(set(RC_ENUM)))}
and attack_path from: {', '.join(sorted(set(AP_ENUM)))}
and the single most-fitting CWE id (e.g. CWE-190) or "N/A".

Changed files: {row.get('files') or '(none)'}
Title: {str(row.get('title') or '')[:200]}
Description (advisory / changelog text): {str(row.get('description') or '')[:900]}
Code diff (truncated):
{(diff or '')[:3000]}

Output ONLY one JSON object on the last line:
{{"label": "...", "root_cause": "...", "attack_path": "...", "cwe": "CWE-XXX"}}"""
    try:
        out = llm._call_llm(prompt)
        m = re.search(r"\{[^{}]*\"label\"[^{}]*\}", out, re.S)
        obj = json.loads(m.group(0)) if m else {}
    except Exception:
        obj = {}
    valid = set(labels)
    lab = obj.get("label") if obj.get("label") in valid else None
    cwe = obj.get("cwe") if re.match(r"CWE-\d+$", str(obj.get("cwe") or ""), re.I) else None
    return {"label": lab, "root_cause": obj.get("root_cause"),
            "attack_path": obj.get("attack_path"), "cwe": cwe}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=Path("data/wallet_vulns.parquet"), type=Path)
    ap.add_argument("--out", default=Path("data/labels.csv"), type=Path)
    ap.add_argument("--pred-cache", default=Path("scratchpad_crawl/llm_pred_cache.json"), type=Path)
    ap.add_argument("--diff-cache", default=Path("scratchpad_crawl/diff_cache.json"), type=Path)
    ap.add_argument("--llm", action="store_true", help="LLM fallback for 'other' rows")
    ap.add_argument("--llm-cache", default=Path("scratchpad_crawl/llm_label_cache.json"), type=Path)
    ap.add_argument("--engine", default="openai")
    ap.add_argument("--model", default="")
    ap.add_argument("--base-url", default="https://ollama.com/v1")
    ap.add_argument("--api-key-env", default="OLLAMA_API_KEY")
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    import os
    llm.ENGINE.update(engine=a.engine,
                      model=a.model or ("gemma4:31b" if a.engine == "openai" else ""),
                      base_url=a.base_url,
                      api_key=os.environ.get(a.api_key_env, "") if a.api_key_env else "")

    df = pd.read_parquet(a.inp)
    preds = json.loads(a.pred_cache.read_text()) if a.pred_cache.exists() else {}
    dcache = json.loads(a.diff_cache.read_text()) if a.diff_cache.exists() else {}

    rows, metas, n_diff, n_label = [], [], 0, 0
    for i, r in enumerate(df.to_dict("records")):
        wallet = r["source_platform"]; url = str(r["source_url"]); lyr = layer(wallet)
        repo = ld.WALLET_REPOS.get(wallet)
        files, pre, post = ([], [], [])
        fix_sha = introduced = ""
        diff = None
        if repo:
            rp = str(ld.repo_path(wallet))
            m = SHA_RE.search(url); mp = PR_RE.search(url); ma = GHSA_URL_RE.search(url)
            if m:
                fix_sha = m.group(1)
                diff = ld.get_diff_cached(url, wallet, dcache)
            elif mp:
                ref = ld._resolve_pr_ref(ld.repo_path(wallet), mp.group(1))
                if ref:
                    fix_sha = ld._run(["git", "-C", rp, "rev-parse", ref]).stdout.strip()
                diff = ld.get_diff_cached(url, wallet, dcache)
            elif ma:  # GHSA advisory page -> resolve the patch-release fix commit
                fix_sha = resolve_advisory(wallet, ma.group(1), str(r.get("title") or "")) or ""
            if not fix_sha and repo:  # changelog/release row -> explicit inline #PR / commit ref
                fix_sha = resolve_inline_ref(wallet, str(r.get("title") or "") + " " + str(r.get("description") or "")) or ""
            if fix_sha and diff is None:
                diff = ld._run(["git", "-C", rp, "show", "--format=", "--unified=3", fix_sha]).stdout or None
            if fix_sha:
                par = ld._run(["git", "-C", rp, "rev-parse", f"{fix_sha}^"])
                introduced = par.stdout.strip() if par.returncode == 0 else ""
        if diff:
            n_diff += 1
            files, pre, post = parse_diff(diff)
        pred = preds.get(url, {}) if isinstance(preds.get(url), dict) else {}
        vclass = str(pred.get("vuln_class") or "")
        hay = " ".join(files) + " " + str(r.get("title") or "") + " " + str(r.get("description") or "")
        label = assign_label(hay, lyr)
        if label != "other":
            n_label += 1
        reason_hay = str(pred.get("reason") or "") + " " + hay
        root_cause = derive(_RC, reason_hay) or _VCLASS_RC.get(vclass, "other")
        attack_path = derive(_AP, reason_hay, "malformed_input")
        rows.append({
            "id": r["id"], "layer": lyr, "label": label,
            "root_cause": root_cause, "attack_path": attack_path,
            "files_changed": json.dumps(files, ensure_ascii=False),
            "pre_fix_code": json.dumps(pre, ensure_ascii=False),
            "post_fix_code": json.dumps(post, ensure_ascii=False),
            "fix_commit": fix_sha, "introduced_in_commit": introduced,
            "cwe_top25": "",
        })
        metas.append({"url": url, "layer": lyr, "files": ", ".join(files[:6]),
                      "title": r.get("title"), "description": r.get("description"),
                      "nocommit": not fix_sha})
        if (i + 1) % 200 == 0:
            a.diff_cache.write_text(json.dumps(dcache))
            print(f"  [labels] {i+1}/{len(df)}", file=sys.stderr)
    a.diff_cache.write_text(json.dumps(dcache))

    # --- LLM fallback for rows still "other" -------------------------------
    if a.llm:
        from concurrent.futures import ThreadPoolExecutor
        cache = json.loads(a.llm_cache.read_text()) if a.llm_cache.exists() else {}
        # LLM on: rows the rules left 'other', PLUS no-commit advisory/CVE rows
        # (no diff, but their advisory text is the fix info — read it from the link)
        todo = [i for i, row in enumerate(rows)
                if row["label"] == "other" or metas[i]["nocommit"]]
        print(f"[labels] LLM on {len(todo)} rows (other + no-commit) "
              f"({sum(1 for i in todo if rows[i]['id'] in cache)} cached)", file=sys.stderr)

        def work(i):
            rid = rows[i]["id"]
            if rid in cache:
                return i, cache[rid]
            diff = dcache.get(metas[i]["url"]) or ""
            res = llm_label(metas[i], diff, metas[i]["layer"])
            return i, res

        done = 0
        with ThreadPoolExecutor(max_workers=a.workers) as ex:
            for i, res in ex.map(work, todo):
                cache[rows[i]["id"]] = res
                if res.get("label"):
                    rows[i]["label"] = res["label"]
                if res.get("root_cause"):
                    rows[i]["root_cause"] = res["root_cause"]
                if res.get("attack_path"):
                    rows[i]["attack_path"] = res["attack_path"]
                if res.get("cwe"):
                    rows[i]["cwe_top25"] = res["cwe"]
                done += 1
                if done % 50 == 0:
                    a.llm_cache.write_text(json.dumps(cache))
                    print(f"  [labels-llm] {done}/{len(todo)}", file=sys.stderr)
        a.llm_cache.write_text(json.dumps(cache))
        n_label = sum(1 for r in rows if r["label"] != "other")

    a.out.parent.mkdir(parents=True, exist_ok=True)
    with a.out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    from collections import Counter
    print(f"[labels] {len(rows)} rows | with diff {n_diff} | labelled {n_label}")
    print("top labels:", Counter(x["label"] for x in rows).most_common(12))
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
