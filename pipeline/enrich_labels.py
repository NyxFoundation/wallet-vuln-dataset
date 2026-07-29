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

# The client build split labels by protocol layer (consensus vs execution).
# Wallets have no such split; the meaningful axis is the registry CATEGORY,
# because what can go wrong in hardware firmware and in a browser extension
# barely overlaps.
import importlib.util as _ilu2
_WS = _ilu2.spec_from_file_location("_wallets", Path(__file__).resolve().parent.parent / "collection" / "wallets.py")
_wal = _ilu2.module_from_spec(_WS); _WS.loader.exec_module(_wal)  # type: ignore
PR_RE = re.compile(r"/pull/(\d+)")
SHA_RE = re.compile(r"/commit/([0-9a-f]{7,40})", re.I)
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
FILE_CAP_LINES = 400
FILE_CAP_CHARS = 16000


def layer(wallet: str) -> str:
    return _wal.WALLET_CONFIG.get(wallet, {}).get("category", "wallet_sdk")


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
#
# The label answers *which part of the custody chain broke*. Rules are split by
# registry category because the same word means different things in different
# repos ("session" is a WalletConnect pairing in infra and a login token in a
# mobile app), then a shared cross-cutting table catches the rest.

_KEY = [  # key material — applies to every category, checked first
    (r"seed[-_ ]?phrase|mnemonic|recovery[-_ ]?phrase|bip[-_ ]?39|slip[-_ ]?0?039", "key:seed-mnemonic"),
    (r"bip[-_ ]?32|bip[-_ ]?44|slip[-_ ]?0?010|derivation[-_ ]?path|\bhdkey\b|xprv|xpub|extended[-_ ]?key", "key:derivation"),
    (r"entropy|\brng\b|csprng|random|getrandom|secure[-_ ]?random", "key:entropy-rng"),
    (r"keystore|keychain|keyring|\bvault\b|secure[-_ ]?enclave|secure[-_ ]?element|encrypted[-_ ]?store", "key:storage"),
    (r"pbkdf2|scrypt|argon2|key[-_ ]?derivation[-_ ]?function|\bkdf\b|password[-_ ]?hash", "key:kdf"),
    (r"zeroize|wipe|scrub|clear[-_ ]?memory|memset_s|explicit_bzero", "key:memory-hygiene"),
    (r"backup|export[-_ ]?key|import[-_ ]?key|restore", "key:backup-restore"),
]

_SIGN = [  # signing correctness
    (r"eip[-_ ]?712|signtypeddata|typed[-_ ]?data|domain[-_ ]?separator", "sign:typed-data"),
    (r"eip[-_ ]?155|chain[-_ ]?id|replay[-_ ]?protect|cross[-_ ]?chain[-_ ]?replay", "sign:replay-protection"),
    (r"nonce[-_ ]?reuse|deterministic[-_ ]?nonce|rfc[-_ ]?6979|\bk[-_ ]?reuse\b|biased[-_ ]?nonce", "sign:nonce"),
    (r"malleab|low[-_ ]?s\b|\bder\b|recovery[-_ ]?id|\brecid\b", "sign:encoding-malleability"),
    (r"blind[-_ ]?sign|clear[-_ ]?sign|display[-_ ]?transaction|what[-_ ]?you[-_ ]?sign", "sign:blind-signing"),
    (r"\bpsbt\b|sighash|witness|taproot|\bschnorr\b", "sign:bitcoin-sighash"),
    (r"personal_sign|eth_sign|message[-_ ]?prefix", "sign:message-signing"),
    (r"secp256|ed25519|ecdsa|curve|scalar|point[-_ ]?decompress", "sign:curve-primitives"),
    (r"signature[-_ ]?verif|verify[-_ ]?sig|sigverify|invalid[-_ ]?signature", "sign:verification"),
]

_APPROVE = [  # spend authority
    (r"unlimited[-_ ]?approval|infinite[-_ ]?approval|max[-_ ]?uint|spending[-_ ]?cap", "approval:unlimited"),
    (r"permit2|eip[-_ ]?2612|erc[-_ ]?2612|\bpermit\b", "approval:permit"),
    (r"setapprovalforall|approve|allowance|revoke", "approval:allowance"),
    (r"session[-_ ]?key|delegat|authoriz", "approval:delegation"),
]

_TRANSPORT = [  # dapp <-> wallet channel
    (r"walletconnect|\bwc\b[-_ ]?uri|pairing|session[-_ ]?topic|\brelay\b", "transport:walletconnect"),
    (r"postmessage|cross[-_ ]?origin|same[-_ ]?origin|origin[-_ ]?check|\bcors\b", "transport:origin"),
    (r"content[-_ ]?script|inject|provider|window\.ethereum|eip[-_ ]?1193", "transport:provider-injection"),
    (r"deeplink|deep[-_ ]?link|universal[-_ ]?link|url[-_ ]?scheme|intent[-_ ]?filter", "transport:deeplink"),
    (r"webview|javascriptinterface|wkwebview|evaluatejavascript", "transport:webview"),
    (r"permission|approve[-_ ]?connection|connected[-_ ]?sites|dapp[-_ ]?permission", "transport:permissions"),
    (r"\brpc\b|json[-_ ]?rpc|method[-_ ]?whitelist|unauthorized[-_ ]?method", "transport:rpc-surface"),
]

_UI = [  # user-facing truthfulness
    (r"phishing|blocklist|blacklist|scam|malicious[-_ ]?site", "ui:phishing-detection"),
    (r"clipboard|paste|copy[-_ ]?address", "ui:clipboard"),
    (r"homoglyph|punycode|unicode|\brtl\b|bidi|spoof|look[-_ ]?alike", "ui:address-spoofing"),
    (r"simulat|preview|decode[-_ ]?transaction|human[-_ ]?readable|estimate", "ui:transaction-preview"),
    (r"display|truncat|checksum[-_ ]?address|render[-_ ]?amount|\bdecimals\b", "ui:display-integrity"),
]

_PLATFORM = [  # OS / browser escapes
    (r"\bxss\b|cross[-_ ]?site[-_ ]?script|innerhtml|dangerouslyset|sanitiz", "platform:xss"),
    (r"prototype[-_ ]?pollution|__proto__|constructor[-_ ]?pollution", "platform:prototype-pollution"),
    (r"\bcsp\b|content[-_ ]?security[-_ ]?policy|unsafe[-_ ]?eval|unsafe[-_ ]?inline", "platform:csp"),
    (r"path[-_ ]?traversal|zip[-_ ]?slip|\.\./|directory[-_ ]?traversal", "platform:path-traversal"),
    (r"deserializ|pickle|unmarshal[-_ ]?untrusted|yaml\.load", "platform:deserialization"),
    (r"allowbackup|exported[-_ ]?activity|screenshot|screen[-_ ]?record|flag_secure", "platform:mobile-hardening"),
    (r"biometric|faceid|touchid|lock[-_ ]?screen|auto[-_ ]?lock|idle[-_ ]?timeout", "platform:auth-lock"),
    (r"sandbox|isolat|\biframe\b|permission[-_ ]?manifest", "platform:sandbox"),
]

_CONTRACT = [  # smart-contract accounts
    (r"reentran", "contract:reentrancy"),
    (r"initializ|uninitialized|\binit\b[-_ ]?once|constructor", "contract:initialization"),
    (r"upgrad|proxy|implementation[-_ ]?slot|storage[-_ ]?collision|delegatecall", "contract:upgrade-proxy"),
    (r"erc[-_ ]?1271|isvalidsignature|contract[-_ ]?signature", "contract:erc1271"),
    (r"erc[-_ ]?4337|userop|validateuserop|entrypoint|paymaster|bundler", "contract:erc4337"),
    (r"threshold|owner|guardian|module|guard|fallback[-_ ]?handler", "contract:access-control"),
    (r"invariant|audit|formal|fuzz", "contract:invariant"),
]

_MPC = [  # threshold signing
    (r"\bdkg\b|key[-_ ]?gen|resharing|refresh", "mpc:keygen-refresh"),
    (r"share|shamir|secret[-_ ]?sharing|lagrange", "mpc:secret-share"),
    (r"paillier|range[-_ ]?proof|zero[-_ ]?knowledge|\bzk\b|commitment", "mpc:proofs"),
    (r"abort|identifiable|malicious[-_ ]?party|rogue[-_ ]?key", "mpc:malicious-party"),
    (r"lattice|small[-_ ]?subgroup|bias", "mpc:cryptanalysis"),
]

_FIRMWARE = [  # hardware wallets
    (r"bootloader|secure[-_ ]?boot|firmware[-_ ]?verif|signature[-_ ]?check[-_ ]?firmware", "firmware:boot-verification"),
    (r"\bpin\b|passphrase|wipe[-_ ]?counter|brute[-_ ]?force|retry[-_ ]?counter", "firmware:pin-passphrase"),
    (r"fault[-_ ]?injection|glitch|voltage|laser|side[-_ ]?channel|power[-_ ]?analysis|constant[-_ ]?time", "firmware:physical-attack"),
    (r"\busb\b|\bhid\b|\bnfc\b|bluetooth|\bble\b|transport[-_ ]?protocol", "firmware:host-transport"),
    (r"display|screen|confirm[-_ ]?on[-_ ]?device|trusted[-_ ]?display", "firmware:trusted-display"),
    (r"secure[-_ ]?element|\bse\b[-_ ]?applet|atecc|optiga", "firmware:secure-element"),
]

_SUPPLY = [
    (r"supply[-_ ]?chain|malicious[-_ ]?(?:package|dependency)|typosquat|postinstall", "supply-chain:dependency"),
    (r"code[-_ ]?signing|notariz|reproducible[-_ ]?build|checksum[-_ ]?verif", "supply-chain:build-integrity"),
    (r"update[-_ ]?channel|auto[-_ ]?update|rollback|downgrade", "supply-chain:update-channel"),
]

_X = [  # cross-cutting, checked last
    (r"crypto|keccak|sha256|\bhash\b|cipher|\baes\b|chacha", "crypto-primitives"),
    (r"serial|encode|decode|marshal|unmarshal|codec|\brlp\b|protobuf|\bcbor\b", "serialization"),
    (r"leveldb|rocksdb|sqlite|indexeddb|/db\b|database|realm", "storage"),
    (r"network|http|fetch|websocket|\bapi\b|node[-_ ]?provider|infura|alchemy", "network-io"),
    (r"\.github|\.circleci|dockerfile|makefile\b|/build/|renovate|/vendor/"
     r"|go\.mod\b|package-lock|yarn\.lock|Cargo\.(?:toml|lock)|\.ya?ml\b|gradle", "build-ci"),
    (r"metric|prometheus|telemetr|tracing|analytics|sentry", "metrics-observability"),
    (r"\bcmd/|/cli/|main\.(?:go|rs)\b|/flags?/", "cli"),
    (r"_test\.(?:go|rs|py|ts|js|kt|swift)|/tests?/|mock_|spec\.(?:ts|js)|\bfuzz", "test"),
]

# Which category-specific tables apply, in priority order. Key material and
# signing come first everywhere: they are the outcomes that actually cost money.
_BY_CATEGORY: dict[str, list] = {
    "browser_extension": [_KEY, _SIGN, _TRANSPORT, _UI, _APPROVE, _PLATFORM],
    "mobile":            [_KEY, _SIGN, _PLATFORM, _TRANSPORT, _UI, _APPROVE],
    "desktop":           [_KEY, _SIGN, _PLATFORM, _TRANSPORT, _UI, _APPROVE],
    "hardware_firmware": [_KEY, _SIGN, _FIRMWARE, _SUPPLY],
    "smart_account":     [_CONTRACT, _SIGN, _APPROVE, _KEY],
    "mpc_tss":           [_MPC, _KEY, _SIGN],
    "wallet_sdk":        [_KEY, _SIGN, _APPROVE, _TRANSPORT, _PLATFORM],
    "node_wallet":       [_KEY, _SIGN, _PLATFORM, _UI],
    "infra":             [_TRANSPORT, _SIGN, _APPROVE, _UI],
}

def _compile(tbl):
    return [(re.compile(p, re.I), l) for p, l in tbl]

_KEY, _SIGN, _APPROVE = _compile(_KEY), _compile(_SIGN), _compile(_APPROVE)
_TRANSPORT, _UI, _PLATFORM = _compile(_TRANSPORT), _compile(_UI), _compile(_PLATFORM)
_CONTRACT, _MPC = _compile(_CONTRACT), _compile(_MPC)
_FIRMWARE, _SUPPLY, _X = _compile(_FIRMWARE), _compile(_SUPPLY), _compile(_X)
_BY_CATEGORY = {k: [_compile(t) if t and isinstance(t[0][0], str) else t for t in v]
                for k, v in _BY_CATEGORY.items()}


def assign_label(hay: str, lyr: str) -> str:
    """`lyr` is the registry category (see layer_of)."""
    tables = _BY_CATEGORY.get(lyr, [_KEY, _SIGN, _TRANSPORT, _PLATFORM])
    for tbl in tables:
        for rx, lab in tbl:
            if rx.search(hay):
                return lab
    for rx, lab in _X:
        if rx.search(hay):
            return lab
    return "other"


# --- root_cause / attack_path (keyword + classifier vuln_class) --------------
# root_cause answers "why was it a bug"; attack_path answers "how is it reached".
# Retargeted from the client build: a wallet is not attacked by a malicious
# block, it is attacked by a malicious *dapp page*, a *crafted signing request*,
# a *malicious QR/deeplink*, or someone holding the device.
_RC = [
    (r"seed|mnemonic|entropy|weak[-_ ]?random|predictable|insufficient[-_ ]?entropy", "weak_key_generation"),
    (r"key[-_ ]?(?:leak|expos|logg)|plaintext[-_ ]?key|secret[-_ ]?in[-_ ]?log|not[-_ ]?cleared|zeroize", "key_material_exposure"),
    (r"derivation[-_ ]?path|hardened|bip[-_ ]?3[29]|slip[-_ ]?0?010|wrong[-_ ]?path", "incorrect_key_derivation"),
    (r"nonce[-_ ]?reuse|k[-_ ]?reuse|biased[-_ ]?nonce|deterministic[-_ ]?nonce", "nonce_reuse"),
    (r"replay|chain[-_ ]?id|domain[-_ ]?separator|eip[-_ ]?155|cross[-_ ]?chain", "missing_replay_protection"),
    (r"signature[-_ ]?verif|verify|sigverify|accept.*invalid[-_ ]?sig|malleab", "signature_verification_flaw"),
    (r"origin|cross[-_ ]?origin|postmessage|unauthorized[-_ ]?(?:dapp|site|caller)|permission[-_ ]?bypass", "missing_origin_authorization"),
    (r"approval|allowance|unlimited|permit|delegat", "excessive_spend_authority"),
    (r"display|preview|truncat|homoglyph|punycode|spoof|misleading|blind[-_ ]?sign", "user_deception"),
    (r"out.of.bounds|bounds check|index out|slice bounds|\boob\b|buffer[-_ ]?overflow", "missing_bounds_check"),
    (r"overflow|underflow|wrapping", "integer_overflow_underflow"),
    (r"nil pointer|null pointer|npe|unwrap|none type|unhandled", "unhandled_error_or_nil"),
    (r"validat|sanitiz|malformed|invalid input|check that|escap", "missing_input_validation"),
    (r"prototype[-_ ]?pollution|\bxss\b|injection|eval", "untrusted_code_execution"),
    (r"reentran", "reentrancy"),
    (r"initializ|uninitialized|storage[-_ ]?collision|upgrade", "unsafe_initialization_or_upgrade"),
    (r"access[-_ ]?control|owner|threshold|guard|privileg|auth", "broken_access_control"),
    (r"race|toctou|concurren|deadlock", "race_condition"),
    (r"deserial|serializ|decode|encode|parse", "serialization_bug"),
    (r"side[-_ ]?channel|timing|constant[-_ ]?time|power[-_ ]?analysis|fault[-_ ]?injection|glitch", "side_channel"),
    (r"oom|out of memory|unbounded|exhaust|memory leak|resource|dos|denial", "resource_exhaustion"),
    (r"supply[-_ ]?chain|dependency|typosquat|postinstall|code[-_ ]?signing", "supply_chain_compromise"),
    (r"crypto|curve|point|paillier|proof|commitment|share", "crypto_misuse"),
    (r"state|storage|balance|corrupt", "improper_state_update"),
]
_AP = [
    (r"malicious (?:dapp|site|website|page)|crafted (?:dapp|page)|attacker.controlled (?:site|origin)", "malicious_dapp"),
    (r"malicious (?:tx|transaction|payload)|crafted (?:tx|transaction)|signing[-_ ]?request", "malicious_signing_request"),
    (r"phishing|spoofed[-_ ]?(?:domain|site)|look[-_ ]?alike|scam", "phishing_site"),
    (r"deeplink|deep[-_ ]?link|universal[-_ ]?link|url[-_ ]?scheme|\bqr\b|intent", "malicious_deeplink_or_qr"),
    (r"walletconnect|pairing|session|\brelay\b", "malicious_pairing_session"),
    (r"malicious[-_ ]?(?:token|nft|contract)|crafted[-_ ]?contract|hostile[-_ ]?contract", "malicious_contract_or_token"),
    (r"malicious[-_ ]?(?:package|dependency)|compromised[-_ ]?(?:package|build)|supply[-_ ]?chain", "compromised_dependency"),
    (r"physical|fault[-_ ]?injection|glitch|laser|voltage|evil[-_ ]?maid|stolen[-_ ]?device", "physical_device_access"),
    (r"malicious[-_ ]?host|compromised[-_ ]?(?:computer|host|companion)|usb|\bhid\b", "compromised_host"),
    (r"local[-_ ]?app|other[-_ ]?app|malicious[-_ ]?app|screen[-_ ]?record|overlay|tapjack|clipboard", "malicious_local_app"),
    (r"malformed|invalid input|crafted input|bad input|parse|oversized|large", "malformed_input"),
    (r"network|\bmitm\b|man.in.the.middle|\brpc\b|node[-_ ]?provider", "hostile_network_or_rpc"),
    (r"\bpeer\b|p2p|gossip", "malicious_peer"),
]
_RC = [(re.compile(p, re.I), v) for p, v in _RC]
_AP = [(re.compile(p, re.I), v) for p, v in _AP]

_VCLASS_RC = {"dos": "resource_exhaustion", "memory": "missing_bounds_check",
              "overflow": "integer_overflow_underflow", "crypto": "crypto_misuse",
              "validation": "missing_input_validation", "auth": "broken_access_control"}


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
