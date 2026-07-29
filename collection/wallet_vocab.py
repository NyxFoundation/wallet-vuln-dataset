#!/usr/bin/env python3
"""wallet_vocab.py — the wallet security vocabulary.

The Ethereum build could lean on consensus vocabulary ("fork choice", "chain
split", "finality") because a client bug is a *protocol* bug. A wallet bug is a
**custody** bug: the money leaves because a key leaked, a signature was produced
over something the user did not see, or an approval was obtained under false
pretences. This module is the vocabulary for that threat model, and it is what
the crawlers search for and what `pipeline/build_security_dataset.py` gates on.

Why this matters more here than it did for clients
--------------------------------------------------
Wallets almost never file a CVE. They ship an app-store update. A CVE-anchored
corpus of wallet vulnerabilities is roughly two orders of magnitude smaller than
the true fix population, so the *keyword surface* is not a convenience — it is
the primary discovery mechanism, with CVE/GHSA acting only as the spine that
calibrates it.

Groups
------
KEY_MATERIAL       seed / entropy / key derivation / storage — direct key loss
SIGNING            what gets signed, and whether the user saw it
APPROVAL           allowance, permit, delegation — theft without a key leak
TRANSPORT          dapp<->wallet channel: origin, session, pairing, deeplink
UI_DECEPTION       address display, clipboard, phishing, blind signing
PLATFORM           mobile/extension platform escapes that reach the key
CONTRACT           smart-account specific defects
MPC                threshold-signature protocol defects
MEMORY             classic memory-safety (hardware firmware, C/C++ cores)
SUPPLY_CHAIN       dependency / build / update-channel compromise
"""

from __future__ import annotations

import re

# --- direct key-material compromise ---------------------------------------
KEY_MATERIAL = [
    "private key leak", "key leak", "seed phrase", "mnemonic", "recovery phrase",
    "entropy", "weak random", "insecure random", "predictable nonce",
    "Math.random", "rng", "csprng", "key derivation", "bip32", "bip39", "bip44",
    "slip-0010", "slip39", "hardened derivation", "xprv", "extended private key",
    "keystore", "keychain", "keyring", "secure enclave", "secure element", "encrypted vault",
    "vault decrypt", "password derivation", "pbkdf2", "scrypt", "argon2",
    "key in logs", "log the key", "plaintext key", "key exposure", "wipe memory",
    "zeroize", "memory not cleared", "key material",
    # bare high-value tokens (word-boundary matched, so "seed" does not fire on
    # "seeded" and "xprv" does not fire inside a base58 blob)
    "seed", "seedphrase", "privkey", "private key", "secret key", "master key",
    "wipe", "scrub", "clear from memory",
]

# --- signing correctness ---------------------------------------------------
SIGNING = [
    "signature verification", "signature malleability", "invalid signature",
    "nonce reuse", "k reuse", "deterministic nonce", "rfc6979",
    "eip-712", "eip712", "typed data", "domain separator", "chainId",
    "eip-155", "replay attack", "cross-chain replay", "signature replay",
    "personal_sign", "eth_sign", "blind sign", "blind signing",
    "unsigned transaction", "sighash", "psbt", "sigverify", "ecdsa", "schnorr",
    "ed25519", "secp256k1", "low-s", "der encoding", "recovery id", "recid",
    "message prefix", "signTypedData",
]

# --- approvals / delegated spend ------------------------------------------
APPROVAL = [
    "unlimited approval", "infinite approval", "approve", "allowance",
    "permit2", "erc-2612", "setApprovalForAll", "revoke approval",
    "spending cap", "delegatecall", "session key", "delegation",
    "increaseAllowance", "drainer", "wallet drainer",
]

# --- dapp <-> wallet transport --------------------------------------------
TRANSPORT = [
    "origin check", "origin validation", "postMessage", "cross-origin",
    "same-origin", "walletconnect", "wc uri", "pairing", "session hijack",
    "session topic", "relay", "deeplink", "deep link", "universal link",
    "custom scheme", "intent filter", "webview", "javascript interface",
    "rpc method", "unauthorized rpc", "permission bypass", "dapp permission",
    "content script", "injected provider", "provider spoof",
]

# --- user-facing deception -------------------------------------------------
UI_DECEPTION = [
    "address display", "address truncation", "homoglyph", "unicode spoof",
    "rtl override", "clipboard", "clipboard hijack", "paste address",
    "phishing", "spoofed domain", "punycode", "transaction preview",
    "decode transaction", "simulation", "misleading", "wrong amount",
    "wrong recipient", "token spoof", "fake token", "scam token",
]

# --- platform escapes reaching key material -------------------------------
PLATFORM = [
    "xss", "cross-site scripting", "prototype pollution", "unsafe-eval",
    "csp bypass", "content security policy", "path traversal", "zip slip",
    "insecure deserialization", "sandbox escape", "screen recording",
    "screenshot", "backup exclusion", "allowBackup", "exported activity",
    "root detection", "jailbreak", "tapjacking", "overlay attack",
    "autofill", "biometric bypass", "lock screen bypass", "auto-lock",
    "sensitive data in backup", "world-readable",
    # passkey / WebAuthn: signing authority rests on the platform
    # authenticator, so an assertion-parsing or flag-checking bug is a direct
    # signing bypass with no key leak involved.
    "passkey", "webauthn", "authenticator", "attestation", "clientDataJSON",
    "authenticatorData", "user presence", "user verification", "up flag",
    "uv flag", "challenge", "rpId", "relying party", "origin binding",
    "credential id", "secp256r1", "p-256", "touchid", "faceid",
    "platform authenticator", "resident key", "discoverable credential",
]

# --- smart-contract accounts ----------------------------------------------
CONTRACT = [
    "reentrancy", "unchecked call", "storage collision", "uninitialized proxy",
    "upgrade authorization", "initializer", "selfdestruct", "module bypass",
    "guard bypass", "owner bypass", "threshold bypass", "erc-1271",
    "isValidSignature", "erc-4337", "userop", "validateUserOp", "paymaster",
    "entrypoint", "bundler", "griefing", "invariant", "audit finding",
]

# --- MPC / threshold signatures -------------------------------------------
MPC = [
    "threshold signature", "tss", "mpc", "secret share", "share leakage",
    "zero-knowledge proof", "range proof", "paillier", "commitment",
    "abort attack", "rogue key", "key resharing", "dkg",
    "biased nonce", "lattice attack", "small subgroup",
    # seedless / embedded wallets: the key is split between device, provider
    # and recovery factor, so the attack is assembling a quorum of shares
    # rather than stealing one secret.
    "shamir", "secret sharing", "share reconstruction", "quorum",
    "recovery factor", "device share", "social recovery", "guardian",
    "oauth", "social login", "email otp", "magic link", "session token",
    "share refresh", "threshold bypass",
]

# --- classic memory safety (firmware, C/C++ cores) ------------------------
MEMORY = [
    "buffer overflow", "stack overflow", "heap overflow", "out-of-bounds",
    "out of bounds", "oob", "use-after-free", "uaf", "double free",
    "integer overflow", "integer underflow", "off-by-one", "memcpy",
    "null pointer", "uninitialized", "segfault", "memory corruption",
    "unsound", "unsafe", "fault injection", "glitch attack", "side channel",
    "timing attack", "power analysis", "constant time",
]

# --- supply chain ----------------------------------------------------------
SUPPLY_CHAIN = [
    "supply chain", "malicious dependency", "compromised package",
    "typosquat", "postinstall", "update channel", "signature of the update",
    "code signing", "reproducible build", "firmware verification",
    "bootloader", "secure boot", "rollback attack", "downgrade attack",
]

# --- generic defect language (kept from the client build) ------------------
GENERIC = [
    "vulnerability", "security fix", "exploit", "attack", "CVE-", "GHSA-",
    "panic", "crash", "hang", "deadlock", "DoS", "denial of service", "OOM",
    "race condition", "TOCTOU", "injection", "bypass", "spoof", "hijack",
    "privilege escalation", "authentication bypass", "access control",
]

GROUPS: dict[str, list[str]] = {
    "key_material": KEY_MATERIAL,
    "signing":      SIGNING,
    "approval":     APPROVAL,
    "transport":    TRANSPORT,
    "ui_deception": UI_DECEPTION,
    "platform":     PLATFORM,
    "contract":     CONTRACT,
    "mpc":          MPC,
    "memory":       MEMORY,
    "supply_chain": SUPPLY_CHAIN,
    "generic":      GENERIC,
}

# Weight per group when scoring security relevance. Direct key compromise and
# signing defects are decisive; generic defect language alone is not, because
# "fix crash" in a wallet UI is usually a UI crash, not a custody bug.
GROUP_WEIGHT: dict[str, float] = {
    "key_material": 1.00,
    "signing":      0.90,
    "mpc":          0.90,
    "contract":     0.75,
    "approval":     0.75,
    "supply_chain": 0.70,
    "transport":    0.65,
    "platform":     0.60,
    "memory":       0.60,
    "ui_deception": 0.55,
    "generic":      0.35,
}

ALL_KEYWORDS: list[str] = list(dict.fromkeys(k for g in GROUPS.values() for k in g))

# Keywords are matched on WORD BOUNDARIES, never as bare substrings. The client
# build learned this the hard way: an NVD substring match put "geth" inside
# `gethostbyaddr` and dumped glibc CVEs into the authoritative tier (its stage
# T2b exists only to undo that). Short, common tokens here — "tx", "se", "sign",
# "mpc", "oob" — would be far worse offenders, so the match is anchored.
_BOUNDARY_CACHE: dict[str, "re.Pattern[str]"] = {}


def _pattern(keyword: str) -> "re.Pattern[str]":
    pat = _BOUNDARY_CACHE.get(keyword)
    if pat is None:
        # \b works for alphanumeric edges; keywords with leading/trailing
        # punctuation (e.g. "CVE-") anchor on the alphanumeric side only.
        #
        # A SPACE inside a keyword matches any word separator: commit messages
        # write "nonce reuse", "nonce-reuse" and "nonce_reuse" interchangeably,
        # and a space-literal pattern silently drops two of the three.
        body = r"[-_\s]+".join(re.escape(part) for part in keyword.split())
        left = r"\b" if keyword[:1].isalnum() else ""
        right = r"\b" if keyword[-1:].isalnum() else ""
        pat = re.compile(left + body + right, re.IGNORECASE)
        _BOUNDARY_CACHE[keyword] = pat
    return pat


def matches(text: str, keywords: list[str]) -> list[str]:
    """Keywords that occur in `text` as whole words."""
    return [k for k in keywords if _pattern(k).search(text or "")]

# --- paths whose modification is custody-sensitive -------------------------
# Used as a corroborating signal: a fix touching one of these is far more
# likely to be a real vulnerability than the same words in a README.
SENSITIVE_PATHS: list[str] = [
    "keyring", "keystore", "keychain", "vault", "seed", "mnemonic", "bip39",
    "bip32", "hdkey", "derivation", "entropy", "random", "crypto", "cipher",
    "encrypt", "decrypt", "signer", "signing", "signature", "sign",
    "transaction", "tx", "psbt", "approve", "allowance", "permission",
    "provider", "rpc", "session", "pairing", "connect", "deeplink",
    "webview", "content-script", "background", "permissions", "origin",
    "secure_element", "se", "bootloader", "firmware", "applet",
    "account", "wallet", "auth", "password", "unlock", "lock",
    "phishing", "blocklist", "allowlist",
]

# Wallet standards whose mis-implementation is itself the bug. Analogous to
# the client build's consensus-spec divergence crawl.
STANDARD_TERMS: dict[str, list[str]] = {
    "bip32":     ["BIP32", "BIP-32", "bip32", "hardened derivation"],
    "bip39":     ["BIP39", "BIP-39", "bip39", "mnemonic checksum"],
    "bip44":     ["BIP44", "BIP-44", "derivation path"],
    "bip174":    ["BIP174", "BIP-174", "PSBT"],
    "slip10":    ["SLIP-0010", "SLIP10", "slip10"],
    "slip39":    ["SLIP-0039", "SLIP39", "shamir backup"],
    "eip712":    ["EIP-712", "EIP712", "signTypedData", "domain separator"],
    "eip155":    ["EIP-155", "EIP155", "chain id replay"],
    "eip1271":   ["EIP-1271", "EIP1271", "isValidSignature"],
    "eip4337":   ["ERC-4337", "EIP-4337", "userOp", "validateUserOp"],
    "eip2612":   ["EIP-2612", "ERC-2612", "permit"],
    "eip3085":   ["EIP-3085", "wallet_addEthereumChain"],
    "caip":      ["CAIP-2", "CAIP-10", "CAIP-25"],
    "rfc6979":   ["RFC6979", "RFC 6979", "deterministic nonce"],
}

# Flattened surface forms, queried independently by crawl_standards_divergence.py.
STANDARD_KEYWORDS: list[str] = [v for vs in STANDARD_TERMS.values() for v in vs]


def score(text: str) -> tuple[float, list[str]]:
    """Weighted security-relevance score in [0, 1] plus the groups that fired.

    The score is the max group weight (a single decisive signal is enough) with
    a small bonus per additional distinct group, so corroboration across
    independent vocabularies raises confidence without letting a pile of weak
    generic words reach the top.
    """
    fired = [g for g, kws in GROUPS.items() if matches(text, kws)]
    if not fired:
        return 0.0, []
    best = max(GROUP_WEIGHT[g] for g in fired)
    bonus = 0.05 * (len(fired) - 1)
    return min(1.0, round(best + bonus, 3)), fired


if __name__ == "__main__":
    print(f"{len(ALL_KEYWORDS)} keywords across {len(GROUPS)} groups; "
          f"{len(SENSITIVE_PATHS)} sensitive paths; {len(STANDARD_TERMS)} standards")
    for t in ["fix: clear seed from memory after unlock",
              "bump lodash to 4.17.21",
              "fix EIP-712 domain separator missing chainId allows signature replay",
              "update README"]:
        print(f"  {score(t)}  <- {t}")


# --- search-term selection -------------------------------------------------
# GitHub's search API is issued one query per term, so the full 266-keyword
# vocabulary cannot be sent per repo (it would be ~266 queries × 157 repos and
# would hit the secondary rate limit long before finishing). These are the
# highest-yield terms: decisive custody language that a real fix commit message
# actually contains, plus a category- and language-specific tail.
#
# Chosen for *commit-message* likelihood, not for completeness — a maintainer
# silently fixing a key leak writes "clear the seed", not "key_material".
_CORE_SEARCH_TERMS: list[str] = [
    "security", "vulnerability", "CVE-", "exploit",
    "private key", "seed", "mnemonic", "entropy", "keystore", "keyring",
    "signature", "signing", "nonce", "replay",
    "approval", "allowance", "phishing", "spoof",
    "origin", "permission", "bypass", "leak",
    "sanitize", "validate", "overflow", "crash",
]

_CATEGORY_SEARCH_TERMS: dict[str, list[str]] = {
    "browser_extension": ["postMessage", "content script", "XSS", "provider", "dapp"],
    "mobile":            ["deeplink", "webview", "keychain", "biometric", "backup"],
    "desktop":           ["password", "encrypt", "storage", "RPC"],
    "hardware_firmware": ["bootloader", "secure element", "PIN", "fault", "constant time"],
    "smart_account":     ["reentrancy", "delegatecall", "initializer", "validateUserOp", "audit"],
    "mpc_tss":           ["share", "DKG", "proof", "commitment", "biased"],
    "wallet_sdk":        ["derivation", "BIP32", "encoding", "ECDSA", "prototype pollution"],
    "node_wallet":       ["wallet", "RPC", "descriptor", "PSBT"],
    "infra":             ["session", "pairing", "relay", "origin", "URI"],
}

_LANGUAGE_SEARCH_TERMS: dict[str, list[str]] = {
    "c":        ["buffer overflow", "memcpy", "out of bounds"],
    "cpp":      ["buffer overflow", "use after free", "uninitialized"],
    "rust":     ["unwrap", "panic", "unsound", "RUSTSEC"],
    "go":       ["panic", "nil pointer", "data race"],
    "js":       ["prototype pollution", "XSS", "unsafe-eval"],
    "python":   ["traceback", "eval", "pickle"],
    "java":     ["IllegalStateException", "NullPointerException"],
    "solidity": ["reentrancy", "unchecked", "invariant"],
    "swift":    ["keychain", "crash"],
    "kotlin":   ["keystore", "crash"],
    "csharp":   ["NullReferenceException"],
    "dart":     ["exception"],
}


def search_terms(slug: str, category: str = "", language: str = "") -> list[str]:
    """Search terms for one repo: core custody language + category + language.

    ~35 terms per repo rather than the full vocabulary — enough recall to find
    silent fixes, few enough to survive GitHub's secondary rate limit across
    157 repos.
    """
    terms = list(_CORE_SEARCH_TERMS)
    terms += _CATEGORY_SEARCH_TERMS.get(category, [])
    terms += _LANGUAGE_SEARCH_TERMS.get(language, [])
    return list(dict.fromkeys(terms))
