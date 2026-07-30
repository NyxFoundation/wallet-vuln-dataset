#!/usr/bin/env python3
"""redact.py — strip credential material from text before publication.

Why this exists
---------------
This corpus quotes commit messages and PR bodies verbatim from public
repositories, and it is a corpus of *security fixes*. Those two facts combine
badly: a commit whose whole purpose is "remove the hardcoded test seed" or
"rotate the leaked key" tends to contain the seed or the key. GitHub's push
protection caught AWS-key-shaped strings in the published parquet, which is what
surfaced the problem — but the AWS pattern is the least of it.

For a **wallet** dataset the material that must never be republished is key
material: BIP-39 mnemonics, extended private keys, raw 32-byte hex keys, PEM
blocks. Those appear in exactly the commits this dataset is built to collect.

Aggregating scattered leaks into one indexed, downloadable table makes them
materially easier to exploit, so the published columns are masked even though the
upstream repos still contain the originals. Most of what this catches is
canonical test material — the BIP-39 "abandon abandon ... about" vector appears
in essentially every wallet's test suite — but the pass does not try to
distinguish live from dead credentials, because it cannot.

Masking is applied to the published artifacts only. Earlier commits in this
repository's history predate this pass and retain the original text.

What is NOT redacted
--------------------
Commit SHAs, base64 integrity hashes, public keys and addresses. They are not
secrets, and destroying them would break `fix_commit` joins and make rows
unreadable. The patterns below are therefore anchored and, where a shape is
ambiguous (40-char base64 could be a secret or a hash), require nearby
credential vocabulary before firing.
"""

from __future__ import annotations

import re

PLACEHOLDER = "XXXXXXX"  # kind is recorded in the manifest tally, not inline

# --- unambiguous credential shapes -----------------------------------------
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # AWS access key id — the prefix makes this unambiguous
    ("AWS-KEY-ID", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b")),
    # GitHub tokens (all current prefixes)
    ("GITHUB-TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b")),
    # Slack / Stripe / SendGrid / Google API keys
    ("SLACK-TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("STRIPE-KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("SENDGRID-KEY", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    ("GOOGLE-API-KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("OPENAI-KEY", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    # PEM private key blocks
    ("PRIVATE-KEY-PEM", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"
        r".*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        re.S)),
    # JWTs (three base64url segments)
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),

    # --- wallet key material: the class that actually matters here ---------
    # BIP-32 extended PRIVATE keys. xpub/ypub/zpub are public and left alone.
    ("XPRV", re.compile(r"\b(?:xprv|yprv|zprv|tprv|uprv|vprv)[1-9A-HJ-NP-Za-km-z]{70,120}\b")),
    # WIF-encoded private keys (mainnet 5/K/L, testnet c)
    ("WIF-KEY", re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")),
    # Raw 32-byte hex private key, but only with credential vocabulary nearby —
    # a bare 64-hex string is far more often a commit SHA pair or a block hash.
    ("HEX-PRIVKEY", re.compile(
        r"(?i)(?:priv(?:ate)?[_ -]?key|secret[_ -]?key|seed|entropy|mnemonic)"
        r"[^\n]{0,40}?\b(?:0x)?[0-9a-f]{64}\b")),
]

# 40-char base64: AWS *secret* keys look exactly like integrity hashes, so only
# redact when credential vocabulary sits nearby.
_AMBIGUOUS_B64 = re.compile(
    r"(?i)(?:aws|secret|access[_ -]?key|api[_ -]?key|token|password|credential)"
    r"[^\n]{0,40}?(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")

# --- BIP-39 mnemonics -------------------------------------------------------
# A full wordlist would be 2048 entries; these are the distinctive leading words
# of the English list plus the ones overwhelmingly common in test vectors. A run
# of >=11 all-lowercase dictionary-ish words next to mnemonic vocabulary is the
# real signal, so the check is structural rather than a wordlist lookup.
_MNEMONIC_CTX = re.compile(r"(?i)mnemonic|seed[_ -]?phrase|recovery[_ -]?phrase|seed[_ -]?words")
_WORD_RUN = re.compile(r"\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b")


def _redact_mnemonics(text: str) -> tuple[str, int]:
    """Redact 12-24 word lowercase runs that sit near mnemonic vocabulary.

    Structural rather than wordlist-based: any 12+ word all-lowercase run in a
    commit that is talking about seed phrases is treated as one, because a false
    positive costs a sentence of prose and a false negative costs someone's coins.
    """
    if not _MNEMONIC_CTX.search(text):
        return text, 0
    n = 0

    def sub(_m: re.Match[str]) -> str:
        nonlocal n
        n += 1
        return PLACEHOLDER

    return _WORD_RUN.sub(sub, text), n


def redact(text: str) -> tuple[str, list[str]]:
    """Return (redacted_text, kinds_redacted)."""
    if not text:
        return text, []
    kinds: list[str] = []
    out = text
    for kind, rx in _PATTERNS:
        out, k = rx.subn(PLACEHOLDER, out)
        if k:
            kinds.append(kind)
    out, k = _AMBIGUOUS_B64.subn(PLACEHOLDER, out)
    if k:
        kinds.append("SECRET")
    out, k = _redact_mnemonics(out)
    if k:
        kinds.append("MNEMONIC")
    return out, kinds


def redact_frame(df, columns=("title", "description", "pre_fix_code", "post_fix_code")):
    """Redact the given columns in place; returns a {kind: count} summary."""
    import collections
    summary: collections.Counter = collections.Counter()
    for col in columns:
        if col not in df.columns:
            continue
        vals, changed = [], 0
        for v in df[col].fillna("").astype(str):
            new, kinds = redact(v)
            if kinds:
                changed += 1
                for k in kinds:
                    summary[k] += 1
            vals.append(new)
        df[col] = vals
        if changed:
            summary[f"rows_touched:{col}"] = changed
    return dict(summary)


if __name__ == "__main__":
    samples = [
        "leaked AKIAIOSFODNN7EXAMPLE in config",
        "remove hardcoded mnemonic: abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about",
        "fix: rotate token ghp_16C7e42F292c6912E7710c838347Ae178B4a",
        "bump lodash to 4.17.21",                                  # keep
        "fix_commit 776656df8be551f8454c64d137d1a4b0e0e0aaaa",     # keep (SHA)
        "integrity sha512-abcdefghijklmnopqrstuvwxyz0123456789ABCD",  # keep
        "aws secret access key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "private key 0x4c0883a69102937d6231471b5dbb6204fe512961708279a0b0b0e0e0e0e0e0e0",
    ]
    for s in samples:
        out, kinds = redact(s)
        flag = "REDACTED " + ",".join(kinds) if kinds else "kept"
        print(f"  [{flag}] {out[:96]}")
