# Silent-fix detection

A **silent fix** is a vulnerability repaired without an advisory: no CVE, no
GHSA, often a commit message that says nothing more than "fix edge case". They
are the majority of all wallet security fixes, so a corpus that cannot recover
them is not a corpus of wallet vulnerabilities — it is a corpus of the handful
that happened to get an advisory.

## Why wallets are worse than clients

The Ethereum-client corpus found that clients patch ~98–100% of vulnerabilities
silently. Wallets have the same incentives plus two more:

1. **No coordinated upgrade to announce.** A client operator must be told to
   upgrade or the network suffers, which at least produces release notes. A
   wallet ships an app-store update that installs itself; there is no
   operational reason to publish anything.
2. **Disclosure is commercially costly.** "Our wallet could leak your seed" is
   a headline, not a changelog entry. The rational disclosure choice for a
   custody product is silence.

The practical consequence: **counting wallet CVEs undercounts the real fix
population by roughly two orders of magnitude.** CVE/GHSA is therefore used
here only as a *spine* — a small, high-confidence set that calibrates and
validates everything else — never as the collection strategy.

## Three recovery methods

### 1. Patch backlinking (deterministic, high precision)

Start from a confirmed advisory (OSV / GHSA / RustSec / NVD) and extract the
exact fixing commit or version from its references, giving `fix_commit` and its
parent `introduced_in_commit`. Precise but bounded by advisory coverage — which
is exactly the coverage this dataset exists to escape. It anchors the corpus
rather than filling it.

Wallet-specific note: advisory coverage is heavily skewed to **npm**. `ethers`,
`viem`, `@walletconnect/*`, `bitcoinjs-lib` and friends get GHSA entries because
downstream consumers run `npm audit`; a mobile wallet gets none. This is why
`collection/wallet_ident.py` maps 95 npm packages — the client build's
Go-and-crates-only view would have seen almost none of the wallet advisory
surface.

### 2. Keyword-gated commit mining (broad recall)

Search each repo's commit and PR history for the custody vocabulary in
`collection/wallet_vocab.py`, then let the gate in
`pipeline/build_security_dataset.py` decide what survives.

Two design choices matter more than they look:

- **Per-repo search terms.** ~34 terms selected from the core custody
  vocabulary plus the repo's category and language, rather than one global
  list. A hardware-firmware repo searches for `bootloader` and `constant time`;
  a JS SDK searches for `prototype pollution` and `XSS`. Using one list across
  181 heterogeneous repos was the single largest recall loss measured during
  the port.
- **Word-boundary matching, never substring.** The client build's stage T2b
  exists solely to undo NVD substring-matching "geth" inside `gethostbyaddr`
  and importing glibc CVEs as authoritative Ethereum findings. The wallet
  vocabulary contains far more dangerous short tokens (`tx`, `se`, `mpc`,
  `oob`, `sign`), and the registry is full of ordinary English words (`safe`,
  `frame`, `core`, `edge`, `jade`, `station`, `sui`). Every keyword is anchored,
  and ambiguous slugs additionally require wallet context in the text before an
  NVD row is accepted for them.

### 3. Training-free LLM classification (recovers what keywords cannot)

The residual — a real fix whose commit message says "cleanup" — is invisible to
any keyword method by construction. `collection/llm_classify_fixes.py` runs an
LLM4VFD-style Chain-of-Thought over *diff + development artifacts + touched
subsystem*, with no fine-tuning, and emits a calibrated `silent_fix_prob`.

The prompt (`PROMPT_VERSION = "wallet-v1"`) is built around the custody threat
model, not the protocol one. It enumerates the ten failure surfaces
(key material, signing, approval, transport, UI deception, platform, contract,
MPC/seedless, passkey, firmware, supply chain) and asks the model to weigh the
**worst-case trigger** — a wallet processes untrusted input from web pages, QR
codes, deeplinks, hostile RPC nodes, malicious tokens, and sometimes an attacker
holding the device.

It also carries an explicit **anti-over-firing instruction**, which the
Ethereum prompt did not need. There, a consensus-class defect counted as
security even with no attacker named, because the pre-fix code could split the
chain. A wallet has no such property: most crashes in wallet UI code are simply
crashes. Without that instruction the classifier labels every `fix: crash` as a
vulnerability and the precision collapses. The rule encoded is: a crash counts
only when it is reachable from untrusted input **or** touches key/signing paths.

Diffs are served from local bare, blobless clones by
`collection/local_diffs.py`, so this pass is not subject to the REST API rate
limit and each diff fetch is a ~1–5 ms local `git` read.

Engine: `claude -p` by default; a local Ollama model or any OpenAI-compatible
endpoint also work (`--engine ollama|openai`).

## How the signals combine

None of the three is trusted alone. The gate keeps a row when **any**
independent signal fires (union = recall) and then tiers it by how much evidence
stacked up (intersection = precision):

| Tier | Evidence |
|---|---|
| `A_authoritative` | carries an advisory id or an advisory-rated severity |
| `B_corroborated` | no id, but ≥ 2 independent signals agree |
| `C_candidate` | a single signal fired — broad recall, noisier |

`silent_fix_prob ≥ 0.70` counts as one such signal, so the LLM pass mainly
*promotes* rows the deterministic gate had left in the noisy candidate tier,
rather than admitting rows on its own authority.

## Honest limits

- A fix that shipped inside a large refactor has no identifiable fix commit and
  is not recoverable by any of the three methods.
- The classifier is imperfect and its errors are not random: it is most likely
  to miss terse fixes in unfamiliar languages, which is also where wallets are
  most diverse.
- Server-side fixes in custodial and MPC-cosigner backends never enter a public
  repo at all.

See [`limitations.md`](./limitations.md) for the full inventory.
