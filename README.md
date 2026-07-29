# wallet-vuln-dataset

A curated corpus of **past security fixes from crypto wallet software** — self-custody
apps, hardware-wallet firmware, smart-contract accounts, MPC/TSS key management, and
the signing libraries every wallet is built on. Every row is one historical
vulnerability fix (a merged PR, commit, advisory, or CVE), normalized to a single
schema, scored for security relevance, and tiered by evidence strength.

Built with the same methodology as
[`NyxFoundation/ethereum-vuln-dataset`](https://github.com/NyxFoundation/ethereum-vuln-dataset),
retargeted from a *protocol* threat model to a **custody** threat model.

> **Status: interim build.** The stealth-PR stage is still crawling; these numbers
> come from the advisory + commit-grep + release/changelog slices and will grow.

```python
import pandas as pd
df = pd.read_parquet("data/wallet_vulns.parquet")

df[df.authority_tier != "C_candidate"]   # the essential slice (8,597 rows)
df[df.confidence == "high"]              # strongest evidence only
```

## Dataset at a glance

| | rows |
|---|---:|
| raw snapshot (all repos) | 46,116 |
| curated (security-only) | **15,022** |
| └ essential slice (tier A ∪ B) | **8,597** |
| by tier | A_authoritative 476 · B_corroborated 8,121 · C_candidate 6,425 |
| by confidence | high 5,455 · medium 8,762 · low 805 |
| by severity | Critical 1 · High 82 · Medium 12 · Low 52 · Info 10,391 · Unrated 4,484 |

**99% of rows are Info or Unrated**, because almost no wallet fix is ever
graded by anyone. Unrated is not low impact — it is the absence of a grader.

De-noising before the gate, and what each stage removes:

| Stage | Drops | Rationale |
|---|---:|---|
| T2 | 2,218 | CI / docs / dep-bump meta-work (title-anchored) |
| T2c | 486 | version bumps whose **package name** is custody vocabulary (`@metamask/eth-hd-keyring`, `@scure/bip39`) — decided on title shape, overriding keyword protection |
| T2d | 4,448 | author-declared `build:`/`ci:`/`test:`/`docs:` work, unless it cites an advisory or is real build-integrity work |
| GATE | 23,942 | no independent security signal fired |

## Why this exists (and why CVE lists are the wrong map)

Ethereum clients silently patch ~98–100% of their vulnerabilities. Wallets are
**worse**: a wallet does not run a network, it ships an app-store update — so there is
usually no advisory, no CVE, and no release note admitting a fix.

That is not a hunch. Crawling the published GitHub Security Advisories of all 181
repositories in this registry returns:

| | |
|---|---:|
| repositories crawled | 181 |
| **published advisories across all of them** | **16** |
| repositories with **zero** advisories | **167 (92%)** |
| security-relevant PR/issue rows from the same repos | 5,299 |
| ratio, non-advisory : advisory | **331 : 1** |

An advisory-anchored wallet vulnerability dataset would have **sixteen rows**. Sixteen,
for the software holding hundreds of billions of dollars. Every advisory that does exist
belongs to an npm library or a US-based company — because npm publishes GHSAs when
downstream consumers run `npm audit`, and because those companies have disclosure
policies. Hardware wallets, mobile wallets and non-US projects contribute **none**.

So CVE/GHSA is used here only as the **spine** that calibrates the crawl. The corpus
itself is recovered from commit history: keyword-gated commit grep, unlabelled
("stealth") PRs touching custody-sensitive paths, and an LLM silent-fix classifier over
the diff. Method: [`docs/silent_fix_detection.md`](docs/silent_fix_detection.md).

## Scope

A repo is in scope when a defect in it can cost a user **funds, key material, or
signing authority**. That is wider than "a wallet app" — it includes the firmware
holding the seed, the contract holding the balance, the MPC library sharding the key,
and libraries like `ethers`, `viem`, `bitcoinjs-lib`, `wallet-core` and WalletConnect,
where a single defect is simultaneously a bug in a hundred wallets.

**181 repositories** — see [`collection/wallets.py`](collection/wallets.py):

| by category | | by custody model | |
|---|---:|---|---:|
| wallet SDK / library | 50 | self-custody | 65 |
| browser extension | 26 | library (no custody) | 55 |
| mobile | 24 | smart-contract account | 27 |
| smart-contract account | 22 | MPC / threshold / seedless | 19 |
| MPC / TSS / seedless | 19 | hardware (secure element) | 15 |
| desktop | 17 | | |
| hardware firmware | 10 | | |
| node wallet | 7 | | |
| connection infra | 6 | | |

Closed-source wallets (Phantom, Exodus, Binance Web3, OKX, Bitget, SafePal, exchange
custodians) publish no commit history, so no silent fix of theirs is observable by
construction. They are excluded and recorded in `docs/limitations.md`.

## The custody threat model

Severity follows what a defect costs the *user*, not CVSS:

| Group | The bug is that… |
|---|---|
| `key_material` | the seed/key leaked, was weakly generated, or was left in memory |
| `signing` | a signature was valid over something the user never approved |
| `approval` | spend authority was obtained without ever touching the key |
| `transport` | the dapp↔wallet channel let an unauthorized origin in |
| `ui_deception` | the user approved the wrong thing because the UI lied |
| `platform` | an OS/browser escape reached the key store |
| `contract` | the smart account's own validation was bypassable |
| `mpc` | the threshold protocol leaked a share, biased a nonce, or let an attacker assemble a quorum |
| `memory` | classic memory corruption in firmware / native cores |
| `supply_chain` | the dependency or update channel was the attack |

Two custody models the Ethereum-client corpus has no analogue for are covered
explicitly:

- **Seedless / embedded wallets** (Privy, Web3Auth, Openfort, Para, thirdweb,
  Magic, Turnkey, Dfns) — the user signs in with email or OAuth and never sees a
  mnemonic; the key is split between device, provider and recovery factor. The
  question stops being "can the seed leak" and becomes "can an attacker assemble
  a quorum of shares". Most of these vendors keep the product SDK closed and
  publish only the cryptographic core — which is precisely the part where a
  defect is catastrophic, so it is in scope even when the product is not.
- **Passkey / biometric wallets** (Coinbase Smart Wallet, `webauthn-sol`,
  `p256-verifier`, Clave, passkey-kit) — signing authority rests on a platform
  authenticator released by Face ID / Touch ID. A mis-parsed `clientDataJSON` or
  an unchecked user-verification flag is a **direct signing bypass with no key
  leak at all**, which is why the WebAuthn verification libraries wallets embed
  are in the registry alongside the wallets themselves.

Defined in [`collection/wallet_vocab.py`](collection/wallet_vocab.py).

## Repository layout

```
collection/   wallets.py (registry) · wallet_vocab.py (threat vocabulary) · crawlers · run_pipeline.sh
pipeline/     build_security_dataset.py — deterministic gate + tiering
tests/        quality gates (schema, no-boilerplate, every-row-has-a-signal)
docs/         methodology, limitations, build reports
data/         wallet_vulns.parquet (curated) · raw/ · manifest.json
```

## License

Data: [CC-BY-4.0](LICENSE), sourced from each wallet's own public repository.
Code under `collection/` and `pipeline/`: MIT.
