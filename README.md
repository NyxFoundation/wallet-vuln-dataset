# wallet-vuln-dataset

A curated corpus of **past security fixes from crypto wallet software** — self-custody
apps, hardware-wallet firmware, smart-contract accounts, MPC/TSS key management, and
the signing libraries every wallet is built on. Every row is one historical
vulnerability fix (a merged PR, commit, advisory, or CVE), normalized to a single
schema, scored for security relevance, and tiered by evidence strength.

Built with the same methodology as
[`NyxFoundation/ethereum-vuln-dataset`](https://github.com/NyxFoundation/ethereum-vuln-dataset),
retargeted from a *protocol* threat model to a **custody** threat model.

> **Status: complete.** All 181 repos crawled across every slice, curated, and
> enriched with area labels and inline pre/post-fix code.

```python
import pandas as pd
df = pd.read_parquet("data/wallet_vulns.parquet")

df[df.authority_tier.isin(["A_authoritative", "B_corroborated"])]  # essential (18,790)
df[df.authority_tier != "A_dependency"]   # everything except third-party advisories
df[df.confidence == "high"]              # strongest evidence only
```

## Dataset at a glance

| | rows |
|---|---:|
| raw snapshot (all repos) | 90,223 |
| curated (security-only) | **27,826** |
| └ essential slice (A_authoritative ∪ B) | **18,790** |
| by tier | A_authoritative 1,424 · **A_dependency 628** · B_corroborated 17,366 · C_candidate 8,408 |
| by confidence | high 9,121 · medium 16,637 · low 2,068 |
| by severity | Critical 1 · High 228 · Medium 848 · Low 50 · Info 10,068 · Unrated 15,544 |
| with a STRIDE category (not `Other`) | 6,531 (23%) |
| with a CWE-Top-25 id | 6,162 (22%) |
| admitted by the LLM silent-fix classifier alone | **1,087** |

**96% of rows are Info or Unrated**, because almost no wallet fix is ever
graded by anyone. Unrated is not low impact — it is the absence of a grader.

**`A_dependency` is a real advisory about someone else's code.** 629 of the
2,053 rows carrying an advisory id (31%) are the repo bumping a dependency that
had a CVE — `rubyzip`, `rails`, `protobufjs`, `lodash`. The evidence is as
strong as any tier-A row and the finding is genuine, but rails is not a custody
path, and only 1.3% of these get a STRIDE category versus 7.1% of the rest.
Kept, separated, and excluded from the essential slice: undivided, the top tier
partly measured *whether Dependabot runs on a repo* — the same confound between
disclosure practice and defect count that this dataset exists to expose.

De-noising before the gate, and what each stage removes:

| Stage | Drops | Rationale |
|---|---:|---|
| T0 | 7 | rows from repos outside `collection/wallets.py`. The registry is the only authority on scope, and this runs regardless of which crawler produced the row — four separate crawlers had shipped with the reference project's repo lists |
| T2 | 7,351 | CI / docs / dep-bump meta-work (title-anchored) |
| T2c | 1,134 | version bumps whose **package name** is custody vocabulary (`@metamask/eth-hd-keyring`, `@scure/bip39`) — decided on title shape, overriding keyword protection |
| T2d | 7,238 | author-declared `build:`/`ci:`/`test:`/`docs:` work, unless it cites an advisory or is real build-integrity work |
| GATE | 47,524 | no independent security signal fired |

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

## What the fixes are about

Every row carries a `label` naming the part of the custody chain that broke,
derived from the diff's changed paths plus the fix text
([`docs/collection.md`](docs/collection.md)). The distribution:

`key:seed-mnemonic` 3,304 · `key:storage` 2,831 · `network-io` 2,328 · `sign:encoding-malleability` 1,354 · `build-ci` 1,154 · `test` 890

`pre_fix_code` / `post_fix_code` hold the before/after hunks inline for
91% of rows, `files_changed` for 95%, and `fix_commit` now resolves for **100%**
— it was 67% until `_resolve_pr_ref` stopped silently returning None on clones
that had never fetched `refs/pull/*`.

## Files

| File | Size | What |
|---|---:|---|
| `data/wallet_vulns.parquet` | 79 MB | **the dataset** — all columns including inline pre/post-fix code |
| `data/wallet_vulns.preview.csv` | 4.9 MB | 5 key columns, browsable on GitHub |
| `data/raw/train.classified.parquet` | 31 MB | pre-gate snapshot, for reproducing the curation |
| `data/manifest.json` | — | per-stage drop counts and redaction tally |

The full CSV export is not committed — at 255 MB it exceeds GitHub's 100 MB file
limit. Regenerate it in one line:

```python
pd.read_parquet("data/wallet_vulns.parquet").to_csv("wallet_vulns.csv", index=False)
```

Inline code is capped at 8 KB and 12 files per row
(`ROW_CAP_CHARS` / `MAX_FILES_PER_ROW` in `pipeline/enrich_labels.py`). Without a
per-row cap a single monorepo commit contributed megabytes, the intermediate hit
16 GB, and the parquet write failed on Arrow's 2 GB-per-column limit.

## Credential masking

The corpus quotes commit text verbatim and is a corpus of *security fixes*, so a
commit whose purpose was "remove the hardcoded test seed" tends to contain the
seed. Every published column is therefore masked to `XXXXXXX` before writing
([`pipeline/redact.py`](pipeline/redact.py)): mnemonics, `xprv`/WIF/raw-hex
private keys, PEM blocks, and cloud/API tokens. Commit SHAs, lockfile integrity
hashes and public keys are deliberately left intact — masking those would break
`fix_commit` joins.

Masking runs on the gate's **input**, before scoring, so the row that ships is
the row that was scored — an earlier version masked at write time, which meant a
handful of rows qualified on evidence the reader could not see. This build masked
69 mnemonics, 21 raw hex private keys, 2 `xprv`, 1 WIF key and 12 cloud tokens. Most are canonical test material (the BIP-39
`abandon … about` vector is in nearly every wallet's test suite), but the pass
does not attempt to tell live credentials from dead ones. Counts are recorded
under `redaction` in [`data/manifest.json`](data/manifest.json).

## Reproduce

The curated table is derived **deterministically** from the raw snapshot — no
network, no API key:

```bash
uv run python pipeline/build_security_dataset.py \
  --in  data/raw/train.classified.parquet \
  --out data/wallet_vulns.parquet
uv run --with pytest python -m pytest tests/ -q
```

To rebuild from an existing crawl (curation + labels, no re-crawling):

```bash
bash scripts/finalize.sh              # stages 4-10
SKIP_LABELS=1 bash scripts/finalize.sh   # gate only, fully offline
```

Re-collecting the raw snapshot is network-bound and slow (~24h for all 181
repos, dominated by GitHub's 30 req/min search limit):

```bash
MODE=full TIER=3 bash collection/run_pipeline.sh
```

## Repository layout

```
collection/   wallets.py (registry) · wallet_vocab.py (threat vocabulary)
              wallet_ident.py (package coords) · gh_rate.py (rate limits)
              crawlers · run_pipeline.sh
pipeline/     build_security_dataset.py — deterministic gate + tiering
              enrich_labels.py — label / root_cause / attack_path / pre+post code
scripts/      finalize.sh — rebuild the dataset from an existing crawl
tests/        quality gates + one regression test per bug that shipped
docs/         methodology, limitations, measured per-slice yield
data/         wallet_vulns.parquet (curated) · raw/ · manifest.json
```

## License

Data: [CC-BY-4.0](LICENSE), sourced from each wallet's own public repository.
Code under `collection/` and `pipeline/`: MIT.
