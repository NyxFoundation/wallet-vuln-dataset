# Limitations & coverage gaps

Read this before relying on the data. Every corpus of "past security fixes" is a
sample of a population it cannot fully observe; this page states what this one
misses and why, so a consumer can reason about the bias rather than inherit it
silently.

## 1. The population is unobservable, and the shortfall is not random

A wallet vulnerability becomes visible here only if its **fix landed in a public
git history**. Three large classes never do:

| Invisible class | Why | Effect on the corpus |
|---|---|---|
| **Closed-source wallets** | no commit history at all | entire products missing (see §2) |
| **Server-side fixes** | custodial and MPC-cosigner logic often lives in a private backend; the public repo holds only the client half | MPC/TSS coverage is skewed toward the *library*, not the deployed service |
| **Fixes that shipped as a rewrite** | a defect quietly removed during a refactor has no "fix" commit | systematically under-counts long-lived design flaws |

The shortfall is **not** uniform: it correlates with commercial secrecy and with
severity (an embarrassing key-leak is likelier to be fixed quietly, or in a
private fork merged as a squashed "improvements" commit). Treat counts as a
lower bound, never as an incidence rate.

## 2. Closed-source wallets are absent by construction

These have significant user bases and are **not** represented:

Phantom · Exodus · Binance Web3 Wallet · OKX Wallet · Bitget Wallet · SafePal ·
Coinomi · Atomic Wallet · Guarda · Trust Wallet (the *app*; only the open
`wallet-core` and `trust-web3-provider` components are covered) · Crypto.com
DeFi Wallet · Ronin Wallet · Argent (mobile app; the Starknet extension and
contracts are covered) · Zerion (app; only the SDK is covered) · Rabby (partially
— desktop is public, some services are not) · every exchange custodian.

Atomic Wallet and Exodus in particular have suffered large real-world losses that
this corpus cannot describe. **Absence here is not evidence of security.** If
anything the inverse: an open history is a precondition for appearing at all, so
the corpus over-represents projects that develop in public.

## 3. CVE/GHSA coverage is a spine, not a census

Wallets rarely file advisories. They ship an app-store update. Consequences:

- The **rated-severity slice is small and biased** toward libraries (npm packages
  get GHSA entries because downstream consumers run `npm audit`; a mobile wallet
  does not). Do not compare a library's advisory count against an app's.
- Most rows are `Unrated`. **Unrated ≠ low impact.**
- Rated rows mix two incompatible severity models: **CVSS** (upstream dependency
  CVEs) and project-assigned grades. A dependency CVSS score says nothing about
  whether user funds were reachable.

## 4. Keyword recall is bounded, in a knowable way

Discovery leans on the vocabulary in `collection/wallet_vocab.py` plus a per-repo
search-term list of ~34 terms. This bounds recall three ways:

- **A fix whose commit message says nothing** ("update", "cleanup", "fix #123")
  is invisible to the keyword pass. This is exactly the silent-fix population the
  LLM classifier exists to recover, and that pass is itself imperfect.
- **GitHub's `search/commits` index is not complete** for very large repos and
  returns HTTP 422 for some; those terms are skipped and logged, not silently
  dropped. `brave/brave-core`, `bitcoin/bitcoin` and `aptos-labs/aptos-core` are
  the repos most affected — they are huge and their wallet code is a subdirectory,
  so per-repo counts for them understate their true fix volume.
- **Non-English commit messages** are under-matched. Several wallets in the
  registry have substantial Chinese-, Russian- or Japanese-language history.

## 5. Monorepos dilute, subdirectories are not isolated

`brave/brave-core`, `bitcoin/bitcoin`, `MystenLabs/sui`, `aptos-labs/aptos-core`
and `monero-project/monero` are whole products in which the wallet is one
component. A row attributed to them may be a fix in code that has nothing to do
with custody. The `label` / `files_changed` columns let you filter, but the crawl
itself does not scope by path.

Conversely, MetaMask's logic is split across `metamask-extension`, `core`,
`snaps`, `eth-sig-util` and more; one logical fix can appear as several rows in
different repos. `cross_reference.py` de-duplicates by fix commit and advisory
id, but **cannot** merge a fix that was independently re-implemented per repo.

## 6. Archived repos are frozen history

18 registry entries are archived upstream (`web3.js`, `MyCrypto`, `Uniswap/wallet`,
`nami`, `leather`, `pera`, `kryptology`, `trezor/connect`, `ledgerjs`, …). Their
history is genuine and worth having, but they receive no new fixes, so their
counts are complete-but-static and will drift as the rest of the corpus grows.

## 7. Severity estimation is a model, not a measurement

Where `severity_estimated` is present it is an LLM judgement mapped onto the
custody threat model, never an authoritative grade. It never overwrites a real
`severity`; `severity_source` records the provenance. Treat estimated tiers as a
triage aid.

## 8. Point-in-time snapshot

The corpus is a crawl, not a live feed. Repos get renamed, transferred and
deleted; several registry slugs already point at redirect targets rather than
their historical names. Re-running the pipeline is the only way to refresh, and a
future run may legitimately return *fewer* rows for a repo that was taken private.

## 9. What this dataset is not

- **Not a vulnerability database.** Rows are *fixes*, some of which fixed bugs
  that were never exploitable in practice.
- **Not a wallet security ranking.** A repo with many rows is one that develops
  in public and writes descriptive commit messages. Using row counts to rank
  wallets by safety inverts the actual signal.
- **Not exploitable-vulnerability disclosure.** Everything here is already
  public and already fixed upstream.
