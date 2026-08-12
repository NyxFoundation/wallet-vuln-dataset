# wallet-vuln-dataset

Every security fix that crypto wallet developers have quietly shipped, collected from
their own public repositories. 33,744 fixes across 174 wallets, hardware firmwares,
smart-contract accounts and signing libraries.

Almost none of them have a CVE. That is the point.

## What this says about the wallet you use

Across all 181 repositories in this registry, the total number of published security
advisories is **16**. 167 repositories have published **zero**.

Every one of those 16 belongs to an npm library or a US-based company. npm publishes
advisories because downstream projects run `npm audit`; US companies publish them
because they have disclosure policies. Trezor, Ledger, Coldcard, BitBox, Keystone,
OneKey, Electrum, BlueWallet, Sparrow, Wasabi, Monero, Keplr and imToken have published
none between them.

That is not a safety ranking. Reading it as one inverts the causality. **Advisory counts
measure whether a project has a disclosure habit, not whether it had bugs.**

Here is what was actually in one of those zero-advisory repositories. Judging all 20,650
of Trezor's firmware commits surfaced 1,956 security fixes, including:

- a **hardcoded signature bypass** — `signature_valid = sectrue` sitting in the firmware
  verification path with a `TODO-remove` comment
- **signing nonces derived from the private key** (RFC 6979), replaced with a hardware
  random source, because the deterministic derivation leaked key material
- **nonce bias in Ed25519 multisig signing** — the nonce was run through a function that
  clamps bits, forcing the value into a predictable subset
- an entropy failure that returned **an ignorable boolean** instead of halting the
  device, so a caller could proceed with weak randomness

None of these have a CVE. If you had checked Trezor's advisory page, you would have seen
nothing, and concluded nothing was wrong.

## What the disclosure record contains

The wallet ecosystem's own advisories and the fixes it ships quietly were read the
same way — an LLM over the diff, one taxonomy of 23 defect mechanisms, no knowledge
of which side a row came from.

Of the 1,325 rows carrying an advisory id or a graded severity — the strongest
evidence tier in this corpus — **51 (4%) are a defect in the wallet's own custody
path.** The rest:

| | rows |
|---|---:|
| a defect in the wallet's own custody path | **51** |
| following a CVE in a third-party dependency | 146 |
| not a defect fix at all | 1,128 |

That last group is security *process* work — reviewers added to CODEOWNERS, code
annotated with CVE references, a fuzz harness for an already-fixed CVE — plus real
bugs outside custody, like a server-side cursor leak. The keyword-free sweep of ten
repositories found **4,608** custody fixes. A ratio of 90 : 1.

**What cannot be claimed from this.** An earlier version of this section said five
defect mechanisms never appear in an advisory. That does not survive. Restricted to
the 51 advisory rows that are genuinely custody fixes, 7 of 22 mechanisms are
absent — and drawing 51 rows at random from the silent distribution leaves 7.4
absent by chance. The mechanism comparison between the two populations is
underpowered, and the zeros in the earlier version came from using all 1,325
advisory rows as the denominator when 1,274 of them repair no defect. The count
comparison above is a full census and stands; the *composition* comparison does
not.

## What breaks, in order

Of the 4,608 fixes recovered by reading every commit of ten widely-used wallets:

| | fixes | what actually goes wrong |
|---|---:|---|
| `signing` | 1,418 | a signature ends up valid over something you never agreed to |
| `key_material` | 968 | the seed or key leaks, is weakly generated, or is left in memory |
| `firmware` | 628 | boot verification, PIN handling, or the trusted display on a hardware wallet |
| `ui_deception` | 572 | you approve the wrong thing because the screen told you something false |
| `transport` | 358 | the channel between a dapp and your wallet lets in an origin it should not |
| `memory` | 182 | memory corruption in firmware or native crypto code |
| `platform` | 162 | an OS or browser escape reaches the key store |
| `approval` | 109 | spend authority is obtained without ever touching your key |

**Signing and UI deception together outweigh key leakage.** The common mental model —
"keep your seed phrase safe and you are fine" — does not match where the bugs are. Most
of these fixes are about a wallet signing or displaying something other than what you
believed you approved, while your seed stayed exactly where it was supposed to be.

## The data

| File | Size | What |
|---|---:|---|
| [`data/keywordless_sweep_wave1.csv`](data/keywordless_sweep_wave1.csv) | 1.6 MB | **start here.** 4,608 fixes from ten mass-market wallets, one row each, with the reason it was judged a security fix |
| `data/wallet_vulns.parquet` | 95 MB | the full corpus — 33,744 rows, all columns, before/after code inline |
| `data/wallet_vulns.preview.csv` | 6 MB | key columns only, browsable in the GitHub UI |
| `data/raw/train.classified.parquet` | 31 MB | pre-filter snapshot, for reproducing the curation |
| [`data/wave1_mechanisms.csv`](data/wave1_mechanisms.csv) | 1.7 MB | the same 4,608 fixes labelled by defect mechanism |
| [`data/advisory_mechanisms.csv`](data/advisory_mechanisms.csv) | 403 KB | all 1,325 advisory-bearing rows, read from the diff, with the verdict and its reason |
| [`data/mechanism_comparison.csv`](data/mechanism_comparison.csv) | — | disclosed vs silent, per mechanism |
| [`data/mechanisms.csv`](data/mechanisms.csv) | 1.1 MB | every mechanism label, keyed by commit URL — the source of the corpus column |
| `data/silent_fix_llm.csv` | 31 MB | every classifier verdict, including the negatives |
| `data/manifest.json` | — | per-stage drop counts and redaction tally |

```python
import pandas as pd
df = pd.read_parquet("data/wallet_vulns.parquet")

df[df.authority_tier.isin(["A_authoritative", "B_corroborated"])]  # 22,133 strongest
df[df.security_verdict != "refuted"]                               # drop the denied
df[df.contest == "all-commits"]                                    # 3,896 keyword-free
df[df.mechanism == "signed-differs-from-shown"]                    # by what went wrong
```

The full CSV export is not committed — at 305 MB it exceeds GitHub's file limit.
`pd.read_parquet(...).to_csv(...)` regenerates it.

### Corpus shape

| | rows |
|---|---:|
| raw snapshot | 94,388 |
| curated | **33,744** |
| └ strongest evidence (`A_authoritative` ∪ `B_corroborated`) | **22,133** |
| by tier | A_authoritative 1,421 · A_dependency 628 · B_corroborated 20,712 · C_candidate 10,983 |
| by severity | Critical 1 · High 228 · Medium 846 · Low 49 · Info 11,646 · Unrated 20,974 |
| with a STRIDE category | 8,703 |
| with a CWE-Top-25 id | 8,238 |
| found by the LLM classifier alone | 7,057 |
| └ from the keyword-free sweep | 3,896 |
| `security_verdict` | unassessed 24,299 · assessed 7,934 · refuted 1,511 |
| with a defect `mechanism` | **6,803** across 22 kinds · 2,642 read but unattributable · 24,299 unread |

**97% of rows are Info or Unrated** because nobody ever graded them. Unrated means no
grader existed, not low impact.

`A_dependency` (628 rows) carries a real advisory about **someone else's** code — the
repo bumping `rails` or `rubyzip` after a CVE. Genuine, and not a custody bug, so it sits
outside the strongest slice. Left mixed in, the top tier partly measured whether
Dependabot runs on a repo.

`label` says which part of the custody chain a fix touched; `mechanism` says **what went
wrong there** — a signature checked against the wrong bytes, a length never validated, a
key left in a place another app can read. It is the column to group by when the question
is "what should I be careful about", and the 22 values are in
[`data/mechanism_comparison.csv`](data/mechanism_comparison.csv).

Only a row an LLM has read can carry one, so the rest say `unclassified` rather than
guessing. Two things the column does not hide: rows found by reading whole histories land
in `other` 5.1% of the time, while rows inherited from the keyword crawl do so 20.6% of
the time — a thinner record makes a weaker label. And a row judged *not* to be a security
fix is 90% `other`, which is correct: there is no defect to attribute.

`security_verdict` records what two independent LLM passes concluded. `refuted` means
both denied it is a security fix. **Those 1,511 rows are still included** — 72% of the
corpus has not been assessed at all, and filtering only the assessed part would hold the
read rows to a standard the unread ones escape.

## How fixes are found

CVE and GHSA are used only to calibrate. The corpus comes from commit history, three ways:

1. **Advisory backlinking** — advisory → fixing commit. Precise, and bounded by the
   coverage this project exists to escape.
2. **Keyword-gated commit mining** — custody vocabulary across each repo's history, with
   per-repo search terms and word-boundary matching.
3. **Reading every commit** — no keyword at all. Judged by an LLM over the diff.

The third recovers what the second cannot, by construction: a fix whose message says
"cleanup" matches no keyword. Measured against each other on the same repositories, rows
recovered without keywords survive an independent security check **69%** of the time
against **24.6%** for keyword-gated rows. Keywords buy recall by spending precision.

Method: [`docs/silent_fix_detection.md`](docs/silent_fix_detection.md) ·
limits: [`docs/limitations.md`](docs/limitations.md)

## Scope

In scope when a defect there can cost you **funds, key material, or signing authority** —
wider than "a wallet app". It includes the firmware holding your seed, the contract
holding your balance, the MPC library sharding your key, and libraries like `ethers`,
`viem`, `bitcoinjs-lib`, `wallet-core` and WalletConnect, where one defect is
simultaneously a bug in a hundred wallets.

**181 repositories** ([`collection/wallets.py`](collection/wallets.py)):

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

Closed-source wallets — Phantom, Exodus, Binance Web3, OKX, Bitget, SafePal, exchange
custodians — publish no commit history, so none of their silent fixes is observable.

### What "silent" does and does not mean

It means **no CVE or GHSA record exists for the fix**. It does not mean nobody was told.
The sweep's clearest case is BTCPay Server's
[TOTP 2FA bypass](https://github.com/btcpayserver/btcpayserver/pull/7491): a TOTP-only
account could be driven through the entire Greenfield API with just an email and
password, because the Basic-auth handler tested `Fido2Credentials.Any()` instead of
whether two-factor was enabled at all. It was patched in an emergency 2.4.2 release under
active exploitation, and covered in the trade press. BTCPay's GitHub advisory list is
nonetheless empty, so every automated tool that watches advisories saw nothing.

That is the failure this corpus measures: not silence toward users, but absence from the
record a scanner can read. Either way, the fix is not in the feed your dependency bot
subscribes to.

Two custody models get explicit coverage:

- **Seedless / embedded** (Privy, Web3Auth, Openfort, Para, thirdweb, Magic, Turnkey,
  Dfns) — you sign in with email or OAuth and never see a mnemonic; the key is split
  across device, provider and recovery factor. The question stops being "can the seed
  leak" and becomes "can an attacker assemble a quorum of shares". Most vendors keep the
  product closed and publish only the cryptographic core, which is exactly the part where
  a defect is catastrophic.
- **Passkey / biometric** (Coinbase Smart Wallet, `webauthn-sol`, `p256-verifier`, Clave,
  passkey-kit) — signing rests on a platform authenticator released by Face ID or Touch
  ID. A mis-parsed `clientDataJSON` or an unchecked user-verification flag is a **signing
  bypass with no key leak at all**, which is why the WebAuthn verification libraries
  wallets embed are in the registry too.

## Keyword-free sweep: where it stands

Ten mass-market repositories done. Every eligible commit judged, no keyword consulted.

| repo | commits judged | fixes found | rate |
|---|---:|---:|---:|
| trezor/trezor-firmware | 20,650 | 1,956 | 9.5% |
| spesmilo/electrum | 15,311 | 962 | 6.3% |
| LedgerHQ/app-ethereum | 2,640 | 459 | 17.4% |
| trustwallet/wallet-core | 4,815 | 365 | 7.6% |
| MetaMask/snaps | 3,325 | 194 | 5.8% |
| RabbyHub/Rabby | 4,489 | 186 | 4.1% |
| bitcoinjs/bitcoinjs-lib | 2,096 | 165 | 7.9% |
| WalletConnect (monorepo) | 4,095 | 143 | 3.5% |
| sparrowwallet/sparrow | 1,938 | 103 | 5.3% |
| safe-fndn/safe-smart-account | 845 | 75 | 8.9% |
| **total** | **60,204** | **4,608** | **7.7%** |

Each repository's most common failure class matches what that repository is for —
`transport` for the dapp-to-wallet channel, `contract` for the smart account, `approval`
for the system that grants third-party code wallet rights, `signing` and `firmware` for
the hardware signers. The classifier is never told which repository it is reading.

**Rate is the wrong way to rank the queue.** Electrum's 6.3% is unremarkable, but across
15,311 commits it produced 962 fixes — 21% of everything found. What matters is rate ×
history length. Neither does the keyword-era rate predict the sweep rate: Sparrow looked
like 15.4% by keyword and came in at 5.3% swept, because a keyword rate measures purity
after filtering, not how much is there.

### Next

36 tier-1 repositories remain, roughly 540,000 commits. Ordering, measured yield and
real cost per repo:

```bash
uv run python scripts/repo_priority.py            # the table
uv run python scripts/repo_priority.py --top 20 --slugs
```

Do not take that list top to bottom. `brave/brave-core` is 60,169 commits at a 2.3%
rate; `MetaMask/metamask-extension` is 42,387 at 3.6%. Both cost more than the entire
first wave and return less. Prefer repositories where a defect reaches custody directly —
hardware firmware, signing libraries, long-lived Bitcoin wallets.

Before more repositories, though: 24,299 rows already in the corpus have never been read
by any classifier, which is why `security_verdict != "refuted"` barely filters and why
two thirds of the corpus has no `mechanism`. Reading those costs no new cloning — 24,035
of them sit in repositories already on disk — and it makes both columns usable:

```bash
uv run python collection/llm_classify_fixes.py --apply --tier all \
    --in <unassessed rows>.parquet --pred-cache scratchpad_crawl/pred_cache.json \
    --apply-out assessed.csv --workers 5 \
    --engine openai --model glm-5.2 \
    --base-url https://ollama.com/v1 --api-key-env OLLAMA_API_KEY
```

Run it after a sweep, not beside one: both draw on the same quota, and two passes
competing spend their time on backoff instead of judging.

### Resume

```bash
export OLLAMA_API_KEY=...
bash scripts/keywordless_sweep.sh <slug> [<slug> ...]
```

Nothing is ever judged twice: verdicts are cached per commit URL in
`scratchpad_crawl/pred_cache.json` (121,000+ entries), so re-entering a finished
repository costs nothing and an interrupted sweep picks up where it stopped. Slugs come
from `collection/wallets.py` and are validated before the first model call.

The judging endpoint is rate-limited. Check it before a long run:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://ollama.com/v1/chat/completions \
  -H "Authorization: Bearer $OLLAMA_API_KEY" -H "Content-Type: application/json" \
  -d '{"model":"glm-5.2","messages":[{"role":"user","content":"ok"}]}'
```

`429` means the quota is spent. The sweep backs off and resumes on its own, but it will
crawl until the window resets. A quota-interrupted pass still yields its output:

```bash
uv run python collection/llm_classify_fixes.py --apply --csv-only \
  --in <enumerated.parquet> --tier all \
  --apply-out out.csv --pred-cache scratchpad_crawl/pred_cache.json
```

Also open:

- **`refuted` rows are not yet excluded** from the strongest slice. Doing that fairly
  needs the assessed share above 28%.
- **Backport detection is recorded but unused.** `is_backport` marks a commit whose patch
  appears on more than one branch. Measured lift over three repositories: 1.74×, 0.94×,
  0.45×. It does not generalise and does not order any work.

## Rebuilding

The curated table derives deterministically from the raw snapshot — no network, no keys:

```bash
uv run python pipeline/build_security_dataset.py \
  --in data/raw/train.classified.parquet --out data/wallet_vulns.parquet
uv run --extra dev python -m pytest tests/ -q      # 144 tests
```

Curation and labels from an existing crawl, without re-crawling:

```bash
bash scripts/finalize.sh                  # stages 4-10
SKIP_LABELS=1 bash scripts/finalize.sh    # gate only, fully offline
```

Re-collecting the raw snapshot is network-bound, roughly 24 hours for all 181
repositories, dominated by GitHub's 30 requests/minute search limit:

```bash
MODE=full TIER=3 bash collection/run_pipeline.sh
```

### Filtering before the gate

| Stage | Drops | Why |
|---|---:|---|
| T0 | 7 | repositories outside `collection/wallets.py`. The registry is the only authority on scope, and this runs whichever crawler produced the row |
| T2 | 7,377 | CI, docs and dependency-bump work, decided on the title |
| T2c | 1,138 | version bumps whose **package name** is custody vocabulary (`@metamask/eth-hd-keyring`, `@scure/bip39`) |
| T2d | 7,403 | author-declared `build:`/`ci:`/`test:`/`docs:` work, unless it cites an advisory or is genuine build integrity |
| GATE | 44,149 | no independent security signal fired |

## Credential masking

This corpus quotes commit text verbatim and collects security fixes, so a commit whose
purpose was "remove the hardcoded test seed" contains the seed. Every published column is
masked to `XXXXXXX` before writing ([`pipeline/redact.py`](pipeline/redact.py)):
mnemonics, `xprv`/WIF/raw-hex private keys, PEM blocks, cloud tokens. Commit SHAs,
lockfile hashes and public keys stay intact — masking those breaks `fix_commit` joins.

Masking runs on the gate's **input**, before scoring, so the row that ships is the row
that was scored. This build masked 69 mnemonics, 21 raw hex private keys, 2 `xprv`, 1 WIF
key and 12 cloud tokens. Most are canonical test vectors — the BIP-39 `abandon … about`
mnemonic is in nearly every wallet's test suite — but the pass does not try to tell live
credentials from dead ones. Counts are in [`data/manifest.json`](data/manifest.json).

## Data quality

`pre_fix_code` / `post_fix_code` carry the before/after hunks inline for 93% of rows,
`files_changed` for 96%, `fix_commit` for 100%. Inline code is capped at 8 KB and 12
files per row; without a cap one monorepo commit contributed megabytes and the parquet
write hit Arrow's 2 GB column limit.

Every row's `label` names the part of the custody chain that broke:

`key:seed-mnemonic` 3,422 · `key:storage` 2,983 · `network-io` 2,760 ·
`sign:encoding-malleability` 1,536 · `build-ci` 1,264 · `test` 1,175 · `key:derivation` 1,007

`build-ci` and `test` rows are meta-work that survived the gate. They are labelled as
such so they can be excluded.

The `is_backport` column in `scratchpad_crawl/allcommits/*.parquet` is **not usable for
the repositories swept before 2026-08-12**. It was meant to mark a fix cherry-picked to a
maintenance branch, on the reasoning that backporting is work a team only does when users
on an old release cannot wait. Detecting it renders every diff in the history, which on a
large repository does not finish, and the column was initialised to `False` — so a
timeout and a repository that genuinely backports nothing produced identical output. Nine
of twelve repositories report a zero of unknown meaning. Only `bitcoinjs-lib` (84),
`ledger-app-eth` (695) and `wallet-core` (448) are real counts.

It is now `boolean` with `NA` for "not determined", and the attempt is capped at 90
seconds rather than 420. A commit-count cut does not predict which repositories can
finish — `ethers` has 2,901 non-merge commits and still cannot render its history, because
what decides it is total diff bytes, and `ethers` carries generated bundles. The signal itself did not
survive testing either: measured lift over the base silent-fix rate was 1.74x, 0.94x and
0.45x on three repositories — no consistent direction — so nothing in the corpus depends
on it.

## Figures

`docs/figures/` holds the four figures behind the findings above, regenerated from
the committed tables so they cannot drift from the data:

| Figure | Shows |
|---|---|
| `fig1_ratio.png` | disclosed advisories against fixes shipped without one |
| `fig2b_composition.png` | all 4,608 silent fixes by defect mechanism, in five groups |
| `fig3_stack.png` | software type against the kind of defect that occurs in it |
| `fig4_folk.png` | signing and display failures against leakage of the key itself |

```bash
uv run --with matplotlib --with numpy --with uharfbuzz --with fonttools \
    --with pandas --with pyarrow python scripts/poster_figures.py
```

Labels are Japanese, and worded for a reader who has never worked on a wallet:
"custody path" appears as 資産の保管・送金処理, and an advisory as 登録された脆弱性情報 —
registered, not 公表された (announced). The figures may only claim the record is
missing, which is all the corpus can see; BTCPay's 2FA bypass was announced loudly
and is still absent from it. Titles state what each figure shows; the takeaway sits
in the subtitle. Every number is read from `data/`, never typed in.

`scripts/poster_figures.py` imports `style.py` from the repository root, so it needs
`PYTHONPATH=.` when run from anywhere other than that root.

## Layout

```
collection/   wallets.py (registry) · wallet_vocab.py (threat vocabulary)
              enumerate_commits.py — keyword-free whole-history enumeration
              llm_classify_fixes.py — the silent-fix judge
              local_diffs.py · gh_rate.py · crawlers · run_pipeline.sh
pipeline/     build_security_dataset.py — deterministic gate, tiering, verdicts
              enrich_labels.py — label / root_cause / attack_path / pre+post code
              redact.py — credential masking
scripts/      keywordless_sweep.sh — sweep repositories one at a time
              repo_priority.py — stars × measured yield × cost
              finalize.sh — rebuild from an existing crawl
tests/        quality gates, plus one regression test per bug that shipped
docs/         method · limitations · per-slice yield
```

Built with the same methodology as
[`NyxFoundation/ethereum-vuln-dataset`](https://github.com/NyxFoundation/ethereum-vuln-dataset),
retargeted from a protocol threat model to a custody one.

## License

Data: [CC-BY-4.0](LICENSE), from each wallet's own public repository.
Code under `collection/`, `pipeline/` and `scripts/`: MIT.
