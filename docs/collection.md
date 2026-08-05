# collection/ — raw acquisition (network-bound)

These scripts rebuild the *raw* snapshot (`data/raw/train.classified.parquet`)
from scratch. They need network access and, for the silent-fix pass, an LLM.
The curated dataset is derived from the raw snapshot **offline** by
`pipeline/build_security_dataset.py` — you do not need any of this to use the
data.

## The three configuration modules

Everything else is a crawler. These three hold all the domain knowledge, and no
crawler hard-codes a repo, keyword, or package name:

| Module | Holds | Why it is separate |
|---|---|---|
| [`wallets.py`](../collection/wallets.py) | the 181-repo registry: `repo`, `category`, `ecosystem`, `custody`, `tier` | one edit adds a wallet everywhere; `tier` lets a crawl be scoped without editing the registry |
| [`wallet_vocab.py`](../collection/wallet_vocab.py) | the custody threat vocabulary — 11 weighted groups, sensitive paths, standards, per-repo search-term selection | the gate *derives* its regexes from this, so crawl and gate cannot drift apart |
| [`wallet_ident.py`](../collection/wallet_ident.py) | package coordinates (npm/Go/crates/PyPI/Maven/NuGet) and per-repo NVD identity patterns | advisory DBs index by package, not repo; and ambiguous slugs need context before an NVD row is accepted |

## Crawlers

| Group | Scripts |
|---|---|
| Per-repo repo crawl | `crawl_wallet_past_fixes.py`, `crawl_ghsa_advisories.py`, `grep_wallet_commits.py`, `mine_wallet_releases.py`, `mine_stealth_prs.py`, `mine_direct_pulls.py`, `parse_wallet_changelogs.py` |
| Advisory databases | `crawl_cve.py`, `crawl_osv.py`, `crawl_rustsec.py`, `crawl_govulncheck.py` |
| Cross-repo | `crawl_cross_wallet.py` |
| Merge + enrich | `merge_crawl_csvs.py`, `build_derived.py`, `cross_reference.py`, `blame_walk.py` |
| Silent-fix classify | `llm_classify_fixes.py` (LLM), `local_diffs.py` (rate-limit-free diffs) |
| Rate-limit plumbing | `gh_rate.py` |
| Orchestrator | `run_pipeline.sh` |

Dropped from the client build because they have no wallet analogue:
`crawl_teku_jira_refs.py` (one client's JIRA), `extract_nimbus_urgency.py` (one
client's release-note template), and `crawl_specs_divergence.py`.

**Why specs-divergence was dropped rather than ported.** It was first retargeted
from `ethereum/consensus-specs` to `bitcoin/bips` + `satoshilabs/slips` +
`ethereum/EIPs`, then deleted, because the concept does not survive the move.
For a client, the spec *is* the contract: a consensus-specs divergence is
directly a client bug. For a wallet, BIPs and EIPs are documentation repos — a
PR to `bitcoin/bips` is a spec discussion, not a fix to any wallet's code.

The signal that *does* matter — a wallet admitting it was not standard-compliant
— is already captured, because `wallet_vocab.STANDARD_TERMS` feeds the per-repo
search terms used by commit-grep and stealth. Measured on the curated corpus:

| standard | rows | | standard | rows |
|---|---:|---|---|---:|
| BIP-174 (PSBT) | 662 | | ERC-4337 | 219 |
| EIP-712 | 511 | | EIP-2612 | 119 |
| BIP-32 | 335 | | EIP-155 | 89 |
| BIP-39 | 321 | | EIP-1271 | 69 |
| BIP-44 | 300 | | SLIP-0039 | 64 |
| | | | RFC 6979 | 34 |

2,779 curated rows reference a wallet standard, including
`ledger-app-eth` "Stale schema hash lets EIP-712 metadata signatures apply to a
different contract" and "Blind-signing bypass in EIP-712 FULL filtering
activation". Fixing the crawler would have added spec-repo chatter, not fixes.

## Running it

```bash
# smoke: tier-1 repos, capped
MODE=smoke bash collection/run_pipeline.sh

# full corpus
MODE=full TIER=3 bash collection/run_pipeline.sh
```

`TIER` scopes the search-heavy stages (1 = 46 mass-market repos, 3 = all 181).
The advisory crawlers are cheap and always cover the whole registry regardless.

## Two scale problems the client build never hit

Going from 11 repos to 181 broke two assumptions. Both are worth knowing about
before modifying a crawler.

### Rate limits are the binding constraint, and 403 is ambiguous

A full crawl issues roughly 5,500 `search/*` calls against a **30 requests per
minute** limit. HTTP 403 is therefore not an exception — it is the expected
steady state. The client crawlers treated any 403 as an auth misconfiguration
and aborted the entire run, which at this scale loses every repo after the
first throttle.

`gh_rate.py` classifies the 403 body instead:

| Kind | Signal | Response |
|---|---|---|
| primary rate limit | `API rate limit exceeded` | sleep until GitHub's own reset timestamp |
| secondary rate limit | `secondary rate limit` / `abuse detection` | exponential backoff |
| real auth failure | anything else | raise immediately |

The third case must stay distinct, or a broken token spins forever instead of
failing loudly.

### `GET /repos/{owner}/{repo}/pulls` silently ignores `labels`

This one produced a 138,738-row over-collection before it was caught. The pulls
endpoint does not support a `labels` query parameter; it ignores the unknown
param and returns **every closed PR**, paginated:

```
pulls?labels=zzznonexistent   -> 100 rows   (all closed PRs)
issues?labels=zzznonexistent  -> 0 rows     (correct)
issues?labels=security        -> 8 rows     (correct)
```

It was latent in the client build because 11 repos had hand-written label maps
whose labels mostly existed. Here the label strategy is **derived** from the
registry category, so most candidate labels (`bootloader`, `signing`,
`keyring`) do not exist on any given repo — and each phantom label dumped that
repo's entire history into the corpus.

Two guards now, both required:

1. `existing_labels(repo)` fetches the repo's real label set once and the crawl
   queries only labels it actually defines.
2. Label-filtered crawls use the **issues** endpoint, which honours `labels`,
   keeping items whose `pull_request.merged_at` is set.

`tests/test_security_dataset.py` asserts the pulls endpoint never returns and
that no single repo exceeds 25% of the corpus.

### The reference project's identity leaks in through a different door each time

Four separate fixes went out for the same bug class — a crawler that kept the
Ethereum-client coordinates it was ported with. Each fix patched one crawler and
added a test for that crawler, and the next full run surfaced another:
`crawl_rustsec` (reth/lighthouse crates), `crawl_govulncheck` (geth/prysm Go
modules), `crawl_cross_wallet` (searched the 11 clients), `crawl_cve`
(`CLIENT_KEYWORDS`). A fifth then turned up in the published data itself:
`merge_crawl_csvs` defaulted every supplementary row's `domain` to the literal
`"ethereum"`, so **90% of the published corpus described itself as an Ethereum
dataset**, and `manifest.json` announced `"11 Ethereum execution + consensus
wallets"` for a 181-repo wallet corpus.

Patching the Nth crawler is not a fix for this, because the defect is that each
crawler is trusted to know what this project covers. The gate now enforces it on
the way **out**, where there is only one door:

- **T0** drops any row whose `source_platform` is not in `collection/wallets.py`
  — the registry is the sole authority on what a wallet repo is, and it does not
  matter which crawler produced the row. It caught seven `eips` rows (spec-repo
  PRs, left behind when the standards slice was deleted) still in the published
  corpus.
- The gate then **stamps** `domain` itself on the survivors instead of trusting
  the crawler's value, and the manifest reads its `domain` and `source` off the
  data rather than from a literal.
- `merge_crawl_csvs` inherits the domain from the table it merges into, and
  refuses to guess when that table is ambiguous.

## Measured yield per slice

Numbers from the current build, so the cost of each stage is visible rather than
assumed.

| Slice | Raw rows | Notes |
|---|---:|---|
| repo advisories (GHSA) | 16 | across **all 181 repos**; 167 repos publish none |
| advisory DBs (OSV/RustSec/govulncheck/NVD) | ~80 | skewed to npm — see below |
| canonical PR/issue crawl | 5,299 | |
| commit-grep | 29,277 | 22% survive de-noise + scoring |
| release notes + changelogs | 2,169 | |
| stealth PRs | 53,286 | 181/181 repos; only **10%** score on title, but **78%** of those are new |
| direct_pulls | ~1,600/repo | most exhaustive, most redundant — **30%** new |

**The advisory slice is 16 rows.** That single number is the argument for
everything else in this directory.

**direct_pulls is the weakest slice, and the pagination sleep — not the rate
limit — was its cost.** It paginates every closed PR per repo and title-filters,
so it is the most exhaustive slice and the most redundant. Measured on the five
largest repos (the MetaMask family):

| | rows |
|---|---:|
| raw rows | 8,140 |
| scoring rows | 1,410 |
| **not already in commit-grep OR stealth** | **418 (30%)** |

30% marginal, against stealth's 78%. It is kept because it is the only slice
that actually walks *all* closed PRs.

**"Uncapped" pagination is unbounded, not thorough.** `--max-pages 0` had no
ceiling, and `MetaMask/eth-phishing-detect` has **255,610 closed PRs (~2,556
pages)** because every blocklist domain addition is a PR. The stage sat on that
one repo for over an hour and would have yielded zero security fixes from it.
brave-core (380 pages), metamask-extension (271) and bitcoin (242) are large for
real reasons but still dominate wall-clock.

The reference client build had exactly this guard — `PR_PAGE_CAP = 2000`, "geth
has ~30k closed PRs; paginating the full list would burn rate-limit" — it was
simply missing from this crawler. `PAGE_CEILING` now defaults to 150 pages
(15,000 most recent closed PRs per repo, override with `DIRECT_PAGE_CEILING`).
Deep history is not lost: commit-grep and stealth are not page-bound and cover
it.

Its `sleep_between` default of 1.0s
was pure waste: this endpoint is on the `core` limit (5,000/hr = 1.4 req/s) and
a running crawl measured 4999/5000 remaining. Large repos have hundreds of pages
(metamask ~300), so the sleep alone cost ~10 min/repo. Lowered to 0.35s
(override with `DIRECT_PAGE_SLEEP`), cutting the stage from ~17h to ~11h with no
loss of coverage; `gh_rate` still backs off if a limit is genuinely hit.

**Stealth PRs look wasteful and are not.** Only 8% of stealth rows score at all
— dependabot PR bodies quote the security advisory of the dependency they bump,
so a body-keyword search matches essentially every one of them. But measuring
the overlap against commit-grep on the first 44 repos:

| | rows | |
|---|---:|---|
| stealth scoring rows | 2,917 | |
| **not already found by commit-grep** | **2,396** | **82%** |
| duplicate of a commit row | 521 | 18% |

So the two slices find *different* things: a squash-merged PR's title often
differs from the commit subject, and merge commits carry no description at all.
Examples recovered only by the stealth slice include `bitcoinjs-lib` "Stricter
ecdsa RFC 6979 adherence" and `bitcoin-core` "ECDSA signature optimization and
more DoS prevention". The low precision is absorbed by the gate (T2c drops the
dependabot rows, the gate drops the unscored remainder); the cost is wall-clock,
not corpus quality.

## Documentation

[silent_fix_detection](./silent_fix_detection.md) · [limitations](./limitations.md)
