"""Quality gates for the curated wallet-vuln-dataset.

Two kinds of test live here:

* **Corpus gates** — properties the built dataset must hold (schema, every row
  carries a security signal, curated ⊂ raw). These skip when the data file is
  absent so the suite is runnable mid-build.
* **Regression gates** — properties of the *collection logic* that cost real
  debugging to discover. Each of these encodes a bug that actually shipped in
  an earlier run; they need no data and always run.
"""
import importlib.util

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CURATED = ROOT / "data" / "wallet_vulns.parquet"
RAW = ROOT / "data" / "raw" / "train.classified.parquet"

def _load(name: str, relpath: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relpath)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

wallets = _load("wallets", "collection/wallets.py")
vocab = _load("wallet_vocab", "collection/wallet_vocab.py")
ident = _load("wallet_ident", "collection/wallet_ident.py")
gate = _load("build_security_dataset", "pipeline/build_security_dataset.py")

REQUIRED_COLS = {
    "id", "source_platform", "severity", "title", "description",
    "source_url", "stride", "cwe_top25", "security_score", "confidence",
}

# ---------------------------------------------------------------------------
# Registry integrity
# ---------------------------------------------------------------------------

def test_registry_repos_are_unique():
    """Two slugs pointing at one repo would double-count every fix in it."""
    repos = [c["repo"] for c in wallets.WALLET_CONFIG.values()]
    dupes = {r for r in repos if repos.count(r) > 1}
    assert not dupes, f"duplicate repos in registry: {dupes}"

def test_registry_fields_are_valid():
    cats = set(vocab.GROUPS) | {
        "browser_extension", "mobile", "desktop", "hardware_firmware",
        "smart_account", "mpc_tss", "wallet_sdk", "node_wallet", "infra"}
    for slug, cfg in wallets.WALLET_CONFIG.items():
        assert cfg["category"] in cats, (slug, cfg["category"])
        assert cfg["custody"] in {"self", "hw", "mpc", "smart", "lib"}, slug
        assert cfg["tier"] in {1, 2, 3}, slug
        assert "/" in cfg["repo"], slug

def test_every_slug_has_a_cve_identity_pattern():
    """A slug with no pattern fails closed, silently dropping its NVD rows."""
    missing = [s for s in wallets.WALLET_CONFIG if s not in ident.CVE_IDENT]
    assert not missing, f"slugs without CVE_IDENT: {missing}"

# ---------------------------------------------------------------------------
# Regression: NVD identity must fail CLOSED
# ---------------------------------------------------------------------------

def test_unknown_slug_fails_closed():
    """An unmapped slug must reject, not accept.

    The client build's stage T2b exists solely to undo NVD substring matches
    ("geth" inside "gethostbyaddr") that reached the authoritative tier. A
    mislabelled CVE in tier A is worse than a missed one, so the default is
    reject.
    """
    assert ident.names_wallet("some glibc advisory", "no-such-wallet") is False

@pytest.mark.parametrize("slug,text,expected", [
    # ambiguous common-word slugs must demand wallet context
    ("safe-contracts", "A vulnerability in the safe C library allows...", False),
    ("safe-contracts", "Gnosis Safe multisig wallet contract allows...", True),
    ("frame", "Stack frame corruption in the JPEG decoder", False),
    ("frame", "Frame wallet for Ethereum mishandles...", True),
    ("edge", "Microsoft Edge browser spoofing issue", False),
    ("edge", "Edge Wallet crypto backup flaw", True),
    ("sui", "sui generis parsing bug", False),
    ("sui", "Sui blockchain wallet key handling", True),
])
def test_ambiguous_slugs_require_wallet_context(slug, text, expected):
    assert ident.names_wallet(text, slug) is expected

# ---------------------------------------------------------------------------
# Regression: keyword matching is WORD-BOUNDARY anchored, never substring
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "redesign the transaction list UI",   # 'design' must not fire 'sign'
    "add unit tests for the tx decoder",  # must not fire on short tokens
    "update README",
    "bump lodash to 4.17.21",
    "refactor button styles",
])
def test_benign_text_scores_zero(text):
    score, groups = vocab.score(text)
    assert score == 0.0, f"{text!r} wrongly fired {groups}"

@pytest.mark.parametrize("text,group", [
    ("clear seed from memory after unlock", "key_material"),
    ("EIP-712 domain separator missing chainId allows signature replay", "signing"),
    ("shamir share reconstruction accepts duplicate indices", "mpc"),
    ("user verification flag not checked in WebAuthn assertion", "platform"),
    ("dapp could bypass origin check via postMessage", "transport"),
])
def test_real_custody_bugs_fire_the_right_group(text, group):
    score, groups = vocab.score(text)
    assert score > 0 and group in groups, (text, score, groups)

def test_separator_variants_all_match():
    """Regression: `[-_]?` never matched a SPACE.

    Commit messages overwhelmingly write "nonce reuse", not "nonce-reuse", so
    the hyphen/underscore-only class silently dropped the most common form.
    """
    for text in ("nonce reuse", "nonce-reuse", "nonce_reuse"):
        assert vocab.score(f"fix {text} in the signer")[0] > 0, text

# ---------------------------------------------------------------------------
# Regression: the gate's vocabulary is DERIVED from wallet_vocab
# ---------------------------------------------------------------------------

def test_gate_vocabulary_tracks_wallet_vocab():
    """If the gate restated its keywords, crawl and gate would drift apart."""
    assert gate.STRONG_RE.search("private key leak")
    assert gate.STRONG_RE.search("signature replay")
    assert not gate.STRONG_RE.search("update the changelog")

def test_gate_scores_benign_rows_zero():
    for t in ("update README", "bump lodash to 4.17.21", "redesign settings UI"):
        assert gate.score_row(t, "", "") == 0.0, t

# ---------------------------------------------------------------------------
# Regression: label strategy must never request a phantom label
# ---------------------------------------------------------------------------

def test_label_strategy_is_registry_driven():
    """Derived, not hand-written — 181 repos cannot be hand-tuned.

    The phantom labels this produces are harmless ONLY because the crawler
    intersects them with the repo's real label set before querying: GitHub's
    pulls endpoint ignores an unknown `labels` param and returns every closed
    PR, which over-collected 138k rows on the first run.
    """
    crawl = _load("crawl_wallet_past_fixes", "collection/crawl_wallet_past_fixes.py")
    assert hasattr(crawl, "existing_labels"), \
        "existing_labels() gone — phantom labels would dump whole repos again"
    src = (ROOT / "collection/crawl_wallet_past_fixes.py").read_text()
    # the area-label and fallback crawls must hit /issues, never /pulls
    assert 'f"repos/{repo}/pulls"' not in src, \
        "pulls endpoint reintroduced; it ignores `labels` and returns all PRs"
    for slug in ("trezor-firmware", "metamask", "viem"):
        cfg = crawl.CL_LABEL_MAP[slug]
        assert cfg["area_labels"] and cfg["strategy"]

# ---------------------------------------------------------------------------
# Corpus gates (skipped until the dataset is built)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def df():
    pd = pytest.importorskip("pandas")
    if not CURATED.exists():
        pytest.skip(f"{CURATED} not built yet")
    return pd.read_parquet(CURATED)

def test_schema(df):
    assert REQUIRED_COLS <= set(df.columns), REQUIRED_COLS - set(df.columns)

def test_nonempty(df):
    assert len(df) > 500

def test_confidence_values(df):
    assert set(df["confidence"].unique()) <= {"high", "medium", "low"}

def test_score_range(df):
    assert df["security_score"].between(0.0, 1.0).all()

def test_every_row_has_a_security_signal(df):
    """GATE: every curated row carries >= 1 independent signal.

    Uses the gate's own count_signals rather than re-implementing its regexes,
    so this test cannot silently drift from the code it is guarding.
    """
    n = df.apply(gate.count_signals, axis=1)
    offenders = df.loc[n == 0, ["source_platform", "title"]].head(10)
    assert int((n == 0).sum()) == 0, f"rows with no signal:\n{offenders}"

def test_no_indiscriminate_pr_dump(df):
    """Regression: no single repo may dominate the corpus.

    The phantom-label bug made one repo contribute its entire PR history. A
    repo above 25% of all rows means it has returned.
    """
    share = df["source_platform"].value_counts(normalize=True)
    assert share.iloc[0] < 0.25, f"{share.index[0]} is {share.iloc[0]:.0%} of the corpus"

def test_curated_is_subset_of_raw(df):
    pd = pytest.importorskip("pandas")
    if not RAW.exists():
        pytest.skip("raw snapshot not built yet")
    raw = pd.read_parquet(RAW)
    assert len(df) < len(raw)
    assert set(df["id"]) <= set(raw["id"])


# ---------------------------------------------------------------------------
# Regression: T2c — dep bumps whose PACKAGE NAME is custody vocabulary
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("title", [
    "Bump @metamask/eth-simple-keyring from 6.0.0 to 6.0.1 (#288)",
    "deps: @metamask/eth-hd-keyring@^6.0.0->^7.0.1 (#275)",
    "chore: bump `@metamask/keyring-api` to ^3.0.0 (#344)",
    "chore: update eth-simple-keyring (#171)",
    "deps: bump @scure/bip39 to 1.2.0",
])
def test_dependency_bumps_are_dropped(title):
    """Wallet packages are NAMED after custody concepts.

    "keyring", "bip39" and "seed" appear in package names, so a routine version
    bump matches the key_material vocabulary and gets protected by the very
    filter meant to drop it. T2c decides on title SHAPE and overrides keyword
    protection.
    """
    assert gate.DEP_BUMP_RE.search(title), title
    assert not gate.ADVISORY_ID_RE.search(title)


@pytest.mark.parametrize("title", [
    "Validate seed across all wordlists (#77)",
    "do not allow re-initialization of keyring instance (#55)",
    "Convert private key to hex string before concatenation",
    "integrate MM @scure/bip39 fork once released (#67)",
    "chore: update validation logic",
    "fix: update keyring unlock to clear the seed",
])
def test_real_fixes_survive_the_dep_bump_rule(title):
    assert not gate.DEP_BUMP_RE.search(title), title


def _t2c_drops(title: str) -> bool:
    """The actual T2c decision: bump-shaped AND not citing an advisory id."""
    return bool(gate.DEP_BUMP_RE.search(title)) and not bool(
        gate.ADVISORY_ID_RE.search(title))


@pytest.mark.parametrize("title", [
    "Bump h2 for RUSTSEC-2024-0332",
    "bump: postcss to resolve CVE-2023-44270",
    "Bump golang.org/x/crypto from 0.16.0 to 0.17.0 for CVE-2023-48795",
])
def test_advisory_citing_bumps_are_kept(title):
    """A bump that cites an advisory id IS a security fix and must survive."""
    assert not _t2c_drops(title), title


# ---------------------------------------------------------------------------
# Regression: T2d — conventional-commit meta-work rescued by keyword protection
# ---------------------------------------------------------------------------

def _t2d_drops(title: str) -> bool:
    return (bool(gate.META_PREFIX_RE.search(title))
            and not gate.ADVISORY_ID_RE.search(title)
            and not gate.SUPPLY_CHAIN_RE.search(title))


@pytest.mark.parametrize("title", [
    "build: supply `-Wl,--high-entropy-va`",   # ASLR linker flag, not key entropy
    "ci: pin github actions",
    "test: add seed derivation cases",
    "refactor: rename keyring fields",
    "docs: document the seed backup flow",
    "style: format keyring.ts",
])
def test_meta_prefix_work_is_dropped(title):
    """The author declared it build/test/docs work; keywords must not override.

    "build: supply -Wl,--high-entropy-va" matched key_material on "entropy",
    picked up a second signal, and reached the CORROBORATED tier — a linker
    flag presented as a key-generation fix.
    """
    assert _t2d_drops(title), title


@pytest.mark.parametrize("title", [
    "build: make the release reproducible",
    "build: verify firmware signature before flashing",
    "ci: add sbom generation",
    "build: enable secure boot checks",
    "chore: bump h2 for RUSTSEC-2024-0332",
])
def test_build_integrity_work_survives(title):
    """Build-integrity IS a real wallet threat surface, not meta-work."""
    assert not _t2d_drops(title), title


@pytest.mark.parametrize("title", [
    "fix: clear seed from memory",
    "security fix: do not let user change seed",
    "ecdsa: adhere strictly to RFC6979",
])
def test_real_fixes_survive_meta_prefix_rule(title):
    assert not _t2d_drops(title), title


# ---------------------------------------------------------------------------
# Regression: SENSITIVE_PATHS tokens must not be noise
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "Bump sha.js from 2.4.11 to 2.4.12 package-lock.json",
    "Bump secp256k1 from 4.0.3 to 4.0.4",
    "docs: enhance fallback handler documentation in Safe.sol",
])
def test_sensitive_paths_do_not_fire_on_noise(text):
    """"se" fired on "Safe.sol" and "lock" on "package-lock.json".

    SENSITIVE_PATHS feeds the gate's corroborating signal, so noisy tokens
    inflated n_signals corpus-wide and pushed ordinary rows into the
    corroborated tier.
    """
    assert vocab.matches(text, vocab.SENSITIVE_PATHS) == [], text


def test_sensitive_paths_still_fire_on_custody_code():
    got = vocab.matches("fix: clear the seed from the keyring vault on unlock",
                        vocab.SENSITIVE_PATHS)
    assert {"seed", "keyring", "vault", "unlock"} <= set(got), got


def test_no_ultrashort_sensitive_path_tokens():
    """Tokens under 4 chars are almost always noise once anchored."""
    tiny = [p for p in vocab.SENSITIVE_PATHS if len(p) < 4]
    assert not tiny, f"ambiguous short path tokens: {tiny}"


# ---------------------------------------------------------------------------
# Regression: no Ethereum-client contamination
# ---------------------------------------------------------------------------

ETH_CLIENT_SLUGS = {"geth", "nethermind", "besu", "erigon", "reth", "lighthouse",
                    "lodestar", "nimbus", "prysm", "teku", "grandine"}


def test_no_ethereum_clients_in_registry():
    assert not (ETH_CLIENT_SLUGS & set(wallets.WALLET_CONFIG))


@pytest.mark.parametrize("module,attr", [
    ("collection/crawl_rustsec.py", "RUST_CLIENT_CRATES"),
    ("collection/crawl_govulncheck.py", "GO_MODULES"),
    ("collection/crawl_osv.py", "CLIENT_PACKAGES"),
    ("collection/crawl_cve.py", "CLIENT_IDENT"),
])
def test_advisory_crawlers_only_know_registry_slugs(module, attr):
    """Ported advisory crawlers kept their Ethereum-client coordinate maps.

    crawl_rustsec still listed reth/lighthouse/grandine crates and
    crawl_govulncheck still listed geth/prysm/erigon Go modules, so a full run
    imported ETHEREUM CLIENT advisories straight into the wallet corpus (56
    geth rows were found in the first pass). All coordinate maps must now
    derive from wallet_ident.PACKAGES.
    """
    mod = _load(module.split("/")[-1][:-3], module)
    slugs = set(getattr(mod, attr))
    stray = slugs - set(wallets.WALLET_CONFIG)
    assert not stray, f"{attr} references non-registry slugs: {sorted(stray)}"


# ---------------------------------------------------------------------------
# Regression: label/attack_path honesty in enrich_labels
# ---------------------------------------------------------------------------

enrich = _load("enrich_labels", "pipeline/enrich_labels.py")


@pytest.mark.parametrize("files,expected", [
    ([".github/workflows/security-code-scanner.yml"], "build-ci"),
    ([".github/workflows/main_ci.yml"], "build-ci"),
    (["docs/security.md"], "build-ci"),
    (["test/hdnode.js"], "test"),
    (["test/ecpair.spec.ts"], "test"),
])
def test_ci_and_test_only_changes_are_labelled_by_path(files, expected):
    """Paths outrank prose when nothing shippable changed.

    A workflow-only change whose title says "signature" was coming back as
    sign:encoding-malleability.
    """
    hay = " ".join(files) + " fix signature verification malleability"
    assert enrich.assign_label(hay, "wallet_sdk", files) == expected


def test_product_code_still_gets_a_custody_label():
    files = ["src/ecdsa.js", "test/ecdsa.js"]
    hay = " ".join(files) + " deterministic nonce rfc6979"
    assert enrich.assign_label(hay, "wallet_sdk", files) == "sign:nonce"


def test_attack_path_has_no_fabricated_default():
    """The client build defaulted to "malformed_input", stamping that claim
    onto every row it could not classify."""
    src = (ROOT / "pipeline/enrich_labels.py").read_text()
    assert 'derive(_AP, reason_hay, "malformed_input")' not in src
    assert 'derive(_AP, reason_hay, "unknown")' in src


# ---------------------------------------------------------------------------
# Regression: cross-wallet / standards crawlers must be wallet-domain
# ---------------------------------------------------------------------------

ETH_PROTOCOL_TERMS = ["fork choice", "fork_choice", "attestation", "slashing",
                      "sync_committee", "epoch_processing", "bls_verify"]


@pytest.mark.parametrize("module", ["collection/crawl_cross_wallet.py"])
def test_cross_and_standards_crawlers_know_only_wallets(module):
    """Both shipped fully Ethereum: crawl_cross_wallet searched wallet repos
    for "geth"/"nimbus"/"prysm" and bumped severity on "fork choice"."""
    mod = _load(module.split("/")[-1][:-3], module)
    names = getattr(mod, "CLIENT_NAMES", None) or getattr(mod, "CLIENT_PATTERNS", {})
    assert set(names) == set(wallets.WALLET_CONFIG), "not registry-driven"
    assert not (ETH_CLIENT_SLUGS & set(names))


ETH_UPSTREAM_REPOS = ["ethereum/go-ethereum", "erigontech/erigon", "sigp/lighthouse",
                      "ChainSafe/lodestar", "Consensys/teku", "prysmaticlabs/prysm",
                      "ethereum/consensus-specs", "ethereum/execution-specs",
                      "ethereum/execution-apis"]


@pytest.mark.parametrize("module,attr", [
    ("collection/crawl_cross_wallet.py", "WALLET_REPOS"),
    ("collection/crawl_cross_wallet.py", "EXTRA_REPOS"),
])
def test_crawler_repo_lists_contain_no_ethereum_upstreams(module, attr):
    """The repos a crawler SEARCHES are a separate list from what it searches FOR.

    Fixing CLIENT_NAMES alone left crawl_cross_wallet's own hardcoded
    WALLET_REPOS pointing at the 11 Ethereum clients, so the stage still emitted
    193 rows sourced from erigon/teku/lodestar/nimbus/reth/geth. The earlier test
    passed throughout, because it only checked CLIENT_NAMES — this one checks the
    search targets.
    """
    mod = _load(module.split("/")[-1][:-3], module)
    val = getattr(mod, attr)
    repos = set(val.values()) if isinstance(val, dict) else set(val)
    stray = repos & set(ETH_UPSTREAM_REPOS)
    assert not stray, f"{attr} still searches Ethereum upstreams: {sorted(stray)}"


def test_cross_wallet_severity_signals_are_custody_not_consensus():
    mod = _load("crawl_cross_wallet", "collection/crawl_cross_wallet.py")
    sig = [s.lower() for s in mod.HIGH_SEVERITY_SIGNALS]
    assert not (set(ETH_PROTOCOL_TERMS) & set(sig)), "consensus terms still present"
    assert "seed" in sig and "nonce reuse" in sig




def test_direct_pulls_filter_is_boundary_anchored():
    """Third place the substring-matching bug appeared.

    `any(kw in text ...)` let "sign" fire on "design"/"assign" and "seed" on
    "seeded". All three keyword call sites now go through vocab.matches().
    """
    src = (ROOT / "collection/mine_direct_pulls.py").read_text()
    assert "any(kw in text for kw in _ALL_KEYWORDS)" not in src
    assert "_vocab.matches(text, _ALL_KEYWORDS)" in src


@pytest.mark.parametrize("text,should_match", [
    ("redesign the assign flow", False),      # design/assign must not fire "sign"
    ("seeded random for tests", False),       # "seeded" must not fire "seed"
    ("improve sensitive data lifetime in memory for BIP-39 seed", True),
])
def test_boundary_matching_across_call_sites(text, should_match):
    assert bool(vocab.matches(text, vocab._CORE_SEARCH_TERMS)) is should_match


# ---------------------------------------------------------------------------
# Regression: EVERY per-crawler domain list must be registry-derived
# ---------------------------------------------------------------------------
# This bug class recurred four times because each crawler carries its own list
# and they serve different roles — what to match, where to search, what to
# iterate. Fixing one and testing only that one gave false confidence twice.
# This table enumerates all of them.

CRAWLER_LISTS = [
    ("collection/crawl_wallet_past_fixes.py", "WALLET_CONFIG"),
    ("collection/local_diffs.py",              "WALLET_REPOS"),
    ("collection/mine_stealth_prs.py",         "WALLET_REPOS"),
    ("collection/mine_direct_pulls.py",        "WALLET_REPOS"),
    ("collection/crawl_ghsa_advisories.py",    "WALLET_REPOS"),
    ("collection/crawl_cross_wallet.py",       "WALLET_REPOS"),
    ("collection/crawl_cross_wallet.py",       "CLIENT_NAMES"),
    ("collection/crawl_cve.py",                "CLIENT_KEYWORDS"),
    ("collection/crawl_cve.py",                "CLIENT_IDENT"),
    ("collection/crawl_osv.py",                "CLIENT_PACKAGES"),
    ("collection/crawl_rustsec.py",            "RUST_CLIENT_CRATES"),
    ("collection/crawl_govulncheck.py",        "GO_MODULES"),
]


@pytest.mark.parametrize("module,attr", CRAWLER_LISTS)
def test_every_crawler_list_is_registry_derived(module, attr):
    """No crawler may key a domain list on anything outside the registry.

    crawl_cve.CLIENT_KEYWORDS was the fourth instance found: it held the 11
    Ethereum clients AND decided which wallets `--wallet all` iterates, so the
    NVD stage queried geth/besu/teku and wrote zero rows for every real wallet.
    """
    mod = _load(module.split("/")[-1][:-3] + "_" + attr.lower(), module)
    keys = set(getattr(mod, attr))
    stray = keys - set(wallets.WALLET_CONFIG)
    assert not stray, f"{module}::{attr} has non-registry keys: {sorted(stray)[:8]}"
    assert not (ETH_CLIENT_SLUGS & keys)


def test_cve_stage_iterates_the_whole_registry():
    """--wallet all must cover all 181 repos, not a subset."""
    mod = _load("crawl_cve_iter", "collection/crawl_cve.py")
    assert len(mod.CLIENT_KEYWORDS) == len(wallets.WALLET_CONFIG)


# ---------------------------------------------------------------------------
# Regression: credential material must never reach a published artifact
# ---------------------------------------------------------------------------

redact = _load("redact", "pipeline/redact.py")


@pytest.mark.parametrize("text,kind", [
    ("leaked AKIAIOSFODNN7EXAMPLE in config", "AWS-KEY-ID"),
    ("rotate token ghp_16C7e42F292c6912E7710c838347Ae178B4a", "GITHUB-TOKEN"),
    ("remove hardcoded mnemonic: abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon about", "MNEMONIC"),
    ("private key 0x4c0883a69102937d6231471b5dbb6204fe512961708279a0b0b0e0e0e0e0e0e0",
     "HEX-PRIVKEY"),
])
def test_credential_material_is_masked(text, kind):
    out, kinds = redact.redact(text)
    assert kind in kinds, (text, kinds)
    assert "XXXXXXX" in out


@pytest.mark.parametrize("text", [
    "bump lodash to 4.17.21",
    "fix_commit 776656df8be551f8454c64d137d1a4b0e0e0aaaa",     # commit SHA
    "integrity sha512-abcdefghijklmnopqrstuvwxyz0123456789ABCD",  # lockfile hash
    "derive xpub6CUGRUo from the account node",                 # public key
])
def test_non_secrets_are_left_alone(text):
    """Redacting SHAs would break fix_commit joins; public keys are not secrets."""
    out, kinds = redact.redact(text)
    assert kinds == [], (text, kinds)
    assert out == text


def test_gate_applies_redaction_before_writing():
    src = (ROOT / "pipeline/build_security_dataset.py").read_text()
    i_redact = src.find("redact_frame")
    i_write = src.find("sec.to_parquet")
    assert i_redact != -1, "gate does not redact"
    assert i_redact < i_write, "redaction must run BEFORE any artifact is written"


def test_published_artifacts_carry_no_credential_material(df):
    """The real gate: whatever is in data/ must be clean.

    GitHub push protection blocked a push over AWS-key-shaped strings, which
    surfaced that the corpus also carried 61 mnemonics, 17 raw hex private keys,
    2 xprv and a WIF key — quoted verbatim from commits whose whole purpose was
    removing them.
    """
    found = []
    for col in ("title", "description"):
        if col not in df.columns:
            continue
        for v in df[col].fillna("").astype(str):
            _, kinds = redact.redact(v)
            if kinds:
                found.extend(kinds)
    assert not found, f"credential material in published data: {set(found)}"


def test_wallet_standards_are_covered_by_the_keyword_slices():
    """crawl_standards_divergence was dropped, not ported.

    For a client the spec IS the contract, so a consensus-specs divergence is
    directly a client bug. For a wallet, BIPs/EIPs are documentation repos — a PR
    there is a spec discussion, not a fix to any wallet. The signal that matters
    (a wallet admitting non-compliance) comes from STANDARD_TERMS feeding the
    per-repo search terms, so that path must keep working.
    """
    for std in ("bip32", "bip39", "bip44", "bip174", "slip10", "eip712",
                "eip155", "eip1271", "eip4337", "rfc6979"):
        assert std in vocab.STANDARD_TERMS, std
    terms = vocab.search_terms("trezor-firmware", "hardware_firmware", "c")
    assert terms, "per-repo search terms must be non-empty"
    assert vocab.matches("fix: EIP-712 domain separator missing chainId",
                         vocab.STANDARD_TERMS["eip712"])


# ---------------------------------------------------------------------------
# Regression: a corrupt diff cache must not break the labelling run
# ---------------------------------------------------------------------------

def test_diff_cache_is_written_atomically():
    """write_text() truncates before writing.

    A run killed mid-checkpoint left a 0-byte diff_cache.json, and every restart
    then died on json.loads at startup — a speed cache taking down the pipeline.
    """
    src = (ROOT / "pipeline/enrich_labels.py").read_text()
    assert "a.diff_cache.write_text(json.dumps(dcache))" not in src
    assert "_write_cache_atomic" in src
    assert "os.replace(tmp, path)" in src


def test_corrupt_diff_cache_is_tolerated(tmp_path):
    """Any unreadable cache state must degrade to "no cache", not raise."""
    src = (ROOT / "pipeline/enrich_labels.py").read_text()
    assert "diff cache unreadable" in src
    assert "json.JSONDecodeError" in src
    # and the real thing: json.loads on a truncated file raises the type we catch
    import json as _json
    bad = tmp_path / "diff_cache.json"
    bad.write_text("")
    with pytest.raises(_json.JSONDecodeError):
        _json.loads(bad.read_text())
