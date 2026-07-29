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
