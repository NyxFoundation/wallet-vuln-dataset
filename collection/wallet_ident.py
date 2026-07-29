#!/usr/bin/env python3
"""wallet_ident.py — package coordinates and CVE-identity patterns per wallet.

Two jobs, both about *not lying to yourself*:

1. `PACKAGES` — where a repo is published, so the ecosystem advisory databases
   (OSV / RustSec / govulncheck / npm audit) can be queried by the coordinate
   they actually index. For wallets this skews heavily to **npm**: `ethers`,
   `viem`, `@walletconnect/*`, `bitcoinjs-lib`, `@trustwallet/wallet-core` and
   friends are npm packages, and npm is where their advisories live. A crawl
   that only spoke Go and crates.io (as the Ethereum-client build did) would
   miss almost the entire wallet advisory surface.

2. `CVE_IDENT` — a regex that must appear in an NVD description before a
   bare-CVE-titled row is accepted for that repo. This is the T2b guard. The
   client build needed it because NVD substring-matched "geth" inside
   `gethostbyaddr` and imported glibc CVEs as authoritative Ethereum findings.
   The wallet registry is *far* more exposed to this: "safe", "frame", "core",
   "sui", "edge", "nami", "pera", "jade", "lace" and "station" are all ordinary
   English words or common product names. Every short or ambiguous slug below
   therefore carries a deliberately narrow pattern requiring wallet context.
"""

from __future__ import annotations

import re

# --- 1. package coordinates -------------------------------------------------
# (ecosystem, package) — ecosystem strings are OSV's own spelling.
PACKAGES: dict[str, list[tuple[str, str]]] = {
    # npm — the dominant wallet ecosystem
    "metamask":            [("npm", "metamask-crx")],
    "metamask-core":       [("npm", "@metamask/keyring-controller"),
                            ("npm", "@metamask/transaction-controller"),
                            ("npm", "@metamask/permission-controller"),
                            ("npm", "@metamask/phishing-controller")],
    "metamask-snaps":      [("npm", "@metamask/snaps-sdk"),
                            ("npm", "@metamask/snaps-utils"),
                            ("npm", "@metamask/snaps-controllers")],
    "metamask-sdk":        [("npm", "@metamask/sdk")],
    "eth-sig-util":        [("npm", "@metamask/eth-sig-util"),
                            ("npm", "eth-sig-util")],
    "eth-hd-keyring":      [("npm", "@metamask/eth-hd-keyring"), ("npm", "eth-hd-keyring")],
    "keyring-controller":  [("npm", "@metamask/keyring-controller"), ("npm", "eth-keyring-controller")],
    "key-tree":            [("npm", "@metamask/key-tree")],
    "eth-phishing-detect": [("npm", "eth-phishing-detect")],
    "ethers":              [("npm", "ethers")],
    "web3js":              [("npm", "web3"), ("npm", "web3-utils"), ("npm", "web3-eth-accounts")],
    "viem":                [("npm", "viem")],
    "wagmi":               [("npm", "wagmi"), ("npm", "@wagmi/core")],
    "ethereumjs":          [("npm", "@ethereumjs/tx"), ("npm", "@ethereumjs/util"),
                            ("npm", "@ethereumjs/wallet"), ("npm", "ethereumjs-util"),
                            ("npm", "ethereumjs-wallet")],
    "noble-curves":        [("npm", "@noble/curves"), ("npm", "@noble/secp256k1")],
    "scure-bip39":         [("npm", "@scure/bip39"), ("npm", "@scure/bip32")],
    "bitcoinjs-lib":       [("npm", "bitcoinjs-lib")],
    "bitcore":             [("npm", "bitcore-lib"), ("npm", "bitcore-wallet-client")],
    "blockchain-wallet":   [("npm", "blockchain-wallet-client")],
    "cosmjs":              [("npm", "@cosmjs/crypto"), ("npm", "@cosmjs/proto-signing"),
                            ("npm", "@cosmjs/stargate")],
    "solana-web3js":       [("npm", "@solana/web3.js")],
    "solana-kit":          [("npm", "@solana/kit")],
    "solana-wallet-adapter": [("npm", "@solana/wallet-adapter-base"),
                              ("npm", "@solana/wallet-adapter-react")],
    "walletconnect":       [("npm", "@walletconnect/core"), ("npm", "@walletconnect/sign-client"),
                            ("npm", "@walletconnect/utils"), ("npm", "@walletconnect/web3wallet"),
                            ("npm", "@walletconnect/ethereum-provider")],
    "reown-appkit":        [("npm", "@reown/appkit"), ("npm", "@web3modal/core")],
    "rainbowkit":          [("npm", "@rainbow-me/rainbowkit")],
    "web3-react":          [("npm", "@web3-react/core")],
    "coinbase-sdk":        [("npm", "@coinbase/wallet-sdk")],
    "trust-provider":      [("npm", "@trustwallet/web3-provider")],
    "wallet-core":         [("npm", "@trustwallet/wallet-core")],
    "safe-sdk":            [("npm", "@safe-global/protocol-kit"),
                            ("npm", "@safe-global/safe-core-sdk"),
                            ("npm", "@safe-global/api-kit")],
    "sequence-js":         [("npm", "@0xsequence/core"), ("npm", "0xsequence")],
    "ambire-common":       [("npm", "ambire-common")],
    "magic":               [("npm", "magic-sdk"), ("npm", "@magic-sdk/provider")],
    "web3auth":            [("npm", "@web3auth/base"), ("npm", "@web3auth/modal")],
    "tkey":                [("npm", "@tkey/core"), ("npm", "@tkey/default")],
    "turnkey":             [("npm", "@turnkey/http"), ("npm", "@turnkey/sdk-browser")],
    "bitgo":               [("npm", "bitgo"), ("npm", "@bitgo/sdk-core")],
    "trezor-connect":      [("npm", "@trezor/connect"), ("npm", "trezor-connect")],
    "ledgerjs":            [("npm", "@ledgerhq/hw-app-eth"), ("npm", "@ledgerhq/hw-transport"),
                            ("npm", "@ledgerhq/hw-app-btc")],
    "onekey-hw-sdk":       [("npm", "@onekeyfe/hd-core")],
    "gridplus":            [("npm", "gridplus-sdk")],
    "coolwallet":          [("npm", "@coolwallet/core")],
    "polkadot-extension":  [("npm", "@polkadot/extension-dapp"), ("npm", "@polkadot/extension-base")],
    "bip39-tool":          [("npm", "bip39")],
    "privy-sss":           [("npm", "shamir-secret-sharing")],
    "thirdweb-js":         [("npm", "thirdweb"), ("npm", "@thirdweb-dev/sdk"),
                            ("npm", "@thirdweb-dev/wallets")],
    "openfort-js":         [("npm", "@openfort/openfort-js")],
    "particle-auth":       [("npm", "@particle-network/auth-core")],
    "web3auth-mpc":        [("npm", "@web3auth/mpc-core-kit")],
    "dfns-sdk":            [("npm", "@dfns/sdk")],
    "passkey-kit":         [("npm", "passkey-kit")],
    "simplewebauthn":      [("npm", "@simplewebauthn/server"),
                            ("npm", "@simplewebauthn/browser")],
    "zerion-sdk":          [("npm", "defi-sdk")],

    # Go
    "openfort-sss":        [("Go", "github.com/openfort-xyz/shamir-secret-sharing-go")],
    "para-mpc":            [("Go", "github.com/getpara/mpc-export")],
    "go-webauthn":         [("Go", "github.com/go-webauthn/webauthn")],
    "duo-webauthn":        [("Go", "github.com/duo-labs/webauthn")],
    "status-go":           [("Go", "github.com/status-im/status-go")],
    "bnb-tss-lib":         [("Go", "github.com/bnb-chain/tss-lib"),
                            ("Go", "github.com/bnb-chain/tss-lib/v2")],
    "kryptology":          [("Go", "github.com/coinbase/kryptology")],
    "taurus-mp-sig":       [("Go", "github.com/taurusgroup/multi-party-sig")],
    "bitbox-app":          [("Go", "github.com/BitBoxSwiss/bitbox-wallet-app"),
                            ("Go", "github.com/digitalbitbox/bitbox-wallet-app")],

    # crates.io
    "zengo-mpecdsa":       [("crates.io", "multi-party-ecdsa")],
    "librustzcash":        [("crates.io", "zcash_client_backend"),
                            ("crates.io", "zcash_primitives"), ("crates.io", "zip32")],
    "liana":               [("crates.io", "liana")],
    "imtoken-tokencore":   [("crates.io", "tcx")],
    "sui":                 [("crates.io", "sui-sdk")],
    "aptos":               [("crates.io", "aptos-sdk")],

    # PyPI
    "electrum":            [("PyPI", "electrum")],
    "hwi":                 [("PyPI", "hwi")],
    "specter":             [("PyPI", "cryptoadvance.specter")],
    "web3py":              [("PyPI", "web3"), ("PyPI", "eth-account"), ("PyPI", "eth-keys")],

    # Maven
    "web3j":               [("Maven", "org.web3j:core"), ("Maven", "org.web3j:crypto")],
    "sparrow":             [("Maven", "com.sparrowwallet:drongo")],
    "webauthn4j":          [("Maven", "com.webauthn4j:webauthn4j-core")],

    # NuGet
    "wasabi":              [("NuGet", "WalletWasabi")],
    "btcpay":              [("NuGet", "BTCPayServer")],
}

# --- 2. NVD identity patterns ----------------------------------------------
# A bare-CVE-titled NVD row is accepted for a slug only if its description
# matches this pattern. Ambiguous slugs demand explicit wallet context.
CVE_IDENT: dict[str, str] = {
    # --- ambiguous / common-word slugs: require wallet context ---
    "safe-contracts":  r"\bgnosis\b|\bsafe\b.{0,40}(?:wallet|multisig|smart account|contract)",
    "safe-wallet":     r"\bgnosis\b|\bsafe\b.{0,40}(?:wallet|multisig|smart account)",
    "safe-sdk":        r"safe.?global|@safe-global|\bsafe\b.{0,30}sdk",
    "safe-modules":    r"\bgnosis\b|\bsafe\b.{0,40}module",
    "safe-react":      r"\bgnosis\b|\bsafe\b.{0,40}(?:wallet|react)",
    "frame":           r"frame\b.{0,40}(?:wallet|ethereum|web3)|floating.{0,10}frame",
    "metamask-core":   r"metamask",
    "core-mobile":     r"\bcore\b.{0,40}(?:wallet|avalanche)|ava.?labs",
    "sui":             r"\bsui\b.{0,40}(?:blockchain|wallet|move|mysten)|mystenlabs",
    "edge":            r"edge\b.{0,40}(?:wallet|crypto|bitcoin)|edgeapp",
    "nami":            r"nami\b.{0,40}(?:wallet|cardano)|cardano.{0,20}nami",
    "pera":            r"pera\b.{0,30}(?:wallet|algorand)|algorand.{0,20}pera",
    "jade":            r"jade\b.{0,40}(?:wallet|hardware|blockstream)|blockstream",
    "lace":            r"lace\b.{0,40}(?:wallet|cardano)|cardano.{0,20}lace",
    "station":         r"station\b.{0,40}(?:wallet|terra|cosmos)|terra.{0,20}station",
    "leather":         r"leather\b.{0,30}(?:wallet|stacks)|hiro.{0,20}wallet",
    "passport":        r"passport\b.{0,40}(?:wallet|hardware|foundation devices)",
    "phoenix":         r"phoenix\b.{0,40}(?:wallet|lightning|acinq)|acinq",
    "magic":           r"magic\.link|magic.?sdk|magiclabs",
    "torus":           r"torus\b.{0,30}(?:wallet|web3auth|key)|web3auth",
    "tangem":          r"\btangem\b",
    "status-go":       r"status.?go|status\.im|status\b.{0,30}(?:wallet|network)",
    "status-desktop":  r"status\.im|status\b.{0,30}desktop",
    "status-mobile":   r"status\.im|status\b.{0,30}mobile",
    "viem":            r"\bviem\b",
    "wagmi":           r"\bwagmi\b",
    "ethers":          r"ethers\.?js|\bethers\b.{0,30}(?:library|npm|package)",
    "web3js":          r"web3\.?js|\bweb3\b.{0,30}(?:javascript|npm|library)",
    "web3py":          r"web3\.?py|\bweb3\b.{0,30}python",
    "web3j":           r"\bweb3j\b",
    "monero":          r"\bmonero\b",
    "zcash":           r"\bzcash\b",
    "bitcoin-core":    r"bitcoin core|\bbitcoind\b",
    "sequence-js":     r"0xsequence|sequence\.js|sequence\b.{0,30}wallet",
    "sequence-contracts": r"0xsequence|sequence\b.{0,30}(?:wallet|contract)",
    "kryptology":      r"\bkryptology\b",
    "backpack":        r"backpack\b.{0,40}(?:wallet|solana|xnft)|coral.?xyz",
    "rainbow":         r"rainbow\b.{0,40}(?:wallet|ethereum)|rainbow\.me",
    "rainbowkit":      r"rainbowkit|@rainbow-me",
    "taho":            r"\btaho\b|tally.?ho\b.{0,30}wallet",
    "argent-x":        r"\bargent\b",
    "argent-contracts": r"\bargent\b",
    "keplr":           r"\bkeplr\b",
    "electrum":        r"\belectrum\b",
    "sparrow":         r"sparrow\b.{0,40}(?:wallet|bitcoin)",
    "wasabi":          r"wasabi\b.{0,40}(?:wallet|bitcoin|coinjoin)",
    "liana":           r"liana\b.{0,40}(?:wallet|bitcoin)|wizardsardine",
    "muun-apollo":     r"\bmuun\b",
    "muun-falcon":     r"\bmuun\b",
    "bisq":            r"\bbisq\b",
    "specter":         r"specter\b.{0,30}(?:desktop|wallet|bitcoin)",
    "hwi":             r"\bhwi\b|hardware wallet interface",
    "gdk":             r"\bgdk\b.{0,40}(?:blockstream|wallet|green)|greenaddress",
    "green-qt":        r"blockstream green|green\b.{0,30}wallet",
    "aptos":           r"\baptos\b",
    "near-wallet":     r"\bnear\b.{0,30}(?:wallet|protocol)",
    "freighter":       r"freighter|stellar.{0,20}wallet",
    # --- embedded / seedless wallets ---
    "privy-sss":       r"\bprivy\b|shamir.?secret.?sharing",
    "openfort-signer": r"\bopenfort\b|opensigner",
    "openfort-sss":    r"\bopenfort\b",
    "openfort-contracts": r"\bopenfort\b",
    "openfort-js":     r"\bopenfort\b",
    "thirdweb-js":     r"\bthirdweb\b",
    "thirdweb-contracts": r"\bthirdweb\b",
    "particle-auth":   r"particle.?network|@particle-network",
    "para-mpc":        r"\bgetpara\b|para\b.{0,30}(?:wallet|mpc|sdk)",
    "web3auth-mpc":    r"web3auth|tor(?:us)?.?labs",
    "lit-peer":        r"lit.?protocol",
    "dfns-sdk":        r"\bdfns\b",
    # --- passkey / WebAuthn ---
    # "base" and "coinbase smart wallet" need context: "base" is unusable bare.
    "webauthn-sol":    r"webauthn.?sol|base\b.{0,40}(?:webauthn|smart wallet)",
    "coinbase-smart-wallet": r"coinbase\b.{0,30}smart wallet|smart wallet\b.{0,30}coinbase",
    "p256-verifier":   r"p256.?verifier|\bdaimo\b",
    "clave":           r"\bclave\b.{0,40}(?:wallet|zksync|passkey)|getclave",
    "passkeys-4337":   r"passkey.{0,30}4337|4337.{0,30}passkey",
    "webauthn-owner-plugin": r"webauthn.?owner|exactly\b.{0,30}webauthn",
    "passkey-kit":     r"passkey.?kit|kalepail",
    "kernel-7579":     r"zerodev|kernel\b.{0,30}(?:7579|plugin)",
    "simplewebauthn":  r"simplewebauthn|@simplewebauthn",
    "go-webauthn":     r"go-?webauthn|github\.com/go-webauthn",
    "webauthn4j":      r"webauthn4j",
    "duo-webauthn":    r"duo-?labs.{0,20}webauthn",
}

# Slugs whose name is distinctive enough that the bare token is safe.
_SELF_IDENT = [
    "metamask", "metamask-mobile", "metamask-snaps", "metamask-sdk", "rabby",
    "rabby-desktop", "enkrypt", "myetherwallet", "mycrypto", "brave-wallet",
    "trezor-firmware", "trezor-suite", "trezor-connect", "ledger-live",
    "ledgerjs", "keystone3", "coldcard", "bitbox02", "bitbox-app",
    "onekey-app", "onekey-firmware", "onekey-hw-sdk", "gridplus", "coolwallet",
    "bluewallet", "bitcoinjs-lib", "bitcore", "bitpay-wallet", "samourai",
    "nunchuk", "btcpay", "breez", "zeus", "eclair", "feather", "yoroi",
    "daedalus", "talisman", "subwallet", "cosmostation", "tonkeeper-web",
    "tonkeeper-ios", "walletconnect", "cosmjs", "ethereumjs", "noble-curves",
    "alphawallet-android", "alphawallet-ios", "cake-wallet", "stack-wallet",
    "zerodev-kernel", "biconomy-scw", "etherspot", "rhinestone", "ambire-wallet",
    "ambire-common", "zengo-mpecdsa", "gotham-city", "fireblocks-mpc", "bitgo",
    "web3auth", "tkey", "turnkey", "librustzcash", "eth-sig-util",
    "account-abstraction", "uniswap-interface", "uniswap-wallet", "wallet-core",
    "coinbase-sdk", "coinbase-mobile-sdk", "reown-appkit", "polkadot-extension",
    "solana-web3js", "solana-kit", "solana-wallet-adapter", "avalanche-wallet",
    "tron-wallet-cli", "zerion-sdk", "imtoken-tokencore", "imtoken-tokencore2",
    "monero-gui", "blockchain-wallet", "scure-bip39", "bip39-tool",
    "alchemy-modular", "alchemy-light", "soul-wallet", "ton-wallet-contract",
    "ledger-app-eth", "ledger-app-btc", "ledger-sdk", "eth-phishing-detect",
    "eth-hd-keyring", "keyring-controller", "key-tree", "trust-provider",
    "bnb-tss-lib", "taurus-mp-sig", "web3-react", "phoenix",
]

for _slug in _SELF_IDENT:
    CVE_IDENT.setdefault(_slug, r"\b" + _slug.replace("-", r"[-_ ]?") + r"\b")

CVE_IDENT.pop("pdf", None)


def names_wallet(description: str, slug: str) -> bool:
    """True when an NVD description actually refers to this wallet.

    Unknown slugs fail *closed* (return False) rather than open: importing a
    mislabelled CVE into the authoritative tier is far more damaging to the
    corpus than missing one, because tier A is what downstream consumers treat
    as ground truth.
    """
    pat = CVE_IDENT.get(slug)
    if not pat:
        return False
    return re.search(pat, description or "", re.IGNORECASE) is not None


if __name__ == "__main__":
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("w", Path(__file__).parent / "wallets.py")
    w = importlib.util.module_from_spec(spec); spec.loader.exec_module(w)
    missing = [s for s in w.WALLET_CONFIG if s not in CVE_IDENT]
    eco = {}
    for pkgs in PACKAGES.values():
        for e, _ in pkgs:
            eco[e] = eco.get(e, 0) + 1
    print(f"CVE_IDENT covers {len(CVE_IDENT)}/{len(w.WALLET_CONFIG)} slugs")
    print(f"  missing (will fail closed): {missing}")
    print(f"PACKAGES: {len(PACKAGES)} repos -> " + " · ".join(f"{k}={v}" for k, v in sorted(eco.items())))
