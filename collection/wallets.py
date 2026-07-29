#!/usr/bin/env python3
"""wallets.py — the wallet registry.

Single source of truth for *which repositories the corpus covers*. Every
crawler imports `WALLET_CONFIG` from here; nothing else hard-codes a repo slug.

Scope rule
----------
A repo is in scope when a defect in it can lead to **loss of user funds, key
material, or signing authority**. That is deliberately wider than "a wallet
app": it includes the hardware firmware that holds the seed, the smart-contract
account that holds the balance, the MPC/TSS library that shards the key, and
the signing/transport libraries every wallet UI is built on (`ethers`, `viem`,
`bitcoinjs-lib`, `wallet-core`, WalletConnect). Historically these libraries
are where the *severe*, cross-wallet bugs live — a single `noble-curves` or
`bitcoinjs-lib` defect is simultaneously a bug in a hundred wallets.

Fields
------
repo        canonical upstream `owner/name` (redirects already resolved)
category    browser_extension | mobile | desktop | hardware_firmware |
            smart_account | mpc_tss | wallet_sdk | node_wallet | infra
ecosystem   chain family the wallet primarily serves
custody     self  (user holds the key)
            hw    (key never leaves a secure element)
            mpc   (key is sharded / threshold)
            smart (key authority is contract-defined)
            lib   (no key custody itself; used by wallets that have it)
tier        1 = mass-market / very widely used, 2 = significant, 3 = niche
archived    upstream is archived (history still valuable; no new fixes)

`tier` exists so a crawl can be scoped ("tier 1 only") without editing the
registry, and so `docs/limitations.md` can state coverage honestly.

Closed-source wallets are intentionally absent and are listed in
`docs/limitations.md` — Phantom, Exodus, Binance Web3 Wallet, OKX Wallet,
Bitget, SafePal, Coinomi, Atomic and the exchange custodians publish no
commit history, so no silent fix of theirs is observable by construction.
"""

from __future__ import annotations

WALLET_CONFIG: dict[str, dict] = {
    # ---- browser extensions / web wallets --------------------------------
    "metamask":            {"repo": "MetaMask/metamask-extension",       "category": "browser_extension", "ecosystem": "evm",      "custody": "self",  "tier": 1},
    "metamask-mobile":     {"repo": "MetaMask/metamask-mobile",          "category": "mobile",            "ecosystem": "evm",      "custody": "self",  "tier": 1},
    "metamask-core":       {"repo": "MetaMask/core",                     "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 1},
    "metamask-snaps":      {"repo": "MetaMask/snaps",                    "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 1},
    "metamask-sdk":        {"repo": "MetaMask/metamask-sdk",             "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 2},
    "eth-phishing-detect": {"repo": "MetaMask/eth-phishing-detect",      "category": "infra",             "ecosystem": "evm",      "custody": "lib",   "tier": 2},
    "eth-sig-util":        {"repo": "MetaMask/eth-sig-util",             "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 1},
    "eth-hd-keyring":      {"repo": "MetaMask/eth-hd-keyring",           "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 2, "archived": True},
    "keyring-controller":  {"repo": "MetaMask/KeyringController",        "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 2, "archived": True},
    "key-tree":            {"repo": "MetaMask/key-tree",                 "category": "wallet_sdk",        "ecosystem": "multi",    "custody": "lib",   "tier": 2},
    "rabby":               {"repo": "RabbyHub/Rabby",                    "category": "browser_extension", "ecosystem": "evm",      "custody": "self",  "tier": 1},
    "rabby-desktop":       {"repo": "RabbyHub/RabbyDesktop",             "category": "desktop",           "ecosystem": "evm",      "custody": "self",  "tier": 3},
    "rainbow":             {"repo": "rainbow-me/rainbow",                "category": "mobile",            "ecosystem": "evm",      "custody": "self",  "tier": 1},
    "taho":                {"repo": "tahowallet/extension",              "category": "browser_extension", "ecosystem": "evm",      "custody": "self",  "tier": 2},
    "enkrypt":             {"repo": "enkryptcom/enKrypt",                "category": "browser_extension", "ecosystem": "multi",    "custody": "self",  "tier": 2},
    "myetherwallet":       {"repo": "MyEtherWallet/MyEtherWallet",       "category": "browser_extension", "ecosystem": "evm",      "custody": "self",  "tier": 2},
    "mycrypto":            {"repo": "MyCryptoHQ/MyCrypto",               "category": "desktop",           "ecosystem": "evm",      "custody": "self",  "tier": 3},
    "brave-wallet":        {"repo": "brave/brave-core",                  "category": "browser_extension", "ecosystem": "multi",    "custody": "self",  "tier": 1},
    "frame":               {"repo": "floating/frame",                    "category": "desktop",           "ecosystem": "evm",      "custody": "self",  "tier": 2},
    "uniswap-wallet":      {"repo": "Uniswap/wallet",                    "category": "mobile",            "ecosystem": "evm",      "custody": "self",  "tier": 2, "archived": True},
    "uniswap-interface":   {"repo": "Uniswap/interface",                 "category": "browser_extension", "ecosystem": "evm",      "custody": "self",  "tier": 1},
    "trust-provider":      {"repo": "trustwallet/trust-web3-provider",   "category": "wallet_sdk",        "ecosystem": "multi",    "custody": "lib",   "tier": 1},
    "wallet-core":         {"repo": "trustwallet/wallet-core",           "category": "wallet_sdk",        "ecosystem": "multi",    "custody": "lib",   "tier": 1},
    "coinbase-sdk":        {"repo": "coinbase/coinbase-wallet-sdk",      "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 1},
    "coinbase-mobile-sdk": {"repo": "coinbase/wallet-mobile-sdk",        "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 3},
    "alphawallet-android": {"repo": "AlphaWallet/alpha-wallet-android",  "category": "mobile",            "ecosystem": "evm",      "custody": "self",  "tier": 2},
    "alphawallet-ios":     {"repo": "AlphaWallet/alpha-wallet-ios",      "category": "mobile",            "ecosystem": "evm",      "custody": "self",  "tier": 2},
    "edge":                {"repo": "EdgeApp/edge-react-gui",            "category": "mobile",            "ecosystem": "multi",    "custody": "self",  "tier": 2},
    "status-go":           {"repo": "status-im/status-go",               "category": "mobile",            "ecosystem": "evm",      "custody": "self",  "tier": 2},
    "status-desktop":      {"repo": "status-im/status-app",              "category": "desktop",           "ecosystem": "evm",      "custody": "self",  "tier": 2},
    "status-mobile":       {"repo": "status-im/status-legacy",           "category": "mobile",            "ecosystem": "evm",      "custody": "self",  "tier": 3, "archived": True},
    "imtoken-tokencore":   {"repo": "consenlabs/token-core",             "category": "wallet_sdk",        "ecosystem": "multi",    "custody": "lib",   "tier": 2, "archived": True},
    "imtoken-tokencore2":  {"repo": "consenlabs/token-core-monorepo",    "category": "wallet_sdk",        "ecosystem": "multi",    "custody": "lib",   "tier": 2},

    # ---- bitcoin & UTXO wallets ------------------------------------------
    "electrum":            {"repo": "spesmilo/electrum",                 "category": "desktop",           "ecosystem": "bitcoin",  "custody": "self",  "tier": 1},
    "bluewallet":          {"repo": "BlueWallet/BlueWallet",             "category": "mobile",            "ecosystem": "bitcoin",  "custody": "self",  "tier": 1},
    "sparrow":             {"repo": "sparrowwallet/sparrow",             "category": "desktop",           "ecosystem": "bitcoin",  "custody": "self",  "tier": 1},
    "wasabi":              {"repo": "WalletWasabi/WalletWasabi",         "category": "desktop",           "ecosystem": "bitcoin",  "custody": "self",  "tier": 1},
    "bitcoin-core":        {"repo": "bitcoin/bitcoin",                   "category": "node_wallet",       "ecosystem": "bitcoin",  "custody": "self",  "tier": 1},
    "bitcoinjs-lib":       {"repo": "bitcoinjs/bitcoinjs-lib",           "category": "wallet_sdk",        "ecosystem": "bitcoin",  "custody": "lib",   "tier": 1},
    "bitpay-wallet":       {"repo": "bitpay/wallet",                     "category": "mobile",            "ecosystem": "bitcoin",  "custody": "self",  "tier": 2},
    "bitcore":             {"repo": "bitpay/bitcore",                    "category": "wallet_sdk",        "ecosystem": "bitcoin",  "custody": "lib",   "tier": 2},
    "blockchain-wallet":   {"repo": "blockchain/My-Wallet-V3",           "category": "wallet_sdk",        "ecosystem": "bitcoin",  "custody": "lib",   "tier": 2, "archived": True},
    "muun-apollo":         {"repo": "muun/apollo",                       "category": "mobile",            "ecosystem": "bitcoin",  "custody": "self",  "tier": 2},
    "muun-falcon":         {"repo": "muun/falcon",                       "category": "mobile",            "ecosystem": "bitcoin",  "custody": "self",  "tier": 2},
    "samourai":            {"repo": "Samourai-Wallet/samourai-wallet-android", "category": "mobile",      "ecosystem": "bitcoin",  "custody": "self",  "tier": 2},
    "green-qt":            {"repo": "Blockstream/green_qt",              "category": "desktop",           "ecosystem": "bitcoin",  "custody": "self",  "tier": 2},
    "gdk":                 {"repo": "Blockstream/gdk",                   "category": "wallet_sdk",        "ecosystem": "bitcoin",  "custody": "lib",   "tier": 2},
    "specter":             {"repo": "cryptoadvance/specter-desktop",     "category": "desktop",           "ecosystem": "bitcoin",  "custody": "self",  "tier": 2},
    "hwi":                 {"repo": "bitcoin-core/HWI",                  "category": "wallet_sdk",        "ecosystem": "bitcoin",  "custody": "lib",   "tier": 2},
    "liana":               {"repo": "wizardsardine/liana",               "category": "desktop",           "ecosystem": "bitcoin",  "custody": "self",  "tier": 3},
    "nunchuk":             {"repo": "nunchuk-io/nunchuk-android",        "category": "mobile",            "ecosystem": "bitcoin",  "custody": "self",  "tier": 3},
    "btcpay":              {"repo": "btcpayserver/btcpayserver",         "category": "node_wallet",       "ecosystem": "bitcoin",  "custody": "self",  "tier": 2},
    "bisq":                {"repo": "bisq-network/bisq",                 "category": "desktop",           "ecosystem": "bitcoin",  "custody": "self",  "tier": 2},
    "stack-wallet":        {"repo": "cypherstack/stack_wallet",          "category": "mobile",            "ecosystem": "multi",    "custody": "self",  "tier": 3},
    "cake-wallet":         {"repo": "cake-tech/cake_wallet",             "category": "mobile",            "ecosystem": "monero",   "custody": "self",  "tier": 2},

    # ---- lightning wallets ------------------------------------------------
    "phoenix":             {"repo": "ACINQ/phoenix",                     "category": "mobile",            "ecosystem": "lightning","custody": "self",  "tier": 2},
    "eclair":              {"repo": "ACINQ/eclair",                      "category": "node_wallet",       "ecosystem": "lightning","custody": "self",  "tier": 2},
    "breez":               {"repo": "breez/breezmobile",                 "category": "mobile",            "ecosystem": "lightning","custody": "self",  "tier": 2},
    "zeus":                {"repo": "ZeusLN/zeus",                       "category": "mobile",            "ecosystem": "lightning","custody": "self",  "tier": 2},

    # ---- privacy-coin wallets ---------------------------------------------
    "monero":              {"repo": "monero-project/monero",             "category": "node_wallet",       "ecosystem": "monero",   "custody": "self",  "tier": 1},
    "monero-gui":          {"repo": "monero-project/monero-gui",         "category": "desktop",           "ecosystem": "monero",   "custody": "self",  "tier": 2},
    "feather":             {"repo": "feather-wallet/feather",            "category": "desktop",           "ecosystem": "monero",   "custody": "self",  "tier": 3},
    "zcash":               {"repo": "zcash/zcash",                       "category": "node_wallet",       "ecosystem": "zcash",    "custody": "self",  "tier": 2, "archived": True},
    "librustzcash":        {"repo": "zcash/librustzcash",                "category": "wallet_sdk",        "ecosystem": "zcash",    "custody": "lib",   "tier": 2},

    # ---- hardware wallet firmware & host apps ------------------------------
    "trezor-firmware":     {"repo": "trezor/trezor-firmware",            "category": "hardware_firmware", "ecosystem": "multi",    "custody": "hw",    "tier": 1},
    "trezor-suite":        {"repo": "trezor/trezor-suite",               "category": "desktop",           "ecosystem": "multi",    "custody": "hw",    "tier": 1},
    "trezor-connect":      {"repo": "trezor/connect",                    "category": "wallet_sdk",        "ecosystem": "multi",    "custody": "lib",   "tier": 2, "archived": True},
    "ledger-live":         {"repo": "LedgerHQ/ledger-live",              "category": "desktop",           "ecosystem": "multi",    "custody": "hw",    "tier": 1},
    "ledger-app-eth":      {"repo": "LedgerHQ/app-ethereum",             "category": "hardware_firmware", "ecosystem": "evm",      "custody": "hw",    "tier": 1},
    "ledger-app-btc":      {"repo": "LedgerHQ/app-bitcoin",              "category": "hardware_firmware", "ecosystem": "bitcoin",  "custody": "hw",    "tier": 2},
    "ledger-sdk":          {"repo": "LedgerHQ/ledger-secure-sdk",        "category": "hardware_firmware", "ecosystem": "multi",    "custody": "hw",    "tier": 2},
    "ledgerjs":            {"repo": "LedgerHQ/ledgerjs",                 "category": "wallet_sdk",        "ecosystem": "multi",    "custody": "lib",   "tier": 2, "archived": True},
    "keystone3":           {"repo": "KeystoneHQ/keystone3-firmware",     "category": "hardware_firmware", "ecosystem": "multi",    "custody": "hw",    "tier": 2},
    "coldcard":            {"repo": "Coldcard/firmware",                 "category": "hardware_firmware", "ecosystem": "bitcoin",  "custody": "hw",    "tier": 2},
    "bitbox02":            {"repo": "BitBoxSwiss/bitbox02-firmware",     "category": "hardware_firmware", "ecosystem": "multi",    "custody": "hw",    "tier": 2},
    "bitbox-app":          {"repo": "BitBoxSwiss/bitbox-wallet-app",     "category": "desktop",           "ecosystem": "multi",    "custody": "hw",    "tier": 2},
    "onekey-app":          {"repo": "OneKeyHQ/app-monorepo",             "category": "mobile",            "ecosystem": "multi",    "custody": "hw",    "tier": 1},
    "onekey-firmware":     {"repo": "OneKeyHQ/firmware",                 "category": "hardware_firmware", "ecosystem": "multi",    "custody": "hw",    "tier": 2},
    "onekey-hw-sdk":       {"repo": "OneKeyHQ/hardware-js-sdk",          "category": "wallet_sdk",        "ecosystem": "multi",    "custody": "lib",   "tier": 3},
    "jade":                {"repo": "Blockstream/Jade",                  "category": "hardware_firmware", "ecosystem": "bitcoin",  "custody": "hw",    "tier": 2},
    "passport":            {"repo": "Foundation-Devices/passport2",      "category": "hardware_firmware", "ecosystem": "bitcoin",  "custody": "hw",    "tier": 3},
    "tangem":              {"repo": "tangem/tangem-app-ios",             "category": "mobile",            "ecosystem": "multi",    "custody": "hw",    "tier": 2},
    "gridplus":            {"repo": "GridPlus/lattice-connect-v2",       "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 3},
    "coolwallet":          {"repo": "CoolBitX-Technology/coolwallet-sdk","category": "wallet_sdk",        "ecosystem": "multi",    "custody": "lib",   "tier": 3},

    # ---- smart-contract accounts (ERC-4337 & multisig) ---------------------
    "safe-contracts":      {"repo": "safe-fndn/safe-smart-account",      "category": "smart_account",     "ecosystem": "evm",      "custody": "smart", "tier": 1},
    "safe-wallet":         {"repo": "safe-global/safe-wallet-monorepo",  "category": "browser_extension", "ecosystem": "evm",      "custody": "smart", "tier": 1},
    "safe-sdk":            {"repo": "safe-global/safe-core-sdk",         "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 1},
    "safe-modules":        {"repo": "safe-fndn/safe-modules",            "category": "smart_account",     "ecosystem": "evm",      "custody": "smart", "tier": 2},
    "safe-react":          {"repo": "5afe/safe-react",                   "category": "browser_extension", "ecosystem": "evm",      "custody": "smart", "tier": 2, "archived": True},
    "account-abstraction": {"repo": "eth-infinitism/account-abstraction","category": "smart_account",     "ecosystem": "evm",      "custody": "smart", "tier": 1},
    "alchemy-modular":     {"repo": "alchemyplatform/modular-account",   "category": "smart_account",     "ecosystem": "evm",      "custody": "smart", "tier": 2},
    "alchemy-light":       {"repo": "alchemyplatform/light-account",     "category": "smart_account",     "ecosystem": "evm",      "custody": "smart", "tier": 2},
    "zerodev-kernel":      {"repo": "zerodevapp/kernel",                 "category": "smart_account",     "ecosystem": "evm",      "custody": "smart", "tier": 2},
    "soul-wallet":         {"repo": "Elytro-eth/soul-wallet-contract",   "category": "smart_account",     "ecosystem": "evm",      "custody": "smart", "tier": 3, "archived": True},
    "biconomy-scw":        {"repo": "bcnmy/scw-contracts",               "category": "smart_account",     "ecosystem": "evm",      "custody": "smart", "tier": 2},
    "etherspot":           {"repo": "etherspot/etherspot-prime-contracts","category": "smart_account",    "ecosystem": "evm",      "custody": "smart", "tier": 3},
    "sequence-contracts":  {"repo": "0xsequence/wallet-contracts",       "category": "smart_account",     "ecosystem": "evm",      "custody": "smart", "tier": 2},
    "sequence-js":         {"repo": "0xsequence/sequence.js",            "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 2},
    "ambire-wallet":       {"repo": "AmbireTech/wallet",                 "category": "browser_extension", "ecosystem": "evm",      "custody": "smart", "tier": 2},
    "ambire-common":       {"repo": "AmbireTech/ambire-common",          "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 2},
    "argent-x":            {"repo": "argentlabs/argent-x",               "category": "browser_extension", "ecosystem": "starknet", "custody": "smart", "tier": 2},
    "argent-contracts":    {"repo": "argentlabs/argent-contracts-starknet","category": "smart_account",   "ecosystem": "starknet", "custody": "smart", "tier": 2},
    "rhinestone":          {"repo": "rhinestonewtf/modulekit",           "category": "smart_account",     "ecosystem": "evm",      "custody": "smart", "tier": 3},

    # ---- MPC / TSS / key-management ---------------------------------------
    "zengo-mpecdsa":       {"repo": "ZenGo-X/multi-party-ecdsa",         "category": "mpc_tss",           "ecosystem": "multi",    "custody": "mpc",   "tier": 2},
    "gotham-city":         {"repo": "ZenGo-X/gotham-city",               "category": "mpc_tss",           "ecosystem": "bitcoin",  "custody": "mpc",   "tier": 3},
    "bnb-tss-lib":         {"repo": "bnb-chain/tss-lib",                 "category": "mpc_tss",           "ecosystem": "multi",    "custody": "mpc",   "tier": 1},
    "fireblocks-mpc":      {"repo": "fireblocks/mpc-lib",                "category": "mpc_tss",           "ecosystem": "multi",    "custody": "mpc",   "tier": 2},
    "kryptology":          {"repo": "coinbase/kryptology",               "category": "mpc_tss",           "ecosystem": "multi",    "custody": "mpc",   "tier": 2, "archived": True},
    "taurus-mp-sig":       {"repo": "taurushq-io/multi-party-sig",       "category": "mpc_tss",           "ecosystem": "multi",    "custody": "mpc",   "tier": 3},
    "web3auth":            {"repo": "Web3Auth/web3auth-web",             "category": "mpc_tss",           "ecosystem": "multi",    "custody": "mpc",   "tier": 2},
    "tkey":                {"repo": "MetaMask/tkey",                     "category": "mpc_tss",           "ecosystem": "multi",    "custody": "mpc",   "tier": 2},
    "torus":               {"repo": "torusresearch/torus-website",       "category": "mpc_tss",           "ecosystem": "multi",    "custody": "mpc",   "tier": 3},
    "turnkey":             {"repo": "tkhq/sdk",                          "category": "mpc_tss",           "ecosystem": "multi",    "custody": "mpc",   "tier": 3},
    "magic":               {"repo": "magiclabs/magic-js",                "category": "wallet_sdk",        "ecosystem": "multi",    "custody": "lib",   "tier": 2},
    "bitgo":               {"repo": "BitGo/BitGoJS",                     "category": "mpc_tss",           "ecosystem": "multi",    "custody": "mpc",   "tier": 2},

    # ---- connection / signing transport -----------------------------------
    "walletconnect":       {"repo": "WalletConnect/walletconnect-monorepo","category": "infra",           "ecosystem": "multi",    "custody": "lib",   "tier": 1},
    "reown-appkit":        {"repo": "reown-com/appkit",                  "category": "infra",             "ecosystem": "multi",    "custody": "lib",   "tier": 1},
    "rainbowkit":          {"repo": "rainbow-me/rainbowkit",             "category": "infra",             "ecosystem": "evm",      "custody": "lib",   "tier": 2},
    "web3-react":          {"repo": "Uniswap/web3-react",                "category": "infra",             "ecosystem": "evm",      "custody": "lib",   "tier": 2, "archived": True},

    # ---- signing / crypto libraries wallets depend on ----------------------
    "ethers":              {"repo": "ethers-io/ethers.js",               "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 1},
    "web3js":              {"repo": "web3/web3.js",                      "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 1, "archived": True},
    "viem":                {"repo": "wevm/viem",                         "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 1},
    "wagmi":               {"repo": "wevm/wagmi",                        "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 1},
    "ethereumjs":          {"repo": "ethereumjs/ethereumjs-monorepo",    "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 2},
    "web3py":              {"repo": "ApeWorX/web3.py",                   "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 2},
    "web3j":               {"repo": "LFDT-web3j/web3j",                  "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 2},
    "noble-curves":        {"repo": "paulmillr/noble-curves",            "category": "wallet_sdk",        "ecosystem": "multi",    "custody": "lib",   "tier": 1},
    "scure-bip39":         {"repo": "paulmillr/scure-bip39",             "category": "wallet_sdk",        "ecosystem": "multi",    "custody": "lib",   "tier": 1},
    "bip39-tool":          {"repo": "iancoleman/bip39",                  "category": "wallet_sdk",        "ecosystem": "multi",    "custody": "lib",   "tier": 2},
    "cosmjs":              {"repo": "cosmos/cosmjs",                     "category": "wallet_sdk",        "ecosystem": "cosmos",   "custody": "lib",   "tier": 1},
    "solana-web3js":       {"repo": "solana-foundation/solana-web3.js",  "category": "wallet_sdk",        "ecosystem": "solana",   "custody": "lib",   "tier": 1},
    "solana-kit":          {"repo": "anza-xyz/kit",                      "category": "wallet_sdk",        "ecosystem": "solana",   "custody": "lib",   "tier": 2},

    # ---- non-EVM ecosystem wallets ----------------------------------------
    "keplr":               {"repo": "chainapsis/keplr-wallet",           "category": "browser_extension", "ecosystem": "cosmos",   "custody": "self",  "tier": 1},
    "cosmostation":        {"repo": "cosmostation/cosmostation-chrome-extension", "category": "browser_extension", "ecosystem": "cosmos", "custody": "self", "tier": 3},
    "station":             {"repo": "stationmoney/station-extension",    "category": "browser_extension", "ecosystem": "cosmos",   "custody": "self",  "tier": 3},
    "solana-wallet-adapter":{"repo": "anza-xyz/wallet-adapter",          "category": "infra",             "ecosystem": "solana",   "custody": "lib",   "tier": 1},
    "backpack":            {"repo": "coral-xyz/backpack",                "category": "browser_extension", "ecosystem": "solana",   "custody": "self",  "tier": 2},
    "polkadot-extension":  {"repo": "polkadot-js/extension",             "category": "browser_extension", "ecosystem": "polkadot", "custody": "self",  "tier": 2},
    "talisman":            {"repo": "TalismanSociety/talisman",          "category": "browser_extension", "ecosystem": "polkadot", "custody": "self",  "tier": 2},
    "subwallet":           {"repo": "Koniverse/SubWallet-Extension",     "category": "browser_extension", "ecosystem": "polkadot", "custody": "self",  "tier": 2},
    "yoroi":               {"repo": "Emurgo/yoroi-frontend",             "category": "browser_extension", "ecosystem": "cardano",  "custody": "self",  "tier": 2},
    "nami":                {"repo": "input-output-hk/nami",              "category": "browser_extension", "ecosystem": "cardano",  "custody": "self",  "tier": 2, "archived": True},
    "lace":                {"repo": "input-output-hk/lace",              "category": "browser_extension", "ecosystem": "cardano",  "custody": "self",  "tier": 2},
    "daedalus":            {"repo": "input-output-hk/daedalus",          "category": "desktop",           "ecosystem": "cardano",  "custody": "self",  "tier": 2},
    "tonkeeper-web":       {"repo": "tonkeeper/tonkeeper-web",           "category": "browser_extension", "ecosystem": "ton",      "custody": "self",  "tier": 2},
    "tonkeeper-ios":       {"repo": "tonkeeper/ios",                     "category": "mobile",            "ecosystem": "ton",      "custody": "self",  "tier": 2},
    "ton-wallet-contract": {"repo": "ton-blockchain/wallet-contract",    "category": "smart_account",     "ecosystem": "ton",      "custody": "smart", "tier": 2},
    "near-wallet":         {"repo": "near/near-wallet",                  "category": "browser_extension", "ecosystem": "near",     "custody": "self",  "tier": 3},
    "sui":                 {"repo": "MystenLabs/sui",                    "category": "node_wallet",       "ecosystem": "sui",      "custody": "self",  "tier": 2},
    "aptos":               {"repo": "aptos-labs/aptos-core",             "category": "node_wallet",       "ecosystem": "aptos",    "custody": "self",  "tier": 2},
    "avalanche-wallet":    {"repo": "ava-labs/avalanche-wallet",         "category": "browser_extension", "ecosystem": "evm",      "custody": "self",  "tier": 3},
    "core-mobile":         {"repo": "ava-labs/core-mobile",              "category": "mobile",            "ecosystem": "evm",      "custody": "self",  "tier": 3},
    "leather":             {"repo": "leather-io/extension",              "category": "browser_extension", "ecosystem": "stacks",   "custody": "self",  "tier": 2, "archived": True},
    "freighter":           {"repo": "stellar/freighter",                 "category": "browser_extension", "ecosystem": "stellar",  "custody": "self",  "tier": 2},
    "pera":                {"repo": "perawallet/pera-wallet",            "category": "mobile",            "ecosystem": "algorand", "custody": "self",  "tier": 2, "archived": True},
    "tron-wallet-cli":     {"repo": "tronprotocol/wallet-cli",           "category": "wallet_sdk",        "ecosystem": "tron",     "custody": "lib",   "tier": 2},
    "zerion-sdk":          {"repo": "zeriontech/defi-sdk",               "category": "wallet_sdk",        "ecosystem": "evm",      "custody": "lib",   "tier": 3},
}

# Language of the repo, used by the ecosystem-specific advisory crawlers
# (RustSec -> Rust, govulncheck -> Go, OSV -> npm/PyPI/Maven/crates/Go).
WALLET_LANGUAGE: dict[str, str] = {
    "wallet-core": "cpp", "brave-wallet": "cpp", "bitcoin-core": "cpp",
    "monero": "cpp", "monero-gui": "cpp", "feather": "cpp", "zcash": "cpp",
    "green-qt": "cpp", "gdk": "cpp", "fireblocks-mpc": "cpp",
    "status-go": "go", "bitbox-app": "go", "bnb-tss-lib": "go",
    "kryptology": "go", "taurus-mp-sig": "go",
    "zengo-mpecdsa": "rust", "gotham-city": "rust", "liana": "rust",
    "librustzcash": "rust", "imtoken-tokencore": "rust", "sui": "rust",
    "aptos": "rust",
    "electrum": "python", "coldcard": "python", "specter": "python",
    "hwi": "python", "web3py": "python",
    "sparrow": "java", "bisq": "java", "web3j": "java",
    "alphawallet-android": "java", "samourai": "java", "tron-wallet-cli": "java",
    "wasabi": "csharp", "btcpay": "csharp",
    "trezor-firmware": "c", "ledger-app-eth": "c", "ledger-app-btc": "c",
    "ledger-sdk": "c", "keystone3": "c", "bitbox02": "c", "jade": "c",
    "passport": "c", "onekey-firmware": "c", "imtoken-tokencore2": "c",
    "safe-contracts": "solidity", "safe-modules": "solidity",
    "account-abstraction": "solidity", "alchemy-modular": "solidity",
    "alchemy-light": "solidity", "zerodev-kernel": "solidity",
    "soul-wallet": "solidity", "biconomy-scw": "solidity",
    "etherspot": "solidity", "sequence-contracts": "solidity",
    "rhinestone": "solidity", "argent-contracts": "cairo",
    "eclair": "scala", "phoenix": "kotlin", "muun-apollo": "kotlin",
    "nunchuk": "kotlin", "coinbase-mobile-sdk": "kotlin",
    "muun-falcon": "swift", "alphawallet-ios": "swift",
    "tangem": "swift", "tonkeeper-ios": "swift", "pera": "swift",
    "breez": "dart", "cake-wallet": "dart", "stack-wallet": "dart",
    "status-mobile": "clojure", "status-desktop": "qml",
}


def language_of(slug: str) -> str:
    """Repo language; defaults to TypeScript/JavaScript (most wallet UIs)."""
    return WALLET_LANGUAGE.get(slug, "js")


def slugs(tier: int | None = None, category: str | None = None) -> list[str]:
    """Registry slugs, optionally filtered by tier ceiling / category."""
    out = []
    for slug, cfg in WALLET_CONFIG.items():
        if tier is not None and cfg.get("tier", 3) > tier:
            continue
        if category is not None and cfg.get("category") != category:
            continue
        out.append(slug)
    return out


def repo_of(slug: str) -> str:
    return WALLET_CONFIG[slug]["repo"]


if __name__ == "__main__":  # tiny introspection helper
    import collections
    print(f"{len(WALLET_CONFIG)} repos in registry")
    for field in ("category", "ecosystem", "custody", "tier"):
        c = collections.Counter(cfg.get(field) for cfg in WALLET_CONFIG.values())
        print(f"  by {field}: " + " · ".join(f"{k}={v}" for k, v in sorted(c.items(), key=lambda x: (-x[1], str(x[0])))))
