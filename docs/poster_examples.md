# ポスター掲載用の実例表

`fig2_compare.png` で有意差が出た原因を、実際のコミットで埋めた表。
図の右側の棒が何を指しているのかを具体で示すことが目的。

## 選定基準

前提として、**修正前の脆弱な状態が実際に出荷されていたこと**を各行で検証している。
これを確認しない限り「修正コミット」は開発途中の後片付けと区別できない。

1. コミットが**既定ブランチ上にある**
2. **修正の親コミットを含み、修正を含まないリリースタグが存在する** —
   すなわち脆弱な状態のまま出荷されたバージョンが実在する
3. その修正に対して **CVE・GHSA が存在しない**
4. クローラの検索語 26 語がコミットタイトルに 1 つも含まれない
5. 広く使われている製品

検証は [`scripts/check_shipped.py`](../scripts/check_shipped.py) で再実行できる。
タイトル・日付・差分は 2026-08-13 に GitHub API と照合済み。

**掲載した差分は抜粋である**（変更のない前後の文脈行は省いてある）。

---

## 1. 承認した額と異なる額の使用許可に署名してしまう

**wallet-core**（署名ライブラリ）· 2020-12 ·
[`f162f0f`](https://github.com/trustwallet/wallet-core/commit/f162f0f16d305755592dd63e21504152193f6990)
**原因: 署名内容と画面表示の不一致** · 出荷済み（2.5.2 以前）

コミットタイトルは `Fix erc20 approve typo (#1226)` — 誤字修正に見える。

```diff
  /* toAddress */ spenderAddress,
- /* amount: */ load(input.transaction().erc20_transfer().amount()));
+ /* amount: */ load(input.transaction().erc20_approve().amount()));
```

ERC-20 の使用許可（approve）を組み立てる際、**許可額を `erc20_approve` ではなく
`erc20_transfer` のフィールドから読んでいた**。利用者が意図した額とは別の額の
使用許可に署名する。

---

## 2. マルチシグ出力が「おつり」として自動承認され得た

**Trezor firmware**（ハードウェアファームウェア）· 2019-10 ·
[`d800fcb`](https://github.com/trezor/trezor-firmware/commit/d800fcbf9f49580c5171b90ace4f37d17964e70b)
**原因: 呼び出し元の権限確認** · 出荷済み

```diff
  if txi.multisig:
      multifp.add(txi.multisig)
+ else:
+     multifp.mismatch = True
```

マルチシグでない入力があっても指紋の不一致が記録されず、**攻撃者の管理する
マルチシグ出力が「おつり」と判定され、確認画面を経ずに承認され得た**。

---

## 3. マルチシグの秘密鍵がメモリに残っていた

**Monero**（フルノードウォレット）· 2020-05 ·
[`c17fe81`](https://github.com/monero-project/monero/commit/c17fe815a2792d13c2385dedeb7aa9ee3a9322c9)
**原因: 鍵のメモリ残留** · 出荷済み（v0.16.0.0 以前）

コミットタイトルは `wallet2: fix multisig data clearing stomping on a vector` —
コンテナの扱いの不具合に見える。

```diff
- memwipe(k.data(), k.size() * sizeof(k[0]));
+ for (auto &v: k) memwipe(v.data(), v.size() * sizeof(v[0]));
```

`k` は「ベクタのベクタ」で、元のコードは**外側のベクタの要素構造だけを消していた**。
内側が指す実際の秘密鍵のバイト列は消されず、メモリに残り続けた。

---

## 4. おつりが誰でも使用可能なスクリプトに送られ得た

**wallet-core**（署名ライブラリ）· 2021-09 ·
[`a02bfd0`](https://github.com/trustwallet/wallet-core/commit/a02bfd0d346a4b7a34f4409f1fff40507f28edf2)
**原因: 入力の長さ・境界検査** · 出荷済み（**69 リリース**、2020-05 〜 2021-08）

コミットタイトルは `BTC Signing reorg (#1574)`。

```diff
+ auto lockingScript = Script::lockScriptForAddress(address, coin);
+ if (lockingScript.empty()) {
+     return {};
+ }
+ return TransactionOutput(amount, lockingScript);
```

出力のロック用スクリプトが空でないかを検証していなかった。空のスクリプトは
**誰でも使用できる**ので、おつりがそこへ送られると資金を失う。
この状態のまま 69 のリリースが出荷されている。

---

## 5. 信頼できない拡張が Ethereum の鍵を導出できた

**MetaMask Snaps**（拡張プラットフォーム）· 2023-06 ·
[`f63f4b9`](https://github.com/MetaMask/snaps/commit/f63f4b941d5ddb314fe7a979eaea0f3895787b65)
**原因: 鍵の導出・保管** · 出荷済み（v0.32.2 〜 v0.34.1 の 5 リリース）

```diff
+ if (FORBIDDEN_COIN_TYPES.includes(value.coinType)) {
+   throw ethErrors.rpc.invalidParams({
+     message: `Coin type ${value.coinType} is forbidden.`,
+   });
+ }
```

サードパーティの Snap が BIP-44 の `coinType` に 60（Ethereum）を指定して
鍵導出を要求できた。**利用者の Ethereum 秘密鍵が第三者コードから導出可能**だった。

---

## 補足として使える 6 件目

「記録がない」と「公表されていない」は別だという限定を 1 行で示したい場合。

| 製品 | 日付 | コミットタイトル | 内容 |
|---|---|---|---|
| [BTCPay Server](https://github.com/btcpayserver/btcpayserver/pull/7491) | 2026-08 | `Fix: TOTP 2FA bypass via Greenfield Basic auth` | TOTP のみのアカウントがメールとパスワードだけで Greenfield API 全体を操作できた。Basic 認証ハンドラが「2要素が有効か」ではなく `Fido2Credentials.Any()` を見ていた |

これは**緊急リリース v2.4.2 として公表され、悪用が確認され、報道もされた**。それでも
BTCPay の GitHub advisory 一覧は空で、CVE も GHSA も存在しない。このコーパスが測るのは
利用者への沈黙ではなく、**スキャナが読める記録からの欠落**である。

---

## 検証で落とした候補

最初に選んだ 5 件のうち 3 件がこの検証で落ちた。**内容ではなく「出荷されたか」で落ちている。**

| 候補 | 落ちた理由 |
|---|---|
| **Rabby** `😄`（2021-04）— `eth_sendTransaction` が確認要求リストに無かった | 修正は最初のリリース **v0.3（2021-06-18）に含まれている**。脆弱な状態は一度も利用者に届いていない。同じコミットに `'eth_getTransactionCount': () => '0x100'` というスタブがあり、開発中のコードだった |
| **Trezor firmware** `feat(extapp): xtask build for ethereum app`（2026-05）— 署名中に `private_key` をコンソール出力 | **`main` に存在しない。** 開発者ブランチ `cepetr/api-crate-fix` にのみあり、製品に入っていない |
| **Ledger app-ethereum** `Remove comments`（2021-04）— ETH2 引き出し権限の検証がコメントアウトされていた | 修正前のリリース 54 件はいずれもコメントアウトされていない状態だった。**コメントアウトされた期間にリリースが挟まっていない** |
| **bitcoinjs-lib** `Removed debug statements.`（2011）— ECDSA の nonce をデバッグ出力 | 内容は最も強烈だが 2011 年で、GHSA 制度以前という反論を受ける |
| **ethers.js** `Updated dist files.`（2020） | **ビルド成果物を更新するリリースコミット**で、修正本体は別コミット。ソース差分を見せる対象にならない |

---

## この検証で判明したコーパスの過大計上

列挙は `git log --all` で全ブランチを歩くため、**未マージのブランチにあるコミットも
判定対象になる**。スイープで回収した 5,457 件を分類すると:

| | 件数 | 割合 |
|---|---:|---:|
| 既定ブランチ上にある | 4,168 | 76% |
| squash マージで SHA が変わったもの | 613 | 11% |
| └ うち同じ修正が既定ブランチ側の行としても計上されている | **475** | 8.7% |
| どのブランチにも属さない・機能ブランチのみ | 676 | 12% |
| └ うちリリースタグに含まれる（出荷はされた） | 約 18% | |

つまり**重複 475 件**と、**利用者に届かなかった約 554 件**が含まれる。
一意で出荷された修正はおよそ **4,400 件**で、公開側の 51 件に対する比率は
107:1 ではなく **約 87:1**。結論の向きは変わらないが、件数は 2 割ほど過大だった。

図と README の 5,457 はこの補正を反映していない。反映するにはゲートに
「既定ブランチに到達し、かつ重複でない」条件を追加して再構築する必要がある。

---

判定根拠の全文は [`data/silent_mechanisms.csv`](../data/silent_mechanisms.csv) の
`reason` 列にある。
