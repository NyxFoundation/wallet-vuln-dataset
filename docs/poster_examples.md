# ポスター掲載用の実例表

`fig2_compare.png` で有意差が出た 5 つの原因を、実際のコミット 1 件ずつで埋めた表。
図の右側の棒が何を指しているのかを具体で示すことが目的。

選定基準は 4 つ。

1. **クローラの検索語 26 語がコミットタイトルに 1 つも含まれない** — キーワード検索が
   原理的に取り落とすことの実例。5 件すべてが該当し、うち 4 件は人間が読んでも
   セキュリティ修正だと分からない
2. **広く使われている製品**
3. **その修正に対して CVE・GHSA が存在しない** — リポジトリ単位ではなくコミット単位で確認
4. **2020 年以降** — GHSA 制度は 2019 年開始なので、それ以前の例は「当時制度がなかった」で
   反論されうる

タイトル・日付・変更ファイル数・差分は 2026-08-13 に GitHub API で照合済み。

**掲載した差分は抜粋である。** 変更のない前後の文脈行は省いてあり、Ledger の例は
復活した検証コード全体のうち中核の 5 行のみ、Trezor の例は元は 1 行の `print` を
紙面幅に合わせて折り返してある。完全な差分は各コミットの URL、または下記の
確認手順で取得できる。

---

## 1. 承認なしに取引が送信され得た

**Rabby**（ブラウザ拡張）· 2021-04 · [`e159539`](https://github.com/RabbyHub/Rabby/commit/e15953926f8f4b15593a543477b188703e5dbe30)
**原因: 呼び出し元の権限確認**

コミットタイトルは `😄` のみ。

```diff
-export const NEED_CONFIRM = ['personal_sign'];
+export const NEED_CONFIRM = ['personal_sign', 'eth_sendTransaction'];
```

`eth_sendTransaction` が確認要求リストに入っていなかった。dapp が送金要求を出すと、
利用者の承認画面を経ずに署名・送信され得た。

---

## 2. 引き出し権限が他人のものであるデポジットに署名してしまう

**Ledger app-ethereum**（ハードウェア）· 2021-04 · [`31ad5e3`](https://github.com/LedgerHQ/app-ethereum/commit/31ad5e3431cc507f001c88accc225b94b6011a31)
**原因: 署名内容と画面表示の不一致**

コミットタイトルは `Remove comments`。実際に消えたのはコメント記号で、
**検証コードそのものが復活している**。

```diff
- //     ... 引き出し鍵の導出（8 行省略）
- //     getEth2PublicKey(withdrawalKeyPath, 4, tmp);
- //     cx_hash_sha256(tmp, 48, tmp, 32);
- //     if (memcmp(tmp, msg->parameter, 32) != 0) {
- //         context->valid = 0;
- //     }
+     ... 引き出し鍵の導出（8 行省略）
+     getEth2PublicKey(withdrawalKeyPath, 4, tmp);
+     cx_hash_sha256(tmp, 48, tmp, 32);
+     if (memcmp(tmp, msg->parameter, 32) != 0) {
+         context->valid = 0;
+     }
```

ETH2 デポジットの引き出し権限が自分の鍵から導出されたものかを照合する処理が、
コメントアウトされたまま出荷されていた。無効な間は、**引き出し権限が攻撃者のものである
デポジットに署名しても端末は警告しない**。32 ETH が攻撃者の側に紐づく。

---

## 3. 署名処理中に秘密鍵をコンソールへ出力していた

**Trezor firmware**（ハードウェアファームウェア）· 2026-05 · [`a3dc14f`](https://github.com/trezor/trezor-firmware/commit/a3dc14f9542a4527d2006336d980f7f8a689f0eb)
**原因: 鍵のメモリ残留**

コミットタイトルは `feat(extapp): xtask build for ethereum app` — ビルド設定の変更に見える。

```diff
-    node = keychain.derive(msg.address_n)
-    print("path validated, node is", node.depth(), node.fingerprint(),
-          node.child_num(), node.chain_code(), node.private_key(), node.public_key())
```

Ethereum の取引署名パスに、`chain_code` と `private_key` をそのまま出力する
デバッグ文が残っていた。3 か月前の修正。

---

## 4. おつりが誰でも使用可能なスクリプトに送られ得た

**wallet-core**（署名ライブラリ）· 2021-08 · [`9d69eb3`](https://github.com/trustwallet/wallet-core/commit/9d69eb33541e7c054d220759237a4f6dcb7d8701)
**原因: 入力の長さ・境界検査**

コミットタイトルは `Minor reorg of TransactionBuilder`。

```diff
+ std::optional<TransactionOutput> TransactionBuilder::prepareOutput(
+         std::string address, Amount amount, enum TWCoinType coin) {
+     auto lockingScript = Script::lockScriptForAddress(address, coin);
+     if (lockingScript.empty()) {
+         return {};
+     }
+     return TransactionOutput(amount, lockingScript);
+ }
```

出力のロック用スクリプトが空でないかを検証していなかった。空のスクリプトは
**誰でも使用できる**ので、おつりがそこへ送られると資金を失う。

---

## 5. 信頼できない拡張が Ethereum の鍵を導出できた

**MetaMask Snaps**（拡張プラットフォーム）· 2023-06 · [`f63f4b9`](https://github.com/MetaMask/snaps/commit/f63f4b941d5ddb314fe7a979eaea0f3895787b65)
**原因: 鍵の導出・保管**

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

## タイトルだけを見た場合

| コミットタイトル | クローラの26語に該当 | 人間が読んで気づくか |
|---|---|---|
| `😄` | なし | ✗ |
| `Remove comments` | なし | ✗ |
| `feat(extapp): xtask build for ethereum app` | なし | ✗ |
| `Minor reorg of TransactionBuilder` | なし | ✗ |
| `Disallow deriving Ethereum keys (#1217)` | なし | △ 鍵の話だとは分かる |

---

## 補足として使える 6 件目

「記録がない」と「公表されていない」は別だという限定を、表の中で 1 行で示したい場合。

| 製品 | 日付 | コミットタイトル | 内容 |
|---|---|---|---|
| [BTCPay Server](https://github.com/btcpayserver/btcpayserver/pull/7491) | 2026-08 | `Fix: TOTP 2FA bypass via Greenfield Basic auth` | TOTP のみのアカウントがメールとパスワードだけで Greenfield API 全体を操作できた。Basic 認証ハンドラが「2要素が有効か」ではなく `Fido2Credentials.Any()` を見ていた |

これは**緊急リリース v2.4.2 として公表され、悪用が確認され、報道もされた**。それでも
BTCPay の GitHub advisory 一覧は空で、CVE も GHSA も存在しない。このコーパスが測っている
のは利用者への沈黙ではなく、**スキャナが読める記録からの欠落**である。

---

## 選定で外したもの

- **bitcoinjs-lib `Removed debug statements.`**（2011）— ECDSA の nonce `k` と `d*r` を
  デバッグ出力しており、秘密鍵が復元可能。内容は最も強烈だが 2011 年で、
  GHSA 制度以前という反論を受ける
- **electrum `update BIP32 to its final spec`**（2013）— 硬化導出で加算ではなく乗算を
  使っており、誤った鍵を導出して資金を失う。同じ理由で除外
- **ethers.js `Updated dist files.`**（2020）— 当初これを選んだが、差分を確認したところ
  **ビルド成果物を更新するリリースコミット**で、修正本体は別コミット（`9947acc`）だった。
  ソース差分を見せる対象として不適切。この確認の副産物として下記の問題が判明した

### ethers のバンドル更新コミットによる二重計上

ethers v4 はコンパイル済み JS をリポジトリ直下に置くため、1 つの修正が
「ソースのコミット」と「バンドル更新のコミット」の 2 回、判定対象になる。

ethers の回収 73 件のうち **18 件（25%）がバンドル更新コミット**で、
おそらくソース側のコミットと重複している。この形を持つのは 16 リポジトリ中 ethers のみで、
silent fix 全体 5,457 件に対しては 0.33%。107:1 の比率は動かない。

以前「生成物のみのコミットは 0 件」と報告したが、あの測定は `dist/` 配下という
パターンで探していたため、リポジトリ直下にビルド成果物を置く ethers を検出できていなかった。

---

判定根拠の全文は [`data/silent_mechanisms.csv`](../data/silent_mechanisms.csv) の
`reason` 列にある。

## 確認手順

```bash
# タイトル・日付・変更ファイル数
gh api /repos/RabbyHub/Rabby/commits/e15953926f8f4b15593a543477b188703e5dbe30 \
   --jq '"\(.commit.message | split("\n")[0]) \(.commit.author.date[0:10]) \(.files|length)"'

# 差分
gh api /repos/RabbyHub/Rabby/commits/e15953926f8f4b15593a543477b188703e5dbe30 \
   --jq '.files[] | select(.patch != null) | .patch'

# その修正に対する CVE・GHSA がないこと
gh api /repos/RabbyHub/Rabby/security-advisories --jq 'length'
```

`trustwallet/wallet-core` だけは公開アドバイザリを 1 件持つ
（`GHSA-7g72-jxww-q9vq`、2024-12、`secret.rs` の鍵露出）。2021 年のおつり検証の修正とは
無関係で、表の主張はコミット単位なので成立する。他の 4 リポジトリは 0 件。
