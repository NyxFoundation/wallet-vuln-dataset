# ポスター掲載用の実例表

`fig2_compare.png` で有意差が出た 5 つの原因を、実際のコミット 1 件ずつで埋めた表。
図の右側の棒が何を指しているのかを具体で示すことが目的。

選定基準は 4 つ。

1. **コミットタイトルが内容を示していない** — キーワード検索が原理的に取り落とすことの実例
2. **広く使われている製品** — 聞いたことのない実装は聴衆に効かない
3. **CVE・GHSA がその修正に対して存在しない** — リポジトリ単位ではなくコミット単位で確認
4. **2020年以降** — GHSA 制度は 2019年開始なので、それ以前の例は「当時制度がなかった」で反論されうる

タイトル・日付・変更ファイル数は 2026-08-13 に GitHub API で照合済み。

| 製品 | 種別 | 日付 | コミットタイトル | 実際に直したもの | 原因（Fig2） |
|---|---|---|---|---|---|
| [Rabby](https://github.com/RabbyHub/Rabby/commit/e15953926f8f4b15593a543477b188703e5dbe30) | ブラウザ拡張 | 2021-04 | `😄` | `eth_sendTransaction` が確認要求リストに入っておらず、**利用者の承認なしに取引が署名・送信され得た** | 呼び出し元の権限確認 |
| [Ledger app-ethereum](https://github.com/LedgerHQ/app-ethereum/commit/31ad5e3431cc507f001c88accc225b94b6011a31) | ハードウェア | 2021-04 | `Remove comments` | ETH2 デポジットの引き出し権限が**自分の鍵に紐づいているかの検証がコメントアウトされていた**。無効な間は、引き出し権限が他人のものであるデポジットに署名してしまう | 署名内容と画面表示の不一致 |
| [Trezor firmware](https://github.com/trezor/trezor-firmware/commit/a3dc14f9542a4527d2006336d980f7f8a689f0eb) | ハードウェアファームウェア | 2026-05 | `feat(extapp): xtask build for ethereum app` | 取引署名中に **`private_key` と `chain_code` をコンソールに出力するデバッグ文**が残っていた | 鍵のメモリ残留 |
| [wallet-core](https://github.com/trustwallet/wallet-core/commit/9d69eb33541e7c054d220759237a4f6dcb7d8701) | ライブラリ | 2021-08 | `Minor reorg of TransactionBuilder` | おつり出力のロック用スクリプトが空でないかの検証が無く、**おつりが誰でも使用可能なスクリプトに送られ得た** | 入力の長さ・境界検査 |
| [ethers.js](https://github.com/ethers-io/ethers.js/commit/4c9d740cdf9bef4690b98340ec56713ed213213e) | ライブラリ | 2020-02 | `Updated dist files.` | 暗号化 JSON ウォレットで**非英語ニーモニックのエントロピー導出に誤ったワードリスト**を渡しており、別の鍵が導出された | 鍵の導出・保管 |

タイトルだけを見て、5 件のうち 1 件でもセキュリティ修正だと判断できるものはない。
`😄`、`Remove comments`、`Updated dist files.`、`Minor reorg of TransactionBuilder` は
いずれもキーワード検索に一切かからない。

## 補足として使える 6 件目

「記録がない」と「公表されていない」は別だという注意書きを表の中で示したい場合。

| 製品 | 日付 | コミットタイトル | 内容 |
|---|---|---|---|
| [BTCPay Server](https://github.com/btcpayserver/btcpayserver/pull/7491) | 2026-08 | `Fix: TOTP 2FA bypass via Greenfield Basic auth` | TOTP のみのアカウントがメールとパスワードだけで Greenfield API 全体を操作できた。Basic 認証ハンドラが「2要素が有効か」ではなく `Fido2Credentials.Any()` を見ていたため |

これは**緊急リリース v2.4.2 として公表され、悪用が確認され、報道もされた**。それでも
BTCPay の GitHub advisory 一覧は空で、CVE も GHSA も存在しない。このコーパスが測っている
のは利用者への沈黙ではなく、**スキャナが読める記録からの欠落**である、という限定を
1 行で示せる。

## 確認手順

```bash
# タイトルと日付
gh api /repos/RabbyHub/Rabby/commits/e15953926f8f4b15593a543477b188703e5dbe30 \
   --jq '.commit.message | split("\n")[0]'

# その修正に対する CVE・GHSA がないこと（リポジトリ単位の一覧）
gh api /repos/RabbyHub/Rabby/security-advisories --jq 'length'
```

`trustwallet/wallet-core` だけは公開アドバイザリを 1 件持つ
（`GHSA-7g72-jxww-q9vq`、2024-12、`secret.rs` の鍵露出）。2021 年のおつり検証の修正とは
無関係で、表の主張はコミット単位なので成立する。他の 4 リポジトリは 0 件。

判定根拠の全文は [`data/silent_mechanisms.csv`](../data/silent_mechanisms.csv) の
`reason` 列にある。
