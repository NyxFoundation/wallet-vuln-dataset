#!/usr/bin/env python3
"""poster_figures.py — figures for the CSS poster, from the committed tables.

    uv run --with matplotlib --with numpy --with uharfbuzz --with fonttools \
        --with pandas --with pyarrow python scripts/poster_figures.py

Every number is read from data/, never typed in, so the poster cannot drift from
the dataset.
"""
from __future__ import annotations

import importlib.util as ilu
from pathlib import Path

import pandas as pd
import style as S

ROOT = Path(__file__).resolve().parent.parent
ADV = pd.read_csv(ROOT / "data/advisory_mechanisms.csv")
# All sixteen swept repositories, not the first ten. wave1_mechanisms.csv is kept
# as the published wave-1 artefact; the figures read the union so they do not
# quietly describe a subset of what has been collected.
def _analysable(df):
    """Rows whose fix reached a product, counted once.

    `git log --all` admits commits from branches that were never merged, and
    counts a squash-merged pull request twice — once under the PR commit, once
    under the squashed one. Neither is visible in the row, so
    scripts/mark_reachable.py flags them and this drops them: without it the
    silent side was 5,457 rows, 892 of which never shipped and 475 of which were
    the same fix counted twice.

    Rows whose flags are NA are KEPT. NA means "not testable" — an advisory row
    identified by a pull-request URL has no SHA to walk from — and dropping the
    untestable would be the loudest possible way to overstate this correction.
    """
    if "on_default" not in df.columns:
        raise SystemExit("run scripts/mark_reachable.py first: the reachability "
                         "columns are missing and the figure would overcount")

    def flag(col, when_missing):
        """CSV round-trips a boolean-with-NA column as the STRINGS "True"/"False".
        `"False"` is a non-empty string and therefore truthy, so a naive read
        silently kept every row — the filter reported 5,457 of 5,457 analysable."""
        v = df[col]
        if v.dtype == object:
            v = v.map({"True": True, "False": False, True: True, False: False})
        return v.astype("boolean").fillna(when_missing)

    reached = flag("on_default", True) | flag("in_release", True)
    return df[reached & ~flag("dup_subject", False)].copy()


ADV = _analysable(ADV)
SIL = _analysable(pd.read_csv(ROOT / "data/silent_mechanisms.csv"))
N_SIL = len(SIL)
N_REPO = SIL["wallet"].nunique()

# The audience is security staff who do not work on wallets. "サイレント修正" is
# the term the poster uses throughout, with its definition attached the first
# time it appears in each figure; the alternative wordings this file used to mix
# ("登録なく出荷された修正", "CVE・GHSA に記録のない") made three figures look
# like they described three populations.
T_SILENT = "サイレント修正"
T_SILENT_DEF = "公開アドバイザリなし"
T_DISCLOSED = "公開アドバイザリあり"
T_DISCLOSED_DEF = "CVE・GHSA 番号が付与されているもの"

_sp = ilu.spec_from_file_location("w", ROOT / "collection/wallets.py")
_w = ilu.module_from_spec(_sp); _sp.loader.exec_module(_w)
CATEGORY = {k: v["category"] for k, v in _w.WALLET_CONFIG.items()}
SIL = SIL.assign(cat=SIL.wallet.map(CATEGORY))

CAT_JA = {
    "hardware_firmware": "ハードウェア\nファームウェア",
    "desktop": "デスクトップ",
    "wallet_sdk": "ウォレット\nSDK・ライブラリ",
    "browser_extension": "ブラウザ拡張",
    "infra": "dApp 接続基盤",
    "smart_account": "スマートコントラクト\nウォレット",
    "node_wallet": "フルノード\nウォレット",
    "mobile": "モバイル",
    "mpc_tss": "MPC・分散署名",
}
CLASS_JA = {
    "signing": "電子署名", "key_material": "鍵・\nシード", "firmware": "ファーム\nウェア",
    "ui_deception": "画面表示の\n偽装", "transport": "通信経路", "memory": "メモリ\n破壊",
    "contract": "スマート\nコントラクト", "approval": "送金権限の\n付与",
}
MECH_JA = {
    "input-bounds-parsing": "入力値の検証不備",
    "signed-differs-from-shown": "署名する内容と画面表示の不一致",
    "authorization-check": "権限チェックの欠落",
    "key-derivation-storage": "鍵の生成・保管の不備",
    "encoding-canonicalization": "エンコード・正規化",
    "key-lifetime-in-memory": "鍵がメモリに残る",
    "signature-verification-gap": "署名検証の欠落",
    "state-race-concurrency": "競合状態",
    "origin-session-auth": "接続元の認証",
    "side-channel-fault": "サイドチャネル・故障注入",
    "replay-scope": "署名の使い回し",
    "nonce-or-randomness": "nonce・乱数",
    "curve-point-validation": "楕円曲線の点の検証",
    "uri-deeplink-handling": "URI・ディープリンク",
    "dependency-supply-chain": "外部ライブラリ",
    "transport-encryption": "通信の暗号化",
    "code-injection-context": "コード注入",
    "secure-boot-rollback": "セキュアブート・巻き戻し防止",
    "privilege-isolation": "権限分離・サンドボックス",
    "protocol-counterparty": "通信相手を信頼しすぎ",
    "type-state-consistency": "型・状態の不整合",
    "missing-authentication": "認証の欠落",
    "other": "特定できず",
}


# --- 1. what the top evidence tier actually contains ------------------------
def fig_ratio(out="fig1_ratio.png"):
    """Two bars on one scale. The 90:1 and the contaminated denominator at once."""
    conf = int((ADV.is_security_fix == 1).sum())
    nc = ADV[ADV.is_security_fix != 1]
    dep = int((nc.mechanism == "dependency-supply-chain").sum())
    rest = len(nc) - dep
    silent = len(SIL)
    W = silent * 1.0

    fig, ax = S.new(12.8, 5.6, xlim=(-W * 0.015, W * 1.30), ylim=(-1.62, 1.30))

    # silent fixes
    S.t(ax, 0, 1.10, f"{T_SILENT}（{T_SILENT_DEF}）", fp="bold", size=15.5,
        color=S.INK, va="center")
    S.t(ax, 0, 0.83, f"{N_REPO} 製品の全変更履歴を 1 件ずつ判定し、出荷されたものだけを計上",
        fp="reg", size=11, color=S.MUTED, va="center")
    S.rrect(ax, 0, 0.36, silent, 0.32, fc=S.RUST, ec="none", rs=0.02, z=2)
    S.t(ax, silent + W * 0.015, 0.52, f"{silent:,}", fp="black", size=30,
        color=S.RUST, va="center")

    # "登録なく" not "公表されずに": the corpus can only observe whether a
    # CVE/GHSA record exists, and the two come apart. BTCPay's TOTP 2FA bypass
    # shipped in an emergency release under active exploitation, with press
    # coverage, and still has no GitHub advisory — it counts as silent here and
    # was in no sense undisclosed.
    # advisory rows, segmented
    S.t(ax, 0, -0.10, T_DISCLOSED, fp="bold", size=15.5,
        color=S.INK, va="center")
    S.t(ax, 0, -0.37, T_DISCLOSED_DEF, fp="reg", size=11,
        color=S.MUTED, va="center")
    x = 0.0
    for n, c in ((conf, S.RUST), (dep, S.SLATE), (rest, S.lighten(S.SLATE, 0.60))):
        S.rrect(ax, x, -0.84, n, 0.32, fc=c, ec="none", rs=0.02, z=2)
        x += n
    S.t(ax, x + W * 0.015, -0.68, f"{len(ADV):,}", fp="black", size=30,
        color=S.SOFT, va="center")

    # 51 of 4,608-scale is a sliver, so the callout carries it. Anchored right of
    # the bar's own total so it cannot collide with the legend below.
    # 51 against a 4,608 scale is a sliver, so the callout carries it. Parked in the
    # empty upper-right of this row so it clears both the row total and the legend,
    # with the arrow approaching from the right rather than across the subtitle.
    S.t(ax, W * 0.56, -0.16, f"うち 資産の保管・送金処理の欠陥\n{conf} 件（4%）",
        fp="bold", size=15.5, color=S.RUST, va="center", linespacing=1.5)
    S.arrow(ax, (W * 0.545, -0.34), (conf * 2.2, -0.60),
            color=S.RUST_L, lw=1.7, ms=12, rad=-0.26)

    for i, (c, lab, n) in enumerate(((S.RUST, "資産の保管・送金処理の欠陥", conf),
                                     (S.SLATE, "外部ライブラリの脆弱性対応", dep),
                                     (S.lighten(S.SLATE, 0.60),
                                      "欠陥の修正ではないもの（規程整備・記載追加など）", rest))):
        yy = -1.14 - i * 0.22
        S.rrect(ax, 0, yy - 0.055, W * 0.016, 0.125, fc=c, ec="none", rs=0.02, z=3)
        S.t(ax, W * 0.030, yy + 0.008, f"{lab}   {n:,}", fp="med", size=11.5,
            color=S.SOFT, va="center")

    fig.subplots_adjust(top=0.775, bottom=0.03, left=0.045, right=0.985)
    S.title_block(fig,
                  f"{T_DISCLOSED}の修正と、{T_SILENT}の件数",
                  f"暗号資産ウォレット {N_REPO} 製品の全変更履歴を対象に、"
                  "各コミットの差分を 1 件ずつ判定した結果。",
                  x=0.045, y=0.965)
    return S.save(fig, out)


# NOTE: a paired-bar figure comparing mechanism shares between the two
# populations used to live here, built around "five mechanisms never appear in an
# advisory". It does not survive. Restricted to the 51 advisory rows that are
# actually custody fixes, 7 of 22 mechanisms are absent — and drawing 51 rows from
# the silent distribution would leave 7.4 absent by chance. The comparison is
# underpowered, and the earlier version got its zeros by using all 1,325 advisory
# rows as the denominator, 1,274 of which repair no defect at all.
#
# What the two populations can be compared on is COUNT, which fig1 does over a
# full census. What the silent fixes are made of is fig2b.


# --- 2b. what the silent fixes are actually made of ------------------------
def fig_compare(out="fig2_compare.png"):
    """Disclosed vs undisclosed composition, ordered by the difference.

    The earlier version showed only the undisclosed side, which cannot answer the
    question the corpus was built for. It also once claimed some mechanisms never
    appear in an advisory — withdrawn, correctly, because it divided by all 1,325
    advisory rows when 1,131 of them repair no defect, leaving nothing testable.

    On the right denominator — rows on each side whose mechanism was identified —
    six differences survive Fisher's exact test with a Holm correction across all
    22 mechanisms. Those six are drawn; the other sixteen are summed into one row
    rather than dropped, because at n=194 a 2% cell is one or two commits and a
    grid of them reads as evidence when it is not.

    Grouped bars with the labels in a left column, not a butterfly with labels
    down the middle: in the butterfly draft every label sat between two rows and
    could be read as belonging to either.
    """
    from scipy.stats import fisher_exact

    A = ADV[ADV.mechanism.notna() & (ADV.mechanism != "other")]
    S_ = SIL[SIL.mechanism != "other"]
    na, ns = len(A), len(S_)
    rec = []
    for m in sorted(set(A.mechanism) | set(S_.mechanism)):
        a, sc = int((A.mechanism == m).sum()), int((S_.mechanism == m).sum())
        _, pv = fisher_exact([[a, na - a], [sc, ns - sc]])
        rec.append({"m": m, "a": a, "s": sc, "p": pv})
    r = pd.DataFrame(rec).sort_values("p").reset_index(drop=True)
    k = len(r)
    r["holm"] = [min(1.0, (k - i) * pv) for i, pv in enumerate(r.p)]
    sig = r[r.holm < 0.05].copy()
    rest = r[r.holm >= 0.05]
    sig["ash"], sig["ssh"] = sig.a / na, sig.s / ns
    sig = sig.assign(d=sig.ssh - sig.ash).sort_values("d")     # disclosed-heavy first

    HERE = {"dependency-supply-chain": "外部ライブラリの脆弱性対応"}
    rows = [(HERE.get(x.m, MECH_JA.get(x.m, x.m)), x.ash, x.ssh, x.a, x.s, True)
            for _, x in sig.iterrows()]
    rows.append((f"有意差のない他 {len(rest)} 原因（合計）",
                 rest.a.sum() / na, rest.s.sum() / ns,
                 int(rest.a.sum()), int(rest.s.sum()), False))

    n = len(rows)
    XMAX = 0.86
    fig, ax = S.new(13.4, 0.92 * n + 2.7, xlim=(-0.72, 1.02), ylim=(-0.95, n + 0.78))
    sc = XMAX / 0.80

    for i, (lab, ash, ssh, a, s_, is_sig) in enumerate(rows):
        y = n - 1 - i
        S.t(ax, -0.035, y + 0.42, lab, fp="bold" if is_sig else "reg", size=13,
            color=S.INK if is_sig else S.MUTED, ha="right", va="center")
        for k2, (v, cnt, col) in enumerate(((ash, a, S.SLATE), (ssh, s_, S.RUST))):
            yy = y + (0.62 if k2 == 0 else 0.16)
            c = col if is_sig else S.lighten(col, 0.55)
            S.rrect(ax, 0, yy - 0.16, max(v * sc, 0.0016), 0.32, fc=c, ec="none",
                    rs=0.004, z=2)
            S.t(ax, v * sc + 0.012, yy, f"{v * 100:.1f}%  （{cnt:,} 件）", fp="med",
                size=11.5, color=c, ha="left", va="center")

    # Legend stacked, not side by side: laid out on one line the second swatch
    # landed on top of the first entry's "n=194".
    for row, (col, lab) in enumerate(((S.SLATE, f"{T_DISCLOSED}（{T_DISCLOSED_DEF}）  n={na}"),
                                      (S.RUST, f"{T_SILENT}（{T_SILENT_DEF}）  n={ns:,}"))):
        yy = n + 0.44 - row * 0.30
        S.rrect(ax, -0.60, yy - 0.07, 0.028, 0.15, fc=col, ec="none", rs=0.004, z=2)
        S.t(ax, -0.556, yy, lab, fp="med", size=12.5, color=col,
            ha="left", va="center")

    S.t(ax, -0.72, -0.66,
        "Fisher 正確確率検定、22 原因にわたる Holm 補正後 p<0.05 の 6 原因を掲載。"
        "割合は各側で原因を特定できた行に対する値。",
        fp="reg", size=11, color=S.MUTED, ha="left", va="center")
    fig.subplots_adjust(top=1 - 1.42 / (0.92 * n + 2.7), bottom=0.03,
                        left=0.035, right=0.985)
    S.title_block(fig,
                  f"{T_DISCLOSED}の修正と{T_SILENT}の、原因別の内訳",
                  f"上から順に、{T_DISCLOSED}側に偏る原因から{T_SILENT}側に偏る原因へ。",
                  x=0.035, y=1 - 0.34 / (0.92 * n + 2.7))
    return S.save(fig, out)


def fig_heatmap(out="fig3_stack.png"):
    """Software type against defect location, with the column totals underneath.

    The totals row carries what used to be a separate figure: signing and display
    defects (1,632 + 628) outnumber key-material ones (1,190 + 304). Two columns
    to a group, bracketed, so the comparison is read off the same table instead of
    asserted in a second one.
    """
    order_c = [c for c in SIL.cat.value_counts().index if c in CAT_JA]
    unknown = sorted(set(SIL.cat.dropna()) - set(CAT_JA))
    if unknown:
        raise SystemExit(f"fig3: no Japanese label for {unknown}; the figure would "
                         f"drop them silently")
    # signing beside ui_deception, key_material beside memory: the grouping is the
    # argument, so adjacency has to encode it.
    order_v = ["signing", "ui_deception", "key_material", "memory",
               "firmware", "transport", "contract", "approval"]
    ct = pd.crosstab(SIL.cat, SIL.vuln_class, normalize="index") * 100
    ct = ct.reindex(index=order_c, columns=order_v).fillna(0.0)
    counts = SIL.cat.value_counts().reindex(order_c).fillna(0).astype(int)
    totals = SIL.vuln_class.value_counts().reindex(order_v).fillna(0).astype(int)

    nr, nc = ct.shape
    # +1 row of totals below the matrix, +1 band of group brackets above it
    fig, ax = S.new(13.2, 0.78 * nr + 3.1,
                    xlim=(-2.35, nc + 0.05), ylim=(-1.60, nr + 1.78))
    for i, cat in enumerate(order_c):
        y = nr - 1 - i
        for j, cls in enumerate(order_v):
            v = ct.loc[cat, cls]
            ax.add_patch(S.plt.Rectangle((j + 0.045, y + 0.09), 0.91, 0.82,
                         fc=S.lighten(S.RUST, 1 - min(v / 70.0, 1.0) * 0.92),
                         ec=S.PAPER, lw=1.6, zorder=2))
            if v >= 3:
                S.t(ax, j + 0.5, y + 0.5, f"{v:.0f}", fp="bold" if v >= 25 else "med",
                    size=13 if v >= 25 else 11,
                    color=S.PAPER if v >= 40 else S.INK, ha="center", va="center",
                    zorder=4)
        # Label and its n on ONE line: stacking them put the count of one row
        # against the second line of the row above it.
        S.t(ax, -0.14, y + 0.50, CAT_JA[cat].replace("\n", ""), fp="med", size=11.5,
            color=S.INK, ha="right", va="center")
        S.t(ax, -0.14, y + 0.14, f"n={counts[cat]:,}", fp="reg", size=9.5,
            color=S.MUTED, ha="right", va="center")

    for j, cls in enumerate(order_v):
        S.t(ax, j + 0.5, nr + 0.16, CLASS_JA[cls], fp="med", size=11.5,
            color=S.SOFT, ha="center", va="bottom", linespacing=1.35)
        S.t(ax, j + 0.5, -0.42, f"{int(totals[cls]):,}", fp="bold", size=13,
            color=S.INK, ha="center", va="center")
    S.t(ax, -0.14, -0.42, "全体の件数", fp="med", size=11.5, color=S.INK,
        ha="right", va="center")

    # Group brackets: the fig4 claim, drawn rather than stated. Two lines, because
    # a bracket spans two columns and one line of this text is twice that wide —
    # side by side the two labels collided over the middle column.
    for x0, x1, lab in ((0, 2, "承認内容と異なる署名・表示"),
                        (2, 4, "鍵・シードそのもの")):
        tot = int(totals[["signing", "ui_deception"]].sum() if x0 == 0
                  else totals[["key_material", "memory"]].sum())
        # The line sits well clear of the count: at a 0.11-unit gap it ran through
        # the numerals' descenders.
        ax.plot([x0 + 0.06, x1 - 0.06], [nr + 0.88, nr + 0.88], color=S.SLATE,
                lw=1.6, zorder=3)
        S.t(ax, (x0 + x1) / 2, nr + 1.44, lab, fp="med", size=12, color=S.SLATE,
            ha="center", va="center")
        S.t(ax, (x0 + x1) / 2, nr + 1.16, f"{tot:,} 件", fp="bold", size=13,
            color=S.SLATE, ha="center", va="center")

    fig.subplots_adjust(top=1 - 1.55 / (0.78 * nr + 3.1), bottom=0.02,
                        left=0.155, right=0.985)
    S.title_block(fig,
                  "ソフトウェア種別ごとの欠陥箇所の分布",
                  f"{T_SILENT}（{T_SILENT_DEF}）{len(SIL):,} 件。数値は各行内の割合（%）、"
                  f"3% 未満は非表示。分類器には種別を与えていない。",
                  x=0.035, y=1 - 0.32 / (0.78 * nr + 3.1))
    return S.save(fig, out)


# --- 5. why yield is the wrong sort key ------------------------------------
if __name__ == "__main__":
    for f in (fig_ratio, fig_compare, fig_heatmap):
        print(f())
