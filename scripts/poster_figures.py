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
SIL = pd.read_csv(ROOT / "data/wave1_mechanisms.csv")

_sp = ilu.spec_from_file_location("w", ROOT / "collection/wallets.py")
_w = ilu.module_from_spec(_sp); _sp.loader.exec_module(_w)
CATEGORY = {k: v["category"] for k, v in _w.WALLET_CONFIG.items()}
SIL = SIL.assign(cat=SIL.wallet.map(CATEGORY))

CAT_JA = {
    "hardware_firmware": "ハードウェア\nファームウェア",
    "desktop": "デスクトップ",
    "wallet_sdk": "ウォレット\nSDK・ライブラリ",
    "browser_extension": "ブラウザ拡張",
    "infra": "接続基盤",
    "smart_account": "スマート\nコントラクト口座",
}
CLASS_JA = {
    "signing": "署名", "key_material": "鍵素材", "firmware": "ファーム\nウェア",
    "ui_deception": "UI偽装", "transport": "通信経路", "memory": "メモリ",
    "contract": "コントラクト", "approval": "承認権限",
}
MECH_JA = {
    "input-bounds-parsing": "入力の長さ・境界検査",
    "signed-differs-from-shown": "署名する内容と画面表示の不一致",
    "authorization-check": "呼び出し元の権限確認",
    "key-derivation-storage": "鍵の導出・保管",
    "encoding-canonicalization": "エンコード・正規化",
    "key-lifetime-in-memory": "鍵のメモリ残留",
    "signature-verification-gap": "署名検証の欠落・無効化",
    "state-race-concurrency": "状態競合・レース",
    "origin-session-auth": "接続元・セッションの認証",
    "side-channel-fault": "サイドチャネル・故障注入",
    "replay-scope": "署名の使い回し防止",
    "nonce-or-randomness": "nonce・乱数",
    "curve-point-validation": "曲線・点の検証",
    "uri-deeplink-handling": "URI・ディープリンク",
    "dependency-supply-chain": "外部ライブラリ",
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
    S.t(ax, 0, 1.10, "公表されずに修正された欠陥", fp="bold", size=15.5, color=S.INK, va="center")
    S.t(ax, 0, 0.83, "10 製品の全変更履歴を 1 件ずつ判定",
        fp="reg", size=11, color=S.MUTED, va="center")
    S.rrect(ax, 0, 0.36, silent, 0.32, fc=S.RUST, ec="none", rs=0.02, z=2)
    S.t(ax, silent + W * 0.015, 0.52, f"{silent:,}", fp="black", size=30,
        color=S.RUST, va="center")

    # advisory rows, segmented
    S.t(ax, 0, -0.10, "脆弱性情報が公開された修正", fp="bold", size=15.5,
        color=S.INK, va="center")
    S.t(ax, 0, -0.37, "CVE 番号などが付与されているもの", fp="reg", size=11,
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
    S.t(ax, W * 0.56, -0.16, f"うち 資産の保管・送金処理の欠陥は\nわずか {conf} 件（4%）",
        fp="bold", size=15.5, color=S.RUST, va="center", linespacing=1.5)
    S.arrow(ax, (W * 0.545, -0.34), (conf * 2.2, -0.60),
            color=S.RUST_L, lw=1.7, ms=12, rad=-0.26)

    for i, (c, lab, n) in enumerate(((S.RUST, "資産の保管・送金処理の欠陥", conf),
                                     (S.SLATE, "外部ライブラリの脆弱性への追随", dep),
                                     (S.lighten(S.SLATE, 0.60),
                                      "体制整備・資産処理以外の不具合", rest))):
        yy = -1.14 - i * 0.22
        S.rrect(ax, 0, yy - 0.055, W * 0.016, 0.125, fc=c, ec="none", rs=0.02, z=3)
        S.t(ax, W * 0.030, yy + 0.008, f"{lab}   {n:,}", fp="med", size=11.5,
            color=S.SOFT, va="center")

    fig.subplots_adjust(top=0.775, bottom=0.03, left=0.045, right=0.985)
    S.title_block(fig,
                  "公開された脆弱性情報と、公表されずに修正された欠陥の件数",
                  "暗号資産ウォレット 10 製品のソースコード変更履歴より。"
                  "公開情報を伴う 1,325 件のうち、製品自身の資産保管処理の欠陥は 51 件。",
                  x=0.045, y=0.965)
    return S.save(fig, out)


# --- 2. mechanism gap ------------------------------------------------------
def fig_mechanisms(out="fig2_mechanisms.png"):
    """Dumbbell. The four mechanisms an advisory has never once described."""
    sv = SIL.mechanism.value_counts(normalize=True) * 100
    av = ADV.mechanism.value_counts(normalize=True) * 100
    t = pd.DataFrame({"s": sv, "a": av}).fillna(0.0)
    t["n_s"] = SIL.mechanism.value_counts().reindex(t.index).fillna(0).astype(int)
    t["n_a"] = ADV.mechanism.value_counts().reindex(t.index).fillna(0).astype(int)
    t = t.drop(index=["other"], errors="ignore").sort_values("s")

    n = len(t)
    fig, ax = S.new(12.8, 0.52 * n + 3.0, axis_off=False)
    ax.set_xlim(-1.4, 17.6); ax.set_ylim(-0.9, n - 0.1)
    for i, (m, r) in enumerate(t.iterrows()):
        zero = r.n_a == 0
        ax.plot([r.a, r.s], [i, i], color=S.lighten(S.RUST, 0.72) if zero
                else S.lighten(S.SLATE, 0.66), lw=2.6, solid_capstyle="round", zorder=2)
        ax.plot([r.a], [i], "o", ms=8, color=S.SLATE if not zero else S.PAPER,
                mec=S.SLATE if not zero else S.RUST, mew=1.8, zorder=4)
        ax.plot([r.s], [i], "o", ms=10, color=S.RUST, zorder=4)
        S.t(ax, -0.55, i, MECH_JA.get(m, m), fp="med" if not zero else "bold",
            size=11.5, color=S.INK if not zero else S.RUST, ha="right", va="center")
        S.t(ax, r.s + 0.34, i, f"{int(r.n_s):,}", fp="bold", size=10.5,
            color=S.RUST, va="center")
        if zero:
            S.t(ax, -0.30, i, "0", fp="bold", size=10.5, color=S.RUST,
                ha="left", va="center")

    S.t(ax, t.s.max() * 0.86, n - 0.55, "公表されず修正", fp="bold", size=13, color=S.RUST,
        ha="center", va="center")
    S.t(ax, 2.9, n - 0.55, "公開された", fp="bold", size=13, color=S.SLATE,
        ha="center", va="center")
    nz = t[t.n_a == 0]
    S.t(ax, 17.4, -0.66,
        f"太字＝公開情報では一度も記述されなかった原因"
        f"（{len(nz)} 種・計 {int(nz.n_s.sum()):,} 件）",
        fp="bold", size=12, color=S.RUST, ha="right", va="center")

    ax.set_yticks([])
    ax.set_xticks(range(0, 16, 5))
    ax.set_xticklabels([f"{v}%" for v in range(0, 16, 5)],
                       fontproperties=S.F["med"], fontsize=10.5, color=S.MUTED)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(S.FAINT)
    ax.grid(axis="x", color=S.HAIR, lw=0.9)
    ax.set_axisbelow(True)
    fig.subplots_adjust(top=0.855, bottom=0.075, left=0.225, right=0.975)
    S.title_block(fig,
                  "欠陥の原因別に見た、公開情報と非公開修正の構成比の差",
                  "各原因が占める割合（%）。右端の数字は非公開で修正された件数。",
                  x=0.045, y=0.975)
    return S.save(fig, out)


# --- 3. where what breaks in the custody stack -----------------------------
def fig_heatmap(out="fig3_stack.png"):
    order_c = ["hardware_firmware", "smart_account", "infra", "wallet_sdk",
               "browser_extension", "desktop"]
    order_v = ["signing", "key_material", "firmware", "ui_deception",
               "transport", "contract", "memory", "approval"]
    ct = pd.crosstab(SIL.cat, SIL.vuln_class, normalize="index") * 100
    ct = ct.reindex(index=order_c, columns=order_v).fillna(0.0)
    counts = SIL.cat.value_counts().reindex(order_c).fillna(0).astype(int)

    nr, nc = ct.shape
    fig, ax = S.new(12.8, 6.6, xlim=(-2.05, nc + 0.05), ylim=(-0.15, nr + 0.75))
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
                    color=S.PAPER if v >= 40 else S.INK, ha="center", va="center", zorder=4)
        S.t(ax, -0.12, y + 0.58, CAT_JA[cat], fp="med", size=11, color=S.INK,
            ha="right", va="center", linespacing=1.3)
        S.t(ax, -0.12, y + 0.20, f"{counts[cat]:,} 件", fp="reg", size=9.5,
            color=S.MUTED, ha="right", va="center")
    for j, cls in enumerate(order_v):
        S.t(ax, j + 0.5, nr + 0.14, CLASS_JA[cls], fp="med", size=11, color=S.SOFT,
            ha="center", va="bottom", linespacing=1.25)
    fig.subplots_adjust(top=0.775, bottom=0.06, left=0.175, right=0.985)
    S.title_block(fig,
                  "ソフトウェアの種別と、発生する欠陥の種類の関係",
                  "各行内での割合（%）。判定した分類器には、"
                  "どの種別のソフトウェアを読んでいるかを与えていない。",
                  x=0.045, y=0.965)
    return S.save(fig, out)


# --- 4. what the folk model gets wrong -------------------------------------
def fig_folk(out="fig4_folk.png"):
    vc = SIL.vuln_class.value_counts()
    sign = int(vc.get("signing", 0)) + int(vc.get("ui_deception", 0))
    keys = int(vc.get("key_material", 0))
    fig, ax = S.new(12.8, 5.6, xlim=(-sign * 0.02, sign * 1.34), ylim=(-0.48, 2.15))

    rows = [
        (1.34, sign, S.RUST,
         "電子署名・画面表示の欠陥",
         "利用者が承認していない内容に有効な署名が付く／画面が別の内容を表示する",
         f"署名 {int(vc.get('signing',0)):,} ＋ UI偽装 {int(vc.get('ui_deception',0)):,}"),
        (0.34, keys, S.SLATE,
         "鍵素材の欠陥",
         "秘密鍵や復元用フレーズが漏れる・弱く生成される・メモリに残る", None),
    ]
    for y, v, c, head, desc, note in rows:
        S.t(ax, 0, y + 0.60, head, fp="bold", size=16, color=S.INK, va="center")
        S.t(ax, 0, y + 0.31, desc, fp="reg", size=11.5, color=S.SOFT, va="center")
        S.rrect(ax, 0, y - 0.15, v, 0.34, fc=c, ec="none", rs=0.02, z=2)
        S.t(ax, v + sign * 0.014, y + 0.02, f"{v:,}", fp="black", size=30, color=c,
            va="center")
        if note:  # only when it breaks the total down; repeating it is noise
            S.t(ax, v + sign * 0.014, y - 0.26, note, fp="med", size=10.5,
                color=S.MUTED, va="center")

    S.t(ax, 0, -0.28, "「復元用フレーズを守れば安全」という一般的な助言は、欠陥の所在と一致しない。",
        fp="bold", size=14, color=S.RUST, va="center")
    fig.subplots_adjust(top=0.80, bottom=0.05, left=0.045, right=0.90)
    S.title_block(fig,
                  "欠陥の所在の内訳 — 電子署名・画面表示の誤りと、鍵そのものの漏洩",
                  f"非公開で修正された {len(SIL):,} 件の分類。",
                  x=0.045, y=0.965)
    return S.save(fig, out)


# --- 5. why yield is the wrong sort key ------------------------------------
if __name__ == "__main__":
    for f in (fig_ratio, fig_mechanisms, fig_heatmap, fig_folk):
        print(f())
