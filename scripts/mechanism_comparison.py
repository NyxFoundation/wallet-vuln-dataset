#!/usr/bin/env python3
"""data/mechanism_comparison.csv — the table behind fig2, generated the same way.

The previous version of this file was written by hand from a wave-1-only
population: its silent_n summed to 4,608 while the figure showed 5,457 and then
4,349. A table and a figure that answer the same question from different numbers
is worse than having only one of them, so this reads the same source, applies the
same reachability filter, and runs the same test.

    uv run python scripts/mechanism_comparison.py
"""
from __future__ import annotations

import pathlib

import pandas as pd
from scipy.stats import fisher_exact

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _flag(df: pd.DataFrame, col: str, when_missing: bool) -> pd.Series:
    v = df[col]
    if v.dtype == object:
        v = v.map({"True": True, "False": False, True: True, False: False})
    return v.astype("boolean").fillna(when_missing)


def analysable(df: pd.DataFrame) -> pd.DataFrame:
    """Shipped, counted once. NA (untestable) is kept — see mark_reachable.py."""
    if "on_default" not in df.columns:
        raise SystemExit("run scripts/mark_reachable.py first")
    reached = _flag(df, "on_default", True) | _flag(df, "in_release", True)
    return df[reached & ~_flag(df, "dup_subject", False)].copy()


def main() -> int:
    adv = analysable(pd.read_csv(ROOT / "data/advisory_mechanisms.csv"))
    sil = analysable(pd.read_csv(ROOT / "data/silent_mechanisms.csv"))
    a = adv[adv.mechanism.notna() & (adv.mechanism != "other")]
    s = sil[sil.mechanism != "other"]
    na, ns = len(a), len(s)

    rows = []
    for m in sorted(set(a.mechanism) | set(s.mechanism)):
        ac, sc = int((a.mechanism == m).sum()), int((s.mechanism == m).sum())
        _, p = fisher_exact([[ac, na - ac], [sc, ns - sc]])
        rows.append({"mechanism": m,
                     "advisory_n": ac, "advisory_pct": round(100 * ac / na, 1),
                     "silent_n": sc, "silent_pct": round(100 * sc / ns, 1),
                     "delta_pct": round(100 * (sc / ns - ac / na), 1),
                     "fisher_p": p})
    df = pd.DataFrame(rows).sort_values("fisher_p").reset_index(drop=True)
    k = len(df)
    # Holm across every mechanism tested, not per row: 22 tests at 0.05 each
    # would be expected to produce one false positive on its own.
    df["holm_p"] = [min(1.0, (k - i) * p) for i, p in enumerate(df.fisher_p)]
    df["significant"] = df.holm_p < 0.05
    df = df.sort_values("delta_pct")

    out = ROOT / "data/mechanism_comparison.csv"
    df.to_csv(out, index=False)
    print(f"wrote {out}")
    print(f"  denominators: advisory n={na}, silent n={ns:,}")
    print(f"  significant after Holm: {int(df.significant.sum())} of {k}")
    print(df[df.significant][["mechanism", "advisory_pct", "silent_pct",
                              "holm_p"]].to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
