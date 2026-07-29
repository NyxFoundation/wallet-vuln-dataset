#!/usr/bin/env python3
"""build_security_dataset.py — turn the raw past-fix crawl into a curated
*security-only* Ethereum vulnerability dataset.

The raw crawl (one row per merged PR / commit / advisory / release note across
the 11 wallets) is high recall but noisy: only ~half the rows are actually
security fixes, and release-note boilerplate inflates severity. This script
applies the collection methodology and emits a curated table where every row is
a genuine security fix, each annotated with a relevance score and a confidence
tier so a consumer can threshold further.

Three stages, run in order (the order matters):

  T1  Drop release-note / urgency boilerplate.
      Nimbus release notes carry an "Urgency guidelines" template
      ("critical update required for Nimbus") that an earlier severity regex
      mis-read as 97 Critical findings — 95 of them bogus. These are not fixes;
      they are dropped outright. Severity from a release header is never trusted.

  T7  Score security relevance (0.0-1.0) from CVE/GHSA ids, severity, and a
      weighted keyword match over title + description. Runs AFTER T1 so the
      bogus release-note severities can't score themselves to 1.0.

  GATE  Mark a row security_relevant when ANY independent signal fires:
        a CVE/GHSA id, a rated severity, a security keyword, an LLM STRIDE
        category, or an LLM CWE-Top-25 label. The curated output keeps only
        these rows. A `confidence` tier (high/medium/low) records how strong the
        evidence is so downstream users can take the high-confidence slice.

Deterministic and offline: same input parquet -> same output. No network, no
API key. (Re-collecting the raw parquet is a separate, network-bound step under
collection/.)

Usage::

    uv run python pipeline/build_security_dataset.py \
        --in  data/raw/train.classified.parquet \
        --out data/wallet_vulns.parquet

    # inspect the effect without writing anything
    uv run python pipeline/build_security_dataset.py --in data/raw/train.classified.parquet --dry-run
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import pandas as pd

# The wallet threat vocabulary is shared with the crawlers so the gate looks
# for exactly what the crawl went out to find (collection/wallet_vocab.py).
import importlib.util as _ilu
_VSPEC = _ilu.spec_from_file_location(
    "_wallet_vocab", Path(__file__).resolve().parent.parent / "collection" / "wallet_vocab.py")
_vocab = _ilu.module_from_spec(_VSPEC); _VSPEC.loader.exec_module(_vocab)  # type: ignore

# --- T1: release-note / urgency boilerplate (not a fix) --------------------
BOILERPLATE_RE = re.compile(
    r"critical update required"
    r"|urgency guidelines"
    r"|high-urgency"
    r"|update is (?:strongly )?recommended for all"
    r"|this is a (?:low|medium|high)-urgency release",
    re.IGNORECASE,
)

# --- T7: weighted security keywords ---------------------------------------
# Identifiers are decisive on their own.
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE)
# Advisory ids that also confer authority (superset of CVE_RE + RustSec).
ADVISORY_ID_RE = re.compile(
    r"CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|RUSTSEC-\d{4}-\d{4}",
    re.IGNORECASE,
)

# --- T2: non-vulnerability meta-work (CI / docs / dep-bump) ----------------
# Title-anchored so a real "Fix <bug>" whose *description* happens to mention
# CI or deps is never dropped. A matching row is removed from the security set
# UNLESS it carries an advisory id or strong vuln language in the title
# (e.g. "Bump h2 for RUSTSEC-2024-0332", "...Handle u64 overflow").
NOISE_TITLE_RE = re.compile(
    r"(?:^|\b)(?:"
    r"bump |chore\(deps|dependabot|renovate"
    r"|pin github actions|github actions|codeql|add .*security scan|security scanning"
    r"|security policy|security\.md|code of conduct|\breadme\b|update copyright"
    r"|update license|documentation update|update docs|docs:|changelog"
    r"|typo in|fix typo|add default security|create security policy"
    r")",
    re.IGNORECASE,
)

# --- T2b: NVD keyword-match false positives --------------------------------
# crawl_cve.py searches NVD by wallet name and matches it as a *substring*
# ("geth" in "gethostbyaddr" / "GetHost", "Gether Technology"; "usb: g…" Linux
# gadget CVEs), dumping unrelated advisories (glibc, X.Org, Samba, Linux USB)
# straight into the authoritative tier. Such a row has a *bare* CVE-id title.
# It is kept only when its description actually names the wallet.
BARE_CVE_TITLE_RE = re.compile(r"^\s*CVE-\d{4}-\d{3,7}\s*$", re.IGNORECASE)
_ISPEC = _ilu.spec_from_file_location(
    "_wallet_ident", Path(__file__).resolve().parent.parent / "collection" / "wallet_ident.py")
_ident = _ilu.module_from_spec(_ISPEC); _ISPEC.loader.exec_module(_ident)  # type: ignore
WALLET_CVE_IDENT: dict[str, str] = _ident.CVE_IDENT


def _nvd_false_positive(title: str, description: str, platform: str) -> bool:
    """True when a bare-CVE-title row's description does NOT name its wallet."""
    if not BARE_CVE_TITLE_RE.match(title or ""):
        return False
    pat = WALLET_CVE_IDENT.get(platform)
    if not pat:
        return True   # unknown platform: not a bare-CVE NVD import, leave it alone
    return re.search(pat, description or "", re.IGNORECASE) is None

# Strong: language that almost always means a custody defect. Built from the
# shared vocabulary's decisive groups (key_material / signing / mpc / contract /
# approval) rather than restated here, so the crawl and the gate cannot drift.
_STRONG_GROUPS = ("key_material", "signing", "mpc", "contract", "approval", "supply_chain")
STRONG_RE = re.compile(
    "|".join(
        (r"\b" if k[:1].isalnum() else "") + re.escape(k) + (r"\b" if k[-1:].isalnum() else "")
        for g in _STRONG_GROUPS for k in _vocab.GROUPS[g]
    )
    # plus the classic severe-defect words, which mean the same thing anywhere
    + r"|\b(?:vulnerabilit(?:y|ies)|exploit|RCE|remote code exec(?:ution)?"
      r"|arbitrary code|use.after.free|double.free|heap (?:overflow|corruption)"
      r"|buffer overflow|out.of.bounds|memory corruption|unsound(?:ness)?"
      r"|privilege escal|auth(?:entication)? bypass|steal(?:ing)? funds"
      r"|loss of funds|fund loss|drain(?:ed|ing)? (?:wallet|funds))\b",
    re.IGNORECASE,
)

# Moderate: bug-class language that is often, but not always, custody relevant
# (a wallet UI crash is a crash; it is not usually a fund-loss bug).
_MODERATE_GROUPS = ("transport", "ui_deception", "platform", "memory", "generic")
MODERATE_RE = re.compile(
    "|".join(
        (r"\b" if k[:1].isalnum() else "") + re.escape(k) + (r"\b" if k[-1:].isalnum() else "")
        for g in _MODERATE_GROUPS for k in _vocab.GROUPS[g]
    )
    + r"|\b(?:hang|deadlock|livelock|data race|infinite loop|unbounded"
      r"|assertion|malformed|untrusted|sanitiz|validate|underflow)\b",
    re.IGNORECASE,
)

HIGH_SEV = frozenset({"critical", "high"})
RATED_SEV = frozenset({"critical", "high", "medium", "low"})

# --- C5': fix-verb × impact co-occurrence ----------------------------------
# A linked-issue API crawl was a dead end (wallet PRs almost never use formal
# `Closes #N`, so closingIssuesReferences is empty). But the impact the terse
# issue would describe is usually stated in the fix itself: "fix panic on …",
# "prevent race condition in …". A fix verb *adjacent to* a crash-class impact
# word is a strong, independent defect signal — far more specific than the bare
# keyword — and it is computable offline on data already in hand.
FIX_IMPACT_RE = re.compile(
    r"\b(?:fix|fixes|fixed|prevent|avoid|guard|handle|resolve|correct|patch)\w*"
    r"\b[^.\n]{0,40}\b(?:crash|panic|segfault|deadlock|hang|freeze|oom"
    r"|out.of.memory|overflow|underflow|data race|race condition|reorg"
    r"|non.?determin|infinite loop|use.after.free|null (?:pointer|deref)|key leak|seed leak|signature replay|replay|nonce reuse|origin check|approval|allowance|phishing|spoof|bypass|leak)\b"
    r"|\b(?:crash|panic|segfault|deadlock|hang|oom|overflow|underflow|reorg"
    r"|race condition)\b[^.\n]{0,25}"
    r"\b(?:fix|fixed|prevent|avoid|guard against|resolved|patch)\w*\b",
    re.IGNORECASE,
)

# --- A2: custody-sensitive code areas --------------------------------------
# A keyword hit *inside* one of these subsystems is a second, independent
# signal — "fix panic in the keyring" stacks kw(panic)+path(keyring) and is
# promoted out of the noisy single-keyword tier. Word-boundary matched so a
# dep-bump like "path-to-regexp" cannot false-match a short path token.
SENSITIVE_PATH_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(p) for p in _vocab.SENSITIVE_PATHS) + r")\b",
    re.IGNORECASE,
)


def score_row(title: str, description: str, severity: str) -> float:
    """Security-relevance score in [0.0, 1.0]. See module docstring."""
    t, d = title or "", description or ""
    s = (severity or "").lower()
    combined = t + " " + d
    if CVE_RE.search(combined):
        return 1.0
    if s in HIGH_SEV:
        return 1.0
    if STRONG_RE.search(t):
        return 0.9
    if STRONG_RE.search(d):
        return 0.8
    if MODERATE_RE.search(t):
        return 0.5
    if MODERATE_RE.search(d):
        return 0.3
    return 0.0


def confidence_tier(row) -> str:
    """high / medium / low evidence that the row is a real vulnerability fix."""
    t, d = str(row["title"] or ""), str(row["description"] or "")
    s = str(row["severity"] or "").lower()
    if CVE_RE.search(t + " " + d) or s in HIGH_SEV or STRONG_RE.search(t):
        return "high"
    if row["cwe_top25"] not in ("", "N/A", None) or s == "medium" or row["security_score"] >= 0.5:
        return "medium"
    return "low"


def count_signals(row) -> int:
    """Number of *independent* security signals firing on a row.

    Multi-signal scoring is the loop's precision lever: dep-bump / CI / docs
    noise fires at most one weak keyword, whereas a real fix stacks several
    (id + severity + strong keyword + sensitive path + linked crash issue …).
    Signals added by later iterations (diff size, review-comment language,
    backport) plug in here via their own columns when present.
    """
    t, d = str(row["title"] or ""), str(row["description"] or "")
    combined = t + " " + d
    s = str(row["severity"] or "").lower()
    n = 0
    if CVE_RE.search(combined):
        n += 1                                   # authoritative id
    if s in RATED_SEV:
        n += 1                                   # rated severity
    if STRONG_RE.search(combined):
        n += 1                                   # strong security keyword
    if MODERATE_RE.search(combined):
        n += 1                                   # moderate bug-class keyword
    if SENSITIVE_PATH_RE.search(combined):
        n += 1                                   # security-sensitive subsystem (A2)
    if FIX_IMPACT_RE.search(combined):
        n += 1                                   # fix-verb × crash-class impact (C5')
    if str(row.get("stride", "Other")) not in ("Other", "", "nan"):
        n += 1                                   # LLM STRIDE (if classified)
    if str(row.get("cwe_top25", "N/A")) not in ("N/A", "", "nan"):
        n += 1                                   # LLM CWE-Top-25
    # Enrichment signals from later loop iterations (absent -> skipped):
    try:
        if float(row.get("silent_fix_prob") or 0) >= 0.70:
            n += 1                               # learned silent-fix classifier (method 1)
    except (TypeError, ValueError):
        pass
    if str(row.get("comment_signal", "")).strip():
        n += 1                                   # review-comment language (B4)
    if str(row.get("linked_issue_signal", "")).strip():
        n += 1                                   # linked crash/fuzzer issue (C5)
    if str(row.get("backport_signal", "")).strip():
        n += 1                                   # cherry-pick / backport (A1)
    return n


def authority_tier(row) -> str:
    """Coarse provenance class so a consumer can take the *essential* slice.

    A_authoritative — an advisory/CVE/GHSA id or an advisory-rated severity: a
                      confirmed vulnerability. Near-zero false positives.
    B_corroborated  — no id, but >=2 independent signals stack (e.g. strong
                      keyword + sensitive path + linked crash issue).
    C_candidate     — a single heuristic keyword only; broad-recall, noisier.
    """
    t, d = str(row["title"] or ""), str(row["description"] or "")
    s = str(row["severity"] or "").lower()
    contest = str(row.get("contest", "")).lower()
    if (CVE_RE.search(t + " " + d) or s in RATED_SEV
            or "advisory" in contest or "cve" in contest):
        return "A_authoritative"
    if count_signals(row) >= 2:
        return "B_corroborated"
    return "C_candidate"


def build(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    n_raw = len(df)
    for col in ("title", "description", "severity", "stride", "cwe_top25", "source_platform"):
        if col not in df.columns:
            df[col] = ""
    # Canonicalize the "unclassified" sentinels once, so the gate/signal logic
    # can treat NaN / "" / "nan" identically to Other/N/A. (Makes the former
    # external `normalize` collection step unnecessary — see run_pipeline.sh.)
    df["stride"] = df["stride"].fillna("Other").replace({"": "Other", "nan": "Other"})
    df["cwe_top25"] = df["cwe_top25"].fillna("N/A").replace({"": "N/A", "nan": "N/A"})
    blob = df["title"].fillna("").astype(str) + " " + df["description"].fillna("").astype(str)

    # T1
    t1_mask = blob.str.contains(BOILERPLATE_RE)
    t1_dropped = df[t1_mask]
    df = df[~t1_mask].copy()

    # T2 — drop CI/docs/dep-bump meta-work (title-anchored, with protections).
    # A row is protected (kept, possibly low-tier) if it cites an advisory id
    # anywhere (a dep-bump "for CVE-… / rustsec vuln" is still a security fix),
    # uses strong vuln language in the title, or carries a rated severity.
    title = df["title"].fillna("").astype(str)
    t2_blob = title + " " + df["description"].fillna("").astype(str)
    noise_mask = title.str.contains(NOISE_TITLE_RE)
    protect = (
        t2_blob.str.contains(ADVISORY_ID_RE)
        | title.str.contains(STRONG_RE)
        | df["severity"].fillna("").str.lower().isin(RATED_SEV)
    )
    t2_mask = noise_mask & ~protect
    t2_dropped = df[t2_mask]
    df = df[~t2_mask].copy()

    # T2b — drop NVD substring-match false positives (unrelated CVEs)
    t2b_mask = pd.Series(
        [
            _nvd_false_positive(t, d, p)
            for t, d, p in zip(
                df["title"].fillna(""),
                df["description"].fillna(""),
                df["source_platform"].fillna(""),
            )
        ],
        index=df.index,
    )
    t2b_dropped = df[t2b_mask]
    df = df[~t2b_mask].copy()

    # T7
    df["security_score"] = [
        score_row(t, d, s)
        for t, d, s in zip(df["title"].fillna(""), df["description"].fillna(""), df["severity"].fillna(""))
    ]

    # GATE — union of independent signals
    gate_blob = df["title"].fillna("") + " " + df["description"].fillna("")
    has_id = gate_blob.str.contains(CVE_RE)
    has_sev = df["severity"].fillna("").str.lower().isin(RATED_SEV)
    has_kw = df["security_score"] >= 0.5
    has_stride = ~df["stride"].fillna("Other").isin(["Other"])
    has_cwe = ~df["cwe_top25"].fillna("N/A").isin(["N/A"])
    # Recall expansion: a fix-verb × crash-class impact co-occurrence in the
    # TITLE admits real crash/DoS fixes whose only keyword sat in the description
    # (score 0.3, below the 0.5 threshold). Title-only — a description-level
    # match also fires on release notes that merely *list* a "fix crash". T2
    # already dropped dep-bump/CI titles upstream.
    has_fiximpact = df["title"].fillna("").str.contains(FIX_IMPACT_RE)
    # Recall expansion via the learned classifier: a row the LLM confidently
    # calls a silent fix (silent_fix_prob >= 0.70) is admitted even if the
    # deterministic keyword gate missed it. Only fires where a classification
    # exists (column present); absent -> no effect.
    if "silent_fix_prob" in df.columns:
        has_silentfix = pd.to_numeric(df["silent_fix_prob"], errors="coerce").fillna(0) >= 0.70
    else:
        has_silentfix = pd.Series(False, index=df.index)
    df["security_relevant"] = (has_id | has_sev | has_kw | has_stride | has_cwe
                               | has_fiximpact | has_silentfix)

    sec = df[df["security_relevant"]].copy()
    # fix_commit (issue #89 field, method-2 backlink): the fixing commit SHA is
    # already in the source URL for /commit/ rows; /pull/ rows need a merge-commit
    # lookup (left blank here — a network step, not part of this offline stage).
    sec["fix_commit"] = sec["source_url"].fillna("").str.extract(
        r"/commit/([0-9a-f]{7,40})", flags=re.IGNORECASE)[0].fillna("")
    sec["confidence"] = sec.apply(confidence_tier, axis=1)
    sec["n_signals"] = sec.apply(count_signals, axis=1)
    sec["authority_tier"] = sec.apply(authority_tier, axis=1)
    sec = sec.drop(columns=["security_relevant"])

    report = {
        "raw_rows": int(n_raw),
        "t1_boilerplate_dropped": int(len(t1_dropped)),
        "t1_dropped_by_source": {k: int(v) for k, v in t1_dropped["source_platform"].value_counts().items()},
        "t2_noise_dropped": int(len(t2_dropped)),
        "t2b_nvd_fp_dropped": int(len(t2b_dropped)),
        "after_t1": int(len(df)),
        "security_rows": int(len(sec)),
        "low_signal_dropped": int(len(df) - len(sec)),
        "by_confidence": {k: int(v) for k, v in sec["confidence"].value_counts().items()},
        "by_authority_tier": {k: int(v) for k, v in sec["authority_tier"].value_counts().items()},
        "by_n_signals": {str(k): int(v) for k, v in sec["n_signals"].value_counts().sort_index().items()},
        "by_source": {k: int(v) for k, v in sec["source_platform"].value_counts().items()},
        "by_severity": {k: int(v) for k, v in sec["severity"].value_counts().items()},
        "by_score": {str(k): int(v) for k, v in sec["security_score"].round(1).value_counts().sort_index().items()},
        "residual_boilerplate_fp": int(
            (sec["title"].fillna("") + " " + sec["description"].fillna("")).str.contains(BOILERPLATE_RE).sum()
        ),
    }
    return sec, report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="inp", required=True, type=Path)
    ap.add_argument("--out", dest="out", type=Path)
    ap.add_argument("--manifest", type=Path)
    ap.add_argument("--report", type=Path)
    ap.add_argument("--silent-fix-csv", type=Path,
                    help="optional source_url->silent_fix_prob CSV from the "
                         "learned classifier; joined as a scoring signal")
    ap.add_argument("--labels-csv", type=Path,
                    help="optional id-keyed labels from enrich_labels.py "
                         "(label / root_cause / attack_path / pre+post code / fix_commit)")
    ap.add_argument("--severity-csv", type=Path,
                    help="optional id-keyed severity estimates from estimate_severity.py "
                         "(severity_estimated / severity_source / impact_type / …)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    df = pd.read_parquet(a.inp)
    # Optional: join the learned silent-fix probability (method 1) as a signal.
    if a.silent_fix_csv and a.silent_fix_csv.exists():
        probs = pd.read_csv(a.silent_fix_csv)
        probs = probs.dropna(subset=["source_url"]).drop_duplicates("source_url")
        df = df.merge(probs[["source_url", "silent_fix_prob"]], on="source_url", how="left")
        print(f"[silent-fix] joined {probs['silent_fix_prob'].notna().sum()} "
              f"classifier scores", file=sys.stderr)
    sec, report = build(df)

    # Optional: fold in the id-keyed label enrichment (docs/label_design.md).
    if a.labels_csv and a.labels_csv.exists():
        labels = pd.read_csv(a.labels_csv).drop_duplicates("id")
        # labels.csv carries authoritative fix_commit / introduced_in_commit / cwe_top25
        sec = sec.drop(columns=[c for c in ("fix_commit", "introduced_in_commit", "cwe_top25")
                                if c in sec.columns])
        sec = sec.merge(labels, on="id", how="left")
        if "cwe_top25" in sec.columns:
            sec["cwe_top25"] = sec["cwe_top25"].replace("", pd.NA).fillna("N/A")
        report["labelled"] = int((sec["label"].fillna("other") != "other").sum())
        print(f"[labels] joined {report['labelled']} area labels", file=sys.stderr)

        # De-dup rows that resolved to the SAME fix commit within a wallet:
        # advisory / changelog / release entries collapse onto the PR/commit they
        # reference. cross_reference ran before #PR resolution so it missed these.
        # Keep the richest representative (has code > PR/commit URL > tier > text).
        fc = sec["fix_commit"].fillna("").astype(str)

        def _dscore(r):
            s = 8.0 if str(r.get("pre_fix_code") or "[]") != "[]" else 0.0
            u = str(r.get("source_url") or "")
            s += 4 if ("/pull/" in u or "/commit/" in u) else 0
            s += {"A_authoritative": 3, "B_corroborated": 2, "C_candidate": 1}.get(r.get("authority_tier"), 0)
            s += min(len(str(r.get("description") or "")), 2000) / 1000
            return s

        sec = sec.assign(_k=sec["source_platform"].astype(str) + "|" + fc, _s=sec.apply(_dscore, axis=1))
        hasfc = fc.str.len() > 0
        before = len(sec)
        dedup = pd.concat([sec[~hasfc],
                           sec[hasfc].sort_values("_s", ascending=False).drop_duplicates("_k", keep="first")])
        sec = dedup.drop(columns=["_k", "_s"]).sort_index()
        report["deduped_fix_commit"] = int(before - len(sec))
        report["security_rows"] = int(len(sec))
        report["by_authority_tier"] = {k: int(v) for k, v in sec["authority_tier"].value_counts().items()}
        print(f"[dedup] removed {report['deduped_fix_commit']} same-fix-commit duplicates "
              f"-> {len(sec)} rows", file=sys.stderr)

    # Optional: fold in bug-bounty severity estimates (docs/severity_labeling.md).
    if a.severity_csv and a.severity_csv.exists():
        svc = pd.read_csv(a.severity_csv).drop_duplicates("id")
        keep = [c for c in ("id", "severity_estimated", "severity_source", "impact_type",
                            "reachability", "blast_radius", "severity_why") if c in svc.columns]
        sec = sec.merge(svc[keep], on="id", how="left")
        if "severity_estimated" in sec.columns:      # normalize tier casing
            cap = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
            sec["severity_estimated"] = sec["severity_estimated"].map(
                lambda x: cap.get(str(x).lower(), x) if pd.notna(x) else x)
        report["by_severity_source"] = {k: int(v) for k, v in
                                        sec.get("severity_source", pd.Series(dtype=str)).value_counts().items()}
        print(f"[severity] joined estimates: {report['by_severity_source']}", file=sys.stderr)

    print(json.dumps(report, indent=2, ensure_ascii=False))
    assert report["residual_boilerplate_fp"] == 0, "T1 leak: boilerplate survived into the security set"

    if a.dry_run:
        return 0
    if not a.out:
        ap.error("--out is required unless --dry-run")
    a.out.parent.mkdir(parents=True, exist_ok=True)
    sec.to_parquet(a.out, index=False)
    print(f"\nwrote {len(sec)} rows -> {a.out}")

    # CSV siblings (parquet isn't viewable on GitHub): a full export + a compact
    # preview that stays under GitHub's ~512 KB table-render limit.
    csv_path = a.out.with_suffix(".csv")
    sec.to_csv(csv_path, index=False)
    prev_cols = [c for c in ("source_platform", "label", "root_cause", "attack_path",
                             "severity", "severity_estimated", "authority_tier", "title", "source_url")
                 if c in sec.columns]
    prev = sec[prev_cols].copy()
    if "title" in prev:
        prev["title"] = prev["title"].astype(str).str.slice(0, 70)
    prev.to_csv(a.out.with_suffix(".preview.csv"), index=False)
    print(f"wrote {csv_path} + {a.out.with_suffix('.preview.csv')}")

    manifest_path = a.manifest or a.out.with_name("manifest.json")
    manifest = {
        "domain": "ethereum",
        "n_rows": int(len(sec)),
        "schema": list(sec.columns),
        "build": report,
        "source": "11 Ethereum execution + consensus wallets (past security fixes)",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote manifest -> {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
