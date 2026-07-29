"""Quality gates for the curated ethereum-vuln-dataset.

These assert the properties that make the corpus "vulnerabilities only": the
build is reproducible, the release-note boilerplate is gone, and every row
carries a security signal.
"""
import re
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
CURATED = ROOT / "data" / "wallet_vulns.parquet"
RAW = ROOT / "data" / "raw" / "train.classified.parquet"

BOILERPLATE = re.compile(r"critical update required|urgency guidelines|high-urgency", re.I)
REQUIRED_COLS = {
    "id", "source_platform", "severity", "title", "description",
    "source_url", "stride", "cwe_top25", "security_score", "confidence",
}


@pytest.fixture(scope="module")
def df():
    return pd.read_parquet(CURATED)


def test_schema(df):
    assert REQUIRED_COLS <= set(df.columns), REQUIRED_COLS - set(df.columns)


def test_nonempty(df):
    assert len(df) > 1000


def test_no_release_boilerplate(df):
    """T1: the phantom-Nimbus-critical class must not survive."""
    blob = df["title"].fillna("") + " " + df["description"].fillna("")
    assert int(blob.str.contains(BOILERPLATE).sum()) == 0


def test_every_row_has_a_security_signal(df):
    """GATE: no row without at least one independent security signal."""
    has_sev = df["severity"].fillna("").str.lower().isin({"critical", "high", "medium", "low"})
    has_kw = df["security_score"] >= 0.5
    has_stride = ~df["stride"].fillna("Other").isin(["Other"])
    has_cwe = ~df["cwe_top25"].fillna("N/A").isin(["N/A"])
    blob = df["title"].fillna("") + " " + df["description"].fillna("")
    has_id = blob.str.contains(r"CVE-\d{4}-\d{4,7}|GHSA-", case=False, regex=True)
    # fix-verb × crash-class impact in the title (recall-expansion gate signal)
    fiximpact = re.compile(
        r"\b(?:fix|fixes|fixed|prevent|avoid|guard|handle|resolve|correct|patch)\w*"
        r"\b[^.\n]{0,40}\b(?:crash|panic|segfault|deadlock|hang|freeze|oom"
        r"|out.of.memory|overflow|underflow|data race|race condition|reorg"
        r"|non.?determin|infinite loop|use.after.free|null (?:pointer|deref))\b"
        r"|\b(?:crash|panic|segfault|deadlock|hang|oom|overflow|underflow|reorg"
        r"|race condition)\b[^.\n]{0,25}"
        r"\b(?:fix|fixed|prevent|avoid|guard against|resolved|patch)\w*\b", re.I)
    has_fiximpact = df["title"].fillna("").str.contains(fiximpact)
    if "silent_fix_prob" in df.columns:
        has_silentfix = pd.to_numeric(df["silent_fix_prob"], errors="coerce").fillna(0) >= 0.70
    else:
        has_silentfix = pd.Series(False, index=df.index)
    assert bool((has_sev | has_kw | has_stride | has_cwe | has_id | has_fiximpact
                 | has_silentfix).all())


def test_confidence_values(df):
    assert set(df["confidence"].unique()) <= {"high", "medium", "low"}


def test_score_range(df):
    assert df["security_score"].between(0.0, 1.0).all()


def test_curated_is_subset_of_raw(df):
    raw = pd.read_parquet(RAW)
    assert len(df) < len(raw)
    assert set(df["id"]) <= set(raw["id"])
