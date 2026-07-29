"""load.py — single entry point for the SPECA vulnerability-reports
corpus hosted on HuggingFace as `NyxFoundation/vulnerability-reports`.

The repo holds one **config per security domain** (`defi`, `lending`,
`oracle`, …). Pick the domain you want at load time.

Consumers should prefer this helper over reading CSVs directly. The
canonical source of truth is HF; CSVs are scratch artifacts.

Example:
    from scripts.datasets.load import load_findings

    df = load_findings(domain="defi")          # default repo + config
    print(df.columns.tolist())
    # ['id', 'source_platform', 'contest', 'issue_id', 'severity',
    #  'title', 'description', 'source_url', 'domain', 'scraped_at',
    #  'source']
    # NOTE: the published parquet ships only `source_platform`. `source`
    # is a *wallet-side* alias added by this loader (see
    # add_compat_aliases), purely so older consumers that still reference
    # `row['source']` keep working without code changes.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd

DEFAULT_REPO = "NyxFoundation/vulnerability-reports"


def load_findings(
    domain: str = "defi",
    *,
    repo_id: str = DEFAULT_REPO,
    split: str = "train",
    local_parquet: str | Path | None = None,
    revision: str = "main",
    add_compat_aliases: bool = True,
) -> "pd.DataFrame":
    """Load a SPECA vulnerability-reports config (one domain).

    Resolution:
        1. If `local_parquet` is given, read it directly. Useful for tests
           and offline development against a freshly-built artifact.
        2. Otherwise, fetch from HF via `datasets.load_dataset`, using
           `repo_id` (default: `NyxFoundation/vulnerability-reports`) with
           `domain` as the config name.

    `add_compat_aliases=True` adds a `source` column as a copy of
    `source_platform`, since pre-migration consumers reference the
    former name.
    """
    import pandas as pd

    if local_parquet is not None:
        df = pd.read_parquet(str(local_parquet))
    else:
        from datasets import load_dataset

        ds = load_dataset(repo_id, name=domain, split=split, revision=revision)
        df = ds.to_pandas()

    if add_compat_aliases and "source_platform" in df.columns and "source" not in df.columns:
        df["source"] = df["source_platform"]

    return df
