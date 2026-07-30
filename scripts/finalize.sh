#!/usr/bin/env bash
# finalize.sh — derive the published dataset from an existing crawl.
#
# run_pipeline.sh does collection AND curation in one pass. This script is the
# curation half only: it takes whatever is already in $WORK and produces
# data/wallet_vulns.{parquet,csv,preview.csv} + data/manifest.json. Use it to
# rebuild after a crawl finishes, after a gate change, or to refresh labels
# without re-crawling anything.
#
# Everything here is offline except stage 10, which reads diffs from the local
# bare clones under $WORK/repos (warm them with collection/local_diffs.py).
#
#   Stage 4  build_derived      canonical CSVs -> train.parquet
#   Stage 5  merge_crawl_csvs   fold in the supplementary CSVs
#   Stage 6  cross_reference    de-dup by advisory id / PR / commit cluster
#   Stage 8  publish raw        -> data/raw/train.classified.parquet
#   Stage 9  curate             THE GATE -> data/wallet_vulns.parquet
#   Stage 10 enrich_labels      label / root_cause / attack_path / pre+post code
#   Stage 9' re-curate          fold the labels into the published table
#
# Env knobs:
#   WORK     crawl working dir            (default: scratchpad_crawl)
#   WORKERS  enrich_labels parallelism    (default 16)
#   SKIP_LABELS=1  stop after stage 9
#
# WORKERS default is 16, not the script's own 6: measured throughput on this
# corpus is ~20 rows/min at 6 workers, i.e. ~12h for 15k rows. The work is
# dominated by lazy blob fetches against the blobless clones, so it is
# network-bound and parallelises well.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

WORK="${WORK:-$REPO/scratchpad_crawl}"
WORKERS="${WORKERS:-16}"
CANON="$WORK/canonical"; SUPP="$WORK/supp"; CVE="$WORK/cve"
DERIVED="$WORK/derived"; TRAIN="$DERIVED/wallet/train.parquet"
export SSL_CERT_FILE="${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}"

PY() { uv run python "$@"; }
step() { echo; echo "=== $* ==="; }

[ -d "$CANON" ] || { echo "FATAL: no canonical dir at $CANON — run collection/run_pipeline.sh first"; exit 1; }

step "Stage 4: build_derived"
SRC=(); shopt -s nullglob
for f in "$CANON"/*.csv; do SRC+=(--source "$f"); done
shopt -u nullglob
[ "${#SRC[@]}" -gt 0 ] || { echo "FATAL: no canonical CSVs"; exit 1; }
echo "${#SRC[@]} canonical sources"
mkdir -p "$DERIVED"
PY collection/build_derived.py --domain wallet --filter-platforms "" \
   --out-dir "$DERIVED" "${SRC[@]}" | tail -2
[ -f "$TRAIN" ] || { echo "FATAL: $TRAIN not produced"; exit 1; }

step "Stage 5: merge supplementary + CVE"
MERGE_DIRS=("$SUPP"); [ -d "$CVE" ] && MERGE_DIRS+=("$CVE")
PY collection/merge_crawl_csvs.py --src-dirs "${MERGE_DIRS[@]}" \
   --parquet "$TRAIN" --out "$TRAIN" | tail -2

step "Stage 6: cross_reference (de-dup)"
PY collection/cross_reference.py --in "$TRAIN" \
   --out "$DERIVED/wallet/train.crossref.parquet" --quiet | tail -2
[ -f "$DERIVED/wallet/train.crossref.parquet" ] && TRAIN="$DERIVED/wallet/train.crossref.parquet"

step "Stage 8: publish raw snapshot"
mkdir -p data/raw && cp "$TRAIN" data/raw/train.classified.parquet
echo "-> data/raw/train.classified.parquet"

CURATE=(pipeline/build_security_dataset.py
        --in data/raw/train.classified.parquet
        --out data/wallet_vulns.parquet
        --manifest data/manifest.json)
[ -f data/silent_fix_llm.csv ] && CURATE+=(--silent-fix-csv data/silent_fix_llm.csv)

step "Stage 9: curate (THE GATE)"
PY "${CURATE[@]}" | tail -3

if [ "${SKIP_LABELS:-0}" = "1" ]; then
  echo; echo "=== done (labels skipped) ==="; exit 0
fi

step "Stage 10: enrich labels (workers=$WORKERS)"
# Warn rather than fail: without clones this stage yields no diffs, and a
# silently unlabelled build is worse than a loud one.
NCLONES=$(ls -d "$WORK"/repos/*.git 2>/dev/null | wc -l)
echo "$NCLONES local clones available"
[ "$NCLONES" -eq 0 ] && echo "WARNING: no clones — pre/post code will be empty. Warm them first:
  for w in \$(uv run python -c 'import importlib.util as i;s=i.spec_from_file_location(\"w\",\"collection/wallets.py\");m=i.module_from_spec(s);s.loader.exec_module(m);print(\" \".join(m.WALLET_CONFIG))'); do
    uv run python collection/local_diffs.py warm --wallet \$w; done"
PY pipeline/enrich_labels.py --in data/wallet_vulns.parquet \
   --out data/labels.csv --workers "$WORKERS" | tail -3

if [ -f data/labels.csv ]; then
  step "Stage 9': re-curate with labels"
  EXTRA=(--labels-csv data/labels.csv)
  [ -f data/severity_est.csv ] && EXTRA+=(--severity-csv data/severity_est.csv)
  PY "${CURATE[@]}" "${EXTRA[@]}" | tail -3
fi

step "Verify"
uv run --with pytest python -m pytest tests/ -q | tail -3

echo
echo "=== DONE -> data/wallet_vulns.parquet (+ .csv / .preview.csv / manifest.json) ==="
