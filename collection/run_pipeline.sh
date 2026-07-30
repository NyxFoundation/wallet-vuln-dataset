#!/usr/bin/env bash
# run_pipeline.sh — end-to-end orchestrator for the wallet-vuln-dataset.
#
# Same staged shape as the ethereum-vuln-dataset pipeline, retargeted to the
# 181-repo wallet registry (collection/wallets.py).
#
#   Stage 1  canonical crawl               -> $WORK/canonical/<wallet>.csv
#   Stage 2  supplementary crawlers        -> $WORK/supp/*.csv
#   Stage 3  advisory DBs (CVE)            -> $WORK/cve/<wallet>.cve.csv
#   Stage 4  build_derived (canonical)     -> $WORK/derived/wallet/train.parquet
#   Stage 5  merge supp + cve (one pass)   -> train.parquet (in place)
#   Stage 6  cross_reference (dedup)       -> train.parquet
#   Stage 7  blame_walk (FULL only)        -> enrich introduced_in_commit
#   Stage 8  publish raw snapshot (copy)   -> data/raw/train.classified.parquet
#   Stage 9  curate                        -> data/wallet_vulns.parquet (+manifest)
#   Stage 10 area labels + inline pre/post code
#
# WHY THE SCALE DIFFERS FROM THE CLIENT BUILD
#   11 client repos -> 181 wallet repos. The search-heavy per-repo crawlers are
#   the rate-limit bottleneck (GitHub's search limit is 30 req/min, and a full
#   crawl issues ~5,500 search calls), so they are TIER-SCOPED: TIER=1 crawls the
#   46 mass-market repos, TIER=2 adds the significant ones, TIER=3 is all 181.
#   The advisory crawlers are cheap and always run over the whole registry.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

MODE="${MODE:-smoke}"
WORK="${WORK:-$REPO/scratchpad_crawl}"
RUN_HEAVY="${RUN_HEAVY:-1}"
if [ "$MODE" = "full" ]; then
  CAP="${CAP:-0}"; PAGES="${PAGES:-0}"; TIER="${TIER:-3}"
else
  CAP="${CAP:-15}"; PAGES="${PAGES:-1}"; TIER="${TIER:-1}"
fi

CANON="$WORK/canonical"; SUPP="$WORK/supp"; CVE="$WORK/cve"
DERIVED="$WORK/derived"; LOGS="$WORK/logs"
TRAIN="$DERIVED/wallet/train.parquet"
mkdir -p "$CANON" "$SUPP" "$CVE" "$DERIVED" "$LOGS"

# urllib-based crawlers (osv/rustsec/govulncheck/cve) need a CA bundle or they
# fail with CERTIFICATE_VERIFY_FAILED and burn minutes on retries.
export SSL_CERT_FILE="${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}"

PY() { uv run python "$@"; }

# The wallet list comes from the registry — never hard-coded here.
WALLETS="$(uv run python -c "
import importlib.util
s=importlib.util.spec_from_file_location('w','collection/wallets.py')
m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
print(' '.join(m.slugs(tier=$TIER)))
")"
N_WALLETS=$(echo "$WALLETS" | wc -w)

# seconds to sleep between per-repo search crawls (secondary-rate-limit guard)
PER_WALLET_SLEEP="${PER_WALLET_SLEEP:-6}"

# run a search-heavy crawler once per repo so one repo's HTTP-403
# secondary-rate-limit abort doesn't lose every other repo's data.
stage_per_wallet() {
  local name="$1"; shift           # remaining args: crawler argv with @WALLET placeholder
  local ok=0 fail=0 i=0
  : >"$LOGS/$name.log"
  echo ">>> [$name] per-wallet over $N_WALLETS repos: $*"
  for w in $WALLETS; do
    i=$((i+1))
    local argv=("${@/@WALLET/$w}")
    if "${argv[@]}" >>"$LOGS/$name.log" 2>&1; then ok=$((ok+1)); else fail=$((fail+1)); echo "    [$name:$w] FAILED" >>"$LOGS/$name.log"; fi
    [ $((i % 20)) -eq 0 ] && echo "    [$name] $i/$N_WALLETS (ok=$ok fail=$fail)"
    sleep "$PER_WALLET_SLEEP"
  done
  echo "    [$name] done (ok=$ok fail=$fail)"
}

# run a stage, log to file, never abort the whole pipeline on one failure
stage() {
  local name="$1"; shift
  echo ">>> [$name] $*"
  if "$@" >"$LOGS/$name.log" 2>&1; then
    echo "    [$name] ok"
  else
    echo "    [$name] FAILED (rc=$?) — see $LOGS/$name.log"; tail -3 "$LOGS/$name.log" | sed 's/^/    | /'
  fi
}

echo "=== MODE=$MODE TIER=$TIER ($N_WALLETS repos) CAP=$CAP PAGES=$PAGES RUN_HEAVY=$RUN_HEAVY WORK=$WORK ==="

# --- Stage 1: canonical crawl ----------------------------------------------
stage_per_wallet canonical PY collection/crawl_wallet_past_fixes.py --wallet @WALLET --out-dir "$CANON" --max-records "$CAP"
# authoritative per-repo Security Advisories (real severity + CVE/GHSA id) —
# the spine that calibrates the keyword crawl. Cheap: one API call per repo.
stage ghsa PY collection/crawl_ghsa_advisories.py --wallet all --out-dir "$CANON"

# --- Stage 2: supplementary crawlers ---------------------------------------
stage_per_wallet commits PY collection/grep_wallet_commits.py --wallet @WALLET --out-dir "$SUPP" --max-records "$CAP"
stage releases  PY collection/mine_wallet_releases.py    --wallet all --out-dir "$SUPP" --max-records "$CAP"
stage changelog PY collection/parse_wallet_changelogs.py --wallet all --out-dir "$SUPP" --max-records "$CAP"
# advisory DBs are cheap and always cover the FULL registry, not just $TIER
stage osv       PY collection/crawl_osv.py            --wallet all --out-dir "$SUPP"
stage rustsec   PY collection/crawl_rustsec.py        --wallet all --out-dir "$SUPP"
stage govuln    PY collection/crawl_govulncheck.py    --wallet all --out-dir "$SUPP"

if [ "$RUN_HEAVY" = "1" ]; then
  stage_per_wallet stealth PY collection/mine_stealth_prs.py  --wallet @WALLET --out-dir "$SUPP" --max-per-wallet "$CAP"
  stage_per_wallet direct  PY collection/mine_direct_pulls.py --wallet @WALLET --out-dir "$SUPP" --max-pages "$PAGES"
  stage cross     PY collection/crawl_cross_wallet.py         --out-dir "$SUPP"
fi

# --- Stage 3: CVE advisory DB ----------------------------------------------
stage cve PY collection/crawl_cve.py --wallet all --out-dir "$CVE"

# --- Stage 4: build_derived from the canonical CSVs ------------------------
SRC_ARGS=()
shopt -s nullglob
for f in "$CANON"/*.csv; do SRC_ARGS+=(--source "$f"); done
shopt -u nullglob
if [ "${#SRC_ARGS[@]}" -eq 0 ]; then
  echo "FATAL: no canonical CSVs produced — aborting"; exit 1
fi
stage build_derived PY collection/build_derived.py --domain wallet \
    --filter-platforms "" --out-dir "$DERIVED" "${SRC_ARGS[@]}"
[ -f "$TRAIN" ] || { echo "FATAL: $TRAIN not produced"; exit 1; }

# --- Stage 5: merge supplementary + CVE CSVs (one pass) --------------------
stage merge PY collection/merge_crawl_csvs.py --src-dirs "$SUPP" "$CVE" --parquet "$TRAIN" --out "$TRAIN"

# --- Stage 6: cross_reference (de-dup GHSA/PR/CVE) -------------------------
stage cross_ref PY collection/cross_reference.py --in "$TRAIN" --out "$DERIVED/wallet/train.crossref.parquet" --quiet
[ -f "$DERIVED/wallet/train.crossref.parquet" ] && TRAIN="$DERIVED/wallet/train.crossref.parquet"

# --- Stage 7: blame_walk (full only; network/git heavy) -------------------
if [ "$MODE" = "full" ] && [ "${SKIP_BLAME:-0}" != "1" ]; then
  stage blame PY collection/blame_walk.py --in "$TRAIN" --out "$TRAIN" \
      --manifest "$DERIVED/wallet/blame_walk_manifest.json"
fi

# --- Stage 8: publish the raw snapshot -------------------------------------
mkdir -p data/raw
stage publish_raw cp "$TRAIN" data/raw/train.classified.parquet

# --- Stage 9: curate --------------------------------------------------------
SILENT_FIX_ARG=()
[ -f data/silent_fix_llm.csv ] && SILENT_FIX_ARG=(--silent-fix-csv data/silent_fix_llm.csv)
CURATE=(pipeline/build_security_dataset.py
        --in data/raw/train.classified.parquet
        --out data/wallet_vulns.parquet
        --manifest data/manifest.json "${SILENT_FIX_ARG[@]}")
stage curate PY "${CURATE[@]}"

# --- Stage 10: area labels + inline pre/post code --------------------------
stage labels PY pipeline/enrich_labels.py \
    --in data/wallet_vulns.parquet --out data/labels.csv
LABEL_ARG=(); [ -f data/labels.csv ] && LABEL_ARG=(--labels-csv data/labels.csv)
SEV_ARG=(); [ -f data/severity_est.csv ] && SEV_ARG=(--severity-csv data/severity_est.csv)
[ -f data/labels.csv ] && stage curate_labelled PY "${CURATE[@]}" "${LABEL_ARG[@]}" "${SEV_ARG[@]}"

echo "=== DONE. Curated -> data/wallet_vulns.parquet (+ .csv / .preview.csv) ==="
