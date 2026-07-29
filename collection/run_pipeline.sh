#!/usr/bin/env bash
# run_pipeline.sh — end-to-end orchestrator for the ethereum-vuln-dataset.
#
# Wires every collection stage that the repo ships as separate scripts into one
# reproducible run, then derives the curated security-only parquet.
#
#   Stage 1  canonical GHSA crawl          -> $WORK/canonical/<wallet>.csv
#   Stage 2  supplementary crawlers        -> $WORK/supp/*.csv
#   Stage 3  advisory DBs (CVE)            -> $WORK/cve/<wallet>.cve.csv
#   Stage 4  build_derived (canonical)     -> $WORK/derived/ethereum/train.parquet
#   Stage 5  merge supp + cve (one pass)   -> train.parquet (in place)
#   Stage 6  cross_reference (dedup)       -> train.parquet
#   Stage 7  blame_walk (FULL only)        -> enrich introduced_in_commit
#   Stage 8  publish raw snapshot (copy)   -> data/raw/train.classified.parquet
#   Stage 9  curate                        -> data/wallet_vulns.parquet (+manifest)
#
# LLM STRIDE/CWE classification is intentionally skipped (stride=Other, cwe=N/A);
# the curation GATE then relies on CVE/GHSA ids, rated severity, and keywords.
#
# Env knobs:
#   MODE      smoke | full        (default smoke)
#   WORK      working dir          (default: scratchpad/crawl)
#   CAP       per-source record cap (smoke default 15, full 0 = uncapped)
#   PAGES     direct_pulls pages    (smoke default 1, full 0 = uncapped)
#   RUN_HEAVY 1 to run search-heavy crawlers (stealth/direct/cross/specs); default 1
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

MODE="${MODE:-smoke}"
WORK="${WORK:-$REPO/scratchpad_crawl}"
RUN_HEAVY="${RUN_HEAVY:-1}"
if [ "$MODE" = "full" ]; then
  CAP="${CAP:-0}"; PAGES="${PAGES:-0}"
else
  CAP="${CAP:-15}"; PAGES="${PAGES:-1}"
fi

CANON="$WORK/canonical"; SUPP="$WORK/supp"; CVE="$WORK/cve"
DERIVED="$WORK/derived"; LOGS="$WORK/logs"
TRAIN="$DERIVED/ethereum/train.parquet"
mkdir -p "$CANON" "$SUPP" "$CVE" "$DERIVED" "$LOGS"

# urllib-based crawlers (osv/rustsec/govulncheck/cve) need a CA bundle or they
# fail with CERTIFICATE_VERIFY_FAILED and burn minutes on retries.
export SSL_CERT_FILE="${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}"

PY() { uv run python "$@"; }
WALLETS="geth nethermind besu erigon reth lighthouse lodestar nimbus prysm teku grandine"
# seconds to sleep between per-wallet search crawls (secondary-rate-limit guard)
PER_CLIENT_SLEEP="${PER_CLIENT_SLEEP:-8}"

# run a search-heavy crawler once per wallet so one wallet's HTTP-403
# secondary-rate-limit abort doesn't lose every other wallet's data.
stage_per_client() {
  local name="$1"; shift           # remaining args: the crawler argv, with @CLIENT placeholder
  local ok=0 fail=0
  : >"$LOGS/$name.log"
  echo ">>> [$name] per-wallet: $*"
  for c in $WALLETS; do
    local argv=("${@/@CLIENT/$c}")
    if "${argv[@]}" >>"$LOGS/$name.log" 2>&1; then ok=$((ok+1)); else fail=$((fail+1)); echo "    [$name:$c] FAILED" | tee -a "$LOGS/$name.log"; fi
    sleep "$PER_CLIENT_SLEEP"
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

echo "=== MODE=$MODE  CAP=$CAP  PAGES=$PAGES  RUN_HEAVY=$RUN_HEAVY  WORK=$WORK ==="

# --- Stage 1: canonical GHSA crawl -----------------------------------------
stage canonical PY collection/crawl_wallet_past_fixes.py --wallet all --out-dir "$CANON" --max-records "$CAP"
# authoritative per-repo Security Advisories (real severity + CVE/GHSA id) —
# the essential-bug spine; written into canonical so Critical is preserved.
stage ghsa PY collection/crawl_ghsa_advisories.py --wallet all --out-dir "$CANON"

# --- Stage 2: supplementary per-wallet crawlers ----------------------------
stage_per_client commits PY collection/grep_wallet_commits.py --wallet @CLIENT --out-dir "$SUPP" --max-records "$CAP"
stage releases  PY collection/mine_wallet_releases.py    --wallet all --out-dir "$SUPP" --max-records "$CAP"
stage changelog PY collection/parse_wallet_changelogs.py --wallet all --out-dir "$SUPP" --max-records "$CAP"
stage osv       PY collection/crawl_osv.py            --wallet all --out-dir "$SUPP"
stage rustsec   PY collection/crawl_rustsec.py        --wallet all --out-dir "$SUPP"
stage govuln    PY collection/crawl_govulncheck.py    --wallet all --out-dir "$SUPP"
stage tekujira  PY collection/crawl_teku_jira_refs.py --out-dir "$SUPP" --max-results "$CAP"

# nimbus urgency: patch the release-note severities, then merge only the patched copy
if [ -f "$SUPP/nimbus.releases.csv" ]; then
  stage nimbusurg PY collection/extract_nimbus_urgency.py --out-dir "$SUPP" \
      --apply-to "$SUPP/nimbus.releases.csv" --apply-out "$SUPP/nimbus.releases.patched.csv"
  [ -f "$SUPP/nimbus.releases.patched.csv" ] && rm -f "$SUPP/nimbus.releases.csv"
fi

if [ "$RUN_HEAVY" = "1" ]; then
  stage_per_client stealth PY collection/mine_stealth_prs.py --wallet @CLIENT --out-dir "$SUPP" --max-per-wallet "$CAP"
  stage_per_client direct  PY collection/mine_direct_pulls.py --wallet @CLIENT --out-dir "$SUPP" --max-pages "$PAGES"
  stage cross   PY collection/crawl_cross_wallet.py   --out-dir "$SUPP"
  stage specs   PY collection/crawl_standards_divergence.py --out-dir "$SUPP" --max-per-term "$CAP"
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
stage build_derived PY collection/build_derived.py --domain ethereum \
    --filter-platforms "" --out-dir "$DERIVED" "${SRC_ARGS[@]}"
[ -f "$TRAIN" ] || { echo "FATAL: $TRAIN not produced"; exit 1; }

# --- Stage 5: merge supplementary + CVE CSVs (one pass) --------------------
# CVE CSVs share the crawl schema, so merge_crawl_csvs ingests them alongside
# the supplementary dir — no separate merge_cve step needed.
stage merge PY collection/merge_crawl_csvs.py --src-dirs "$SUPP" "$CVE" --parquet "$TRAIN" --out "$TRAIN"

# --- Stage 6: cross_reference (de-dup GHSA/PR/CVE) -------------------------
stage cross_ref PY collection/cross_reference.py --in "$TRAIN" --out "$DERIVED/ethereum/train.crossref.parquet" --quiet
[ -f "$DERIVED/ethereum/train.crossref.parquet" ] && TRAIN="$DERIVED/ethereum/train.crossref.parquet"

# --- Stage 7: blame_walk (full only; network/git heavy) -------------------
if [ "$MODE" = "full" ] && [ "${SKIP_BLAME:-0}" != "1" ]; then
  stage blame PY collection/blame_walk.py --in "$TRAIN" --out "$TRAIN" \
      --manifest "$DERIVED/ethereum/blame_walk_manifest.json"
fi

# --- Stage 8: publish the raw snapshot -------------------------------------
# No stride/cwe munging here: build_security_dataset canonicalizes the
# unclassified sentinels itself, so this is just a copy of the crossref output.
mkdir -p data/raw
stage publish_raw cp "$TRAIN" data/raw/train.classified.parquet

# --- Stage 9: curate --------------------------------------------------------
# Optionally fold in the learned silent-fix signal (gemma4:31b via
# llm_classify_fixes.py --apply). Present -> promotes classified C_candidate
# fixes to the corroborated tier; absent -> deterministic build only.
SILENT_FIX_ARG=()
[ -f data/silent_fix_llm.csv ] && SILENT_FIX_ARG=(--silent-fix-csv data/silent_fix_llm.csv)
CURATE=(pipeline/build_security_dataset.py
        --in data/raw/train.classified.parquet
        --out data/wallet_vulns.parquet
        --manifest data/manifest.json "${SILENT_FIX_ARG[@]}")
stage curate PY "${CURATE[@]}"

# --- Stage 10: area labels + inline pre/post code (docs/label_design.md) -----
# Derives label / root_cause / attack_path / files_changed / pre+post code /
# fix_commit / introduced_in_commit from the local diffs, then re-curates so the
# columns land in the dataset. Needs the local clones (local_diffs warm/warm-prs).
stage labels PY pipeline/enrich_labels.py \
    --in data/wallet_vulns.parquet --out data/labels.csv
LABEL_ARG=(); [ -f data/labels.csv ] && LABEL_ARG=(--labels-csv data/labels.csv)
# optional bug-bounty severity estimates (estimate_severity.py --apply); present
# -> joined as severity_estimated / severity_source; absent -> skipped.
SEV_ARG=(); [ -f data/severity_est.csv ] && SEV_ARG=(--severity-csv data/severity_est.csv)
[ -f data/labels.csv ] && stage curate_labelled PY "${CURATE[@]}" "${LABEL_ARG[@]}" "${SEV_ARG[@]}"

echo "=== DONE. Curated -> data/wallet_vulns.parquet (+ .csv / .preview.csv) ==="
