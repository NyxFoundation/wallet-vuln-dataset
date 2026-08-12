#!/usr/bin/env bash
# keywordless_sweep.sh — judge every commit of a repo, one repo at a time.
#
# The keyword crawl asks "does this commit's text mention security?", which is
# the one question a silent fix answers wrongly by definition. This sweep asks
# the LLM about every commit that structurally could contain a defect, and never
# consults the wording. Measured on the existing corpus, rows recovered this way
# are ~3x more likely to survive an independent STRIDE check than rows the
# keyword gate admitted (69% vs 24.6%).
#
# Repos are taken in descending star order because that is the order in which a
# defect affects the most users. Yield is NOT uniform — measured silent-fix rate
# ranges from 25% (LedgerHQ/app-ethereum) to 0.3% (solana-web3.js) — so
# scripts/repo_priority.py records the measured rate next to the star count and
# the operator can skip a repo on evidence rather than on size.
#
# Resumable by construction: predictions are cached per commit URL, so a repo
# already swept costs nothing to re-enter and an interrupted sweep resumes where
# it stopped. Nothing already judged is ever re-judged.
#
#   WORK      working dir                (default: scratchpad_crawl)
#   WORKERS   concurrent LLM calls       (default: 8)
#   MODEL     engine model               (default: glm-5.2)
#   LIMIT     cap commits per repo       (default: 0 = all)
#
# Usage:
#   scripts/keywordless_sweep.sh bitcoinjs-lib wallet-core noble-curves
#   scripts/keywordless_sweep.sh $(uv run python scripts/repo_priority.py --top 10 --slugs)
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
WORK="${WORK:-$REPO/scratchpad_crawl}"
WORKERS="${WORKERS:-8}"
MODEL="${MODEL:-glm-5.2}"
LIMIT="${LIMIT:-0}"
OUT="$WORK/allcommits"
# ONE prediction cache for every pass in this project, keyed by commit URL. The
# caches were briefly split per-pass, which meant a commit reached by both the
# keyword crawl and this sweep got paid for twice — the sweep's whole premise is
# that judging is the expensive part, so nothing may ever be judged twice.
CACHE="$WORK/pred_cache.json"
DIFFS="$WORK/diff_cache.json"
mkdir -p "$OUT"

[ -n "${OLLAMA_API_KEY:-}" ] || { echo "FATAL: \$OLLAMA_API_KEY is not set"; exit 1; }
export SSL_CERT_FILE="${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}"

# One classifier at a time, always. Three separate double-starts during
# development each had two processes writing the same prediction cache and
# silently clobbering each other's checkpoints; the symptom looked like a
# throughput problem, not a correctness one. `ps -eo comm` matches the
# executable, not the argv of the shell running this script.
running() { ps -eo comm,args | awk '$1 ~ /^python/ && /llm_classify_fixes/' | wc -l; }

# Every slug up front, before a single model call: a name that is not in the
# registry is a typo, and discovering that repo-by-repo means the sweep runs for
# an hour and then reports a repo it never touched. `app-ethereum` for
# `ledger-app-eth` failed exactly this way.
BAD=$(uv run python - "$@" <<'PY'
import importlib.util as ilu, sys, pathlib
r = pathlib.Path(__file__).resolve()
s = ilu.spec_from_file_location("w", "collection/wallets.py")
m = ilu.module_from_spec(s); s.loader.exec_module(m)
print(" ".join(w for w in sys.argv[1:] if w not in m.WALLET_CONFIG))
PY
)
[ -n "$BAD" ] && { echo "FATAL: not in collection/wallets.py: $BAD"; exit 1; }

FAILED=""
for W in "$@"; do
  echo; echo "=== $W ==="
  n=$(running); [ "$n" -ne 0 ] && { echo "ABORT: $n classifier process(es) already running"; exit 1; }

  PQ="$OUT/$W.parquet"
  if [ -f "$PQ" ]; then
    echo "[enumerate] cached -> $PQ"
  else
    LIM=(); [ "$LIMIT" -gt 0 ] && LIM=(--limit "$LIMIT")
    if ! uv run python collection/enumerate_commits.py --wallet "$W" --out "$PQ" "${LIM[@]}"; then
      # A skipped repo must be loud. wallet-core was dropped silently here when
      # its enumeration died, and the sweep reported success for a repo it had
      # never judged.
      echo "[$W] ERROR: enumeration failed — REPO SKIPPED, re-run it later"
      FAILED="$FAILED $W"
      continue
    fi
  fi

  uv run python collection/llm_classify_fixes.py --apply \
      --in "$PQ" --tier all \
      --apply-out "$OUT/$W.verdict.csv" \
      --pred-cache "$CACHE" --cache "$DIFFS" \
      --workers "$WORKERS" \
      --engine openai --model "$MODEL" \
      --base-url https://ollama.com/v1 --api-key-env OLLAMA_API_KEY

  # The writer prints this line last. Its absence means the pass died rather
  # than finished — a distinction the run's own row counter cannot make, and one
  # that was misread as a clean finish once already.
  if [ -f "$OUT/$W.verdict.csv" ]; then
    echo "[$W] $(( $(wc -l < "$OUT/$W.verdict.csv") - 1 )) judged"
  else
    echo "[$W] WARNING: no verdict csv — the pass did not complete"
  fi
done

echo
[ -n "$FAILED" ] && echo "=== REPOS SKIPPED (enumeration failed):$FAILED ==="
echo "=== sweep done. Fold in with: ==="
echo "  uv run python scripts/merge_keywordless.py            # report"
echo "  uv run python scripts/merge_keywordless.py --write    # apply"
