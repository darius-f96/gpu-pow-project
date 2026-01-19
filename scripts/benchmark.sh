#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/sha1_nonce"

DATA_HEX="${DATA_HEX:-706C656173652067697665206D65206120676F6F64206772616465}"
SUFFIX_HEX="${SUFFIX_HEX:-FF23}"
NONCE_LEN="${NONCE_LEN:-8}"
MAX_BATCHES="${MAX_BATCHES:-200}"
REPORT_EVERY="${REPORT_EVERY:-50}"
TRIALS="${TRIALS:-1}"

EXTRA_ARGS=("$@")

CONFIGS=(
  "256 256 8"
  "512 256 8"
  "512 256 16"
  "1024 256 16"
  "1024 512 8"
)

if [[ ! -x "${BIN}" ]]; then
  echo "Binary not found at ${BIN}. Build with: make"
  exit 1
fi

echo "GPU info:"
if command -v nvidia-smi >/dev/null 2>&1; then
  nvidia-smi --query-gpu=name,driver_version,clocks.current.sm,clocks.current.memory,power.limit --format=csv
else
  echo "nvidia-smi not available"
fi

echo
echo "Input:"
echo "  DATA=${DATA_HEX}"
echo "  SUFFIX=${SUFFIX_HEX}"
echo "  NONCE_LEN=${NONCE_LEN}"
echo "  MAX_BATCHES=${MAX_BATCHES}"
echo "  REPORT_EVERY=${REPORT_EVERY}"
echo "  TRIALS=${TRIALS}"
echo

for cfg in "${CONFIGS[@]}"; do
  read -r blocks threads per_thread <<<"${cfg}"
  echo "== Run: blocks=${blocks} threads=${threads} per_thread=${per_thread} =="
  sum=0
  min=""
  max=""
  for ((t = 1; t <= TRIALS; ++t)); do
    if [[ "${TRIALS}" -gt 1 ]]; then
      echo "-- Trial ${t}/${TRIALS}"
    fi
    output=$("${BIN}" --data "${DATA_HEX}" --suffix "${SUFFIX_HEX}" \
      --nonce-len "${NONCE_LEN}" \
      --blocks "${blocks}" --threads "${threads}" --per-thread "${per_thread}" \
      --max-batches "${MAX_BATCHES}" --report "${REPORT_EVERY}" \
      "${EXTRA_ARGS[@]}" || true)
    printf "%s\n" "${output}"
    if printf "%s\n" "${output}" | rg -q "Bench complete:"; then
      mhps=$(printf "%s\n" "${output}" | awk '/Bench complete:/ {print $(NF-1)}')
      if [[ -n "${mhps}" ]]; then
        sum=$(awk -v s="${sum}" -v v="${mhps}" 'BEGIN {printf "%.6f", s+v}')
        if [[ -z "${min}" ]] || awk -v a="${mhps}" -v b="${min}" 'BEGIN {exit !(a<b)}'; then
          min="${mhps}"
        fi
        if [[ -z "${max}" ]] || awk -v a="${mhps}" -v b="${max}" 'BEGIN {exit !(a>b)}'; then
          max="${mhps}"
        fi
      fi
    fi
  done
  if [[ "${TRIALS}" -gt 1 ]] && [[ -n "${min}" ]]; then
    avg=$(awk -v s="${sum}" -v n="${TRIALS}" 'BEGIN {printf "%.2f", s/n}')
    printf "Bench summary (MH/s): avg=%s min=%s max=%s\n" "${avg}" "${min}" "${max}"
  fi
  echo
done

echo "Note: use --bench to run fixed batches and avoid early-stop bias."
