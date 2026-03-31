#!/usr/bin/env bash

set -euo pipefail

MODE_LABEL="${1:-current-mode}"
COLD_RUNS="${COLD_RUNS:-5}"
WARM_RUNS="${WARM_RUNS:-5}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-10}"
MAX_TIME="${MAX_TIME:-30}"
SKIP_COLD="${SKIP_COLD:-0}"

URLS=(
  "https://s8westeurope.blob.core.windows.net/public/latency-test.json"
  "https://s8southeastasia.blob.core.windows.net/public/latency-test.json"
  "https://s8eastus.blob.core.windows.net/public/latency-test.json"
  "https://q9japaneast.blob.core.windows.net/public/latency-test.json"
  "https://s8australiaeast.blob.core.windows.net/public/latency-test.json"
  "https://s8uksouth.blob.core.windows.net/public/latency-test.json"
)

LABELS=(
  "West Europe"
  "Southeast Asia"
  "East US"
  "Japan East"
  "Australia East"
  "UK South"
)

median() {
  local values=("$@")
  local count="${#values[@]}"
  local sorted=()
  local mid
  local old_ifs="${IFS}"

  if [[ "$count" -eq 0 ]]; then
    echo "n/a"
    return
  fi

  IFS=$'\n' sorted=($(printf '%s\n' "${values[@]}" | sort -n))
  IFS="${old_ifs}"
  mid=$(( count / 2 ))

  if (( count % 2 == 1 )); then
    echo "${sorted[$mid]}"
  else
    awk -v a="${sorted[$((mid - 1))]}" -v b="${sorted[$mid]}" 'BEGIN { printf "%.6f\n", (a + b) / 2 }'
  fi
}

run_cold_test() {
  local label="$1"
  local url="$2"
  local totals=()
  local starts=()
  local dnses=()
  local connects=()
  local tlses=()
  local remote=""
  local i
  local result
  local dns
  local connect
  local tls
  local start
  local total

  echo
  echo "Cold test: ${label}"
  echo "URL: ${url}"

  for ((i = 1; i <= COLD_RUNS; i++)); do
    result="$(curl -sS -o /dev/null \
      --connect-timeout "${CONNECT_TIMEOUT}" \
      --max-time "${MAX_TIME}" \
      -w '%{time_namelookup}\t%{time_connect}\t%{time_appconnect}\t%{time_starttransfer}\t%{time_total}\t%{remote_ip}\n' \
      "${url}")"

    IFS=$'\t' read -r dns connect tls start total remote <<<"${result}"
    dnses+=("${dns}")
    connects+=("${connect}")
    tlses+=("${tls}")
    starts+=("${start}")
    totals+=("${total}")

    printf '  run=%d dns=%ss connect=%ss tls=%ss start=%ss total=%ss remote=%s\n' \
      "${i}" "${dns}" "${connect}" "${tls}" "${start}" "${total}" "${remote}"
  done

  printf '  median dns=%ss connect=%ss tls=%ss start=%ss total=%ss\n' \
    "$(median "${dnses[@]}")" \
    "$(median "${connects[@]}")" \
    "$(median "${tlses[@]}")" \
    "$(median "${starts[@]}")" \
    "$(median "${totals[@]}")"
}

run_warm_test() {
  local label="$1"
  local url="$2"
  local totals=()
  local starts=()
  local dnses=()
  local connects=()
  local tlses=()
  local remote=""
  local curl_args=()
  local line
  local i=1
  local dns
  local connect
  local tls
  local start
  local total
  local warm_dnses=()
  local warm_connects=()
  local warm_tlses=()
  local warm_starts=()
  local warm_totals=()

  echo
  echo "Warm test: ${label}"
  echo "URL: ${url}"

  for ((i = 1; i <= WARM_RUNS; i++)); do
    curl_args+=(
      -o /dev/null
      -w '%{time_namelookup}\t%{time_connect}\t%{time_appconnect}\t%{time_starttransfer}\t%{time_total}\t%{remote_ip}\n'
      "${url}"
    )
  done

  i=1
  while IFS= read -r line; do
    IFS=$'\t' read -r dns connect tls start total remote <<<"${line}"
    dnses+=("${dns}")
    connects+=("${connect}")
    tlses+=("${tls}")
    starts+=("${start}")
    totals+=("${total}")
    if (( i > 1 )); then
      warm_dnses+=("${dns}")
      warm_connects+=("${connect}")
      warm_tlses+=("${tls}")
      warm_starts+=("${start}")
      warm_totals+=("${total}")
    fi

    printf '  run=%d dns=%ss connect=%ss tls=%ss start=%ss total=%ss remote=%s\n' \
      "${i}" "${dns}" "${connect}" "${tls}" "${start}" "${total}" "${remote}"
    i=$((i + 1))
  done < <(
    curl -sS \
      --connect-timeout "${CONNECT_TIMEOUT}" \
      --max-time "${MAX_TIME}" \
      "${curl_args[@]}"
  )

  printf '  median dns=%ss connect=%ss tls=%ss start=%ss total=%ss\n' \
    "$(median "${dnses[@]}")" \
    "$(median "${connects[@]}")" \
    "$(median "${tlses[@]}")" \
    "$(median "${starts[@]}")" \
    "$(median "${totals[@]}")"
  if (( WARM_RUNS > 1 )); then
    printf '  reused median dns=%ss connect=%ss tls=%ss start=%ss total=%ss\n' \
      "$(median "${warm_dnses[@]}")" \
      "$(median "${warm_connects[@]}")" \
      "$(median "${warm_tlses[@]}")" \
      "$(median "${warm_starts[@]}")" \
      "$(median "${warm_totals[@]}")"
  fi
}

echo "Azure latency benchmark"
echo "Mode label: ${MODE_LABEL}"
echo "Cold runs per URL: ${COLD_RUNS}"
echo "Warm runs per URL: ${WARM_RUNS}"
echo "Connect timeout: ${CONNECT_TIMEOUT}s"
echo "Max time: ${MAX_TIME}s"
echo "Skip cold tests: ${SKIP_COLD}"

for idx in "${!URLS[@]}"; do
  if [[ "${SKIP_COLD}" != "1" ]]; then
    run_cold_test "${LABELS[$idx]}" "${URLS[$idx]}"
  fi
  run_warm_test "${LABELS[$idx]}" "${URLS[$idx]}"
done
