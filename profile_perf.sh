#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || $# -lt 1 ]]; then
  cat <<'EOF'
Usage:
  ./profile_perf.sh <input.cfile> [output.pcap] [extra main_script args...]

Examples:
  ./profile_perf.sh "/path/to/input.cfile" /tmp/wifi_output.pcap --freq-offset 0
  ./profile_perf.sh "/path/to/input.cfile" --freq-offset 0

Outputs:
  perf.data
  perf_report_dso_symbol.txt
  perf_report_symbol.txt
  perf_report_self_dso_symbol.txt
  perf_table_top_self.txt
  perf_table_top_inclusive.txt
  perf_table_gnuradio.txt
  perf_stat.txt
  run_profile_stdout.log
  run_profile_stderr.log
EOF
  exit 0
fi

PERF_BIN="$(command -v perf || true)"
if [[ -z "${PERF_BIN}" ]]; then
  echo "ERROR: perf not found in PATH."
  echo "Install perf first (see commands in assistant message)."
  exit 1
fi

KERNEL_REL="$(uname -r)"
KERNEL_TOOLS_PKG="linux-tools-${KERNEL_REL}"
KERNEL_CLOUD_TOOLS_PKG="linux-cloud-tools-${KERNEL_REL}"

INPUT_FILE="$1"
shift

rm -f perf.data perf.data.old perf_report_dso_symbol.txt perf_report_symbol.txt \
      perf_report_self_dso_symbol.txt perf_table_top_self.txt \
      perf_table_top_inclusive.txt perf_table_gnuradio.txt perf_stat.txt \
      run_profile_stdout.log run_profile_stderr.log

# Quick sanity check for WSL/tool mismatch (perf exists but cannot run for current kernel).
if ! "${PERF_BIN}" stat -e task-clock -- true >/dev/null 2> run_profile_stderr.log; then
  ALT_PERF="$(ls -d /usr/lib/linux-tools/*/perf 2>/dev/null | sort -V | tail -n1 || true)"
  if [[ -n "${ALT_PERF}" ]] && "${ALT_PERF}" stat -e task-clock -- true >/dev/null 2>> run_profile_stderr.log; then
    PERF_BIN="${ALT_PERF}"
    echo "[profile] Falling back to kernel-tools perf: ${PERF_BIN}" | tee -a run_profile_stderr.log
  else
    echo "ERROR: perf is installed but cannot run on this kernel (${KERNEL_REL})." | tee -a run_profile_stderr.log
    echo "Install matching tools package(s) and retry:" | tee -a run_profile_stderr.log
    echo "  sudo apt update" | tee -a run_profile_stderr.log
    echo "  sudo apt install ${KERNEL_TOOLS_PKG} ${KERNEL_CLOUD_TOOLS_PKG}" | tee -a run_profile_stderr.log
    echo "If unavailable on your distro, try:" | tee -a run_profile_stderr.log
    echo "  sudo apt install linux-tools-generic linux-cloud-tools-generic" | tee -a run_profile_stderr.log
    echo "Then rerun this script; it will auto-pick /usr/lib/linux-tools/*/perf." | tee -a run_profile_stderr.log
    exit 2
  fi
fi

echo "[profile] Using perf: ${PERF_BIN}"
echo "[profile] Input: ${INPUT_FILE}"
echo "[profile] Kernel: ${KERNEL_REL}"

# Stat summary (cycles/instructions/task-clock) for the whole run.
set +e
"${PERF_BIN}" stat -e task-clock,cycles,instructions,cache-misses \
  -o perf_stat.txt \
  -- "${ROOT_DIR}/run_local.sh" "${INPUT_FILE}" "$@" \
  > run_profile_stdout.log 2> run_profile_stderr.log
STAT_RC=$?
set -e
if [[ ${STAT_RC} -ne 0 ]]; then
  echo "ERROR: workload failed during perf stat (exit=${STAT_RC})."
  echo "See run_profile_stderr.log for the underlying runtime error."
  if rg -q "Failed to create FFTW wisdom lockfile" run_profile_stderr.log 2>/dev/null; then
    echo "Detected FFTW wisdom lockfile failure."
    echo "Run: rm -f ~/.gr_fftw_wisdom.lock"
    echo "Then rerun this script."
  fi
  exit ${STAT_RC}
fi

# Per-function call graph profile (userspace focus).
set +e
"${PERF_BIN}" record -e cycles:u -F 499 -g --call-graph dwarf,16384 \
  -- "${ROOT_DIR}/run_local.sh" "${INPUT_FILE}" "$@" \
  >> run_profile_stdout.log 2>> run_profile_stderr.log
REC_RC=$?
set -e
if [[ ${REC_RC} -ne 0 ]]; then
  echo "ERROR: workload failed during perf record (exit=${REC_RC})."
  echo "See run_profile_stderr.log for the underlying runtime error."
  if rg -q "Failed to create FFTW wisdom lockfile" run_profile_stderr.log 2>/dev/null; then
    echo "Detected FFTW wisdom lockfile failure."
    echo "Run: rm -f ~/.gr_fftw_wisdom.lock"
    echo "Then rerun this script."
  fi
  exit ${REC_RC}
fi

"${PERF_BIN}" report --stdio --sort=dso,symbol -i perf.data > perf_report_dso_symbol.txt
"${PERF_BIN}" report --stdio --sort=symbol -i perf.data > perf_report_symbol.txt
"${PERF_BIN}" report --stdio --no-children --sort=dso,symbol -i perf.data > perf_report_self_dso_symbol.txt

# Build compact human-readable tables.
awk '
  BEGIN {
    print "| Rank | Self % | DSO | Symbol |";
    print "|---:|---:|---|---|";
    rank = 0;
  }
  match($0, /^[[:space:]]*([0-9]+\.[0-9]+)%[[:space:]]+([^ ].*[^ ])$/, m) {
    rest = m[2];
    split(rest, a, /  +/);
    if (length(a) >= 2) {
      dso = a[1];
      sym = a[2];
      rank++;
      if (rank <= 40) {
        printf "| %d | %s | %s | %s |\n", rank, m[1], dso, sym;
      }
    }
  }
' perf_report_self_dso_symbol.txt > perf_table_top_self.txt

awk '
  BEGIN {
    print "| Rank | Children % | Self % | DSO | Symbol |";
    print "|---:|---:|---:|---|---|";
    rank = 0;
  }
  match($0, /^[[:space:]]*([0-9]+\.[0-9]+)%[[:space:]]+([0-9]+\.[0-9]+)%[[:space:]]+(.+)$/, m) {
    rest = m[3];
    split(rest, a, /  +/);
    if (length(a) >= 2) {
      dso = a[1];
      sym = a[2];
      rank++;
      if (rank <= 40) {
        printf "| %d | %s | %s | %s | %s |\n", rank, m[1], m[2], dso, sym;
      }
    }
  }
' perf_report_dso_symbol.txt > perf_table_top_inclusive.txt

{
  echo "| Rank | Self % | DSO | Symbol |";
  echo "|---:|---:|---|---|";
  awk '
    match($0, /^[[:space:]]*([0-9]+\.[0-9]+)%[[:space:]]+([^ ].*[^ ])$/, m) {
      rest = m[2];
      split(rest, a, /  +/);
      if (length(a) >= 2) {
        printf "%s|%s|%s\n", m[1], a[1], a[2];
      }
    }
  ' perf_report_self_dso_symbol.txt \
  | rg -i 'gnuradio|ieee802_11|sync_short|sync_long|frame_equalizer|decode_mac|block_executor' \
  | head -n 40 \
  | awk -F'|' '{printf "| %d | %s | %s | %s |\n", NR, $1, $2, $3}'
} > perf_table_gnuradio.txt

echo "[profile] Done."
echo "[profile] Generated:"
echo "  - perf_stat.txt"
echo "  - perf_report_dso_symbol.txt"
echo "  - perf_report_symbol.txt"
echo "  - perf_report_self_dso_symbol.txt"
echo "  - perf_table_top_self.txt"
echo "  - perf_table_top_inclusive.txt"
echo "  - perf_table_gnuradio.txt"
echo "  - run_profile_stdout.log"
echo "  - run_profile_stderr.log"
