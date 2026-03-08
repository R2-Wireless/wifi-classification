#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export PYTHONPATH="${ROOT_DIR}/external/python:${ROOT_DIR}/external/build/python/bindings:${ROOT_DIR}/external/build/python:${PYTHONPATH:-}"
export LD_LIBRARY_PATH="${ROOT_DIR}/external/build/lib:${LD_LIBRARY_PATH:-}"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  echo "Usage: ./run_local.sh <input.cfile> [output.pcap] [extra args...]"
  echo
  echo "Examples:"
  echo "  ./run_local.sh /path/to/input.cfile"
  echo "  ./run_local.sh /path/to/input.cfile /tmp/debug_output.pcap --freq-offset 0"
  exit 0
fi

# Merge stderr into stdout so shell redirection like `> ttt.log` captures
# both normal logs and diagnostics from C++ blocks.
python3 "${ROOT_DIR}/main_script_14.py" "$@" 2>&1
