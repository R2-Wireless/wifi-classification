#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export PYTHONPATH="${ROOT_DIR}/external/python:${ROOT_DIR}/external/build/python/bindings:${ROOT_DIR}/external/build/python:${PYTHONPATH:-}"
export LD_LIBRARY_PATH="${ROOT_DIR}/external/build/lib:${LD_LIBRARY_PATH:-}"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  echo "Usage: ./run_analyzer_local.sh <input_dir> [extra args...]"
  echo
  echo "Example:"
  echo "  ./run_analyzer_local.sh /path/to/cfiles --verbose"
  exit 0
fi

python3 "${ROOT_DIR}/enhanced_frame_analyzer_v3.py" "$@"
