#!/usr/bin/env bash
# The verification gate — CI mirrors these commands exactly.
set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-.venv/bin/python}"
if [ ! -x "$PYTHON" ]; then
  echo "missing venv — bootstrap: uv venv .venv && uv pip install -e '.[dev]'" >&2
  exit 1
fi

"$PYTHON" -m ruff check src tests
"$PYTHON" -m mypy src/nx_auth tests
"$PYTHON" -m pytest -q
