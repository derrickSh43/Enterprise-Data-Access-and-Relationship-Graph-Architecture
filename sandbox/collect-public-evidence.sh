#!/usr/bin/env bash
# Run from Git Bash. Raw command output is captured privately, never exported.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .venv/Scripts/python.exe ]]; then
  PYTHON=.venv/Scripts/python.exe
elif [[ -x .venv/bin/python ]]; then
  PYTHON=.venv/bin/python
else
  echo 'Repository Python environment missing.' >&2
  exit 1
fi
"$PYTHON" sandbox/public_evidence.py
