#!/usr/bin/env bash
# Argus Scanner Launcher
# Activates virtual environment and runs the scanner with proper PYTHONPATH

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate virtual environment
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
else
    echo "Error: Virtual environment not found. Run: python -m venv .venv"
    exit 1
fi

# Set PYTHONPATH and run scanner
export PYTHONPATH="$SCRIPT_DIR"
python argus/main.py "$@"
