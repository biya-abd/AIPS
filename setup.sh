#!/usr/bin/env bash
# AIPS setup script for Kali Linux.
#
# What this script does:
#   - checks Python 3.9+ is available
#   - creates a local virtual environment (./venv)
#   - installs the pinned dependencies from requirements.txt
#   - creates ./data/ for the SQLite DB and audit log
#   - copies .env.example to .env if .env doesn't exist yet
#
# What this script deliberately does NOT do:
#   - it does not touch any firewall rule or policy
#   - it does not change AIPS_MODE (stays "monitor" unless you edit .env)
#   - it does not expose anything to the network (AIPS_HOST stays 127.0.0.1)
#   - it does not install system packages (apt) -- only Python deps in a venv
set -euo pipefail

cd "$(dirname "$0")"

echo "=== AIPS setup ==="

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not found. Install it first (e.g. 'sudo apt install python3 python3-venv')."
  exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 9 ]; }; then
  echo "ERROR: Python 3.9+ required, found $PY_VERSION"
  exit 1
fi
echo "Python $PY_VERSION OK"

if [ ! -d venv ]; then
  echo "Creating virtual environment..."
  python3 -m venv venv
else
  echo "Virtual environment already exists, reusing it."
fi

echo "Installing dependencies..."
./venv/bin/pip install --upgrade pip --quiet
./venv/bin/pip install -r requirements.txt --quiet
echo "Dependencies installed."

mkdir -p data
echo "data/ directory ready."

if [ ! -f .env ]; then
  cp .env.example .env
  chmod 600 .env
  echo "Created .env from .env.example (permissions set to 600)."
  echo "  -> Edit .env and set OPENROUTER_API_KEY before starting AI features."
  echo "  -> Run 'python3 -m app.collectors.log_discovery' and set TARGET_* values."
else
  echo ".env already exists, leaving it untouched."
fi

echo ""
echo "=== Setup complete ==="
echo "Next steps:"
echo "  1. python3 -m app.collectors.log_discovery   # read-only target discovery"
echo "  2. edit .env with the discovered log path and your OpenRouter key"
echo "  3. ./start.sh"
