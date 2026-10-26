#!/usr/bin/env bash
# Starts the AIPS dashboard. Run ./setup.sh first if you haven't.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d venv ]; then
  echo "ERROR: venv not found. Run ./setup.sh first."
  exit 1
fi
if [ ! -f .env ]; then
  echo "ERROR: .env not found. Run ./setup.sh first, then edit .env."
  exit 1
fi

# Read AIPS_HOST / AIPS_PORT out of .env for the uvicorn bind (falls back to
# config.py's own defaults if unset -- this is just for the uvicorn CLI args).
HOST=$(grep -E '^AIPS_HOST=' .env | cut -d= -f2- || true)
PORT=$(grep -E '^AIPS_PORT=' .env | cut -d= -f2- || true)
HOST=${HOST:-127.0.0.1}
PORT=${PORT:-8080}

mkdir -p data
echo "Starting AIPS on http://${HOST}:${PORT} (PID will be written to aips.pid)"
nohup ./venv/bin/uvicorn app.main:app --host "$HOST" --port "$PORT" > data/aips.out.log 2>&1 &
echo $! > aips.pid
sleep 1
if kill -0 "$(cat aips.pid)" 2>/dev/null; then
  echo "AIPS started (PID $(cat aips.pid)). Logs: data/aips.out.log"
  echo "Dashboard: http://${HOST}:${PORT}"
else
  echo "AIPS failed to start -- check data/aips.out.log for the error."
  exit 1
fi
