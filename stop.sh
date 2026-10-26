#!/usr/bin/env bash
# Stops the AIPS dashboard started by ./start.sh.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f aips.pid ]; then
  echo "No aips.pid found -- AIPS doesn't appear to be running (or wasn't started with start.sh)."
  exit 0
fi

PID=$(cat aips.pid)
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  echo "Sent stop signal to AIPS (PID $PID)."
  sleep 1
  if kill -0 "$PID" 2>/dev/null; then
    echo "Still running, forcing stop..."
    kill -9 "$PID" || true
  fi
  echo "AIPS stopped."
else
  echo "PID $PID is not running (stale pidfile)."
fi
rm -f aips.pid

echo "Note: this only stops the AIPS process. It does NOT remove any"
echo "enforcement blocks that are currently active -- those expire on their"
echo "own schedule, or use the dashboard's Response Center to roll them back"
echo "before stopping if you want them removed immediately."
