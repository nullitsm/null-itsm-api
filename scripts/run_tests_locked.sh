#!/usr/bin/env bash
# Run pytest with a filesystem lock so parallel Phase 2 workstreams never
# recreate the shared test database under each other (conftest drops and
# recreates null_itsm_test at session start). Usage:
#   scripts/run_tests_locked.sh [pytest args...]
# The lock is stolen after 10 minutes (a crashed run must not block
# everyone forever). Do NOT run bare `pytest` while siblings are working.
set -euo pipefail
LOCK_DIR="/tmp/null-itsm-pytest.lock"
cd "$(dirname "$0")/.."
acquire() {
  while true; do
    if mkdir "$LOCK_DIR" 2>/dev/null; then
      echo "$$" > "$LOCK_DIR/pid"
      return 0
    fi
    if [ -d "$LOCK_DIR" ]; then
      age=$(( $(date +%s) - $(stat -c %Y "$LOCK_DIR") ))
      if [ "$age" -gt 600 ]; then
        echo "Stealing stale pytest lock (age ${age}s)"
        rm -rf "$LOCK_DIR"
        continue
      fi
    fi
    echo "Waiting for pytest lock..."
    sleep 10
  done
}
release() { rm -rf "$LOCK_DIR"; }
trap release EXIT
acquire
echo "pytest lock acquired"
.venv/bin/python -m pytest "$@"
