#!/bin/bash
# entrypoint.sh — container startup for CDF Manager (nginx + proxy.py).
#
# /data is expected to be a bind-mounted host directory. It holds:
#   config.py       — bootstrapped from env vars on first boot, then left
#                      alone (see generate_config.py) so in-app admin
#                      password changes persist across restarts
#   state.json, users.json, sessions.json, settings.json
#                      — auto-created by proxy.py on first use

set -euo pipefail

mkdir -p /data
cd /data

python3 /app/docker/generate_config.py

# proxy.py resolves `import config` relative to its own file location
# (/app), not the process cwd — symlink so that lookup finds the copy
# that lives in the persistent volume. Writes through a symlink land on
# the target file, so config.py edits (e.g. password changes) persist.
ln -sf /data/config.py /app/config.py

nginx -g 'daemon off;' &
NGINX_PID=$!

python3 /app/proxy.py &
PROXY_PID=$!

# Forward a container stop request to both children.
trap 'kill -TERM "$NGINX_PID" "$PROXY_PID" 2>/dev/null || true' TERM INT

# If either process exits — crash or otherwise — bring the container down
# too, rather than limping along with only half the app running. Docker's
# restart policy (e.g. `--restart unless-stopped`) handles recovery.
if wait -n "$NGINX_PID" "$PROXY_PID"; then
    EXIT_CODE=0
else
    EXIT_CODE=$?
fi
echo "entrypoint.sh: a supervised process exited (code $EXIT_CODE) — stopping container"
kill -TERM "$NGINX_PID" "$PROXY_PID" 2>/dev/null || true
exit "$EXIT_CODE"
