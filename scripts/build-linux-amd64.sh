#!/usr/bin/env bash
# Build rcvd as a static binary for Linux (x86-64).
#
# By default this ONLY builds a local artifact (./rcvd-amd64). Pass --deploy (or DEPLOY=true)
# to also install it to /usr/local/bin/rcvd on THIS machine (the admin PC) and restart the
# systemd service — so "a new amd64 build" can mean build-and-deploy in one step.
#
# Usage:
#   ./scripts/build-linux-amd64.sh                 # build only → ./rcvd-amd64
#   ./scripts/build-linux-amd64.sh --deploy        # build + install /usr/local/bin/rcvd + restart
#   DEPLOY=true ./scripts/build-linux-amd64.sh      # same, via env var
#   ./scripts/build-linux-amd64.sh myout --deploy   # custom output name + deploy
#
# Deploy needs root (sudo). If sudo requires a TTY this script can't provide, it prints the
# exact install+restart command for you to run yourself.
set -euo pipefail

DEPLOY="${DEPLOY:-false}"
OUTPUT=""
for arg in "$@"; do
    case "$arg" in
        --deploy) DEPLOY=true ;;
        *) OUTPUT="$arg" ;;   # first non-flag positional = output name
    esac
done
OUTPUT="${OUTPUT:-rcvd-amd64}"

BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.buildDate=${BUILD_DATE}" \
    -o "${OUTPUT}" \
    ./cmd/rcvd

echo "Built ${OUTPUT} (${BUILD_DATE})"

if [ "$DEPLOY" != "true" ]; then
    exit 0
fi

# --- deploy to this machine (admin PC: systemd) ---
echo "Deploying ${OUTPUT} → /usr/local/bin/rcvd (sudo) + restarting rcvd.service ..."
if sudo install -m 755 "${OUTPUT}" /usr/local/bin/rcvd \
   && sudo systemctl restart rcvd; then
    echo "Deployed. Running version:"
    /usr/local/bin/rcvd --version
else
    echo ""
    echo "Deploy could not run automatically (sudo may need a TTY). Run this yourself:" >&2
    echo "  sudo install -m 755 ${OUTPUT} /usr/local/bin/rcvd && sudo systemctl restart rcvd && /usr/local/bin/rcvd --version" >&2
    exit 1
fi
