#!/usr/bin/env bash
# Build rcvd as a static binary for macOS (Intel, x86-64).
# This script builds on a macOS host or in a cross-compilation environment.
set -euo pipefail

BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUTPUT="${1:-rcvd-macos-amd64}"

# macOS with amd64 architecture
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.buildDate=${BUILD_DATE}" \
    -o "${OUTPUT}" \
    ./cmd/rcvd

echo "Built ${OUTPUT} (${BUILD_DATE})"
echo ""
echo "To deploy to a remote macOS host:"
echo "  scp ${OUTPUT} <user>@<macos-host>:/tmp/rcvd"
echo "  ssh <user>@<macos-host> 'sudo install -m 755 /tmp/rcvd /usr/local/bin/rcvd'"
