#!/usr/bin/env bash
# Build rcvd as a static binary for Linux aarch64 (any distro, e.g. Alpine on ARM boards).
# Build-only — no deploy. Cross-compiles from any host (pure Go, CGO disabled).
set -euo pipefail

BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
OUTPUT="${1:-rcvd-arm64}"

GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE}" \
    -o "${OUTPUT}" \
    ./cmd/rcvd

echo "Built ${OUTPUT} (${BUILD_DATE})"
