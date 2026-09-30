#!/usr/bin/env bash
# Build rcvd as a static binary for Linux aarch64 (e.g. Alpine on ARM boards).
# Build-only — no deploy. Cross-compiles from any host (pure Go, CGO disabled).
set -euo pipefail

BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUTPUT="${1:-rcvd-arm64}"

GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.buildDate=${BUILD_DATE}" \
    -o "${OUTPUT}" \
    ./cmd/rcvd

echo "Built ${OUTPUT} (${BUILD_DATE})"
