# rcvd - build/install entry points for the single Go binary.
#
# `make build` is the canonical host-arch production recipe (static, -trimpath, stripped,
# build-stamped) - see the `build:` target below. The cross-compile targets delegate to the
# per-target scripts in scripts/ (which set GOOS/GOARCH but use the same flags).
#
#   make            # build a native binary           → ./rcvd
#   make build      # same
#   make build-linux-amd64  # Linux x86-64            → ./rcvd-amd64
#   make build-linux-arm64  # Linux aarch64           → ./rcvd-arm64
#   make build-mac-amd64    # macOS Intel (x86-64)    → ./rcvd-macos-amd64  (native or cross)
#   make build-mac-arm64    # macOS Apple Silicon     → ./rcvd-macos-arm64
#   make man        # render man/rcvd.1 from man/rcvd.1.md (go-md2man)
#   make test       # go test ./...
#   make install    # install binary + man page (PREFIX=/usr/local, needs sudo)
#   make uninstall  # remove installed binary + man page
#   make clean      # remove built artifacts
#
# Install paths follow the GNU convention and are overridable, e.g. a non-root user install:
#   make install PREFIX=$HOME/.local

SHELL      := /usr/bin/env bash
BIN        := rcvd
PREFIX     ?= /usr/local
DESTDIR    ?=
BINDIR     := $(DESTDIR)$(PREFIX)/bin
MANDIR     := $(DESTDIR)$(PREFIX)/share/man/man1
MD2MAN     ?= $(HOME)/go/bin/go-md2man
INSTALL    ?= install

.PHONY: all build build-linux-amd64 build-linux-arm64 build-mac-amd64 build-mac-arm64 man test install uninstall clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.buildDate=$$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o $(BIN) ./cmd/rcvd

build-linux-amd64:
	scripts/build-linux-amd64.sh

build-linux-arm64:
	scripts/build-alpine-arm64.sh

build-mac-amd64:
	scripts/build-macos-amd64.sh

build-mac-arm64:
	scripts/build-macos-arm64.sh

# rcvd.1 is generated from rcvd.1.md - never hand-edit the roff.
man:
	@if [ ! -x "$(MD2MAN)" ]; then \
		echo "go-md2man not found at $(MD2MAN) — install: go install github.com/cpuguy83/go-md2man/v2@latest" >&2; \
		exit 1; \
	fi
	$(MD2MAN) -in man/rcvd.1.md -out man/rcvd.1
	@echo "rendered man/rcvd.1"

test:
	go test ./...

# Installs the current ./$(BIN) if present; otherwise builds it first.
install: man
	@[ -f "$(BIN)" ] || $(MAKE) build
	$(INSTALL) -d "$(BINDIR)" "$(MANDIR)"
	$(INSTALL) -m 755 "$(BIN)"       "$(BINDIR)/$(BIN)"
	$(INSTALL) -m 644 man/rcvd.1     "$(MANDIR)/rcvd.1"
	@echo "installed: $(BINDIR)/$(BIN)  +  $(MANDIR)/rcvd.1"

uninstall:
	rm -f "$(BINDIR)/$(BIN)" "$(MANDIR)/rcvd.1"
	@echo "removed: $(BINDIR)/$(BIN)  +  $(MANDIR)/rcvd.1"

clean:
	rm -f "$(BIN)" rcvd-amd64 rcvd-arm64 rcvd-macos-amd64 rcvd-macos-arm64
