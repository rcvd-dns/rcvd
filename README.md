# RCVD

## Resilient, Cryptographic, Verifiable DNS

**DNS engine that only uses standards compliant encrypted transports**

`rcvd` is a privacy-first DNS **engine** in a single static Go binary: all upstream
queries encrypted (DoQ → DoT → DoH), with built-in caching, blocklists, and DNSSEC
validation. It runs in one of four shapes:

- **Mode 1 (Resolver):** Accept plain DNS from local clients, encrypt everything upstream.

- **Mode 2 (Upstream Service):** Accept encrypted DNS (DoH/DoT/DoQ) from remote clients: power a public resolver, corporate endpoint, ISP encrypted DNS service, Wireless Router etc.

- **Both:** Same host - Run both modes simultaneously in a _single process_ with a shared cache between modes.

- **Hybrid:** Same host - Run each mode as a separate process with separate config files. (isolated process model, better for carrier grade, large enterprise, ISP deployments.)

See [MODE-1.md](docs/MODE-1.md) and [MODE-2.md](docs/MODE-2.md) for detailed architecture.

---

Most resolvers treat encrypted DNS as best-effort. They fall back to cleartext
port 53 when the secure path fails. `rcvd` refuses that choice. 
If every encrypted upstream fails, it returns `SERVFAIL` rather than a plaintext query. 
Encryption here is not a feature you switch on, it is a guarantee the engine inherently supports.

`rcvd` does not ask for your trust. It lets you **verify**. Inspect every upstream's
full TLS certificate chain with e.g. `--verify-upstream`, `--verify-pin` and audit the
running posture live with `--audit`.

Core Idea: `rcvd` does not do outbound cleartext dns.

---

## Protocols

| Protocol | RFC | Status |
|----------|-----|--------|
| DoQ — DNS-over-QUIC | RFC 9250 | Supported |
| DoT — DNS-over-TLS | RFC 7858 | Supported |
| DoH — DNS-over-HTTPS | RFC 8484 | Supported |
| DNSSEC Validation | RFC 4033-4035 | Supported |
| ODoH — Oblivious DoH | RFC 9230 | Planned |

**Protocol priority: DoQ → DoT → DoH** within each upstream (DoH is the port-443 escape
hatch, not the preferred protocol); the upstreams themselves are tried in config-file order.

## Features

- **Encrypted forwarding** — DoQ, DoT, DoH to upstream resolvers (AdGuard, Quad9, Cloudflare, etc.)
- **Multi-upstream fallback** — automatic health checks, two-phase state machine (aggressive startup, gentle runtime)
- **DNS cache** — in-memory, TTL-aware, configurable max size (default 4096 entries)
- **Blocklists** — plain domain list + hosts file formats, wildcard support, auto-detect
- **DNSSEC validation** — well-formedness + cryptographic verification, permissive or strict mode
- **Upstream service** — expose DoH, DoT, DoQ endpoints for browsers and other tools (Mode 2)
- **TLS automation** — Let's Encrypt via certmagic for Mode 2 production deployments
- **Live statistics** — `rcvd --stats` via Unix socket: queries, cache hit rate, latency, per-protocol breakdown, DNSSEC
- **Upstream verification** — `rcvd --verify-upstream` probes each configured upstream, displays full TLS cert chain, fingerprint, chain validity, hostname match, and expiry — no running instance needed
- **Static binary** — single self-contained binary, `CGO_ENABLED=0`, runs on Alpine/musl/glibc
- **TOML configuration** — one config file per instance, with unknown-key detection

## Quick Start

```bash
# Build the production binary — static, stripped, path-trimmed (small, no debug symbols).
# Use this, not a bare `go build` (which leaves the symbol table + DWARF in, ~2x the size).
make build

# Run the flagship example — Mode 1 + Mode 2 in one process, sharing one cache
./rcvd --config etc/flagship-dualmode.toml

# Query it as a plain-DNS client (Mode 1)
dig @127.0.0.1 -p 5300 example.com +short

# Query the encrypted DoH endpoint (Mode 2; self-signed cert in the example)
curl -k 'https://127.0.0.1:8443/dns-query?name=example.com&type=A' \
     -H 'accept: application/dns-json'

# Check live stats — watch the shared cache hit rate climb
./rcvd --stats --config etc/flagship-dualmode.toml

# Verify each upstream's TLS certificate chain (no running instance needed)
./rcvd --verify-upstream --config etc/flagship-dualmode.toml
```

`make build` needs only Go and `make`. See [Building](#building) for the exact flags,
cross-compilation, and a no-`make` fallback.

## Configuration

RCVD is configured with a single TOML file per instance. Three heavily-commented example
configs in [`etc/`](etc/) cover the main deployment shapes — start with the flagship:

| Example config | Role | What it shows |
|----------------|------|---------------|
| [`etc/flagship-dualmode.toml`](etc/flagship-dualmode.toml) | Mode 1 **+** Mode 2 | One process serving both plaintext LAN clients and encrypted DoH/DoH3 clients, **sharing one warm cache**. Start here. |
| [`etc/mode1-forwarder-3providers.toml`](etc/mode1-forwarder-3providers.toml) | Mode 1 only | A 3-provider fallback chain across all three transports (AdGuard DoQ → Cloudflare DoT → Quad9 DoH) with the `[fallback]` health state machine. |
| [`etc/mode2-doh-service.toml`](etc/mode2-doh-service.toml) | Mode 2 only | Exposing a DoH + DoH3 endpoint, with all three TLS-certificate options (self-signed, bring-your-own, or automatic Let's Encrypt via ACME). |

A minimal Mode-1 resolver config looks like this:

```toml
stats_enabled = true

[resolver]
enabled = true
listen = "127.0.0.1:5300"

[[upstreams]]
name = "AdGuard DoQ"
host = "dns.adguard.com"      # TLS SNI / certificate hostname — keep this a hostname
# ip = "change-me"            # pin the dial IP (see below) — avoids a cleartext bootstrap lookup
port = 853
doq = true

[cache]
enabled = true
mode = "aggressive"           # "light" | "standard" | "aggressive"
max_size = 4096

[dnssec]
enabled = true

[logging]
level = "info"
format = "text"
```

### Bootstrap hardening: pin the upstream `ip`

Without an `ip`, RCVD must resolve the upstream's hostname (e.g. `dns.adguard.com`) to get a
dial target — and that very first lookup can only go out as **cleartext DNS**, the exact leak
RCVD exists to prevent. Setting `ip` makes the dial target explicit, so there is zero cleartext
bootstrap. `host` is still used for TLS SNI / certificate validation; put the IP in `ip`, never
in `host`.

The example configs ship this line commented so they run out-of-the-box; uncomment it and
replace `"change-me"` with the provider's current IP for a production deployment. (RCVD rejects
an invalid `ip` at config load, so a leftover `"change-me"` cannot silently ship.) See
[CONFIG.md](docs/CONFIG.md#upstreams--define-encrypted-upstream-dns-servers) for details.

## Building

RCVD is a single Go binary with no C dependencies. With `go` and `make` installed:

```bash
make build          # host-arch production binary → ./rcvd
make test           # go test ./...
make install        # install binary + man page (PREFIX=/usr/local, needs sudo)
```

`make build` wraps the production recipe below — static, stripped, and path-trimmed.
A bare `go build ./cmd/rcvd` also works, but keeps the symbol table and DWARF debug info,
producing a binary roughly twice the size — fine for local hacking, not for shipping.
If you'd rather not use `make` (or want to see exactly what it runs), the production build is:

```bash
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o rcvd ./cmd/rcvd
```

What each part does:

| Flag | Effect |
|------|--------|
| `CGO_ENABLED=0` | Pure-Go static binary — no libc linkage, so one binary runs on musl (Alpine) and glibc, and inside `scratch`/distroless containers. |
| `-trimpath` | Removes local filesystem paths (your `$HOME`, GOPATH) from the binary — smaller, reproducible, and no build-machine paths leak into a shipped artifact. |
| `-ldflags "-s -w"` | Strips the symbol table (`-s`) and DWARF debug info (`-w`), significantly shrinking the binary. |
| `-X main.buildDate=…` | Embeds the UTC build timestamp that `rcvd --version` reports (defaults to `unknown` if omitted). |

Cross-compile for another OS/arch by setting `GOOS`/`GOARCH` — the flags above are unchanged:

```bash
# Linux aarch64 (e.g. an ARM single-board router)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
  -ldflags "-s -w -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o rcvd-arm64 ./cmd/rcvd
```

The Makefile also has convenience cross-compile targets (`make build-arm64`,
`make build-mac-amd64`, `make build-mac-arm64`). Cross-compiled binaries for every
supported OS/arch are produced by the CI pipeline.

### Testing

```bash
make test      # or: go test ./...
```

Developed and run on Linux and NetBSD. Binaries for macOS and FreeBSD are
cross-compiled from the same pure-Go source but have not yet been runtime-tested.

## Deployment Notes

Kernel tuning (UDP buffers for DoQ), and the operational differences between
always-on router and roaming-laptop deployments, are covered in
[docs/deployment.md](docs/deployment.md).

## Packaging

Service units and platform packaging (OpenRC, systemd, launchd, Homebrew) live
under [`packaging/`](packaging/) — see the packaging directory for full details.

## Pre-Release Development History
- see HISTORY.md

## Author

`rcvd` is designed and built by [Christopher Mosetick](https://cpm.is) · office@cpm.is
