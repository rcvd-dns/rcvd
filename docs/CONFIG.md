# RCVD Configuration Guide

RCVD is configured entirely via TOML files. There is **no mandatory default configuration** — users and administrators are expected to evaluate example configs for their use case and create their own configuration file.

This guide documents all available configuration options and their implications.

---

## Overview

RCVD operates in two independent modes:

1. **Resolver Mode** — Listen for DNS queries from local clients, forward to encrypted upstreams
2. **Upstream Service Mode** — Offer encrypted DNS endpoints (DoH/DoT/DoQ) for other tools to use

Each configuration file enables at least one mode. See [MODE-1.md](MODE-1.md) and [MODE-2.md](MODE-2.md) for detailed architecture.

### Running Both Modes Simultaneously

**RCVD supports running both modes in a single process.** Enable both `[resolver]` and `[upstream_service]` in one config file:

```toml
# Both modes, single process — shared cache
stats_enabled = true

[resolver]
enabled = true
listen = "127.0.0.1:5300"

[upstream_service]
enabled = true
listen_doh = "0.0.0.0:8443"
listen_dot = "0.0.0.0:853"
listen_doq = "0.0.0.0:853"
tls_cert_autogen = true  # testing only; use tls_automation = true for production

[[upstreams]]
name = "AdGuard DoQ"
host = "dns.adguard.com"
port = 853
doq = true

[cache]
enabled = true
max_size = 4096
```

When both modes run in one process, they share the same cache, blocklist, DNSSEC validator, and statistics. A cache hit from a Mode 1 query is immediately available to a Mode 2 query.

**Alternatively, run two separate processes** with different config files for fault isolation (recommended for internet-facing Mode 2):

```bash
rcvd -config rcvd-resolver.toml    # Mode 1 only
rcvd -config rcvd-upstream.toml   # Mode 2 only
```

See the Deployment Guidance section in [MODE-2.md](MODE-2.md) for when to use each approach.

---

## Quick Start: Resolver Mode

```toml
stats_enabled = true

[resolver]
enabled = true
listen = "127.0.0.1:5300"

[[upstreams]]
name = "AdGuard DoQ"
host = "dns.adguard.com"
port = 853
doq = true

[cache]
enabled = true
max_size = 4096

[dnssec]
enabled = true

[logging]
level = "info"
```

Run with: `rcvd -config your-config.toml`

Check live stats with: `rcvd --stats -config your-config.toml`

---

## Configuration Structure

### Top-Level Options

```toml
stats_enabled = true   # Enable live statistics via rcvd --stats (default: false)
```

**Options:**
- `stats_enabled` (bool, optional) — Enable the statistics Unix socket
  - Default: `false`
  - When enabled, exposes a Unix socket for the `rcvd --stats` command
  - **When disabled (the default), no socket is created** — the daemon never binds a Unix socket, so there is no local query surface at all
  - Socket path: `/run/rcvd/<config-name>.sock` (or `/tmp/rcvd-<config-name>.sock` if `/run/rcvd/` does not exist)
  - Query with: `rcvd --stats -config <path>` — shows queries, cache hit rate, latency, per-protocol breakdown, DNSSEC counters

---

### `[resolver]` — Mode 1: Listen for Client Queries

Enable this to listen for DNS queries from local clients (systemd-resolved, dnsmasq, other resolvers).

```toml
[resolver]
enabled = true              # Enable resolver mode (required if upstream_service is disabled)
listen = "127.0.0.1:5300"   # Address:port to listen on (default: 127.0.0.1:5300)
```

**Options:**
- `enabled` (bool, required) — Enable this mode
- `listen` (string, optional) — Bind address and port
  - Default: `127.0.0.1:5300` (coexists with systemd-resolved on 53)
  - Examples: `127.0.0.1:5300`, `0.0.0.0:53` (requires CAP_NET_BIND_SERVICE)

**Note on Port 5300:** Port 5300 is chosen to coexist with systemd-resolved, which typically listens on 127.0.0.1:53 (loopback) and 127.0.0.53:53.  
RCVD on 5300 can be used as an upstream for systemd-resolved, dnsmasq, or other local DNS tools.

---

### `[[upstreams]]` — Define Encrypted Upstream DNS Servers

At least one upstream is required. Each upstream must support at least one encrypted protocol (DoQ, DoT, or DoH).

```toml
[[upstreams]]
name = "AdGuard DoQ"           # Friendly name for logging
host = "dns.adguard.com"       # Hostname for TLS certificate validation (SNI)
ip = "94.140.14.14"            # Optional: IP to dial (avoids DNS bootstrap lookup)
port = 853                      # Port (853 for DoQ/DoT, 443 for DoH)

# Protocol selection (at least one required)
doq = true                      # DNS-over-QUIC (RFC 9250)
dot = false                     # DNS-over-TLS (RFC 7858)
doh = false                     # DNS-over-HTTPS (RFC 8484)

# DoH-specific
doh_path = "/dns-query"         # HTTP path (only if doh = true)

# Optional: Public key pinning
pinned_pubkey = "..."           # Hex-encoded SPKI hash (deferred)

# Optional: 0-RTT session resumption (PRIVACY TRADEOFF — see below)
quic_0rtt = false               # Enable QUIC 0-RTT (default: false, privacy-first) — not yet implemented
```

**Options:**
- `name` (string, required) — Friendly name for logs and metrics
- `host` (string, required) — Hostname or IP address used for TLS certificate validation (SNI)
- `ip` (string, optional) — IP address to dial instead of resolving `host` via DNS (see [host vs ip](#host-vs-ip--avoiding-the-dns-bootstrap-problem) below)
- `port` (int, required) — Port number (853 for DoQ/DoT, 443 for DoH)
- `doq` (bool, optional) — Enable DNS-over-QUIC (RFC 9250)
- `dot` (bool, optional) — Enable DNS-over-TLS (RFC 7858)
- `doh` (bool, optional) — Enable DNS-over-HTTPS (RFC 8484)
- `doh_path` (string, optional) — HTTP path for DoH (default: `/dns-query`)
- `quic_0rtt` (bool, optional) — Enable QUIC 0-RTT (see QUIC 0-RTT section below) — **not yet implemented**

**Multiple Upstreams:**

RCVD supports multiple upstreams with automatic fallback:

```toml
[[upstreams]]
name = "Primary - AdGuard DoQ"
host = "dns.adguard.com"
ip = "94.140.14.14"
port = 853
doq = true

[[upstreams]]
name = "Secondary - Cloudflare DoT"
host = "cloudflare-dns.com"
ip = "1.1.1.1"
port = 853
dot = true

[[upstreams]]
name = "Tertiary - Quad9 DoH"
host = "dns.quad9.net"
ip = "9.9.9.9"
port = 443
doh = true
doh_path = "/dns-query"
```

When multiple upstreams are defined, RCVD uses the fallback resolver with health checks:
- Tries primary upstream first
- Falls back to secondary if primary fails
- Falls back to tertiary if secondary fails
- Returns SERVFAIL if all upstreams are unavailable (never cleartext)

---

### `host` vs `ip` — Avoiding the DNS Bootstrap Problem

The `host` and `ip` fields serve different purposes:

| Field | Purpose | Example |
|-------|---------|---------|
| `host` | TLS certificate validation (SNI) | `"dns.adguard.com"` |
| `ip` | Network dial target | `"94.140.14.14"` |

**How it works:**
- `host` is always used for TLS ServerName Indication (SNI). The upstream server's TLS certificate must be valid for this hostname — this is how rcvd verifies it is talking to the real server.
- `ip`, when set, is the actual network address rcvd connects to. The TLS handshake still validates the certificate against `host`.
- When `ip` is omitted, rcvd resolves `host` via the system DNS resolver before connecting.

**The bootstrap problem:** rcvd never sends cleartext DNS. If rcvd is your system's default (or only) DNS resolver, there is no plaintext DNS available to resolve a hostname like `dns.adguard.com` in the first place. rcvd needs DNS to reach its own DNS upstream — a circular dependency.

Setting `ip` breaks the loop. rcvd dials the IP directly — no DNS lookup needed.

**When to set `ip`:**
- **Required** when rcvd is the system's default or only DNS resolver and `host` is a hostname.
- **Recommended** in all cases where `host` is a hostname. It eliminates a DNS lookup on every cold connection and makes startup deterministic.
- **Not needed** when `host` is already an IP address (e.g., `host = "1.1.1.1"`).

**Can you put an IP in `host`?** Yes — `host = "1.1.1.1"` works when the upstream's TLS certificate includes that IP in its Subject Alternative Names. Cloudflare (`1.1.1.1`) and Quad9 (`9.9.9.9`) issue certificates with their IPs as SANs. In this case, `ip` is unnecessary.

**Can you use only `ip` without `host`?** No — `host` is required. It is the TLS ServerName and must match the upstream's certificate. `ip` is always optional.

**Examples:**

```toml
# Recommended: hostname + pinned IP (no DNS lookup needed to start)
[[upstreams]]
name = "AdGuard"
host = "dns.adguard.com"
ip = "94.140.14.14"
port = 853
doq = true

# Also valid: IP-only when the cert includes the IP as a SAN
[[upstreams]]
name = "Cloudflare"
host = "1.1.1.1"
port = 853
dot = true

# Fragile: hostname without ip (needs another DNS resolver to start)
[[upstreams]]
name = "AdGuard"
host = "dns.adguard.com"
port = 853
doq = true
```

**Validation:** The `ip` field is validated at config load time. It must be a valid IPv4 or IPv6 address. Invalid values cause a config error.

**Verifying:** Use `rcvd --verify-upstream` to probe each upstream and confirm the TLS certificate chain, hostname match, and expiry. The `ip` field is used for dialing during verification, same as at runtime.

---

## Protocol Priority & Fallback

When an upstream supports multiple protocols (e.g., both DoQ and DoT), RCVD tries them in this order:

1. **DoQ** (RFC 9250) — Preferred (lowest latency, multiplexed streams)
2. **DoT** (RFC 7858) — Secondary (reliable, widely supported)
3. **DoH** (RFC 8484) — Tertiary (port 443 escape hatch, lower performance)

Example fallback: If AdGuard supports both DoQ and DoT:

```toml
[[upstreams]]
name = "AdGuard Multi-Protocol"
host = "dns.adguard.com"
port = 853
doq = true   # Try DoQ first
dot = true   # Fall back to DoT if DoQ fails
```

RCVD attempts DoQ. If the connection fails, it retries with DoT on the next query.

---

## QUIC 0-RTT: Speed vs. Privacy Tradeoff

### What is 0-RTT?

**0-RTT** (Zero Round Trip Time) is QUIC's session resumption feature. It controls **when and how often** cryptographic handshakes occur:

**Handshake Timeline:**

| Connection | 0-RTT Disabled | 0-RTT Enabled |
|-----------|----------------|---------------|
| **1st connection** | Full handshake (1 RTT) | Full handshake (1 RTT) |
| **2nd+ connections** | Full handshake every time (1 RTT each) | Reuse session keys (0 RTT) |
| **Handshake frequency** | Every query | Only on first connection |

**Speed comparison:**
- **0-RTT disabled:** Every connection requires a full cryptographic handshake (slower, more private)
- **0-RTT enabled:** First connection has handshake, repeat connections reuse session keys (faster, less private)

**Privacy cost:**
- When 0-RTT is enabled, the upstream server can link multiple queries to the same client session
- The server sees: "Query A, Query B, and Query C all came from the same client"
- This breaks query anonymity (potential privacy issue)

### Default Configuration

RCVD defaults to **`quic_0rtt = false`** (privacy-first):

```toml
[resolver]
enabled = true
listen = "127.0.0.1:5300"

[[upstreams]]
name = "AdGuard DoQ"
host = "dns.adguard.com"
port = 853
doq = true
quic_0rtt = false  # Default: privacy over speed
```

Each new connection uses a fresh session (slower, more private).

### Enabling 0-RTT for Speed

If you prioritize speed over anonymity (e.g., internal corporate resolver), enable 0-RTT:

```toml
[[upstreams]]
name = "AdGuard DoQ"
host = "dns.adguard.com"
port = 853
doq = true
quic_0rtt = true   # Enable session resumption (faster, less private)
```

**When to enable `quic_0rtt = true`:**
- Internal corporate networks (queries are already known to your organization)
- Low-latency, high-throughput scenarios where privacy is less critical
- Environments where the upstream provider is fully trusted

**When to keep `quic_0rtt = false`:**
- Public-facing resolvers (privacy is paramount)
- Scenarios where upstream providers are not fully trusted
- When anonymity between queries matters
- Default for privacy-first deployments

### Technical Note: QUIC 0-RTT in Academic Literature

The tradeoff between 0-RTT performance and session linkability is well-documented in the original QUIC protocol paper:

> "A common load balancing method employed by servers is to use multiple IP addresses for the same hostname, and repeat TCP connections to the same domain may end up at different server IP addresses. Since QUIC combines the cryptographic layer with transport, it uses 0-RTT handshakes with repeat connections to the same origin."
>
> — Google QUIC Transport Protocol, SIGCOMM '17 (August 2017), Page 13

This highlights the fundamental design choice: QUIC prioritizes connection reuse (0-RTT) for performance, which enables servers to link multiple queries to the same client session. RCVD makes this choice configurable rather than mandatory, allowing administrators to prioritize privacy when needed.

**RFC 9250 (DNS-over-QUIC)** acknowledges this in Section 5.2, recommending session resumption but not mandating it. RCVD respects this by making it configurable. The privacy implications are yours to evaluate.

---

## Fallback & Health Checks

### `[fallback]` — Protocol Fallback State Machine

Configure how RCVD handles upstream failures and recovery.

```toml
[fallback]
# Phase 1 (startup): Aggressive health checks
phase1_timeout_ms = 2000           # Timeout marking upstream DOWN (default: 2000)
phase1_duration_s = 300            # Duration of aggressive phase (default: 300 = 5 min)

# Phase 2 (runtime): Gentle health checks
phase2_failure_threshold = 3       # Consecutive failures before DOWN (default: 3)
phase2_slow_threshold_ms = 200     # Response time threshold (informational)

# Health check probing
health_check_interval_s = 30       # Interval for probing DOWN upstreams (default: 30)
```

**Options:**
- `phase1_timeout_ms` (int, optional) — Timeout in milliseconds during startup
  - Default: 2000 (2 seconds)
  - If an upstream doesn't respond within this time during the first 5 minutes, it's marked DOWN
  - Use aggressive timeouts during startup to quickly detect unreachable upstreams

- `phase1_duration_s` (int, optional) — Duration of aggressive phase
  - Default: 300 (5 minutes)
  - After startup, RCVD switches to gentle mode

- `phase2_failure_threshold` (int, optional) — Consecutive failures before marking DOWN
  - Default: 3 (three consecutive failures mark upstream DOWN)
  - Gentle mode prevents flapping from transient failures

- `phase2_slow_threshold_ms` (int, optional) — Response time threshold
  - Default: 200 (informational only, doesn't mark DOWN)
  - Used for logging slow responses

- `health_check_interval_s` (int, optional) — How often to probe DOWN upstreams
  - Default: 30 (every 30 seconds)
  - Allows recovery from temporary failures

**State Machine:**

```
Phase 1 (startup, 0-5 min):
  UP: Query succeeds
  DOWN: Query timeout > 2s

Phase 2 (runtime):
  UP: Queries succeed
  SLOW: Single failure or slow response
  DOWN: 3 consecutive failures

Health check ticker: Every 30s, probe DOWN upstreams
  DOWN → UP: Upstream recovered, resume queries
```

---

## DNSSEC Validation

### `[dnssec]` — DNSSEC Validation Settings

```toml
[dnssec]
enabled = true                 # Enable DNSSEC validation (default: true)
validate_all = false           # Validate all responses (default: false)
root_key_file = ""             # Override the embedded IANA root anchor (default: embedded)
```

**Options:**
- `enabled` (bool, optional) — Enable DNSSEC validation
  - Default: `true` (validation enabled)
  - Set to `false` to disable (not recommended)

- `validate_all` (bool, optional) — Strict validation
  - Default: `false` (only validate signed zones)
  - Set to `true` for maximum security (may cause failures with misconfigured zones)

- `root_key_file` (string, optional) — Path to the DNSSEC **root** trust anchor
  - Default: empty — rcvd uses the IANA root anchor **embedded** in the binary at
    compile time. This is the published, public root KSK digest (the same value every
    DNSSEC validator uses); it is not a secret and needs no setup to work out of the box.
  - When set, rcvd loads the anchor from that file instead. The file may be either:
    - **IANA `root-anchors.xml`** (DS format) — from <https://data.iana.org/root-anchors/root-anchors.xml>, or
    - **BIND-style `root.key`** (DNSKEY format) — the file most distros already ship
      and keep updated via their package manager or `unbound-anchor`.

  Known system paths by platform:

  | Platform | Package | Path | Verified |
  |---|---|---|---|
  | Debian / Ubuntu / Linux Mint | `dns-root-data` | `/usr/share/dns/root.key` | ✅ |
  | Debian / Ubuntu / Linux Mint | `dns-root-data` | `/var/lib/unbound/root.key` | ✅ |
  | Alpine Linux | `dnssec-root` | `/usr/share/dnssec-root/trusted-key.key` | ✅ |
  | FreeBSD | — | `/var/unbound/root.key` | unverified |
  | NetBSD | — | `/var/unbound/root.key` | unverified |
  | macOS (Homebrew) | — | `/usr/local/etc/unbound/root.key` | unverified |
  | macOS (MacPorts) | — | `/opt/local/etc/unbound/root.key` | unverified |

  - The format is auto-detected. A missing/unreadable path is a startup error.

**When to set `root_key_file`:** Point it at your OS's system anchor file so the
**distribution owns trust-anchor updates** (including the rare root KSK rollover) through
its normal package/`unbound-anchor` machinery, rather than depending on an rcvd rebuild.
This is the recommended setup for packaged/long-lived deployments. For a quick start or a
container, the embedded anchor is fine.

> **Root KSK rollover caveat.** rcvd does **not** yet track root key rollovers automatically
> (RFC 5011). The embedded anchor is a point-in-time snapshot; if you rely on it, a future
> root KSK rollover requires an updated rcvd binary. Using `root_key_file` with the system
> anchor sidesteps this. See the tracked item in `ISSUES.md`.

**Note:** DNSSEC validation is a security feature. Keep it enabled by default.

---

## Caching

### `[cache]` — DNS Response Caching

```toml
[cache]
enabled = true                 # Enable caching (default: true)
max_size = 4096                # Maximum cache entries (default: 4096)
ttl_min = 60                   # Minimum TTL in seconds (default: 60)
ttl_max = 86400                # Maximum TTL in seconds (default: 86400 = 24h)
prefetch = false               # not currently available. Prefetch expiring entries (default: false)
```

**Options:**
- `enabled` (bool, optional) — Enable response caching
  - Default: `true` (caching enabled)
  - Set to `false` to disable caching entirely (all queries bypass cache)

- `max_size` (int, optional) — Maximum number of cached entries
  - Default: 4096
  - Scales linearly with memory usage (~1KB per entry)

- `ttl_min` (int, optional) — Minimum TTL in seconds
  - Default: 60 (don't cache responses with TTL < 60s)
  - Prevents excessive cache of short-lived records

- `ttl_max` (int, optional) — Maximum TTL in seconds
  - Default: 86400 (24 hours)
  - Cap extremely long TTLs to free memory periodically

- `prefetch` (bool, optional) — Prefetch expiring entries
  - Default: `false` (not yet implemented)
  - Planned for Phase 4 (background refresh of entries approaching expiration)
  - Currently, expired entries are lazily deleted on access only

**Cache Behavior:**
- Responses are cached according to their TTL (Time To Live)
- Cached entries are returned without querying upstreams
- Reduces latency and upstream load
- Memory usage scales with cache size (~1KB per entry, ~4MB for 4096 entries)
- **In-memory only** — cache is cleared on restart; no disk persistence
- When Mode 1 and Mode 2 run in the same process, they share one cache

---

## Blocklists

### `[blocklists]` — Domain Filtering

```toml
[blocklists]
enabled = true                 # Enable blocklist filtering (default: true)
files = [
  "blocklists/adblock.list",
  "blocklists/malware.hosts"
]
update_urls = [
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  "https://www.oisd.nl/domainswild"
]
update_interval = "12h"        # How often to fetch fresh lists
```

**Options:**
- `enabled` (bool, optional) — Enable blocklist filtering
  - Default: `true` (filtering enabled)

- `files` (list of strings, optional) — Local blocklist files
  - Supported formats:
    - Plain domain list (one domain per line): `example.com`
    - Hosts file format: `127.0.0.1 example.com`
  - Wildcards supported: `*.example.com` (blocks all subdomains)

- `update_urls` (list of strings, optional) — URLs to fetch fresh lists
  - Updates are fetched on the specified interval
  - Useful for keeping malware/phishing lists current

- `update_interval` (string, optional) — Update frequency — **not yet implemented**
  - Default: `"12h"` (every 12 hours)
  - Examples: `"1h"`, `"6h"`, `"24h"`

**Blocklist Behavior:**
- Queries for blocked domains return NXDOMAIN (domain does not exist)
- Never returns a fake IP address (maintains DNS integrity)
- Blocked queries increment the aggregate "Blocked (NXDOMAIN)" statistic — the blocked
  domain name itself is never logged

**Hot-reload (`rcvd -blocklist-reload`):**
- Edit the `files` on disk, then run `rcvd -config … -blocklist-reload` to reload them
  into the running process — no restart, so statistics, cache, and connections are all preserved.
- The whole in-memory set is rebuilt from the files and atomically swapped in, so **both added
  and removed** domains take effect (unlike a startup load, which only adds).
- Asynchronous and non-blocking: the command returns immediately with an acknowledgment while the
  rescan runs in the background (a large list can take ~a minute on slow storage), so DNS is never
  paused. Final counts land in the daemon log when the swap completes.
- Only local `files` are reloaded; `update_urls` are not re-fetched. Requires `stats_enabled = true`
  (it uses the same Unix socket as `-stats`/`-audit`).

---

## Query Logging — Not a Feature (By Design)

RCVD has **no per-query logging facility, and will not have one.** A privacy DNS engine
does not ship a feature whose purpose is to record what was queried. There is no
`[query_log]` config section.

This is a deliberate design decision, not a missing feature:
- The operational log (`[logging]`, below) records startup/shutdown and errors only — it
  **never records queried domain names**, even on failure paths.
- Aggregate, non-identifying counts (totals, cache hit rate, DNSSEC outcomes) are available
  via the in-memory statistics socket (`stats_enabled`, below) — never per-query, never with
  client identity.

If you need to see what posture the running instance holds (listeners, no-cleartext
enforcement, cache type), that is the role of `--audit` — which also reports no per-client
or per-query data.

---

## Statistics

### `stats_enabled` — Live Statistics via Unix Socket

RCVD exposes live statistics via a Unix socket when `stats_enabled = true` is set at the top of the config file. Statistics are queried with:

```bash
rcvd --stats -config /etc/rcvd/rcvd.toml
```

**Example output:**

```
Queries
  Total Queries:               1,204
  Cache Hits:                  891
  Cache Misses:                313
  Hit Rate:                    74.0%
  Upstream Errors:             2
  DNSSEC Validated:            298

Cache
  Current Size:                312 / 4,096
  Cache Hits:                  891
  Cache Misses:                313
  Hit Rate:                    74.0%

Protocol Breakdown (Outbound)
  DoQ Queries:                 1,198
  DoT Queries:                 4
  DoH Queries:                 2

Protocol Breakdown (Inbound, Mode 2)
  DoQ Served:                  843
  DoT Served:                  291
  DoH Served:                  70

Latency
  Avg Latency:                 12ms
  Max Latency:                 143ms
```

**Notes:**
- "Protocol Breakdown (Outbound)" = queries rcvd sent to upstream (DoQ/DoT/DoH). Present in all modes.
- "Protocol Breakdown (Inbound, Mode 2)" = clients connected to rcvd's encrypted endpoints. Only shown when Mode 2 has served at least one query.
- Statistics are in-memory only — reset on restart.
- The socket path is derived from the config file path: `/run/rcvd/<config-name>.sock`
- This one socket is the daemon's control channel for **all** of `-stats`, `-audit`, and
  `-blocklist-reload`. Setting `stats_enabled = false` disables the socket entirely, so **`-audit`
  and live blocklist reload stop working too** — not just `-stats`. With the socket off, the only way
  to pick up blocklist file edits is a full process restart.

---

## Logging

### `[logging]` — Application Logging

```toml
[logging]
level = "info"                 # Log level (default: "info")
format = "text"                # Log format (default: "text")
file = "/var/log/rcvd/rcvd.log" # Log destination (default: /var/log/rcvd/rcvd.log)
```

**Options:**
- `file` (string, optional) — Log destination
  - Default: `"/var/log/rcvd/rcvd.log"` (a file; the directory must exist and be writable)
  - Special values:
    - `"stdout"` — log to standard output (**container-friendly**: makes `podman logs` /
      `docker logs` and log aggregators capture rcvd's output; no log file/dir to manage)
    - `"stderr"` — log to standard error
  - Any other value is treated as a file path (created/appended, mode 0640)
- `level` (string, optional) — Log verbosity
  - Options: `"debug"`, `"info"`, `"warn"`, `"error"`
  - Default: `"info"` (startup/stop messages only)
    - **What IS logged at `info`:** RCVD startup and shutdown messages only
    - **What IS NOT logged at `info`:** Individual DNS queries (never — queried names are never logged at any level), upstream health state changes, configuration details, protocol debug info
  - Use `"debug"` for upstream state machine details, health check activity, and protocol-level diagnostics

- `format` (string, optional) — Log output format
  - Options: `"text"`, `"json"`
  - Default: `"text"` (human-readable, suitable for syslog and journalctl)
  - Use `"json"` for structured logging to log aggregators (Elasticsearch, Splunk, etc.)

---

## Upstream Service Mode (Mode 2)

### `[upstream_service]` — Expose DoH/DoT/DoQ Endpoints

```toml
[upstream_service]
enabled = false                # Enable upstream service mode
listen_doh = "0.0.0.0:8443"    # DoH HTTPS endpoint
listen_dot = "0.0.0.0:853"     # DoT TLS endpoint (TCP)
listen_doq = "0.0.0.0:853"     # DoQ QUIC endpoint (UDP — same port as DoT, different transport)

# TLS certificate — one of three options required:
tls_automation = false         # Option 1: Let's Encrypt via certmagic (production)
tls_cert = "/path/to/cert.pem" # Option 2: Provided cert file (production)
tls_key  = "/path/to/key.pem"  # Option 2: Provided key file
tls_cert_autogen = false       # Option 3: Auto-generate self-signed (testing only)
```

**Options:**
- `enabled` (bool, optional) — Enable upstream service mode
  - Default: `false`
  - Set to `true` to expose encrypted DNS endpoints for other tools

- `listen_doh` (string, optional) — DoH HTTPS endpoint (TCP)
  - Default port 8443 (non-privileged); use 443 for standard HTTPS with `CAP_NET_BIND_SERVICE`

- `listen_dot` (string, optional) — DoT TLS endpoint (TCP port 853)

- `listen_doq` (string, optional) — DoQ QUIC endpoint (UDP port 853)
  - DoT and DoQ can both use port 853 — they bind to different OS sockets (TCP vs UDP)

**TLS Certificate Options (pick ONE) — each maps to a different deployment topology:**

| Option | Use it for | Notes |
|--------|-----------|-------|
| `tls_automation` | **Direct-to-browser DoH + public endpoints** | Real CA-trusted cert (Let's Encrypt via certmagic). REQUIRED if a browser connects to rcvd directly. |
| `tls_cert` / `tls_key` | **Bring-your-own cert** | Tailscale (`tailscale cert`), corporate CA, manually-obtained LE, etc. Must have a DNS-ID in SAN. |
| `tls_cert_autogen` | **Dev/test, OR behind a trust-terminating proxy** | Self-signed. Fine for `curl -k`/local validation, and for the Quick-Tunnel / nginx-sidecar pattern where the proxy presents the real cert. **NOT for direct browser DoH.** |

- `tls_automation` (bool) — automatic Let's Encrypt via certmagic; configure the `[tls_automation]`
  section (below). **The only option that works for a browser pointed directly at rcvd's Mode-2
  endpoint.** Needs a real domain + reachable challenge (HTTP-01 or DNS-01).

- `tls_cert` / `tls_key` (string) — paths to an existing cert + key you supply. Must contain a
  DNS-ID in SubjectAltName per RFC 5280 / RFC 8310.

- `tls_cert_autogen` (bool) — self-signed cert generated at startup (SAN covers the configured
  `listen_*` addresses). Two valid uses: (1) **dev/test** — validate the endpoint with `curl -k`,
  scripts, or another rcvd; (2) **behind a TLS-terminating proxy that doesn't verify upstream** —
  e.g. the Cloudflare Quick Tunnel + nginx sidecar, where clients see the proxy's real cert and the
  rcvd↔proxy hop is internal. **Does NOT work for direct browser DoH:** Firefox/Zen's DoH (TRR)
  path requires a CA-trusted cert and ignores manual self-signed exceptions — the browser silently
  refuses to resolve. Also violates RFC 8310 Strict Privacy Profile for direct clients. For browser
  DoH, use `tls_automation`.

**TLS certificate priority (when more than one is set — matches the code):**
`tls_automation` → `tls_cert_autogen` → `tls_cert`/`tls_key`. NOTE the middle position of
`tls_cert_autogen`: if you set BOTH `tls_cert_autogen = true` AND `tls_cert`/`tls_key`, you get the
SELF-SIGNED cert (autogen wins over your files). Set only the one you want. (See TODO/ISSUES for a
possible future re-ordering so bring-your-own beats autogen.)

---

### `[tls_automation]` — Let's Encrypt via certmagic

Required when `tls_automation = true` in `[upstream_service]`.

```toml
[upstream_service]
enabled = true
tls_automation = true
listen_doh = "0.0.0.0:443"
listen_dot = "0.0.0.0:853"
listen_doq = "0.0.0.0:853"

[tls_automation]
on_demand = true
allowed_domains = ["dns.example.com"]
email = "admin@example.com"
storage_dir = "/var/lib/rcvd/certs"
staging = false   # true = Let's Encrypt staging (for testing)
```

**Options:**
- `on_demand` (bool) — Fetch certificates on first TLS handshake
  - No pre-configuration of domain needed before starting rcvd
  - 3–5s latency on first connection to a new domain, instant thereafter
- `allowed_domains` (list of strings) — Domain allowlist for on-demand cert issuance
- `email` (string) — Contact email for Let's Encrypt expiry notices
- `storage_dir` (string) — Directory for certificate storage (default: `$HOME/.rcvd/certs`)
- `staging` (bool) — Use Let's Encrypt staging CA for testing (certs not trusted by clients)
- `challenge` (string) — ACME challenge type. `"http"` (default; HTTP-01 / TLS-ALPN-01, needs
  inbound :80/:443 to rcvd) or `"dns01"` (DNS-01 via a libdns provider; **no inbound port**, works
  behind tunnels/CGNAT). An invalid value is rejected at startup.

#### DNS-01 challenge

When `challenge = "dns01"`, certmagic proves domain control by writing an `_acme-challenge` TXT
record through your DNS provider's API — so rcvd needs no reachable inbound port.

- `dns_provider` (string) — the libdns provider. **Supported: `cloudflare`** (MVP). An unsupported
  value is rejected at config load (not lazily at first cert issuance).

The provider API **token** is supplied from **exactly one** of three explicit sources. Setting more
than one is a hard startup error — there is no precedence or fallback chain, so "where the secret
came from" is never ambiguous:

| Key | Source | Notes |
|---|---|---|
| `dns_api_token` | inline literal in the config | Simplest for one-off deploys not tracked in git. |
| `dns_api_token_env` | the **name** of an env var to read | e.g. `"RCVD_LIBDNS_API_TOKEN"`. rcvd reads `os.Getenv(name)`; unset/empty = error. The launcher (`podman --env-file`, compose `env_file`, systemd `EnvironmentFile`, `export`) owns putting it in the environment. |
| `dns_api_token_file` + `dns_api_token_key` | a dotenv (`KEY=value`) file rcvd parses | `dns_api_token_key` is **required** and names the line (e.g. `"CLOUDFLARE_API_TOKEN"`) — there is no default. A relative `dns_api_token_file` resolves **next to the config file**; absolute is used as-is. |

```toml
[tls_automation]
on_demand       = true
allowed_domains = ["dns.example.com"]
email           = "admin@example.com"
storage_dir     = "/var/lib/rcvd/certs"
staging         = false
challenge       = "dns01"
dns_provider    = "cloudflare"

# Pick EXACTLY ONE token source:
dns_api_token     = "cf_xxx"                  # 1. inline
# dns_api_token_env  = "RCVD_LIBDNS_API_TOKEN"   # 2. env var (containers / IaC)
# dns_api_token_file = ".env"                 # 3. dotenv file next to this config ...
# dns_api_token_key  = "CLOUDFLARE_API_TOKEN" #    ... naming the line to read
```

**Security:** scope the token narrowly (Cloudflare: `Zone:DNS:Edit` on the one zone). In production
prefer `dns_api_token_env` or `dns_api_token_file` (0600, gitignored) over the inline literal.

---

## Example Configurations

### Example 1: Simple Resolver (Recommended for Most Users)

```toml
stats_enabled = true

[resolver]
enabled = true
listen = "127.0.0.1:5300"

[[upstreams]]
name = "AdGuard DoQ"
host = "dns.adguard.com"
port = 853
doq = true

[cache]
enabled = true
max_size = 4096

[dnssec]
enabled = true

[logging]
level = "info"
format = "text"
```

Use with: `systemd-resolved` configured to forward to `127.0.0.1:5300`

### Example 2: Multi-Upstream with Fallback (Router Deployment)

Use on a high traffic router for DNS failover across three providers.

```toml
stats_enabled = true

[resolver]
enabled = true
listen = "192.0.2.1:5354"   # LAN IP, RCVD-specific port

[[upstreams]]
name = "AdGuard DoQ"
host = "dns.adguard.com"
port = 853
doq = true

[[upstreams]]
name = "Cloudflare DoT"
host = "cloudflare-dns.com"
port = 853
dot = true

[[upstreams]]
name = "Quad9 DoH"
host = "dns.quad9.net"
port = 443
doh = true
doh_path = "/dns-query"

[cache]
enabled = true
max_size = 4096

[dnssec]
enabled = true

[fallback]
phase1_duration_s = 300
phase2_failure_threshold = 3
health_check_interval_s = 30

[logging]
level = "info"
```

### Example 3: Speed-Optimized (0-RTT Enabled)

```toml
[resolver]
enabled = true
listen = "127.0.0.1:5300"

[[upstreams]]
name = "AdGuard DoQ (Fast)"
host = "dns.adguard.com"
port = 853
doq = true
quic_0rtt = true  # Enable session resumption for speed

[logging]
level = "info"
```

Use in environments where speed matters more than per-query anonymity.

### Example 4: Privacy-Maximized (0-RTT Disabled, No Query Logging)

```toml
stats_enabled = true

[resolver]
enabled = true
listen = "127.0.0.1:5300"

[[upstreams]]
name = "AdGuard DoQ (Private)"
host = "dns.adguard.com"
port = 853
doq = true
quic_0rtt = false  # Explicit: privacy-first (default)

[cache]
enabled = true
max_size = 4096

[dnssec]
enabled = true
validate_all = true  # Strict DNSSEC validation

[blocklists]
enabled = true
files = ["blocklists/privacy.list"]

[logging]
level = "info"     # Logs startup/stop only (no query details, no upstream state)
```

Use for privacy-conscious deployments. Individual queries are never logged locally (RCVD has
no query-logging facility by design), and startup/stop messages are minimal.

**Note:** If you omit the `[logging]` section entirely, RCVD defaults to `level = "info"` and `format = "text"` anyway. You only need to specify `[logging]` if you want non-default behavior (e.g., `level = "debug"` for upstream state changes or `format = "json"`).

---

## Hybrid Usage: Running Both Modes on One Server

RCVD supports two approaches for running both modes. See [MODE-2.md](MODE-2.md) for a full comparison.

**Option A: Single Process (recommended for home, lab, small team)**
Enable both `[resolver]` and `[upstream_service]` in one config file. Both modes share the same cache, blocklist, and DNSSEC validator. A cache hit from a Mode 1 query is immediately usable by a Mode 2 client. See the Quick Start example at the top of this guide.

**Option B: Two Processes (recommended for production, internet-facing Mode 2)**
Run separate RCVD processes with separate configs for fault isolation and independent restart. A Mode 2 crash does not affect Mode 1 LAN resolution.

### Use Case: Corporate Intranet Router with Public Forwarding

**Scenario:**
- Internal corporate network with DHCP clients (employees, IoT devices)
- Internal clients need to resolve internal corporate domains + public internet domains
- A separate public resolver or upstream server needs to accept encrypted DNS requests from external partners or branch offices
- You want to run one tool (RCVD) that handles both

**Solution: Run RCVD twice (two separate processes)**

**Process 1: Resolver Mode (handles internal client queries)**
```toml
# rcvd-internal-router.toml
[resolver]
enabled = true
listen = "192.0.2.1:53"    # Listen on router's LAN interface

[[upstreams]]
name = "Internal Corporate DNS"
host = "198.51.100.1"            # Internal corporate resolver
port = 853
dot = true

[[upstreams]]
name = "Public Fallback (Quad9)"
host = "dns.quad9.net"
port = 443
doh = true
doh_path = "/dns-query"

[logging]
level = "info"
```

Start with: `rcvd -config rcvd-internal-router.toml`

**Process 2: Upstream Service Mode (exposes encrypted endpoints for external partners)**
```toml
# rcvd-upstream-service.toml
[upstream_service]
enabled = true
listen_dot = "0.0.0.0:853"   # Accept DoT from external networks
listen_doh = "0.0.0.0:8443"  # Accept DoH from external networks
tls_cert = "/etc/rcvd/server.crt"
tls_key = "/etc/rcvd/server.key"

[[upstreams]]
name = "Public Resolver (Cloudflare)"
host = "cloudflare-dns.com"
port = 853
dot = true

[logging]
level = "info"
```

Start with: `rcvd -config rcvd-upstream-service.toml`

**System Architecture:**
```
Internal Clients (192.0.2.0/24)
    |
    v
[RCVD Resolver Mode on 192.0.2.1:53]
    |
    +---> Internal Corporate DNS (198.51.100.1:853 DoT)
    |
    +---> Public Fallback (Quad9 DoH)

External Partners
    |
    v
[RCVD Upstream Service Mode on 0.0.0.0:853/8443]
    |
    +---> Public Resolver (Cloudflare DoT)
```

**Benefits:**
- ✅ Single tool (RCVD) handles both internal and external DNS
- ✅ Separate configuration per process (easy to manage)
- ✅ Each process has independent upstreams and health checks
- ✅ Can restart one mode without affecting the other
- ✅ Scales to support complex network architectures

**Process Management (systemd example):**

```ini
# /etc/systemd/system/rcvd-internal.service
[Unit]
Description=RCVD Resolver Mode (Internal)
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rcvd -config /etc/rcvd/rcvd-internal-router.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/rcvd-upstream.service
[Unit]
Description=RCVD Upstream Service Mode (External)
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rcvd -config /etc/rcvd/rcvd-upstream-service.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Start both: `systemctl start rcvd-internal rcvd-upstream`

### Other Hybrid Scenarios

**Split Role: Resolver + Metrics Endpoint**
- Process 1: Resolver mode (port 5300) handles client queries
- Process 2: Upstream service mode (port 9090 metrics) exposes Prometheus metrics

**High Availability: Primary + Backup**
- Process 1: Primary resolver (port 5300)
- Process 2: Backup resolver (port 5301) for failover

**Load Distribution: Separate Services by Record Type**
- Process 1: Resolver mode for A/AAAA queries
- Process 2: Upstream service mode for MX/NS queries (advanced use case)

**Key Principle:** Each RCVD process is independent. Run as many as needed for your architecture.

---

## No Mandatory Default Configuration

**Important:** RCVD does not provide a mandatory default configuration. Every deployment requires an explicit configuration file.

This design ensures:
- ✅ Users understand their configuration before deploying
- ✅ No accidental misconfigurations (e.g., 0-RTT enabled unintentionally)
- ✅ Admins can evaluate tradeoffs (speed vs. privacy) for their use case
- ✅ No hidden defaults that may not suit all scenarios

**Recommendation:** Start with Example 1 (Simple Resolver) and customize as needed.

---

## Configuration Validation

RCVD validates the configuration file on startup:

1. **Unknown keys**: Any typo or deprecated option is rejected with an error
2. **Mutual exclusion**: At least one mode (resolver or upstream_service) must be enabled
3. **Upstream requirements**: Each upstream must specify at least one protocol (DoQ, DoT, or DoH)

Example error if you typo an option:

```
config error: unknown config keys: [resolver listten]
                                            ^^^^^^ typo detected
```

This fail-fast approach prevents subtle misconfigurations.

---

## Further Reading

- **[MODE-1.md](MODE-1.md)** — Resolver mode: query flow, listen address, typical deployments
- **[MODE-2.md](MODE-2.md)** — Upstream service mode: TLS certs, DoH/DoT/DoQ endpoints, deployment guidance
- **RFC 9250** (DNS-over-QUIC) — `/docs/reference/RFC-9250.txt`
- **RFC 7858** (DNS-over-TLS) — `/docs/reference/RFC-7858.txt`
- **RFC 8484** (DNS-over-HTTPS) — `/docs/reference/RFC-8484.txt`
- **RFC 4033, 4034, 4035** (DNSSEC) — `/docs/reference/RFC-40*.txt`

---

## Questions or Issues?

If your configuration fails validation, check:
1. TOML syntax (mismatched `[[` brackets, missing quotes, etc.)
2. Unknown config keys (typos in option names)
3. At least one upstream with DoQ, DoT, or DoH enabled
4. At least one mode (resolver or upstream_service) enabled

Run with: `rcvd -config your-config.toml` to see detailed error messages.
