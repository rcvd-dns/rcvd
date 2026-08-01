# RCVD — Mode 1: Resolver

## What is Mode 1?

Mode 1 is RCVD's **local DNS resolver** role. RCVD listens for standard plain DNS queries
from clients on your local machine or network, and forwards every query to an upstream server
using an encrypted protocol (DoQ, DoT, or DoH). Clients need no special software or
configuration — they talk plain DNS to RCVD exactly as they would to any DNS resolver.

This is the **"last mile encryption"** model: the cleartext hop exists only on the local
loopback or LAN interface, never on the public internet. All traffic leaving the machine
toward an upstream resolver is encrypted.

Mode 1 is the foundation of RCVD's DNS Engine. Mode 2 builds on top of it.

---

## Listen Address

```toml
[resolver]
enabled = true
listen = "127.0.0.1:5300"   # default: loopback, non-privileged port
```

- Both **UDP and TCP** listen on the same address
- Configurable to any address: `192.0.2.1:5354` for a LAN router, `0.0.0.0:53` with `CAP_NET_BIND_SERVICE` for port 53
- Default port `5300` coexists with systemd-resolved (port 53)
- Router deployments typically use `192.0.2.1:5354` (LAN IP, RCVD-specific port)

---

## Inbound Protocol

Clients speak **plain DNS** to RCVD in Mode 1:

| Transport | Format | Notes |
|-----------|--------|-------|
| UDP | RFC 1035 DNS wire format | Standard, max 512 bytes |
| TCP | RFC 1035 with 2-byte length prefix | Used for large responses, AXFR, explicit TCP |

This is intentional. Clients — `dig`, `nslookup` , `systemd-resolved`, browsers, operating system resolvers — all speak plain DNS natively. No client-side changes are required.

---

## Query Flow

Every incoming query passes through the DNS Engine in this order:

```
Client (plain DNS, UDP or TCP)
    │
    ▼
1. Parse DNS message
    │
    ▼
2. Blocklist check
    ├── Blocked? → Return NXDOMAIN (domain suppressed)
    └── Not blocked? → Continue
    │
    ▼
3. Cache lookup
    ├── Hit? → Return cached response immediately (no upstream query)
    └── Miss? → Continue
    │
    ▼
4. Resolve via upstream
    │  Protocol priority: DoQ → DoT → DoH
    │  Health state machine: Phase 1 aggressive (startup) → Phase 2 gentle (runtime)
    ├── All upstreams failed? → Return SERVFAIL (never cleartext fallback)
    └── Success? → Continue
    │
    ▼
5. DNSSEC validation (if enabled)
    ├── Validation failed? → Return SERVFAIL, discard response
    └── Validation passed? → Set AD flag (RFC 4035 §3.2.3), continue
    │
    ▼
6. Cache response (TTL-aware, in-memory)
    │
    ▼
7. Return response to client (plain DNS, same transport as query)
```

**No cleartext DNS ever leaves the machine toward an upstream resolver.**
If all encrypted upstreams fail, RCVD returns SERVFAIL — it does not fall back to port 53.

---

## Outbound Protocol

RCVD connects to upstream resolvers using encrypted protocols only:

| Protocol | RFC | Transport | Default Port |
|----------|-----|-----------|-------------|
| DoQ — DNS-over-QUIC | RFC 9250 | QUIC/UDP | 853 |
| DoT — DNS-over-TLS | RFC 7858 | TLS/TCP | 853 |
| DoH — DNS-over-HTTPS | RFC 8484 | HTTPS/TCP | 443 |

**Priority order: DoQ → DoT → DoH**

DoQ is preferred (lower latency, no head-of-line blocking). DoH is the last resort
(port 443 escape hatch through restrictive firewalls — not the preferred protocol).

Multiple upstreams can be configured. The fallback state machine tracks health per upstream
and skips DOWN upstreams automatically, recovering them via periodic health checks.

---

## TLS Certificates

**None required.** Mode 1 accepts plain DNS inbound — no TLS on the client-facing side.

TLS is used only on the **outbound** connections to upstream resolvers, and those certs
are validated against the upstream server's public certificate (e.g., AdGuard, Quad9,
Cloudflare) — no local cert management needed.

---

## DNS Engine Components (Shared with Mode 2)

Mode 1 uses all engine components. These are the same instances shared with Mode 2
when both modes run simultaneously:

| Component | Purpose |
|-----------|---------|
| **Resolver** | Fallback chain: DoQ → DoT → DoH to upstream public resolvers |
| **Cache** | In-memory TTL-aware response cache (cleared on restart) |
| **Blocklist** | Domain suppression (plain list + hosts file formats, wildcard support) |
| **DNSSEC Validator** | Signature verification (permissive or strict mode) |
| **Statistics** | Atomic counters: queries, cache hits/misses, latency, per-protocol, DNSSEC |

---

## Configuration

```toml
stats_enabled = true

[resolver]
enabled = true
listen = "127.0.0.1:5300"

[[upstreams]]
name = "AdGuard"
host = "dns.adguard.com"
port = 853
doq = true

[[upstreams]]
name = "Cloudflare DoT"
host = "cloudflare-dns.com"
port = 853
dot = true

[cache]
enabled = true
max_size = 4096

[dnssec]
enabled = true

[logging]
level = "info"
format = "text"
```

See `repos/rcvd/etc/rcvd-resolver.toml` for the full production example.

---

## Statistics

When `stats_enabled = true`, query `rcvd --stats -config <path>` to see:

```
Protocol Breakdown (Outbound)
  DoQ Queries:                 1,204    ← queries rcvd sent to upstream via DoQ
  DoT Queries:                 12       ← queries via DoT (fallback)
  DoH Queries:                 3        ← queries via DoH (last resort fallback)
```

"Outbound" always means **rcvd → upstream server**. These counters reflect which
encrypted protocol was used to reach the upstream resolver for each query.

In Mode 1 only, the "Protocol Breakdown (Inbound, Mode 2)" section is omitted from
the stats output (all served counters are zero).

---

## Typical Deployments

**Workstation (personal machine):**
```
listen = "127.0.0.1:5300"
```
Point systemd-resolved, `/etc/resolv.conf`, or application DNS to `127.0.0.1:5300`.

**Router (LAN DNS server):**
```
listen = "192.0.2.1:5354"   # LAN IP, RCVD port
```
DHCP hands out `192.0.2.1` as the DNS server. nftables permits port 5354 on LAN interfaces.
All LAN clients resolve through RCVD automatically — zero per-client configuration.

**systemd-resolved stub:**
Configure `/etc/systemd/resolved.conf` with `DNS=127.0.0.1:5300` and `DNSStubListener=no`.
RCVD handles all resolution; systemd-resolved provides the `/etc/resolv.conf` stub.

---

## Relationship to Mode 2

Mode 1 and Mode 2 can run simultaneously in the same RCVD process, sharing the same DNS
Engine. See [MODE-2.md](MODE-2.md) for the encrypted endpoint role.

The key difference:

| | Mode 1 | Mode 2 |
|-|--------|--------|
| **Inbound from client** | Plain DNS (UDP/TCP) | Encrypted DNS (DoH/DoT/DoQ) |
| **Outbound to upstream** | Encrypted (DoQ/DoT/DoH) | Encrypted (DoQ/DoT/DoH) |
| **TLS cert required** | No | Yes |
| **Client config needed** | No (plain DNS) | Yes (DoH URL or DoT/DoQ server) |

---

## Deployment Guidance: Single Process vs. Two Processes

RCVD can run Mode 1 and Mode 2 simultaneously in a single process. This is the default and
works well for many deployments. However, splitting them into two separate processes is the
production recommendation when Mode 2 is internet-facing.

### Single Process (Both Modes) — Good For: Home, Lab, Small Team

**Advantages:**
- **Shared cache** — a domain resolved by a Mode 1 LAN client is immediately available to
  a Mode 2 DoH client, and vice versa. This is a real, measurable benefit: double the cache
  effectiveness, half the upstream queries, lower latency for everyone.
- One binary, one config file, one PID, one `rcvd --stats` call shows the full picture
- Shared blocklist and DNSSEC validator — single source of truth, lower memory
- Simple to deploy and monitor

**Risks:**
- A crash in one mode takes down the other. If Mode 2 DoQ hits a quic-go edge case and
  panics, Mode 1 LAN clients lose DNS.
- Resource contention — a flood of Mode 2 clients competes for upstream connections with
  Mode 1 local queries. Your own DNS resolution could slow down.

### Two Processes (Separate Modes) — Good For: Production, Internet-Facing

**Advantages:**
- **Fault isolation** — Mode 2 crash does not affect Mode 1 LAN resolution
- **Security boundary** — Mode 2 is internet-facing (higher attack surface), Mode 1 is
  LAN-only. A compromise of the Mode 2 process does not automatically compromise LAN DNS.
- Independent restarts — update Mode 2 TLS certs without touching Mode 1
- Independent resource limits — `cgroup` or `ulimit` per process
- Cleaner logs — each process logs only its own traffic

**Cost:**
- No shared cache — each process maintains its own, upstream queries may be duplicated
- Two config files, two services, two stats sockets to query
- Slightly more memory (two blocklists, two resolver pools)

### Recommendation

| Deployment | Recommendation |
|------------|----------------|
| Home router, personal workstation | Single process — shared cache benefit is real, risk is low |
| Small team, home lab, Tailscale | Single process — simplicity wins |
| Public DoH endpoint on a VPS | Two processes — fault isolation and security boundary matter |
| Corporate DoT/DoQ upstream | Two processes — independent scaling and restart |
| Mixed: LAN resolver + public DoH | Two processes — different trust boundaries |

This is the same pattern Caddy and nginx follow: you *can* serve everything from one process,
but production deployments often split by trust boundary.
