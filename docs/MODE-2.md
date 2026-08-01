# RCVD — Mode 2: Upstream Service

## What is Mode 2?

Mode 2 is RCVD's **encrypted DNS endpoint** role. RCVD listens for encrypted DNS queries
from clients using DoH, DoT, or DoQ, and forwards them to an upstream resolver using the
same encrypted protocols. Both the inbound connection from the client and the outbound
connection to the upstream are encrypted.

In Mode 2, RCVD **is the upstream** — the server that other DNS tools, browsers, operating
systems, or resolvers point to. Clients must be configured to use DoH/DoT/DoQ explicitly.

This enables use cases such as:
- A public or private encrypted DNS server for your organization or team
- A DoH endpoint for Firefox, Chrome, or other browsers via custom DoH URL
- An encrypted DNS upstream for Unbound, Technitium, AdGuard Home, or similar tools
- A Tailscale-private DNS server with full encryption end-to-end

Mode 2 uses the same DNS Engine as Mode 1. Only the client-facing protocol differs.

---

## Listen Addresses

```toml
[upstream_service]
enabled = true
listen_doh = "0.0.0.0:8443"   # HTTPS/TCP  (non-standard port, avoids privilege requirement)
listen_dot = "0.0.0.0:853"    # TLS/TCP    (standard DoT port, requires CAP_NET_BIND_SERVICE)
listen_doq = "0.0.0.0:853"    # QUIC/UDP   (standard DoQ port, requires CAP_NET_BIND_SERVICE)
```

### Port 853: DoT and DoQ can share the same port number

DoT and DoQ both default to port 853 — this is not a conflict. They use **different
transport protocols** and bind to completely independent OS sockets:

| Listener | Port | Transport | OS Socket Type |
|----------|------|-----------|----------------|
| DoH | 8443 | TCP | `SOCK_STREAM` |
| DoT | 853 | **TCP** | `SOCK_STREAM` |
| DoQ | 853 | **UDP** | `SOCK_DGRAM` (QUIC over UDP) |

The kernel routes traffic by `(transport, port)` pair — `853/TCP` goes to the DoT
listener, `853/UDP` goes to the DoQ listener. A client connecting TCP to port 853 gets
DoT; a client sending QUIC/UDP to port 853 gets DoQ.

This is intentional per the RFCs: RFC 7858 specifies DoT on TCP port 853, RFC 9250
specifies DoQ on UDP port 853.

### Privilege note

Ports below 1024 require `CAP_NET_BIND_SERVICE` on Linux. DoH defaults to port 8443
(non-privileged) to allow running without special capabilities. Use the OpenRC init
script or systemd service file (which sets `AmbientCapabilities=CAP_NET_BIND_SERVICE`)
to bind port 443 or 853 if needed.

Each listener is configured independently. You can enable only the protocols you need:

```toml
# DoH only (no privilege needed)
listen_doh = "0.0.0.0:8443"

# DoT + DoQ only (standard ports, both on 853 — TCP and UDP respectively)
listen_dot = "0.0.0.0:853"
listen_doq = "0.0.0.0:853"

# DoH on standard port 443 (requires CAP_NET_BIND_SERVICE)
listen_doh = "0.0.0.0:443"
```

---

## Inbound Protocol

Clients connect to RCVD Mode 2 using encrypted DNS protocols:

| Protocol | RFC | Transport | Format |
|----------|-----|-----------|--------|
| DoH — DNS-over-HTTPS | RFC 8484 | HTTP/2 POST | `POST /dns-query`, body = DNS wire format, `Content-Type: application/dns-message` |
| DoT — DNS-over-TLS | RFC 7858 | TLS/TCP | TLS handshake, then 2-byte length prefix + DNS wire format |
| DoQ — DNS-over-QUIC | RFC 9250 | QUIC/UDP | Per-stream, 2-byte length prefix + DNS wire format |

**RCVD never accepts plain DNS in Mode 2.** All client connections are encrypted.

---

## Query Flow

Every incoming encrypted query passes through the same DNS Engine as Mode 1:

```
Client (DoH / DoT / DoQ — encrypted)
    │
    ▼
1. Decrypt and parse DNS message
    │  DoH: extract from HTTP POST body
    │  DoT: read TLS stream, strip 2-byte length prefix
    │  DoQ: read QUIC stream, strip 2-byte length prefix
    │
    ▼
2. Blocklist check
    ├── Blocked? → Return NXDOMAIN (encrypted response back to client)
    └── Not blocked? → Continue
    │
    ▼
3. Cache lookup
    ├── Hit? → Return cached response (encrypted, no upstream query)
    └── Miss? → Continue
    │
    ▼
4. Resolve via upstream
    │  Protocol priority: DoQ → DoT → DoH
    │  Health state machine: Phase 1 aggressive (startup) → Phase 2 gentle (runtime)
    ├── All upstreams failed? → Return SERVFAIL (encrypted, never cleartext fallback)
    └── Success? → Continue
    │
    ▼
5. DNSSEC validation (if enabled)
    ├── Validation failed? → Return SERVFAIL (encrypted)
    └── Validation passed? → Set AD flag (RFC 4035 §3.2.3), continue
    │
    ▼
6. Cache response (TTL-aware, in-memory)
    │
    ▼
7. Return encrypted response to client
    │  DoH: HTTP 200 OK, body = DNS wire format
    │  DoT: TLS stream, 2-byte length prefix + DNS wire format
    │  DoQ: QUIC stream, 2-byte length prefix + DNS wire format
```

**Both the inbound and outbound connections are encrypted.**
No cleartext DNS at any point in the chain.

---

## Outbound Protocol

Identical to Mode 1 — RCVD uses the same resolver and fallback chain:

| Protocol | RFC | Transport | Default Port |
|----------|-----|-----------|-------------|
| DoQ — DNS-over-QUIC | RFC 9250 | QUIC/UDP | 853 |
| DoT — DNS-over-TLS | RFC 7858 | TLS/TCP | 853 |
| DoH — DNS-over-HTTPS | RFC 8484 | HTTPS/TCP | 443 |

**Priority order: DoQ → DoT → DoH.** Never port 53 cleartext.

---

## TLS Certificates

**Required.** Mode 2 must present a valid TLS certificate to clients for DoH, DoT, and DoQ.

RCVD supports three certificate options (applied in priority order):

### 1. Automated — Let's Encrypt via certmagic (Production Recommended)

```toml
[upstream_service]
tls_automation = true

[tls_automation]
on_demand = true
allowed_domains = ["dns.example.com"]
email = "admin@example.com"
storage_dir = "/var/lib/rcvd/certs"
staging = false   # true = Let's Encrypt staging (for testing)
```

- Certificates fetched automatically during TLS handshake (on-demand)
- Auto-renewed before expiry
- 3–5s latency on the first connection to a new domain, instant thereafter
- No pre-configuration of domain required before starting RCVD
- **Requires a publicly reachable server with a real domain name**

### 2. Provided Certificate Files (Production)

```toml
[upstream_service]
tls_cert = "/etc/rcvd/tls/cert.pem"
tls_key  = "/etc/rcvd/tls/key.pem"
```

- Bring your own certificate (Let's Encrypt, enterprise CA, Cloudflare CA, etc.)
- Must be a valid X.509 certificate with DNS-ID in SubjectAltName (RFC 5280, RFC 6125)
- Required for RFC 8310 Strict Privacy Profile compliance
- Suitable for corporate/private deployments where cert issuance is managed externally

### 3. Auto-generated Self-Signed (Testing Only)

```toml
[upstream_service]
tls_cert_autogen = true
```

- Generates a 2048-bit RSA certificate at startup (CN=localhost, SAN=127.0.0.1)
- Valid for 365 days
- **NOT suitable for production** — violates RFC 8310 Strict Privacy Profile
- Rejected by browsers, `curl`, `dig +tls`, `dnsprobe`, and other compliant clients
- Use only for local development and testing with `--insecure` flags

---

## DNS Engine Components (Shared with Mode 1)

Mode 2 uses the same engine instances as Mode 1. When both modes run simultaneously,
they share:

| Component | Purpose |
|-----------|---------|
| **Resolver** | Fallback chain: DoQ → DoT → DoH to upstream public resolvers |
| **Cache** | In-memory TTL-aware response cache (cleared on restart) |
| **Blocklist** | Domain suppression (plain list + hosts file formats, wildcard support) |
| **DNSSEC Validator** | Signature verification (permissive or strict mode) |
| **Statistics** | Atomic counters: queries, cache hits/misses, latency, per-protocol, DNSSEC |

A cache hit from a Mode 1 query is immediately available to a Mode 2 query for the same
domain, and vice versa.

---

## Configuration

```toml
stats_enabled = true

[upstream_service]
enabled = true
listen_doh = "0.0.0.0:8443"
listen_dot = "0.0.0.0:853"
listen_doq = "0.0.0.0:853"
tls_cert_autogen = true   # testing; use tls_automation = true for production

[[upstreams]]
name = "AdGuard"
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

See `repos/rcvd/etc/rcvd-upstream.toml` for the full production example.
See `repos/rcvd/docs/STANDALONE-DOH-DEPLOYMENT.md` for deployment patterns.

---

## Statistics

When `stats_enabled = true`, query `rcvd --stats -config <path>` to see:

```
Protocol Breakdown (Outbound)
  DoQ Queries:                 1,204    ← queries rcvd sent to upstream via DoQ
  DoT Queries:                 0
  DoH Queries:                 0

Protocol Breakdown (Inbound, Mode 2)
  DoQ Served:                  843      ← clients connected to rcvd via DoQ
  DoT Served:                  291      ← clients connected to rcvd via DoT
  DoH Served:                  70       ← clients connected to rcvd via DoH
```

The "Inbound, Mode 2" section only appears when at least one `*Served` counter is non-zero.
In Mode 1 only deployments, this section is omitted from the output.

---

## Typical Deployments

**Public encrypted DNS server (VPS with domain):**
```
tls_automation = true          # certmagic handles Let's Encrypt
listen_doh = "0.0.0.0:443"    # standard HTTPS port (requires privilege)
listen_dot = "0.0.0.0:853"
listen_doq = "0.0.0.0:853"
```
Users configure `https://dns.example.com/dns-query` as their DoH resolver.

**Firefox custom DoH endpoint:**
```
listen_doh = "127.0.0.1:8443"
tls_cert_autogen = true
```
Firefox Settings → Privacy & Security → DNS over HTTPS → Custom:
`https://127.0.0.1:8443/dns-query`

**Tailscale private resolver (team or home lab):**
RCVD runs on a Tailscale node. Tailscale provides the encryption tunnel; RCVD provides
the DNS engine. Other nodes set their DNS to the Tailscale IP of the RCVD host.

**Corporate DoT/DoQ upstream for Unbound or AdGuard Home:**
```
listen_dot = "198.51.100.10:853"
listen_doq = "198.51.100.10:853"
tls_cert = "/etc/rcvd/tls/corp-cert.pem"
tls_key  = "/etc/rcvd/tls/corp-key.pem"
```
Unbound or AdGuard Home configured to forward to `198.51.100.10@853` with TLS validation.

---

## Relationship to Mode 1

Mode 1 and Mode 2 can run simultaneously in the same RCVD process, sharing the same DNS
Engine. See [MODE-1.md](MODE-1.md) for the plain DNS resolver role.

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
- Certificate renewal failure (certmagic) could trigger errors that affect the whole process.

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
