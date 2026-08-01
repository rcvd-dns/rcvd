# DNS Protocol & Port Mapping

Clear reference for DNS encryption protocols and their standard ports.

## Quick Reference Table

| Protocol | RFC | Transport | Well-Known Port | Default | Notes |
|----------|-----|-----------|-----------------|---------|-------|
| **DoQ** | 9250 | UDP (QUIC) | **853** | 853 | MUST use 853 unless mutual agreement |
| **DoT** | 7858 | TCP (TLS) | **853** | 853 | MUST use 853 unless mutual agreement |
| **DoH** | 8484 | TCP (HTTP/2) | **443** | 443 | HTTPS, shares port with web traffic |
| **DNS** | 1035 | UDP | 53 | 53 | Cleartext, no encryption |
| **DNS-TCP** | 1035 | TCP | 53 | 53 | Cleartext, no encryption |

---

## Detailed Explanation

### DoQ (DNS-over-QUIC) — RFC 9250

**Well-known port:** UDP **853**

**RFC 9250 Section 4.1.1 — Port Selection:**

> By default, a DNS server that supports DoQ MUST listen for and accept QUIC connections on the dedicated UDP port 853 (Section 8), unless there is a mutual agreement to use another port.
>
> By default, a DNS client desiring to use DoQ with a particular server MUST establish a QUIC connection to UDP port 853 on the server, unless there is a mutual agreement to use another port.
>
> DoQ connections MUST NOT use UDP port 53. This recommendation against use of port 53 for DoQ is to avoid confusion between DoQ and the use of DNS over UDP [RFC1035].

**Key Points:**
- ✅ **Port 853 is mandatory** by default
- ✅ **UDP protocol** (QUIC runs over UDP)
- ✅ **MUST NOT use port 53** (explicitly forbidden in RFC)
- ✅ Alternative ports allowed only with **mutual agreement**
- ✅ Port 443 mentioned as **operationally beneficial** alternative (less likely to be blocked)

**Example:**
```bash
# Correct DoQ connection
q example.com @quic://dns.adguard.com:853

# WRONG - RFC forbids this
q example.com @quic://dns.adguard.com:53  # ❌ NOT ALLOWED
```

---

### DoT (DNS-over-TLS) — RFC 7858

**Well-known port:** TCP **853**

**RFC 7858 Section 3.1 — Port Selection:**

> By default, a DNS server that supports DNS over TLS MUST listen for and accept TCP connections on port 853, unless it has mutual agreement with its clients to use a port other than 853 for DNS over TLS.
>
> A DNS client desiring to use DNS over TLS with a particular server MUST establish a TCP connection to port 853 on the server, unless it has mutual agreement with its server to use a port other than 853.

**Key Points:**
- ✅ **Port 853 is mandatory** by default
- ✅ **TCP protocol** (TLS runs over TCP)
- ✅ Same port as DoQ (853), different transport (TCP vs UDP)
- ✅ Alternative ports allowed only with **mutual agreement**
- ✅ Port 443 can be used as alternative (mutual agreement)

**Example:**
```bash
# Correct DoT connection
q example.com @tls://dns.adguard.com:853

# Also valid with mutual agreement
q example.com @tls://dns.adguard.com:443
```

---

### DoH (DNS-over-HTTPS) — RFC 8484

**Well-known port:** TCP **443** (HTTPS)

**RFC 8484 Section 3.1 — Service Discovery:**

> HTTPS clients that wish to use DoH with a specific server SHOULD resolve the DNS name in the URI using their preferred DNS resolver.
>
> A default URI template might be:
> ```
> https://dnsserver.example.net/dns-query
> ```

**Key Points:**
- ✅ **Port 443 is standard** (HTTPS default)
- ✅ **TCP protocol** (HTTP/2 runs over TLS/TCP)
- ✅ Shares port with regular HTTPS web traffic
- ✅ Uses HTTP POST method
- ✅ Endpoint path: typically `/dns-query` (configurable)

**Example:**
```bash
# Correct DoH connection
q example.com @https://dns.adguard.com:443/dns-query

# Note: port 443 is implied for HTTPS
q example.com @https://dns.adguard.com/dns-query
```

---

## Why Are DoQ and DoT Both on Port 853?

**Port 853 is shared** because:

1. **Same use case:** Both are encrypted DNS protocols
2. **Different transport:**
   - DoQ = QUIC (UDP-based, multiplexed, low-latency)
   - DoT = TLS (TCP-based, traditional)
3. **Server detection:**
   - Try **UDP port 853** first (DoQ)
   - If unavailable, try **TCP port 853** (DoT)
   - If neither works, fall back to **HTTPS (port 443)**

This is the **fallback priority** in RFC 9250 §5.2:
```
DoQ (UDP 853) → DoT (TCP 853) → DoH (HTTPS 443)
```

---

## RCVD Test Configuration Ports

Our test setup uses:

| Test | Protocol | Upstream | Upstream Port | RCVD Listen Port | Why |
|------|----------|----------|---------------|------------------|-----|
| Phase 1 | DoQ | dns.adguard.com | **853** (UDP) | 127.0.0.1:**5354** | Standard RFC 9250 |
| Phase 2 DoT | DoT | dns.adguard.com | **853** (TCP) | 127.0.0.1:**5355** | Standard RFC 7858 |
| Phase 2 DoH | DoH | dns.adguard.com | **443** (HTTPS) | 127.0.0.1:**5355** | Standard RFC 8484 |

**Why different RCVD listen ports (5354, 5355)?**
- Testing isolation (avoid port conflicts between tests)
- Not production addresses (testing only)
- Production RCVD would listen on 127.0.0.1:**5300** or 0.0.0.0:**53**

---

## Port Usage Summary

### Inbound (Server → Listening for clients)

```
Port 853 UDP ← DoQ clients
Port 853 TCP ← DoT clients
Port 443 TCP ← DoH clients (HTTPS)
```

### Outbound (RCVD → Upstream resolvers)

```
RCVD → 853 UDP → AdGuard (DoQ query)
RCVD → 853 TCP → AdGuard (DoT query)
RCVD → 443 TCP → AdGuard (DoH query)
```

---

## RFC Citations

**RFC 9250 (DoQ):**
- Section 4.1.1: Port selection mandatory for port 853
- Section 8.2: Reservation of dedicated port 853

**RFC 7858 (DoT):**
- Section 3.1: Port 853 for DNS over TLS
- Section 3.2: Connection and query/response handling

**RFC 8484 (DoH):**
- Section 3: HTTPS and URI format
- Section 4.1: DoH requests and responses

---

## Bottom Line

| Question | Answer |
|----------|--------|
| **What port for DoQ?** | **UDP 853** (RFC 9250 mandatory) |
| **What port for DoT?** | **TCP 853** (RFC 7858 mandatory) |
| **What port for DoH?** | **TCP 443 HTTPS** (RFC 8484 standard) |
| **Can they share port 853?** | Yes! DoQ = UDP, DoT = TCP (different transports) |
| **Can I use different ports?** | Only with **mutual agreement** between client and server |
| **Why test on 5354/5355?** | Testing isolation (non-production addresses) |

---

## Real-World Examples

**Query AdGuard DNS via DoQ:**
```bash
# Port 853 UDP - QUIC
q example.com @quic://dns.adguard.com:853
```

**Query AdGuard DNS via DoT:**
```bash
# Port 853 TCP - TLS
q example.com @tls://dns.adguard.com:853
```

**Query AdGuard DNS via DoH:**
```bash
# Port 443 HTTPS - HTTP/2 POST
q example.com @https://dns.adguard.com:443/dns-query
```

All three protocols, one upstream server, different ports/transports.
