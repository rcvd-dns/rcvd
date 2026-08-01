# RCVD Features

- [TOML Config File](#toml-config-file)
- [Mode 1 — Encrypting Forwarder](#mode-1)
- [Mode 2 — Encrypted DNS Server](#mode-2)
- [Blocklist](#blocklist)
- [Cache](#cache)
- [Statistics](#statistics)
- [DNSSEC](#dnssec)
- [Verify Upstream](#verify-upstream)
- [Multiple Instances](#multiple-instances-wireguard-style-config-model)


RCVD is a powerful, modern _DNS Engine_, it's important to understand the top-level features.

# Top Level Features

## TOML Config File

Configuration is a single TOML file. Human readable and writable by hand. Fully self-contained. No database, no web UI required. Simple to read, simple to diff, simple to version control. Use more than one config file for different scenarios. Change or deploy as your needs change.

## MODE-1
Mode 1 is the RCVD **encrypting forwarder** role.  
Localhost or Trusted LAN DNS clients send standard DNS queries to RCVD; RCVD encrypts and forwards them to an upstream resolver using DoQ, DoT, or DoH. No plaintext DNS ever reaches the Internet.

## MODE-2
Mode 2 turns RCVD into an **encrypted DNS server**.  
It listens for DoQ, DoT, or DoH connections from localhost, trusted LAN clients, or the public internet, and forwards queries to upstream resolvers - all traffic encrypted end to end.  
RCVD handles TLS certificates automatically, with no external reverse proxy required.


## Blocklist

The blocklist loads asynchronously - DNS is available immediately on startup.  
blocklist loading happens in the background on a separate goroutine, regardless of media speed, file size, or how many block files you need to load.

Blocked domains return NXDOMAIN  

The blocklist check runs **before** the cache — a blocked query never touches the cache, so cache hit/miss counters remain accurate and are never inflated by blocked traffic.

Blocked queries are counted separately in statistics (`blocked_queries`), giving operators a clean picture of both filtered and resolved traffic.

Blocklist status is logged at both ends — operators can follow progress in the log without grepping:

```
main.go:141: blocklist: loading 1 source(s) in background — queries resolve normally during load
main.go:239: blocklist: loaded /etc/rcvd/domainswild
```

The `Blocklist` section in `rcvd --stats` only appears after loading completes. Its presence is confirmation that filtering is active.

Validated on Alpine aarch64 (SD-card storage) with a 328K-entry blocklist (~60s load time from slow media).

## Cache

In-memory DNS response cache with TTL-aware eviction. Configurable size (default 4096 entries). The cache sits between the blocklist and the upstream resolver — only queries that pass the blocklist check are eligible for caching.

Cache hits and misses are tracked separately in statistics, with no false counts from blocked queries.

## Statistics

RCVD exposes built-in DNS query statistics via a Unix socket, readable with `rcvd --stats`. No external metrics infrastructure required.

Counters include: total queries, cache hits/misses, blocked queries, how many blocklist files loaded, per-protocol breakdowns (DoQ/DoT/DoH), DNSSEC validation results, upstream latency (min/avg/max), and uptime.

> The query pipeline order — blocklist → cache → upstream — ensures each counter reflects only what it should: blocked queries never inflate cache stats, and cache hits never inflate upstream query counts.

> Statistics are privacy-safe by design - aggregates only, no per-client IP tracking, no query content stored.

Validated in real-world development environments with live traffic:  
- Linux Mint amd64
- Alpine Linux (MUSL-C) arm64. 

- Accuracy confirmed through extended real-world testing against live DNS traffic.

## Verify Upstream

`rcvd --verify-upstream` probes every configured upstream and displays the full TLS certificate chain — no running instance needed. For each upstream it shows: subject, issuer, SANs, validity dates, key type, and SHA256 fingerprint.

Three assertions are printed per upstream: chain validity, hostname match, and days until expiry. Exit code 0 means all upstreams pass; exit code 1 means at least one failed.

This makes the cryptographic trust chain human-readable and inspectable — consistent with RCVD's "Verifiable" design principle. Admins can confirm exactly which certificates stand between their DNS queries and the upstream resolver, before trusting it with live traffic.


# Secondary Features

## Multiple Instances (WireGuard-Style Config Model)

Multiple RCVD instances can run simultaneously on the same bare-metal machine, virtual machine, or container, each pointed at a different config file. Each instance binds its own listen address, maintains its own cache, and exposes its own Unix socket with independent statistics.

```
# host-01
rcvd --config /etc/rcvd/rcvd-home.toml
rcvd --config /etc/rcvd/rcvd-work.toml
```

This follows the WireGuard model: one binary, behavior entirely defined by the config file. Useful for advanced deployment scenarios such as serving different upstream resolvers or blocklists to different network interfaces or VLANs from a single host.