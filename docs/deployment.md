# RCVD Deployment Notes

Operational tuning notes for deploying RCVD on Linux hosts. This document
focuses on the kernel-level settings that affect DNS-over-QUIC (DoQ)
performance, with separate guidance for workstations and servers.

## UDP Receive Buffer (`net.core.rmem_max`)

> **TL;DR:** The upstream quic-go library assumes deployment on a server, so
> you may see warnings about UDP receive buffer size (`net.core.rmem_max`) on
> a normal workstation. These are cosmetic on a workstation — safe to ignore.
> On servers under real load, tune the buffer (see below).

### The Warning

When RCVD starts on Linux, you may see a quic-go warning in the logs:

```
failed to sufficiently increase receive buffer size
(was: 208 kiB, wanted: 7168 kiB, got: 416 kiB).
See https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes for details.
```

### What It Means

QUIC runs over UDP. The kernel buffers incoming UDP packets between when
they arrive on the wire and when the application (RCVD) reads them. If the
buffer is too small and packets arrive in a burst — which is normal for
QUIC's congestion control — the kernel drops packets, forcing QUIC to
retransmit and degrading performance.

quic-go requests **7168 KiB (7 MiB)** for receive and send buffers. Linux
caps the request at `net.core.rmem_max` / `net.core.wmem_max`. On most
default installs these are set well below 7 MiB, so the warning fires.

The warning is **non-fatal**. RCVD will still work, just less efficiently
under load.

### When To Care

| Scenario                                                            | Action             |
|---------------------------------------------------------------------|--------------------|
| Single-user workstation, light DNS load                             | Ignore             |
| Developer workstation, occasional testing                           | Ignore             |
| Shared workstation (e.g. multi-user dev machine)                    | Tune if convenient |
| LAN / office / home / cloud lab server or router (multiple clients) | Tune               |
| Production server / router, many concurrent clients                 | **Tune**           |

The threshold where this matters is roughly **hundreds of queries per
second sustained** or **bursty traffic patterns** with many concurrent
upstreams. A workstation issuing a handful of queries per minute will
never notice.

## Workstation Considerations

On a developer workstation or single-user desktop:

- The warning is cosmetic. You can safely ignore it.
- Default `net.core.rmem_max` on most distros ranges from 208 KiB to 7 MiB,
  with 208 KiB being the most common default (Debian, Ubuntu, Alpine).
  This is fine for typical workstation DNS query rates (1–10 qps).
- If you find the warning noisy in logs, you can tune the values, but
  this is a preference, not a requirement.

### Optional: Silence the Warning on a Workstation

If you want to raise the limits and silence the warning:

```bash
sudo sysctl -w net.core.rmem_max=7340032
sudo sysctl -w net.core.wmem_max=7340032
```

This applies until reboot. For persistence across reboots, use the
`/etc/sysctl.d/` drop-in approach shown in the **Server Considerations**
section below.

## Server Considerations

On a server resolving DNS for multiple downstream clients, the receive
buffer matters. Insufficient buffer space causes UDP drops under load,
which translates to:

- Increased query latency (retransmissions)
- Wasted CPU on the upstream resolver re-sending data
- Reduced throughput ceiling

### Recommended Server Tuning

Apply the following sysctl values. The 7 MiB max matches quic-go's request,
and the 2 MiB default gives most UDP sockets enough headroom out of the box:

```bash
# /etc/sysctl.d/99-rcvd.conf
net.core.rmem_max=7340032
net.core.wmem_max=7340032
net.core.rmem_default=2097152
net.core.wmem_default=2097152
```

Apply without reboot:

```bash
sudo sysctl --system
```

Verify:

```bash
sysctl net.core.rmem_max net.core.wmem_max
```

### Higher-Throughput Servers

For resolvers handling sustained high query rates (e.g. an org-wide
resolver, public service, or aggregator), consider going larger:

```bash
# /etc/sysctl.d/99-rcvd.conf
net.core.rmem_max=16777216
net.core.wmem_max=16777216
```

quic-go will use up to its requested 7 MiB; the additional headroom
protects against other UDP-heavy workloads on the same host.

## Laptop (Sleep/Wake) vs. Always-On Deployments

RCVD runs on both always-on hosts (dedicated routers, servers) and laptops
that suspend and resume frequently. Both are fully supported, but the
sleep/wake cycle on a roaming workstation produces a few cosmetic effects
worth knowing about.

### Always-On Router / Server

- No sleep/wake cycles — the network stack stays clean.
- Uptime tracking is reliable.
- No spurious parse errors from stale kernel network buffers.
- The intended shape for production DNS infrastructure (ISP, enterprise,
  home-router deployments).

### Laptop / Roaming Workstation

- Excellent for privacy-first roaming (hotel WiFi, coffee shops, airports) —
  encrypted upstreams mean the local network never sees cleartext DNS.
- After a resume, you may see harmless `parse query error` entries in the log:
  these come from UDP buffer residue left in the kernel across the suspend,
  not from a real query failure.
- The uptime statistic can read inaccurately across suspend/resume cycles.
- When interfaces go down and back up, DNS may be briefly unavailable during
  the network state transition.
- Queries are handled gracefully throughout — these conditions are logged but
  not blocking, and there is no cleartext fallback.

**Recommended mitigation:** run RCVD under a service manager with automatic
restart — e.g. a systemd unit with `Restart=on-failure` — so it recovers
cleanly across network transitions. See [`packaging/`](../packaging/) for the
service units.

The log noise on laptops is cosmetic and does not indicate DNS failure.

## Other Kernel Considerations

### File Descriptor Limits

A resolver under load may open many sockets and streams. Raise the
per-process limit in the systemd unit file or via PAM:

```ini
# /etc/systemd/system/rcvd.service
[Service]
LimitNOFILE=65536
```

This is more relevant when RCVD serves many clients or proxies queries
to many upstream resolvers simultaneously.

### Conntrack (firewall state table)

If RCVD runs behind a stateful firewall (iptables/nftables with
`conntrack`), high QUIC connection churn can fill the conntrack table.
This is generally a server-side concern, not a workstation issue.

Symptoms: random connection failures, `nf_conntrack: table full`
messages in `dmesg`.

Mitigations:
- Raise `net.netfilter.nf_conntrack_max` (server only)
- Or mark UDP port 853 traffic as `NOTRACK` if firewall policy allows

## Per-Distribution Notes

### Debian / Ubuntu

Default `net.core.rmem_max` is typically 208 KiB. Tuning is recommended
for servers. The `sysctl.d` drop-in approach above works as-is.

### Alpine Linux

Defaults are similar to Debian. Use `/etc/sysctl.d/` for persistence.
Note that Alpine uses musl libc and OpenRC, but the kernel sysctls
behave the same way.

### Fedora / RHEL

Defaults often higher than Debian (around 4 MiB) but still below the
quic-go target. Tuning recommended for servers.

### FreeBSD / OpenBSD

BSD systems use different sysctl names for UDP buffer tuning. The
per-socket send/receive space and the maximum socket buffer are the
relevant knobs:

```sh
# FreeBSD — apply now
sysctl net.inet.udp.recvspace=2097152
sysctl net.inet.udp.maxdgram=65535
sysctl kern.ipc.maxsockbuf=8388608

# Persist across reboots in /etc/sysctl.conf
net.inet.udp.recvspace=2097152
kern.ipc.maxsockbuf=8388608
```

`kern.ipc.maxsockbuf` is the ceiling a socket may request, so it must be
at least as large as quic-go's 7 MiB target (8 MiB above leaves headroom);
`net.inet.udp.recvspace` sets the default UDP receive buffer. OpenBSD uses
the same `net.inet.udp.recvspace` name and applies values via
`/etc/sysctl.conf` identically. Verify with `sysctl net.inet.udp.recvspace
kern.ipc.maxsockbuf`.

### Container Hosts

If running RCVD inside a container, sysctls must be set on the **host**
kernel, not in the container. Most container runtimes (Podman, Docker)
do not allow modifying these from inside the container by default.

For orchestrated container deployments, apply the sysctl values at the
host / node level (via the OS provisioning layer) rather than per-container.

## References

- quic-go UDP buffer tuning: <https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes>
- RFC 9250 (DNS-over-QUIC): <https://datatracker.ietf.org/doc/rfc9250/>
- Linux kernel network tuning (`man 7 udp`, `man 7 socket`)
