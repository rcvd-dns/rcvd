# Sandbox DNS Egress Guide  

This guide describes how to configure rcvd as a default-deny DNS egress gateway for sandboxed or untrusted workloads, such as CI runners, build containers, third-party plugins, or automated agents. By restricting DNS resolution exclusively to explicitly allowed domain suffixes, operators prevent DNS-based data exfiltration and out-of-band network communication. rcvd enforces name-level policy, while host firewall rules ensure rcvd is the only outbound DNS path available to the sandbox.  

## The Threat: DNS as an Exfiltration Channel  

Isolated execution environments frequently restrict or monitor outbound HTTP and HTTPS egress. However, DNS egress is often left unrestricted or forwarded to a recursive resolver that can query arbitrary names on the public internet. This permits any code running in the sandbox to establish an out-of-band communication channel using DNS queries alone.  

In an NS-delegation attack pattern (such as with dynamic IP mapping services like nip.io), a sandboxed process requests resolution for an attacker-controlled name like `_acme-challenge.203-0-113-7.example.net`. The recursive resolver follows authoritative NS delegations directly to the attacker-controlled nameserver IP (203.0.113.7). Outbound exfiltration data is encoded directly into the query labels, and inbound commands or data return within DNS answer records such as TXT.  

Standard DNS blocklists cannot mitigate this risk. Blocklists rely on matching known malicious domains or advertising networks, whereas sandboxed code or an attacker can dynamically synthesize unique, ephemeral subdomains under any registered apex or delegation domain.  

## Why Default-Deny  

Because the query name itself carries the exfiltration payload, forwarding an unknown query name to an upstream recursive resolver immediately exposes the data outside the host, even if the eventual DNS response is NXDOMAIN or the connection is dropped later.  

Under a default-deny architecture, rcvd intercepts queries before they leave the host. If a requested name does not match an explicit suffix entry in the allowlist, rcvd answers locally and immediately. The query name is never transmitted upstream, preventing the exfiltration payload from reaching external networks or resolvers.  

## Architecture  

```
+-------------------------------------------------------------+
| Sandbox Network Subnet (198.51.100.0/24)                    |
|                                                             |
|   +-----------------------+                                 |
|   | Sandboxed Workload    |                                 |
|   +-----------+-----------+                                 |
+---------------|---------------------------------------------+
                | plain DNS query (UDP/TCP :5300)
                v
+-------------------------------------------------------------+
| rcvd Gateway Host (192.0.2.53)                              |
|                                                             |
|   +-----------------------+                                 |
|   | rcvd Gateway          |                                 |
|   | [allowlist]           | <--- Denied query: return local |
|   | (Mode 1 Resolver)     |      REFUSED + EDE 18           |
|   +-----------+-----------+      (Never forwarded)          |
+---------------|---------------------------------------------+
                | encrypted DNS query (DoT/DoQ :853 or DoH :443)
                | (Allowed suffixes only)
                v
+-------------------------------------------------------------+
| Pinned Upstream Resolver (203.0.113.10)                     |
+-------------------------------------------------------------+
```

rcvd enforces domain name policy, ensuring that only explicitly permitted suffixes can be resolved. The host firewall enforces path integrity, ensuring that rcvd is the only accessible DNS path for the sandbox and that rcvd itself only connects to verified upstream addresses.  

## Firewall Requirements  

rcvd cannot configure the host packet filter. Operators must implement host firewall rules adhering to two core principles:  

1. Sandbox hosts (e.g., subnet 198.51.100.0/24) may reach only rcvd's listen address and port (192.0.2.53:5300) for DNS. Drop all other UDP and TCP traffic on port 53, port 853 (DoT and DoQ), and block known public DoH endpoints or, preferably, drop all outbound port 443 traffic except an explicit allow set.  
2. The rcvd gateway host itself must never initiate outbound cleartext DNS on port 53. It may only reach the specific, pinned upstream resolver IP addresses on port 853 or port 443.  

### nftables Example  

The following minimal `nftables.conf` demonstrates packet filtering for a gateway routing traffic between a sandbox subnet and upstream networks:  

```nftables
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        # Allow loopback traffic
        iif "lo" accept

        # Allow established and related traffic
        ct state established,related accept

        # Allow management access (e.g. SSH from operator subnet)
        # ip saddr 192.0.2.0/24 tcp dport 22 accept

        # Allow DNS from sandbox to rcvd Mode 1 on 192.0.2.53:5300
        ip saddr 198.51.100.0/24 ip daddr 192.0.2.53 udp dport 5300 accept
        ip saddr 198.51.100.0/24 ip daddr 192.0.2.53 tcp dport 5300 accept
    }

    chain forward {
        type filter hook forward priority filter; policy drop;

        # Block direct DNS and DoT/DoQ egress attempts from the sandbox
        ip saddr 198.51.100.0/24 tcp dport { 53, 853 } drop
        ip saddr 198.51.100.0/24 udp dport { 53, 853 } drop

        # Note: chain policy drop covers all other forward traffic, including DoH on port 443.
        # To allow outbound HTTPS for the sandbox, add an explicit destination allow set here:
        # ip saddr 198.51.100.0/24 ip daddr { 203.0.113.20, 203.0.113.21 } tcp dport 443 accept

        # Allow established outbound traffic
        ct state established,related accept
    }

    chain output {
        type filter hook output priority filter; policy drop;

        # Allow loopback traffic
        oif "lo" accept

        # Allow established and related traffic
        ct state established,related accept

        # Permit rcvd to connect only to pinned upstream resolver on encrypted ports
        ip daddr 203.0.113.10 tcp dport 853 accept
        ip daddr 203.0.113.10 udp dport 853 accept
        ip daddr 203.0.113.10 tcp dport 443 accept

        # Explicitly drop any outbound cleartext DNS from the gateway host
        udp dport 53 drop
        tcp dport 53 drop
    }
}
```

## rcvd Configuration  

Below is a complete, minimal configuration for running rcvd in Mode 1 with the allowlist enabled.  

### /etc/rcvd/rcvd.toml  

```toml
[resolver]
enabled = true
listen  = "192.0.2.53:5300"

[[upstreams]]
name          = "upstream-dot"
host          = "dns.example.net"
ip            = "203.0.113.10"
port          = 853
dot           = true
pinned_pubkey = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

[allowlist]
enabled = true
mode    = "default-deny"
files   = ["/etc/rcvd/allow.txt"]

[logging]
file = "stderr"
```

In the `[[upstreams]]` section, `host` provides the expected TLS server name for SNI and certificate validation, while `ip` is the pinned dial address used for connecting directly without prior DNS lookups.  

Key operational behaviors:  
- `mode = "default-deny"` is required; it is currently the only implemented allowlist mode.  
- The allowlist applies to both Mode 1 and Mode 2 listeners.  
- The allowlist loads before any listener starts. If it is enabled and cannot be loaded (missing file, empty, or invalid line), rcvd refuses to start. It never runs open while loading.  
- `mode = "exempt"` is reserved and rejected by configuration validation.  
- `files` accepts more than one path, and entries from all files are merged. A common pattern is a narrow base list plus a broader temporary list, for example `files = ["/etc/rcvd/allow.txt", "/etc/rcvd/allow-temp.txt"]`. To retire the temporary entries, empty that file (comments only) and run `rcvd -allowlist-reload`; the base list keeps serving. Every listed file must exist, and a bad line in any file fails the whole load, so the previous list stays active. The load also fails if all files together contain no entries.  
- `rcvd -allowlist-reload` re-reads the allowlist files in the running daemon and swaps them in atomically, without a restart. It requires `stats_enabled = true` (the control socket). On success it prints `allowlist reloaded: N entries from M file(s)` and exits 0. On any error it prints `allowlist reload FAILED, previous list still active: ...` and exits 1; the previous list keeps serving. Names removed from the list are refused immediately, even if an answer is cached.  

### /etc/rcvd/allow.txt  

The allowlist file contains one domain per line. Blank lines and lines starting with `#` are ignored. Bare TLDs, hosts-file IP mappings, and malformed names cause load errors.  

```
# /etc/rcvd/allow.txt
# Specify explicit domains permitted for sandbox egress.
# Replace example domains below with verified internal package registries and hosts.

# Allow apex and all subdomains under example.com (e.g., example.com, api.example.com)
example.com

# Allow all subdomains under example.org, but not the apex itself
*.example.org

# Permitted source repositories and registry endpoints (placeholders)
registry.example.net
git.example.net
```

## Behavior Reference  

The following table summarizes rcvd query handling:  

| Query Scenario | Response Code | Forwarded Upstream? | Cached Locally? | Description |
|---|---|---|---|---|
| Allowed name | NOERROR (or upstream code) | Yes | Yes | Name matches allowlist suffix; query forwards over encrypted upstream. |
| Denied name | REFUSED | No | No | Name not permitted by allowlist. Returns REFUSED with RFC 8914 EDE code 18 (Prohibited) if client sent EDNS. |
| Allowed, but blocklisted | NXDOMAIN | No | No | Domain matches allowlist suffix but matches `[blocklists]`. Blocklist rules take precedence. |
| DDR `resolver.arpa` | NOERROR | No | No | Discovery of Designated Resolvers query answered locally by Mode 2. |
| Upstream failure | SERVFAIL | Attempted | No | Upstream unreachable or encryption verification fails. rcvd never falls back to cleartext. |

Denied queries increment the `Denied (allowlist):` metric displayed in `rcvd --stats`.  

## Verification  

Verify the sandbox egress configuration using standard command-line tools.  

### 1. Test Permitted Name Resolution  

Query an allowed domain from the sandbox or test client:  

```console
$ dig @192.0.2.53 -p 5300 www.example.com A
```

The output should report `status: NOERROR` and return the expected address records in the answer section.  

### 2. Test Denied Name Interception  

Query an unlisted or simulated exfiltration domain:  

```console
$ dig @192.0.2.53 -p 5300 _acme-challenge.203-0-113-7.example.net TXT
```

Verify that the response returns `status: REFUSED` and includes an RFC 8914 Extended DNS Error option:  

```
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 41824
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; EDE: 18 (Prohibited)
```

### 3. Check Service Statistics  

Inspect query processing metrics using `rcvd --stats`:  

```console
$ rcvd --stats
```

The summary output will reflect denied queries under the counter:  

```
Denied (allowlist): 1
```

### 4. Packet Capture Verification  

Verify with `tcpdump` on the rcvd gateway host that denied query names never leave the machine:  

```console
# tcpdump -ni any 'port 53 or port 853 or port 443'
```

While running the capture, issue the denied query above. The packet trace should confirm:  
- Zero outbound packets sent on port 53, 853, or 443 for the denied domain name. Only background encrypted sessions to the pinned upstream resolver IP (203.0.113.10) may appear.  

To observe local query processing, run a separate capture on the listen port:  

```console
# tcpdump -ni any 'port 5300'
```

This capture confirms:  
- Inbound query arrival on port 5300 from the sandbox.  
- Local REFUSED response sent back to the sandbox on port 5300.  

## Limitations  

- **Trusted Parent Suffixes**: Suffix-level matching allows any subdomain beneath an entry like `example.com`. If an allowed domain hosts user-controlled wildcard records or public routing services, sandboxed code can still encode data into those subdomains. Keep allowlist entries restricted strictly to trusted zones.  
- **Defense in Depth**: DNS egress control addresses out-of-band DNS tunneling. It does not replace network-level restrictions on HTTP, HTTPS, or raw TCP/UDP outbound connections.  

## Roadmap  

The following security enhancements are planned for subsequent releases:  
- **Query-type allowlist**: Restrict allowable query types (e.g., permitting only A, AAAA, CNAME, and HTTPS records, while refusing TXT, NULL, and ANY records).  
- **Underscore label enforcement**: Require underscore-prefixed labels (such as `_acme-challenge`) to have explicit individual allowlist entries rather than inheriting permission from an allowed parent domain.  
- **Tunnel heuristics**: Real-time traffic analysis for anomalies, including query name length, label entropy, unique-subdomain velocity per client, and unusually large response payloads.  
- **Alert and kill hook**: Configurable notification hooks and automated shutdown actions triggered on the first denied or anomalous query.  
- **Built-in self-test**: An integrated verification utility demonstrating that the DNS path is closed and denied names are refused without forwarding.  

## Sources  

https://archive.is/ZvRFu  
https://www.rfc-editor.org/rfc/rfc8914  
https://www.rfc-editor.org/rfc/rfc9462  
