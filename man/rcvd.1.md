# rcvd 1 "21 July 2026" "rcvd 0.1.0" "User Commands"

## NAME

rcvd \- Resilient, Cryptographic, Verifiable DNS

## SYNOPSIS

**rcvd** [**-config** *path*] [*flag*]

## DESCRIPTION

**rcvd** is a single statically-linked binary that performs privacy-first encrypted DNS
forwarding and serving. Its defining invariant: every query that leaves the host does so over
an encrypted transport. If every configured encrypted upstream fails, **rcvd** returns SERVFAIL
rather than falling back to cleartext DNS. Port 53 is never a plaintext egress: **rcvd** may
accept plaintext queries on a **loopback** port 53 (Mode 1), but every query leaving the host
is encrypted, and binding port 53 on a non-loopback interface is rejected at startup.

**rcvd** operates in two modes, selectable per configuration file:

**Mode 1 (Forwarder):** Accepts plain DNS from local or LAN clients (loopback or configured
listen address) and forwards each query upstream over an encrypted transport (DoQ, DoT, or
DoH). The client-to-rcvd link is plaintext; the off-host leg is always encrypted.

**Mode 2 (Upstream Service):** Exposes encrypted DoH, DoT, and/or DoQ endpoints that other
resolvers or browsers query directly. Both ends of the query path are then encrypted. TLS
certificates are provided via auto-generated self-signed certificate (testing),
operator-supplied cert/key, or certmagic ACME automation.

Because both the forwarding and serving legs are encrypted, two or more **rcvd** instances in 
different locations can be chained - a Mode 1 forwarder pointing at another instance's Mode 
2 endpoint - with the off-host link encrypted end to end.

Both modes may run simultaneously from a single process, sharing one in-memory cache.

All flags are boolean (they take no value argument). The config file path is the one exception
and uses **-config** *path*. Passing a path as a bare positional argument is an error — see
**COMMON MISTAKES** below.

## OPTIONS

**-config** *path*

Path to the TOML configuration file. Defaults to **rcvd.toml** in the current directory. For system deployments use the full path, e.g. **/etc/rcvd/rcvd.toml**.

**-stats**

Connect to the running instance's Unix socket and print aggregate statistics, then exit. Requires **stats_enabled = true** in the configuration file. The socket path is derived from the config file name.

**-audit**

Connect to the running instance's Unix socket and print the live posture report: active listeners, no-cleartext invariant confirmation, and cache type. Requires **stats_enabled = true**. The posture reflects the running process's loaded configuration — not just the file on disk — confirming what is actually in force.

**-blocklist-reload**

Connect to the running instance's Unix socket and trigger a hot-reload of the blocklist **files** (from **[blocklists] files**), then exit. Requires **stats_enabled = true**. The reload rebuilds the entire in-memory set from the files on disk and atomically swaps it in, so both **added and removed** domains take effect without restarting the process — preserving statistics, cache, and connections. It is asynchronous and non-blocking: the command returns immediately with an acknowledgment while the (potentially minute-long) rescan runs in the background, exactly like the startup load, so DNS is never paused. Final counts are written to the daemon log when the swap completes. Edit the file(s), then run this. Only local **files** are reloaded; **update_urls** are not re-fetched.

**-verify-upstream**

Load the configuration, probe every configured upstream with a real, **CA-validating** TLS handshake, and print the certificate chain for each: subject, issuer, SANs, validity window, key type, and SHA-256 fingerprint. Does not require a running instance. Exits non-zero if any upstream probe fails.

This verb asks only "does the upstream present a CA-valid (Web-PKI or private-CA) certificate for its name?" — it is intentionally **not** pin-aware. An upstream that is verified in production by an SPKI **pin** (a self-signed leg with **pinned_pubkey** set) will FAIL here with *certificate signed by unknown authority* — that is EXPECTED and does not mean the live path is broken. The output flags such an upstream and points to **-verify-pin**. Use **-verify-pin** to validate a pinned upstream.

**-verify-pin**

Load the configuration and, for every upstream that has **pinned_pubkey** set, dial it the way the live pinned resolver path does (no CA-chain check; exact SubjectPublicKeyInfo match) and report **OK** or **MISMATCH** against the configured pin. Upstreams with no pin are skipped. Does not require a running instance. Exits zero only if every pinned upstream matches — suitable for cron/monitoring to catch a silent key rotation on the far end. This is the AUDIT verb of the pin lifecycle; see **-show-pin** for bootstrap.

**-show-pin** *index*

Probe the upstream at the given **0-based index** into the **[[upstreams]]** list, and print JUST its leaf SPKI pin (**sha256//BASE64**) to standard output — nothing else — ready to paste into that upstream's **pinned_pubkey**. All diagnostics go to standard error, so `pin=$(rcvd -show-pin 0 -config /etc/rcvd/rcvd.toml)` captures exactly the pin. No pin need be configured (that is the point — you are generating one). Works against a self-signed leg. This is the BOOTSTRAP verb of the pin lifecycle: **-show-pin** (generate) → **pinned_pubkey** (configure) → **-verify-pin** (audit).

**-verify-self**

Probe THIS instance's own Mode-2 listeners (DoH/DoT/DoQ) with a real TLS handshake and print the certificate presented to clients: subject, issuer, SANs, validity window, key type, fingerprint, and the leaf **SPKI pin** (**sha256//BASE64**). The pin is the same value a client configures as **pinned_pubkey** and validates with **-verify-pin**, so an operator managing both ends can copy it directly from this output. Classifies the cert source as SELF-SIGNED (tls_cert_autogen) or CA-ISSUED (certmagic/ACME or bring-your-own). Requires the instance to be running with Mode 2 enabled. If Mode 2 is disabled, reports that there is nothing to verify.

**-server-name** *name*

TLS SNI hostname to use when probing with **-verify-self**. Defaults to the hostname derived from each listener's configured address. Pass the real public DoH hostname when the instance uses certmagic on-demand TLS, so the cert is materialized for inspection.

**-version**

Print the version string and build timestamp, then exit.

**-help**

Print a short usage summary, then exit.

## COMMON MISTAKES

**rcvd** action flags are boolean and do not consume a path argument. Passing a path
positionally is silently parsed as a leftover argument and causes an error. The config
path always goes with **-config**:

	WRONG:  rcvd --stats /etc/rcvd/rcvd.toml
	RIGHT:  rcvd -config /etc/rcvd/rcvd.toml -stats

	WRONG:  rcvd --verify-self /etc/rcvd/rcvd.toml
	RIGHT:  rcvd -config /etc/rcvd/rcvd.toml -verify-self

**rcvd** will print a diagnostic naming the unexpected argument and show the corrected form.

## EXAMPLES

**Run a Mode-1 forwarder (local host)**

	rcvd -config /etc/rcvd/rcvd-resolver.toml

**Run a Mode-1 LAN-facing router forwarder**

	rcvd -config /etc/rcvd/rcvd-router.toml

**Run a Mode-2 upstream service (DoH/DoT/DoQ endpoint)**

	rcvd -config /etc/rcvd/rcvd-upstream.toml

**Query live statistics from a running instance**

	rcvd -config /etc/rcvd/rcvd.toml -stats

**Inspect the live posture of a running instance**

	rcvd -config /etc/rcvd/rcvd.toml -audit

**Hot-reload the blocklist after editing it (no restart, stats preserved)**

	# edit /etc/rcvd/domainswild — add or remove domains
	rcvd -config /etc/rcvd/rcvd.toml -blocklist-reload

**Verify TLS certificates of all configured upstreams (CA validation)**

	rcvd -config /etc/rcvd/rcvd.toml -verify-upstream

**Generate the SPKI pin for the first upstream (bootstrap a pin)**

	pin=$(rcvd -config /etc/rcvd/rcvd.toml -show-pin 0)
	# paste $pin into that upstream's pinned_pubkey = "sha256//…"

**Validate configured pins against the live servers (audit)**

	rcvd -config /etc/rcvd/rcvd.toml -verify-pin

**Inspect the TLS certificate this Mode-2 instance presents to clients**

	rcvd -config /etc/rcvd/rcvd-upstream.toml -verify-self

**Inspect the cert using a specific hostname (for certmagic on-demand TLS)**

	rcvd -config /etc/rcvd/rcvd-upstream.toml -verify-self -server-name doh.example.com

## FILES

**/etc/rcvd/**

Default directory for configuration files. Multiple config files are kept here; one is activated per running instance via **-config**.

**/etc/rcvd/rcvd.toml** (or symlink)

The conventionally active configuration file on production deployments.

**/run/rcvd/\*.sock**

Unix sockets for the statistics and audit interface, one per running instance. The socket name is derived from the config file name (e.g. **rcvd.toml** → **rcvd.sock**).

**/var/log/rcvd/rcvd.log**

Default log file (used when **[logging] file** is unset). Set **file = "stdout"** in the **[logging]** section to log to stdout instead (recommended for containers), or **file = "stderr"**.

## CONFIGURATION

Configuration is TOML. Strict unknown-key rejection is enforced: any unrecognized key is a
hard startup error rather than a silently-ignored typo.

Key sections:

**[resolver]** — Mode 1 forwarder settings. **enabled** activates Mode 1 (a config may define
this section without turning it on). **listen** sets the address and port (default
**127.0.0.1:5300**). Binding port 53 on a non-loopback address is rejected at startup.

**[[upstreams]]** — One block per upstream. **host** is the hostname used for TLS SNI and
certificate validation (required). **name** is an optional label for statistics output, and
**port** is **required** and explicit — rcvd assumes no default, so state the port you intend
to reach (typically 853 for DoQ/DoT, 443 for DoH). Each block selects
exactly one encrypted protocol: **doq = true** (DNS-over-QUIC, RFC 9250), **dot = true**
(DNS-over-TLS, RFC 7858), or **doh = true** (DNS-over-HTTPS, RFC 8484). For DoH, **doh_path**
sets the query path (default **/dns-query**) and **doh3 = true** uses HTTP/3 over QUIC (DoH3)
instead of HTTP/2 over TCP. Multiple blocks provide ordered fallback.

The optional **ip** field pins the dial target so the upstream needs no name resolution at
startup. Without it, rcvd cannot resolve the hostname itself — it has no cleartext bootstrap
path — so you must supply the address (obtained out-of-band, e.g. with **dig** or **q**). 
The optional **pinned_pubkey** field pins the upstream's leaf SubjectPublicKeyInfo as **sha256//BASE64** 
(see **-show-pin** to generate one and **-verify-pin** to audit it); when set, that upstream is 
validated by exact key match rather than CA chain, enabling a self-signed encrypted leg.

**[upstream_service]** — Mode 2 service settings. **enabled** activates Mode 2. **listen_doh**,
**listen_dot**, and **listen_doq** set the endpoint addresses; **doh3 = true** also serves DoH3
(HTTP/3 over QUIC) on the **listen_doh** address. TLS is configured via **tls_cert_autogen**
(self-signed), **tls_cert**/**tls_key** (bring-your-own), or **tls_automation** (certmagic).
With **tls_cert_autogen**, **tls_cert_hosts** adds extra hostnames or IPs to the self-signed
certificate's SAN (e.g. a tunnel or LAN name that clients connect by) on top of the auto-derived
listen-address hosts and loopback.

**[tls_automation]** — certmagic/ACME settings (when **tls_automation = true**). **challenge**
is **http** (default) or **dns01** (no inbound port; for tunnels/CGNAT). For **dns01**, set a
supported **dns_provider** (MVP: **cloudflare**) and supply the API token from EXACTLY ONE of
**dns_api_token** (inline), **dns_api_token_env** (name of an environment variable), or
**dns_api_token_file** + **dns_api_token_key** (a dotenv file rcvd parses; a relative path
resolves next to the config file). Setting more than one token source is a startup error.

**[blocklists]** — DNS filtering. **enabled** (default **true**) turns filtering on or off.
**files** is a list of local blocklist files, each a plain domain list (preferred) or a hosts-file
(auto-detected); wildcard entries (**\*.example.com**) are supported. **update_urls** lists remote
blocklists to fetch. A matched name is answered without leaving the host.

**[fallback]** — Multi-upstream health and failover. **phase1_duration_s** (default **300**) is
the startup window of aggressive health checks before settling into steady state.
**phase2_failure_threshold** is the number of consecutive failures that marks an upstream DOWN.
**health_check_interval_s** (default **30**) sets the steady-state probe interval. Together these
drive the ordered fallback across the configured **[[upstreams]]**.

**[cache]** — In-memory TTL cache. **enabled** (default **true**) turns caching on or off.
**type** selects a preset: **light**, **standard** (default), or **aggressive** (raises the
TTL floor to 300s AND the TTL ceiling to 7 days, and enables negative caching and serve-stale).
The preset is mutually exclusive with the manual **ttl_min**/**ttl_max**/**neg_ttl_max**/
**serve_stale_max_s** knobs; setting both is a startup error.

**[dnssec]** — DNSSEC validation. Enabled by default. By default it validates against the IANA
root trust anchor **embedded** in the binary (the public root KSK digest; no setup needed).
**root_key_file** overrides this with an operator-supplied anchor — either IANA
**root-anchors.xml** (DS) or a BIND-style **root.key** (DNSKEY), auto-detected. Point it at the
system anchor (e.g. **/var/lib/unbound/root.key**) so the OS owns trust-anchor updates,
including the rare root KSK rollover, which rcvd does not yet track automatically (RFC 5011).

**[logging]** — **level** is **debug**, **info** (default), **warn**, or **error**. **format**
is **text** (default) or **json**. **file** is the log destination: an explicit path, or the
special values **stdout** or **stderr**. When unset it defaults to **/var/log/rcvd/rcvd.log**.

**stats_enabled** — Set to **true** to enable the Unix socket for **-stats** and **-audit**.

See **docs/CONFIG.md** in the source tree for full documentation of all keys.

## EXIT STATUS

**0**
	Success.

**1**
	Configuration error, upstream probe failure, or runtime error.

**2**
	Invalid command-line usage (e.g. unexpected positional argument).

## SEE ALSO

**dig(1)**, **dnsmasq(8)**, **systemd-resolved(8)**, **resolvectl(1)**

rcvd source and documentation: **https://rcvd.net**

## HISTORY

rcvd was originally created in 2026 as a privacy-first, encryption-mandatory DNS engine, 
focusing on the IETF standardized transports: DoT, DoH, and DoQ

## AUTHORS

Christopher Mosetick	office@cpm.is
