// SPDX-License-Identifier: MIT
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config represents the full RCVD configuration.
type Config struct {
	StatsEnabled    bool                `toml:"stats_enabled"` // enable runtime statistics (default: false)
	Resolver        ResolverConfig      `toml:"resolver"`
	UpstreamService UpstreamConfig      `toml:"upstream_service"`
	Upstreams       []UpstreamServer    `toml:"upstreams"`
	DNSSEC          DNSSECConfig        `toml:"dnssec"`
	Blocklists      BlocklistConfig     `toml:"blocklists"`
	Cache           CacheConfig         `toml:"cache"`
	Metrics         MetricsConfig       `toml:"metrics"` // RESERVED — not yet implemented (Prometheus endpoint deferred; internal/metrics/metrics.go not built)
	Logging         LoggingConfig       `toml:"logging"`
	Fallback        FallbackConfig      `toml:"fallback"`
	TLSAutomation   TLSAutomationConfig `toml:"tls_automation"`
}

// ResolverConfig — Mode 1: Listen for client DNS queries, forward to upstreams
type ResolverConfig struct {
	Enabled bool   `toml:"enabled"`
	Listen  string `toml:"listen"` // default: 127.0.0.1:5300
}

// UpstreamConfig — Mode 2: Expose DoH/DoT/DoQ endpoints for other tools
// UpstreamConfig — Mode 2: Expose DoH/DoT/DoQ endpoints for other tools.
//
// TLS option → use-case mapping (pick ONE; code precedence: automation > autogen > cert/key —
// note autogen currently beats bring-your-own cert/key if both are set; set only one):
//
//	tls_automation  — certmagic/ACME real CA-trusted cert. Use for DIRECT-to-browser DoH
//	                  (Firefox/Zen DoH/TRR REQUIRES a CA-trusted cert and ignores self-signed
//	                  exceptions) and any public endpoint. Needs a real domain + DNS-01/HTTP-01.
//	tls_cert/tls_key— bring-your-own cert (Tailscale `tailscale cert`, corporate CA, etc.).
//	tls_cert_autogen— self-signed. For DEV/TEST (curl -k, local validation) OR behind a
//	                  TLS-terminating proxy that doesn't verify upstream (the Quick Tunnel /
//	                  nginx-sidecar pattern, where the proxy presents the real cert to clients).
//	                  DOES NOT WORK for direct browser DoH — the browser will refuse it.
type UpstreamConfig struct {
	Enabled        bool   `toml:"enabled"`
	ListenDoH      string `toml:"listen_doh"`       // e.g., 0.0.0.0:8443
	DoH3           bool   `toml:"doh3"`             // also serve DoH3 (HTTP/3 over QUIC/UDP) on the ListenDoH addr
	ListenDoT      string `toml:"listen_dot"`       // e.g., 0.0.0.0:853
	ListenDoQ      string `toml:"listen_doq"`       // e.g., 0.0.0.0:853
	TLSCert        string `toml:"tls_cert"`         // bring-your-own cert file (with tls_key)
	TLSKey         string `toml:"tls_key"`          // bring-your-own key file (with tls_cert)
	TLSCertAutoGen bool   `toml:"tls_cert_autogen"` // self-signed: dev/test OR behind a trust-terminating proxy; NOT direct-browser
	// TLSCertHosts adds extra hostnames/IPs to the self-signed (tls_cert_autogen) cert's SAN,
	// on top of the auto-derived listen-address hosts + loopback. Use it when clients connect by
	// a name that isn't the bind address — e.g. a tunnel hostname (doh-dev.rcvd.net) or a LAN
	// hostname (router.lan). IP literals go in the IP SAN, names in the DNS SAN. Ignored unless
	// tls_cert_autogen is set (real certs come from tls_automation / your own cert files).
	TLSCertHosts  []string `toml:"tls_cert_hosts"`
	TLSAutomation bool     `toml:"tls_automation"` // certmagic/ACME real cert: for direct-browser DoH + public endpoints
}

// UpstreamServer represents an encrypted upstream DNS server
type UpstreamServer struct {
	Name string `toml:"name"` // "Quad9", "Cloudflare", "Nextdns"
	Host string `toml:"host"` // hostname for TLS SNI / cert validation (or IP if no separate ip field)
	IP   string `toml:"ip"`   // optional: dial target IP — avoids DNS lookup for hostname (bootstrap safety)
	Port int    `toml:"port"` // required, explicit (no default); 853 for DoT/DoQ, 443 for DoH

	// Protocol selection (at least one required)
	DoQ bool `toml:"doq"` // DNS-over-QUIC (RFC 9250)
	DoT bool `toml:"dot"` // DNS-over-TLS (RFC 7858)
	DoH bool `toml:"doh"` // DNS-over-HTTPS (RFC 8484)

	// DoH-specific
	DoHPath string `toml:"doh_path"` // default: /dns-query
	DoH3    bool   `toml:"doh3"`     // when DoH: use HTTP/3 over QUIC (DoH3) instead of HTTP/2 over TCP

	// Optional: Pin public key
	PinnedPubKey string `toml:"pinned_pubkey"`
}

// DialHost returns the address to use for TCP/QUIC dialing.
// If IP is set, returns IP (avoids DNS lookup). Otherwise returns Host.
func (u *UpstreamServer) DialHost() string {
	if u.IP != "" {
		return u.IP
	}
	return u.Host
}

// validatePinnedPubKey checks that a pinned_pubkey value, when set, is a
// well-formed "sha256//BASE64" pin decoding to exactly 32 bytes. An empty value
// is valid (means "no pin, use normal CA validation"). This runs at config load
// so a malformed pin fails fast at startup rather than silently disabling pinning.
// The actual format check is ParsePin (pin.go) — the single source of truth shared
// with the resolver's live verifier, so the two can never drift.
func validatePinnedPubKey(pin string) error {
	if pin == "" {
		return nil
	}
	_, err := ParsePin(pin)
	return err
}

// DNSSECConfig — DNSSEC validation settings
type DNSSECConfig struct {
	Enabled     bool `toml:"enabled"`      // default: true
	ValidateAll bool `toml:"validate_all"` // validate all responses
	// RootKeyFile overrides the embedded IANA root trust anchor with an
	// operator-supplied file. Accepts IANA root-anchors.xml (DS) or a BIND-style
	// root.key (DNSKEY), auto-detected. Empty = use the embedded anchor. Set this
	// to the system anchor (e.g. /var/lib/unbound/root.key) so the OS owns updates.
	RootKeyFile string `toml:"root_key_file"`
}

// BlocklistConfig — Blocklist loading and updating
type BlocklistConfig struct {
	Enabled        bool     `toml:"enabled"`         // default: true
	Files          []string `toml:"files"`           // local files (plain domain list or hosts format)
	UpdateURLs     []string `toml:"update_urls"`     // fetch fresh lists
	UpdateInterval string   `toml:"update_interval"` // RESERVED — not yet implemented (pairs with deferred SIGHUP/periodic blocklist reload)
}

// CacheConfig — DNS response caching.
//
// Mode is an operator-convenience preset. It is MUTUALLY EXCLUSIVE with the manual TTL/
// negative/stale knobs (ttl_min, ttl_max, neg_ttl_max, serve_stale_max_s): set a mode OR
// tune those by hand, not both — combining them is a startup error (enforced in Load).
// max_size is orthogonal and may be set alongside a mode. Modes (axes: TTL + negative/stale):
//
//	"light"      — fresher data, more upstream traffic (ttl_min 0, ttl_max 1h, no neg/stale)
//	"standard"   — current behavior (ttl_min 60, ttl_max 24h, no neg/stale) [DEFAULT]
//	"aggressive" — minimize upstream queries (ttl_min 300, ttl_max 7d, negative caching
//	               ≤300s, serve-stale ≤1h on upstream failure)
//
// See docs/cache-modes-design.md.
type CacheConfig struct {
	Enabled bool   `toml:"enabled"`  // default: true
	Type    string `toml:"type"`     // "light" | "standard" | "aggressive" (default: standard)
	MaxSize int    `toml:"max_size"` // max entries, default: 4096
	TTLMin  int    `toml:"ttl_min"`  // minimum TTL in seconds
	TTLMax  int    `toml:"ttl_max"`  // maximum TTL in seconds

	// NegTTLMax caps negative (NXDOMAIN/NODATA) cache TTL in seconds. 0 = negative caching off.
	NegTTLMax int `toml:"neg_ttl_max"`
	// ServeStaleMaxS bounds serving a stale answer past expiry on upstream failure, in seconds.
	// 0 = serve-stale off. Never emits cleartext (stale answer was validated + encrypted).
	ServeStaleMaxS int `toml:"serve_stale_max_s"`

	Prefetch bool `toml:"prefetch"` // RESERVED — not yet implemented (no-op)
}

// MetricsConfig — Prometheus metrics endpoint (off by default)
type MetricsConfig struct {
	Enabled bool   `toml:"enabled"` // default: false
	Listen  string `toml:"listen"`  // e.g., 127.0.0.1:9090
}

// LoggingConfig — Application logging
type LoggingConfig struct {
	Level  string `toml:"level"`  // debug, info, warn, error (default: info)
	Format string `toml:"format"` // text or json (default: text)
	File   string `toml:"file"`   // optional: log file path (default: stderr if not set)
}

// FallbackConfig — Protocol fallback state machine
type FallbackConfig struct {
	// Phase 1 (startup): aggressive health checks
	Phase1TimeoutMs int `toml:"phase1_timeout_ms"` // RESERVED — not yet implemented (NewFallbackResolver takes phase1_duration_s, not a phase-1 timeout)
	Phase1DurationS int `toml:"phase1_duration_s"` // default: 300 (5min)

	// Phase 2 (runtime): gentle health checks
	Phase2FailureThreshold int `toml:"phase2_failure_threshold"` // consecutive failures = DOWN
	Phase2SlowThresholdMs  int `toml:"phase2_slow_threshold_ms"` // RESERVED — not yet implemented (StateSLOW threshold not yet wired into NewFallbackResolver)

	// Health check
	HealthCheckIntervalS int `toml:"health_check_interval_s"` // default: 30
}

// TLSAutomationConfig — certmagic-based TLS certificate automation
type TLSAutomationConfig struct {
	// OnDemand enables SNI-based on-demand certificate fetching from Let's Encrypt.
	// When enabled, certificates are fetched on first TLS handshake for each domain.
	// Requires AllowedDomains to be non-empty (prevents ACME abuse).
	OnDemand bool `toml:"on_demand"` // default: false

	// AllowedDomains restricts which domains certmagic will fetch certificates for.
	// Only used when OnDemand is true. Example: ["dns.example.com", "resolver.example.org"]
	AllowedDomains []string `toml:"allowed_domains"`

	// StorageDir is the directory to store ACME account data and certificates.
	// Default: $HOME/.rcvd/certs (created with 0700 permissions if needed).
	StorageDir string `toml:"storage_dir"`

	// Email is the ACME account contact email (optional but recommended).
	// Let's Encrypt uses this for certificate expiry notifications.
	Email string `toml:"email"`

	// Staging uses Let's Encrypt staging CA (untrusted certs, no rate limits).
	// Enable for testing to avoid hitting production ACME rate limits.
	Staging bool `toml:"staging"` // default: false

	// Challenge selects the ACME challenge type:
	//   "http"  (default) — HTTP-01 / TLS-ALPN-01; requires inbound :80/:443 to rcvd.
	//   "dns01"           — DNS-01 via a libdns provider; NO inbound port needed.
	//                       Works behind Cloudflare tunnels, CGNAT, and firewalls.
	// When "dns01", DNSProvider and DNSAPIToken are required.
	Challenge string `toml:"challenge"` // default: "http"

	// DNSProvider names the libdns provider for DNS-01 (e.g. "cloudflare").
	// Required when Challenge = "dns01". Must be one of SupportedDNSProviders;
	// an unknown value is rejected at config load (not lazily at cert issuance).
	DNSProvider string `toml:"dns_provider"`

	// --- DNS-01 token sources (choose EXACTLY ONE when Challenge = "dns01") ---
	//
	// The token is acquired from one explicit source. We do NOT chain or apply
	// precedence: setting more than one of these is a hard config error. This keeps
	// "where did the secret come from" unambiguous from day one.
	//
	// SECURITY: scope the token to a single zone (Zone:DNS:Edit) where possible.
	// Prefer _env or _file (0600) over the inline literal in production / IaC.

	// DNSAPIToken — source 1: the token inline in the config file. Simplest for
	// one-off deployments not tracked in git.
	DNSAPIToken string `toml:"dns_api_token"`

	// DNSAPITokenEnv — source 2: the NAME of an environment variable to read the
	// token from (e.g. "RCVD_DNS_API_TOKEN"). rcvd reads os.Getenv(that name);
	// the variable being unset/empty is a hard error. The launcher (podman
	// --env-file, compose env_file, systemd EnvironmentFile, a plain export) owns
	// putting it in the environment — rcvd does not parse a file in this mode.
	DNSAPITokenEnv string `toml:"dns_api_token_env"`

	// DNSAPITokenFile — source 3: path to a dotenv (KEY=value) file that rcvd
	// itself opens and parses. A relative path is resolved against the directory
	// of the config file (so a bare ".env" sits next to rcvd.toml regardless of
	// the process working directory); an absolute path is used as-is.
	// Requires DNSAPITokenKey to name which line to read.
	DNSAPITokenFile string `toml:"dns_api_token_file"`

	// DNSAPITokenKey — REQUIRED with DNSAPITokenFile: the KEY whose value in the
	// dotenv file is the token (e.g. "CLOUDFLARE_API_TOKEN"). There is no default —
	// the operator names the line explicitly, since the key name is provider- and
	// operator-specific. Setting this without DNSAPITokenFile is a config error.
	DNSAPITokenKey string `toml:"dns_api_token_key"`
}

// SupportedDNSProviders is the single source of truth for which libdns DNS-01
// providers rcvd accepts. config.Validate() rejects any other dns_provider at
// load time, and rcvd_tls.newDNS01Solver constructs the matching provider; both
// reference this list so they cannot drift. Add a provider here AND add its case
// in newDNS01Solver. MVP: cloudflare only.
var SupportedDNSProviders = []string{"cloudflare"}

// IsSupportedDNSProvider reports whether name is an accepted libdns provider.
func IsSupportedDNSProvider(name string) bool {
	for _, p := range SupportedDNSProviders {
		if p == name {
			return true
		}
	}
	return false
}

// Load parses a TOML config file and returns a validated Config.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Seed the "default: true" fields BEFORE decode. TOML only overwrites keys the
	// operator actually wrote, so an omitted `enabled` keeps this true, while an
	// explicit `enabled = false` still turns the section off. Without this, Go's bool
	// zero-value (false) would silently leave DNSSEC/blocklist/cache OFF when the key
	// is absent — contradicting the documented defaults (see rcvd(1) CONFIGURATION).
	cfg := Config{
		DNSSEC:     DNSSECConfig{Enabled: true},
		Blocklists: BlocklistConfig{Enabled: true},
		Cache:      CacheConfig{Enabled: true},
	}
	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, fmt.Errorf("parse TOML: %w", err)
	}

	// Check for unknown keys (typos, deprecated options)
	if len(md.Undecoded()) > 0 {
		return nil, fmt.Errorf("unknown config keys: %v", md.Undecoded())
	}

	// Cache "type" preset and the manual TTL/negative/stale knobs are mutually exclusive:
	// pick the convenience preset OR tune by hand, not both. This avoids any ambiguity about
	// whether a manual value (especially a 0) overrides or is overridden by the preset.
	// max_size is intentionally NOT in this set — it's memory footprint, orthogonal to the
	// TTL/stale behavior a mode describes, so e.g. mode="aggressive" + max_size=8192 is fine.
	if md.IsDefined("cache", "type") {
		var conflicting []string
		for _, key := range []string{"ttl_min", "ttl_max", "neg_ttl_max", "serve_stale_max_s"} {
			if md.IsDefined("cache", key) {
				conflicting = append(conflicting, key)
			}
		}
		if len(conflicting) > 0 {
			return nil, fmt.Errorf(
				"cache: type = %q cannot be combined with manual key(s) %v — set a type "+
					"(\"light\"/\"standard\"/\"aggressive\") OR tune ttl_min/ttl_max/neg_ttl_max/"+
					"serve_stale_max_s by hand, not both",
				cfg.Cache.Type, conflicting)
		}
	}

	// Resolve the DNS-01 token from its single explicit source (env var or dotenv
	// file) into DNSAPIToken, so the rest of rcvd consumes one field regardless of
	// source. Done before Validate so Validate sees the materialized token.
	// Relative dns_api_token_file is resolved against the config file's directory.
	if err := cfg.resolveDNSAPIToken(filepath.Dir(path)); err != nil {
		return nil, err
	}

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

// resolveDNSAPIToken enforces "exactly one token source" and materializes the
// chosen source into TLSAutomation.DNSAPIToken. Only relevant for DNS-01; for any
// other challenge it is a no-op (the token-source keys are validated as orphaned
// elsewhere in Validate). configDir is the directory of the config file, used to
// resolve a relative dns_api_token_file.
func (c *Config) resolveDNSAPIToken(configDir string) error {
	t := &c.TLSAutomation

	// Count which sources are set so two-or-more is a hard error.
	var set []string
	if t.DNSAPIToken != "" {
		set = append(set, "dns_api_token")
	}
	if t.DNSAPITokenEnv != "" {
		set = append(set, "dns_api_token_env")
	}
	if t.DNSAPITokenFile != "" {
		set = append(set, "dns_api_token_file")
	}

	if len(set) > 1 {
		return fmt.Errorf(
			"tls_automation: multiple DNS-01 token sources set (%s) — choose exactly one of "+
				"dns_api_token, dns_api_token_env, or dns_api_token_file", strings.Join(set, ", "))
	}

	// dns_api_token_key only makes sense with dns_api_token_file.
	if t.DNSAPITokenKey != "" && t.DNSAPITokenFile == "" {
		return fmt.Errorf("tls_automation: dns_api_token_key set without dns_api_token_file")
	}

	switch {
	case t.DNSAPITokenEnv != "":
		val := os.Getenv(t.DNSAPITokenEnv)
		if val == "" {
			return fmt.Errorf(
				"tls_automation: dns_api_token_env names %q but that environment variable is unset or empty",
				t.DNSAPITokenEnv)
		}
		t.DNSAPIToken = val

	case t.DNSAPITokenFile != "":
		if t.DNSAPITokenKey == "" {
			return fmt.Errorf(
				"tls_automation: dns_api_token_file is set but dns_api_token_key is empty — " +
					"name the KEY to read from the file (e.g. dns_api_token_key = \"CLOUDFLARE_API_TOKEN\")")
		}
		path := t.DNSAPITokenFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(configDir, path)
		}
		val, err := tokenFromDotenv(path, t.DNSAPITokenKey)
		if err != nil {
			return fmt.Errorf("tls_automation: dns_api_token_file: %w", err)
		}
		t.DNSAPIToken = val
	}

	return nil
}

// tokenFromDotenv reads key's value from a dotenv (KEY=value) file. It skips blank
// lines and # comments, accepts an optional leading "export ", and strips one layer
// of surrounding single/double quotes. It warns (does not fail) if the file is
// group/world-readable, since it holds a secret. Missing key or empty value errors.
func tokenFromDotenv(path, key string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("%w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr,
			"WARNING: token file %s is group/world-readable (%#o) — it holds a secret; chmod 600 it\n",
			path, info.Mode().Perm())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%w", err)
	}

	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(k) != key {
			continue
		}
		v = strings.TrimSpace(v)
		// Strip one matched layer of surrounding quotes.
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if v == "" {
			return "", fmt.Errorf("key %q in %s has an empty value", key, path)
		}
		return v, nil
	}
	return "", fmt.Errorf("key %q not found in %s", key, path)
}

// Validate checks for mutual-exclusion and required fields.
func (c *Config) Validate() error {
	// At least one mode must be enabled
	if !c.Resolver.Enabled && !c.UpstreamService.Enabled {
		return fmt.Errorf("at least one mode must be enabled (resolver or upstream_service)")
	}

	// Resolver: set defaults
	if c.Resolver.Enabled && c.Resolver.Listen == "" {
		c.Resolver.Listen = "127.0.0.1:5300"
	}

	// Reject resolver binding port 53 on a non-loopback interface.
	// Port 53 on 0.0.0.0 or a LAN IP makes rcvd a cleartext-accepting stub for the whole
	// network — violates the zero-cleartext design. Loopback (127.x, ::1) is fine: that is
	// the intended router deployment (dnsmasq → rcvd 127.0.0.1:53).
	if c.Resolver.Enabled {
		host, port, err := net.SplitHostPort(c.Resolver.Listen)
		if err == nil && port == "53" {
			ip := net.ParseIP(host)
			if ip != nil && !ip.IsLoopback() {
				return fmt.Errorf(
					"resolver listen %q: binding port 53 on a non-loopback interface is not allowed — "+
						"rcvd must not accept cleartext DNS from the network. "+
						"Use a loopback address (127.0.0.1:53 or [::1]:53) and let your router/firewall "+
						"forward external port 53 traffic to it",
					c.Resolver.Listen,
				)
			}
		}
	}

	// At least one upstream required
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream server required")
	}

	// Validate each upstream
	for i, up := range c.Upstreams {
		if up.Name == "" {
			return fmt.Errorf("upstream[%d]: name required", i)
		}
		if up.Host == "" {
			return fmt.Errorf("upstream[%d]: host required", i)
		}
		if up.IP != "" && net.ParseIP(up.IP) == nil {
			return fmt.Errorf("upstream[%d]: invalid ip address %q", i, up.IP)
		}
		if !up.DoQ && !up.DoT && !up.DoH {
			return fmt.Errorf("upstream[%d]: at least one protocol (doq, dot, doh) required", i)
		}
		// doh3 (HTTP/3 over QUIC) is a transport variant of doh; it has no meaning
		// without doh enabled on the same upstream.
		if up.DoH3 && !up.DoH {
			return fmt.Errorf("upstream[%d]: doh3 requires doh = true (DoH3 is DoH over HTTP/3)", i)
		}
		// Port is mandatory and explicit — rcvd does not assume a protocol default
		// (853/443). The operator states the port they intend to reach, so a typo or
		// an omitted key fails loudly rather than silently dialing a port they never
		// chose. A missing key decodes to 0.
		if up.Port == 0 {
			return fmt.Errorf("upstream[%d]: port is required — set it explicitly "+
				"(e.g. port = 853 for DoQ/DoT, port = 443 for DoH); rcvd assumes no default", i)
		}
		if up.Port < 0 || up.Port > 65535 {
			return fmt.Errorf("upstream[%d]: invalid port %d (must be 1-65535)", i, up.Port)
		}
		// A pinned public key, if set, must be a well-formed SPKI SHA-256 pin.
		// Validate at load so a malformed pin is a startup error, never a silent
		// no-op that would leave the connection unpinned. The resolver re-parses
		// the same format when it builds the TLS verifier.
		if err := validatePinnedPubKey(up.PinnedPubKey); err != nil {
			return fmt.Errorf("upstream[%d]: %w", i, err)
		}

		// Set protocol defaults
		if up.DoHPath == "" && up.DoH {
			up.DoHPath = "/dns-query"
		}
	}

	// TLS automation: validate the ACME challenge + DNS-01 provider/token at load
	// time so a typo'd dns_provider or a missing token fails at startup, not lazily
	// when the first certificate is requested.
	if err := c.validateTLSAutomation(); err != nil {
		return err
	}

	// DNSSEC trust anchors: when enabled, main loads cfg.DNSSEC.RootKeyFile if set,
	// otherwise the embedded IANA root-anchors.xml. Existence/parse of the file is
	// checked at load time (below) so a bad path fails fast rather than silently
	// falling back to the embedded anchor at runtime.
	if c.DNSSEC.Enabled && c.DNSSEC.RootKeyFile != "" {
		if _, err := os.Stat(c.DNSSEC.RootKeyFile); err != nil {
			return fmt.Errorf("dnssec: root_key_file %q: %w", c.DNSSEC.RootKeyFile, err)
		}
	}

	// Cache: resolve type preset, then apply explicit overrides.
	if err := c.resolveCacheType(); err != nil {
		return err
	}
	if c.Cache.Enabled && c.Cache.MaxSize == 0 {
		c.Cache.MaxSize = 4096
	}

	// Fallback: set defaults
	if c.Fallback.Phase1TimeoutMs == 0 {
		c.Fallback.Phase1TimeoutMs = 2000
	}
	if c.Fallback.Phase1DurationS == 0 {
		c.Fallback.Phase1DurationS = 300
	}
	if c.Fallback.Phase2FailureThreshold == 0 {
		c.Fallback.Phase2FailureThreshold = 3
	}
	if c.Fallback.HealthCheckIntervalS == 0 {
		c.Fallback.HealthCheckIntervalS = 30
	}

	// Logging: set defaults
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "text"
	}
	// Default to /var/log/rcvd/rcvd.log if not specified (most deployments expect file logging).
	// Use the special value file = "stdout" to log to standard output instead (container-friendly:
	// makes `podman logs` / `docker logs` and log aggregators work). Handled in cmd/rcvd/main.go.
	if c.Logging.File == "" {
		c.Logging.File = "/var/log/rcvd/rcvd.log"
	}

	return nil
}

// validateTLSAutomation checks the ACME challenge type and, for DNS-01, the
// provider + that a token was resolved. Token-source mutual-exclusion and the
// env/file materialization happen earlier in resolveDNSAPIToken (Load); this is
// the load-time fail-fast for challenge/provider so a misconfig errors at startup
// rather than lazily at first certificate issuance.
func (c *Config) validateTLSAutomation() error {
	t := &c.TLSAutomation
	challenge := t.Challenge

	// Challenge must be empty (defaults to http), "http", or "dns01".
	if challenge != "" && challenge != "http" && challenge != "dns01" {
		return fmt.Errorf("tls_automation: invalid challenge %q (want \"http\" or \"dns01\")", challenge)
	}

	// The DNS-01 token-source keys are meaningless for any other challenge.
	if challenge != "dns01" {
		if t.DNSProvider != "" || t.DNSAPIToken != "" || t.DNSAPITokenEnv != "" ||
			t.DNSAPITokenFile != "" || t.DNSAPITokenKey != "" {
			return fmt.Errorf(
				"tls_automation: dns_provider/dns_api_token* are only valid with challenge = \"dns01\"")
		}
		return nil
	}

	// DNS-01: provider required and must be supported (shared allowlist).
	if t.DNSProvider == "" {
		return fmt.Errorf("tls_automation: challenge = \"dns01\" requires dns_provider")
	}
	if !IsSupportedDNSProvider(t.DNSProvider) {
		return fmt.Errorf("tls_automation: unsupported dns_provider %q (supported: %s)",
			t.DNSProvider, strings.Join(SupportedDNSProviders, ", "))
	}

	// A token must have been resolved (from any of the three sources).
	if t.DNSAPIToken == "" {
		return fmt.Errorf(
			"tls_automation: challenge = \"dns01\" requires a token — set exactly one of " +
				"dns_api_token, dns_api_token_env, or dns_api_token_file")
	}

	return nil
}

// resolveCacheType resolves the cache configuration. The "type" preset and the manual
// TTL/negative/stale knobs are mutually exclusive (enforced in Load), so two paths apply:
//
//   - A mode is set ("light"/"standard"/"aggressive"): the preset OWNS ttl_min, ttl_max,
//     neg_ttl_max, and serve_stale_max_s outright. (max_size is independent and untouched.)
//   - No mode is set: the advanced-operator path. Any field the operator set by hand stands
//     as decoded; any field left at zero is filled from the "standard" baseline, so a bare
//     [cache] block (or any pre-cache-type config) behaves exactly as before cache modes
//     existed. Caveat: because zero doubles as "unset" here, an operator wanting a literal
//     ttl_min = 0 (no floor) should select mode = "light" instead.
//
// Unknown mode → hard error.
func (c *Config) resolveCacheType() error {
	mode := strings.ToLower(strings.TrimSpace(c.Cache.Type))
	c.Cache.Type = mode

	switch mode {
	case "light":
		c.Cache.TTLMin, c.Cache.TTLMax, c.Cache.NegTTLMax, c.Cache.ServeStaleMaxS = 0, 3600, 0, 0
	case "standard":
		c.Cache.TTLMin, c.Cache.TTLMax, c.Cache.NegTTLMax, c.Cache.ServeStaleMaxS = 60, 86400, 0, 0
	case "aggressive":
		c.Cache.TTLMin, c.Cache.TTLMax, c.Cache.NegTTLMax, c.Cache.ServeStaleMaxS = 300, 604800, 300, 3600
	case "":
		// No mode → "standard" baseline fills any unset field; manual values are preserved.
		if c.Cache.TTLMin == 0 {
			c.Cache.TTLMin = 60
		}
		if c.Cache.TTLMax == 0 {
			c.Cache.TTLMax = 86400
		}
		// neg/stale default off (0) when no mode — leave as decoded.
	default:
		return fmt.Errorf("cache type %q invalid (must be \"light\", \"standard\", or \"aggressive\")", mode)
	}
	return nil
}

// Warnings returns non-fatal configuration advisories that callers should log at startup.
// Call after Validate() succeeds.
func (c *Config) Warnings() []string {
	var w []string
	if c.Resolver.Enabled {
		host, port, err := net.SplitHostPort(c.Resolver.Listen)
		if err == nil && port != "53" {
			ip := net.ParseIP(host)
			if ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
				w = append(w, fmt.Sprintf(
					"resolver listen %q: binding on a non-loopback interface — "+
						"ensure this interface is trusted and not exposed to the public internet",
					c.Resolver.Listen,
				))
			}
		}
	}
	return w
}
