// SPDX-License-Identifier: MIT
package config

import (
	"os"
	"testing"
)

// TestConfigLoad verifies basic config loading and validation.
func TestConfigLoad(t *testing.T) {
	// Phase 1: Basic test to ensure config struct is valid
	// Full test with actual file comes in Phase 1.2
	cfg := &Config{}
	if cfg == nil {
		t.Fatal("config should not be nil")
	}
}

// TestConfigValidate checks validation logic.
func TestConfigValidate(t *testing.T) {
	cfg := &Config{
		Resolver: ResolverConfig{
			Enabled: true,
			Listen:  "127.0.0.1:5300",
		},
		Upstreams: []UpstreamServer{
			{
				Name: "Test",
				Host: "1.1.1.1",
				Port: 853,
				DoQ:  true,
			},
		},
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("validate should succeed: %v", err)
	}

	if cfg.Resolver.Listen != "127.0.0.1:5300" {
		t.Error("listen address not preserved")
	}
}

// TestConfigValidateNoUpstream checks that validation fails without upstreams.
func TestConfigValidateNoUpstream(t *testing.T) {
	cfg := &Config{
		Resolver: ResolverConfig{
			Enabled: true,
		},
		Upstreams: []UpstreamServer{}, // Empty
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("validate should fail without upstreams")
	}
}

// TestConfigValidateIPField checks the optional ip field on upstreams.
func TestConfigValidateIPField(t *testing.T) {
	// Valid: ip field with valid IPv4
	cfg := &Config{
		Resolver:  ResolverConfig{Enabled: true},
		Upstreams: []UpstreamServer{{Name: "Test", Host: "dns.adguard.com", IP: "94.140.14.14", Port: 853, DoQ: true}},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid IPv4 ip field should pass: %v", err)
	}

	// Valid: ip field empty (backward compatible)
	cfg.Upstreams[0].IP = ""
	if err := cfg.Validate(); err != nil {
		t.Errorf("empty ip field should pass: %v", err)
	}

	// DialHost() returns IP when set
	cfg.Upstreams[0].IP = "94.140.14.14"
	if dh := cfg.Upstreams[0].DialHost(); dh != "94.140.14.14" {
		t.Errorf("DialHost() should return ip, got %q", dh)
	}

	// DialHost() falls back to host when ip is empty
	cfg.Upstreams[0].IP = ""
	if dh := cfg.Upstreams[0].DialHost(); dh != "dns.adguard.com" {
		t.Errorf("DialHost() should return host, got %q", dh)
	}

	// Invalid: ip field with bad value
	cfg.Upstreams[0].IP = "not-an-ip"
	if err := cfg.Validate(); err == nil {
		t.Error("invalid ip field should fail validation")
	}
}

// TestValidatePort53Loopback checks that port 53 on loopback is allowed (router use case).
func TestValidatePort53Loopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:53", "[::1]:53"} {
		cfg := &Config{
			Resolver:  ResolverConfig{Enabled: true, Listen: addr},
			Upstreams: []UpstreamServer{{Name: "Test", Host: "dns.adguard.com", Port: 853, DoQ: true}},
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("loopback port 53 %q should be allowed: %v", addr, err)
		}
	}
}

// TestValidatePort53NonLoopback checks that port 53 on a non-loopback address is rejected.
func TestValidatePort53NonLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:53", "192.0.2.1:53"} {
		cfg := &Config{
			Resolver:  ResolverConfig{Enabled: true, Listen: addr},
			Upstreams: []UpstreamServer{{Name: "Test", Host: "dns.adguard.com", Port: 853, DoQ: true}},
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("non-loopback port 53 %q should be rejected", addr)
		}
	}
}

// TestWarningsNonLoopbackNonPrivileged checks that non-loopback on a non-53 port produces a warning.
func TestWarningsNonLoopbackNonPrivileged(t *testing.T) {
	cfg := &Config{
		Resolver:  ResolverConfig{Enabled: true, Listen: "198.51.100.1:5300"},
		Upstreams: []UpstreamServer{{Name: "Test", Host: "dns.adguard.com", Port: 853, DoQ: true}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("should not be a hard error: %v", err)
	}
	if w := cfg.Warnings(); len(w) == 0 {
		t.Error("expected a warning for non-loopback non-53 listen address")
	}
}

// TestWarningsLoopbackNoWarning checks that a normal loopback config produces no warnings.
func TestWarningsLoopbackNoWarning(t *testing.T) {
	cfg := &Config{
		Resolver:  ResolverConfig{Enabled: true, Listen: "127.0.0.1:5300"},
		Upstreams: []UpstreamServer{{Name: "Test", Host: "dns.adguard.com", Port: 853, DoQ: true}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w := cfg.Warnings(); len(w) != 0 {
		t.Errorf("expected no warnings for loopback config, got: %v", w)
	}
}

// TestCacheModePresets checks that each mode resolves to the expected baselines.
func TestCacheModePresets(t *testing.T) {
	cases := []struct {
		mode                                      string
		ttlMin, ttlMax, negTTLMax, serveStaleMaxS int
	}{
		{"", 60, 86400, 0, 0}, // empty → standard
		{"standard", 60, 86400, 0, 0},
		{"light", 0, 3600, 0, 0},
		{"aggressive", 300, 604800, 300, 3600},
		{"AGGRESSIVE", 300, 604800, 300, 3600}, // case-insensitive
	}
	for _, tc := range cases {
		cfg := &Config{
			Resolver:  ResolverConfig{Enabled: true, Listen: "127.0.0.1:5300"},
			Cache:     CacheConfig{Enabled: true, Type: tc.mode},
			Upstreams: []UpstreamServer{{Name: "T", Host: "1.1.1.1", Port: 853, DoQ: true}},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("mode %q: validate failed: %v", tc.mode, err)
		}
		if cfg.Cache.TTLMin != tc.ttlMin || cfg.Cache.TTLMax != tc.ttlMax ||
			cfg.Cache.NegTTLMax != tc.negTTLMax || cfg.Cache.ServeStaleMaxS != tc.serveStaleMaxS {
			t.Errorf("mode %q: got ttlMin=%d ttlMax=%d neg=%d stale=%d; want %d/%d/%d/%d",
				tc.mode, cfg.Cache.TTLMin, cfg.Cache.TTLMax, cfg.Cache.NegTTLMax, cfg.Cache.ServeStaleMaxS,
				tc.ttlMin, tc.ttlMax, tc.negTTLMax, tc.serveStaleMaxS)
		}
	}
}

// TestCacheModeUnknown checks that an unknown mode string is a hard error.
func TestCacheModeUnknown(t *testing.T) {
	cfg := &Config{
		Resolver:  ResolverConfig{Enabled: true, Listen: "127.0.0.1:5300"},
		Cache:     CacheConfig{Enabled: true, Type: "turbo"},
		Upstreams: []UpstreamServer{{Name: "T", Host: "1.1.1.1", Port: 853, DoQ: true}},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("unknown cache mode should fail validation")
	}
}

// writeTempConfig writes cfg text to a temp file and returns its path.
func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/rcvd.toml"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

const baseUpstream = `
[resolver]
enabled = true
listen = "127.0.0.1:5300"
[[upstreams]]
name = "T"
host = "1.1.1.1"
port = 853
doq = true
`

// TestCacheModeConflictsWithManualKeys: mode + a manual TTL/neg/stale key = startup error.
func TestCacheModeConflictsWithManualKeys(t *testing.T) {
	for _, key := range []string{"ttl_min = 120", "ttl_max = 100", "neg_ttl_max = 60", "serve_stale_max_s = 30"} {
		body := baseUpstream + "\n[cache]\nenabled = true\ntype = \"aggressive\"\n" + key + "\n"
		path := writeTempConfig(t, body)
		if _, err := Load(path); err == nil {
			t.Errorf("mode + manual %q should be a startup error", key)
		}
	}
}

// TestCacheModeWithMaxSizeAllowed: mode + max_size is fine (max_size is orthogonal).
func TestCacheModeWithMaxSizeAllowed(t *testing.T) {
	body := baseUpstream + "\n[cache]\nenabled = true\ntype = \"aggressive\"\nmax_size = 8192\n"
	path := writeTempConfig(t, body)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("mode + max_size should be allowed: %v", err)
	}
	if cfg.Cache.MaxSize != 8192 || cfg.Cache.TTLMin != 300 || cfg.Cache.ServeStaleMaxS != 3600 {
		t.Errorf("aggressive + max_size: got max=%d ttlMin=%d stale=%d", cfg.Cache.MaxSize, cfg.Cache.TTLMin, cfg.Cache.ServeStaleMaxS)
	}
}

// TestCacheManualOnlyAllowed: no mode + manual keys is the advanced path, values stand.
func TestCacheManualOnlyAllowed(t *testing.T) {
	body := baseUpstream + "\n[cache]\nenabled = true\nttl_min = 120\nttl_max = 7200\n"
	path := writeTempConfig(t, body)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("manual-only config should be allowed: %v", err)
	}
	if cfg.Cache.TTLMin != 120 || cfg.Cache.TTLMax != 7200 {
		t.Errorf("manual values not preserved: ttlMin=%d ttlMax=%d", cfg.Cache.TTLMin, cfg.Cache.TTLMax)
	}
	if cfg.Cache.NegTTLMax != 0 || cfg.Cache.ServeStaleMaxS != 0 {
		t.Errorf("manual config should default neg/stale off: neg=%d stale=%d", cfg.Cache.NegTTLMax, cfg.Cache.ServeStaleMaxS)
	}
}

// TestCacheBareIsStandard: a bare [cache] (no mode, no TTLs) behaves like standard.
func TestCacheBareIsStandard(t *testing.T) {
	body := baseUpstream + "\n[cache]\nenabled = true\n"
	path := writeTempConfig(t, body)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("bare cache config should be allowed: %v", err)
	}
	if cfg.Cache.TTLMin != 60 || cfg.Cache.TTLMax != 86400 {
		t.Errorf("bare cache should default to standard (60/86400): got %d/%d", cfg.Cache.TTLMin, cfg.Cache.TTLMax)
	}
}

// TestConfigValidateNoProtocol checks that validation fails without protocol selection.
func TestConfigValidateNoProtocol(t *testing.T) {
	cfg := &Config{
		Resolver: ResolverConfig{
			Enabled: true,
		},
		Upstreams: []UpstreamServer{
			{
				Name: "Bad",
				Host: "1.1.1.1",
				Port: 853,
				// All protocols false — should fail
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("validate should fail without protocol selection")
	}
}

// --- DNS-01 token-source + provider validation ---------------------------------

// tlsAutomationBlock builds a [tls_automation] block with the given inner keys,
// appended to baseUpstream. mode 2 (upstream service) is enabled because TLS
// automation is a Mode-2 concern.
func dns01Config(inner string) string {
	return baseUpstream + `
[upstream_service]
enabled = true
[tls_automation]
challenge = "dns01"
dns_provider = "cloudflare"
` + inner + "\n"
}

// writeSibling writes a file next to the config (same temp dir) and returns its
// base name, so a relative dns_api_token_file resolves against the config dir.
func writeSibling(t *testing.T, configPath, name, body string) string {
	t.Helper()
	if err := os.WriteFile(dirOf(configPath)+"/"+name, []byte(body), 0600); err != nil {
		t.Fatalf("write sibling %s: %v", name, err)
	}
	return name
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

func TestDNS01TokenInline(t *testing.T) {
	path := writeTempConfig(t, dns01Config(`dns_api_token = "inline_tok"`))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("inline token should load: %v", err)
	}
	if cfg.TLSAutomation.DNSAPIToken != "inline_tok" {
		t.Errorf("token = %q, want inline_tok", cfg.TLSAutomation.DNSAPIToken)
	}
}

func TestDNS01TokenFromEnv(t *testing.T) {
	t.Setenv("RCVD_TEST_TOK", "env_tok")
	path := writeTempConfig(t, dns01Config(`dns_api_token_env = "RCVD_TEST_TOK"`))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("env token should load: %v", err)
	}
	if cfg.TLSAutomation.DNSAPIToken != "env_tok" {
		t.Errorf("token = %q, want env_tok", cfg.TLSAutomation.DNSAPIToken)
	}
}

func TestDNS01TokenEnvUnset(t *testing.T) {
	path := writeTempConfig(t, dns01Config(`dns_api_token_env = "RCVD_DEFINITELY_UNSET_VAR"`))
	if _, err := Load(path); err == nil {
		t.Error("unset env var named by dns_api_token_env should error")
	}
}

func TestLoadForDiagnosticsSkipsTokenCheck(t *testing.T) {
	// Read-only verbs (--verify-self etc.) never issue certs, so a missing DNS-01
	// token must NOT block loading a tls_automation config. Same config that makes
	// Load fail (above) must load clean via LoadForDiagnostics, and the token stays
	// unmaterialized (empty), since nothing consumes it on that path.
	path := writeTempConfig(t, dns01Config(`dns_api_token_env = "RCVD_DEFINITELY_UNSET_VAR"`))
	cfg, err := LoadForDiagnostics(path)
	if err != nil {
		t.Fatalf("LoadForDiagnostics should not require the DNS-01 token: %v", err)
	}
	if cfg.TLSAutomation.DNSAPIToken != "" {
		t.Errorf("diagnostics load should not materialize the token, got %q", cfg.TLSAutomation.DNSAPIToken)
	}
}

func TestDNS01TokenFromFileRelative(t *testing.T) {
	path := writeTempConfig(t, dns01Config(
		`dns_api_token_file = ".env"`+"\n"+`dns_api_token_key = "CLOUDFLARE_API_TOKEN"`))
	writeSibling(t, path, ".env", "# comment\nexport CLOUDFLARE_API_TOKEN=\"file_tok\"\nOTHER=x\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("file token should load: %v", err)
	}
	if cfg.TLSAutomation.DNSAPIToken != "file_tok" {
		t.Errorf("token = %q, want file_tok", cfg.TLSAutomation.DNSAPIToken)
	}
}

func TestDNS01TokenFileMissing(t *testing.T) {
	path := writeTempConfig(t, dns01Config(
		`dns_api_token_file = "nope.env"`+"\n"+`dns_api_token_key = "K"`))
	if _, err := Load(path); err == nil {
		t.Error("missing token file should error")
	}
}

func TestDNS01TokenFileMissingKey(t *testing.T) {
	path := writeTempConfig(t, dns01Config(
		`dns_api_token_file = ".env"`+"\n"+`dns_api_token_key = "ABSENT"`))
	writeSibling(t, path, ".env", "PRESENT=x\n")
	if _, err := Load(path); err == nil {
		t.Error("absent key in token file should error")
	}
}

func TestDNS01TokenFileWithoutKey(t *testing.T) {
	path := writeTempConfig(t, dns01Config(`dns_api_token_file = ".env"`))
	writeSibling(t, path, ".env", "K=v\n")
	if _, err := Load(path); err == nil {
		t.Error("dns_api_token_file without dns_api_token_key should error")
	}
}

func TestDNS01TokenKeyWithoutFile(t *testing.T) {
	path := writeTempConfig(t, dns01Config(`dns_api_token_key = "K"`))
	if _, err := Load(path); err == nil {
		t.Error("dns_api_token_key without dns_api_token_file should error")
	}
}

func TestDNS01MultipleTokenSources(t *testing.T) {
	t.Setenv("RCVD_TEST_TOK", "x")
	path := writeTempConfig(t, dns01Config(
		`dns_api_token = "a"`+"\n"+`dns_api_token_env = "RCVD_TEST_TOK"`))
	if _, err := Load(path); err == nil {
		t.Error("two token sources should be a hard error")
	}
}

func TestDNS01NoToken(t *testing.T) {
	path := writeTempConfig(t, dns01Config(""))
	if _, err := Load(path); err == nil {
		t.Error("dns01 with no token source should error")
	}
}

func TestDNS01UnsupportedProvider(t *testing.T) {
	body := baseUpstream + `
[upstream_service]
enabled = true
[tls_automation]
challenge = "dns01"
dns_provider = "rout53"
dns_api_token = "x"
`
	if _, err := Load(writeTempConfig(t, body)); err == nil {
		t.Error("unsupported dns_provider should error at load")
	}
}

func TestDNS01MissingProvider(t *testing.T) {
	body := baseUpstream + `
[upstream_service]
enabled = true
[tls_automation]
challenge = "dns01"
dns_api_token = "x"
`
	if _, err := Load(writeTempConfig(t, body)); err == nil {
		t.Error("dns01 without dns_provider should error")
	}
}

func TestTLSAutomationInvalidChallenge(t *testing.T) {
	body := baseUpstream + "\n[tls_automation]\nchallenge = \"bogus\"\n"
	if _, err := Load(writeTempConfig(t, body)); err == nil {
		t.Error("invalid challenge should error")
	}
}

func TestTLSAutomationTokenKeysWithoutDNS01(t *testing.T) {
	// http challenge but DNS-01 keys present → orphaned-key error.
	body := baseUpstream + "\n[tls_automation]\nchallenge = \"http\"\ndns_api_token = \"x\"\n"
	if _, err := Load(writeTempConfig(t, body)); err == nil {
		t.Error("dns_api_token with non-dns01 challenge should error")
	}
}

// TestAutogenRejectedWithPinnedUpstream covers the startup guard for the one
// pinning footgun that is detectable from a single config: Mode 2 serving an
// autogen (per-start, therefore moving) key while this same instance pins an
// upstream. Autogen + pinning is a delayed failure — fine until a restart, then
// every pinned client breaks at once — so it must fail at load, not in the field.
func TestAutogenRejectedWithPinnedUpstream(t *testing.T) {
	validPin := "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	pinnedUpstream := `
[resolver]
enabled = true
listen = "127.0.0.1:5300"
[[upstreams]]
name = "T"
host = "1.1.1.1"
port = 853
doq = true
pinned_pubkey = "` + validPin + `"
`

	// autogen + a pinned upstream = rejected.
	body := pinnedUpstream + "\n[upstream_service]\nenabled = true\nlisten_doq = \"10.0.0.1:853\"\ntls_cert_autogen = true\n"
	if _, err := Load(writeTempConfig(t, body)); err == nil {
		t.Error("tls_cert_autogen with a pinned upstream should error")
	}

	// The same shape with a stable file-based cert is the SUPPORTED pinning
	// deployment (a router's encrypted LAN leg with a stable cert) — must still load.
	ok := pinnedUpstream + "\n[upstream_service]\nenabled = true\nlisten_doq = \"10.0.0.1:853\"\ntls_cert = \"/etc/rcvd/router.crt\"\ntls_key = \"/etc/rcvd/router.key\"\n"
	if _, err := Load(writeTempConfig(t, ok)); err != nil {
		t.Errorf("file-based cert with a pinned upstream should be valid, got: %v", err)
	}

	// autogen with NO pin anywhere is the dev/test + container-suite case: allowed.
	devTest := baseUpstream + "\n[upstream_service]\nenabled = true\nlisten_doq = \"127.0.0.1:8853\"\ntls_cert_autogen = true\n"
	if _, err := Load(writeTempConfig(t, devTest)); err != nil {
		t.Errorf("tls_cert_autogen without any pin should be valid, got: %v", err)
	}

	// A pinned upstream with Mode 2 disabled must not trip the guard - the pin is
	// this instance's CLIENT leg, and nothing here serves a moving key.
	clientOnly := pinnedUpstream + "\n[upstream_service]\nenabled = false\ntls_cert_autogen = true\n"
	if _, err := Load(writeTempConfig(t, clientOnly)); err != nil {
		t.Errorf("pinned upstream with mode 2 disabled should be valid, got: %v", err)
	}
}

// TestValidatePinnedPubKey covers the SPKI-pin format gate applied at config load.
func TestValidatePinnedPubKey(t *testing.T) {
	// A real 32-byte SHA-256 base64 value (all-zero digest) is a well-formed pin.
	validPin := "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	good := []string{"", validPin} // empty = "no pin", must be allowed
	for _, p := range good {
		if err := validatePinnedPubKey(p); err != nil {
			t.Errorf("expected %q to be valid, got: %v", p, err)
		}
	}

	bad := []string{
		"AAAA",         // missing scheme prefix
		"sha1//AAAA",   // wrong scheme
		"sha256//!!!",  // invalid base64
		"sha256//AAAA", // decodes to 3 bytes, not 32
	}
	for _, p := range bad {
		if err := validatePinnedPubKey(p); err == nil {
			t.Errorf("expected %q to be rejected, got nil", p)
		}
	}
}

// TestAdvertiseIPsValidation covers the DDR ipv4hint/ipv6hint override. A bad value here
// cannot degrade gracefully: discovering clients dial the hint directly instead of resolving
// the SVCB Target, so a typo points every mobile client at the wrong host.
func TestAdvertiseIPsValidation(t *testing.T) {
	svc := func(extra string) string {
		return baseUpstream + "\n[upstream_service]\nenabled = true\nlisten_doh = \"0.0.0.0:443\"\ntls_cert_autogen = true\n" + extra
	}

	// The QA-rig shape: wildcard bind + explicit public dual-stack addresses.
	dualStack := svc("advertise_ips = [\"35.159.188.251\", \"2a05:d014:16d8:ae00::11\"]\n")
	if _, err := Load(writeTempConfig(t, dualStack)); err != nil {
		t.Errorf("dual-stack advertise_ips should be valid, got: %v", err)
	}

	// Unset is valid — DDR still works for spec-conformant clients (Android aside).
	if _, err := Load(writeTempConfig(t, svc(""))); err != nil {
		t.Errorf("advertise_ips unset should be valid, got: %v", err)
	}

	// A hostname is rejected: SVCB hints are addresses, and nothing resolves this.
	if _, err := Load(writeTempConfig(t, svc("advertise_ips = [\"doh3.qa.rcvd.net\"]\n"))); err == nil {
		t.Error("hostname in advertise_ips should error")
	}

	// A wildcard tells a client nothing to dial.
	if _, err := Load(writeTempConfig(t, svc("advertise_ips = [\"0.0.0.0\"]\n"))); err == nil {
		t.Error("unspecified address in advertise_ips should error")
	}

	// A DoQ-only box still designates itself under RFC 9462 §3, so hints are meaningful
	// there — advertise_ips must be accepted without a DoH listener.
	doqOnly := baseUpstream + "\n[upstream_service]\nenabled = true\nlisten_doq = \"0.0.0.0:853\"\ntls_cert_autogen = true\nadvertise_ips = [\"203.0.113.9\"]\n"
	if _, err := Load(writeTempConfig(t, doqOnly)); err != nil {
		t.Errorf("advertise_ips on a DoQ-only box should be valid, got: %v", err)
	}

	// With no encrypted listener at all there is no endpoint to describe.
	noListener := baseUpstream + "\n[upstream_service]\nenabled = true\ntls_cert_autogen = true\nadvertise_ips = [\"203.0.113.9\"]\n"
	if _, err := Load(writeTempConfig(t, noListener)); err == nil {
		t.Error("advertise_ips with no encrypted listener should error")
	}
}
