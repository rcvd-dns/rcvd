// SPDX-License-Identifier: MIT
// Package tls provides TLS certificate automation for rcvd's upstream service.
// It uses certmagic (Apache 2.0) for automatic ACME certificate management,
// enabling production-ready DoH/DoT/DoQ without manual cert setup.
//
// How rcvd diverges from certmagic's Caddy defaults
//
// certmagic is written primarily for Caddy — a public-facing web server whose job is to
// terminate TLS for many on-demand domains and stay up no matter what. rcvd is a privacy
// DNS engine with a different threat model and a different failure posture, so it drives
// certmagic against several of those defaults on purpose:
//
//   - No cleartext DNS, ever (rcvd's founding principle). certmagic's default DNS-01 solver
//     runs a propagation self-check that queries the authoritative nameserver directly over
//     cleartext UDP :53. rcvd disables it (PropagationTimeout = -1) and substitutes a fixed
//     PropagationDelay, so issuance never emits a cleartext DNS query. See newNoCleartextDNS01Solver.
//   - Fail loudly, do not defer. Caddy favors on-demand issuance at the first TLS handshake so
//     a server can boot before its certs exist. For a resolver that is wrong — a silent deferral
//     turns into a hung handshake with no diagnosable error. When pre-issuing (on_demand=false)
//     rcvd uses ManageSync so a bad ACME/DNS-01 config surfaces at startup, not at first query.
//   - Logging is rcvd's, not certmagic's. certmagic logs to its own zap sink; under an init
//     system that sink is lost. rcvd routes certmagic's logger into the rcvd log file so ACME
//     issuance progress and errors are actually visible. See newZapLogger.
//   - Strict ALPN, no HTTP/1.1. The base tls.Config here advertises only "h2"; each Mode-2
//     listener then pins its own transport ("doq"/"h2"/"h3"). rcvd never falls back to
//     HTTP/1.1 the way a general web server might. See GetTLSConfig.
package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/rcvd-dns/rcvd/internal/config"
)

// newZapLogger builds a *zap.Logger that writes to the same io.Writer as the given
// rcvd *log.Logger, so certmagic's internal (zap) output lands in the rcvd log file.
// Level is INFO (certmagic's issuance progress + errors) with a compact console encoder.
//
// Divergence from certmagic's default (see the package doc): certmagic logs to its own zap
// sink, which is fine for Caddy but disappears under an init system that only captures the
// daemon's own log. Routing it here is what makes a stuck DNS-01 challenge diagnosable.
func newZapLogger(l *log.Logger) *zap.Logger {
	enc := zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
		TimeKey:        "", // rcvd's log.Logger already stamps the time on each line
		LevelKey:       "level",
		NameKey:        "logger",
		MessageKey:     "msg",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
	})
	ws := zapcore.AddSync(l.Writer())
	core := zapcore.NewCore(enc, ws, zapcore.InfoLevel)
	return zap.New(core).Named("certmagic")
}

// AutomationConfig configures certmagic-based TLS automation.
type AutomationConfig struct {
	// OnDemand enables SNI-based on-demand certificate fetching.
	// Certificates are fetched from Let's Encrypt on first TLS handshake
	// for each domain. cached thereafter.
	OnDemand bool

	// AllowedDomains restricts which domains certmagic will fetch certificates
	// for. Required when OnDemand is true (prevents abuse).
	// Example: ["dns.example.com", "resolver.example.org"]
	AllowedDomains []string

	// StorageDir is the directory to store ACME account data and certificates.
	// Default: $HOME/.rcvd/certs
	StorageDir string

	// Email is the ACME account email (optional but recommended for expiry notices).
	Email string

	// Staging uses Let's Encrypt staging endpoint (no rate limits, untrusted certs).
	// Enable for testing to avoid hitting production rate limits.
	Staging bool

	// Challenge selects the ACME challenge type: "http" (default; HTTP-01/TLS-ALPN-01,
	// requires inbound :80/:443) or "dns01" (DNS-01 via a libdns provider, no inbound
	// port — works behind tunnels/CGNAT). When "dns01", DNSProvider+DNSAPIToken required.
	Challenge string

	// DNSProvider names the libdns provider for DNS-01 (currently: "cloudflare").
	DNSProvider string

	// DNSAPIToken is the DNS provider API token used to write the _acme-challenge TXT
	// record. Security: scope to a single zone where possible.
	DNSAPIToken string
}

// Manager manages TLS certificate automation via certmagic.
type Manager struct {
	cfg    *AutomationConfig
	magic  *certmagic.Config
	logger *log.Logger
}

// NewManager creates a TLS automation manager.
// Call GetTLSConfig() to get a *tls.Config suitable for listeners.
func NewManager(cfg *AutomationConfig, logger *log.Logger) (*Manager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("automation config required")
	}
	if cfg.OnDemand && len(cfg.AllowedDomains) == 0 {
		return nil, fmt.Errorf("on_demand_tls requires allowed_domains (prevents abuse of ACME endpoint)")
	}
	if cfg.Challenge == "dns01" {
		if cfg.DNSProvider == "" {
			return nil, fmt.Errorf("challenge=dns01 requires dns_provider")
		}
		if cfg.DNSAPIToken == "" {
			return nil, fmt.Errorf("challenge=dns01 requires dns_api_token")
		}
	} else if cfg.Challenge != "" && cfg.Challenge != "http" {
		return nil, fmt.Errorf("invalid challenge %q (want \"http\" or \"dns01\")", cfg.Challenge)
	}

	// Resolve storage directory
	storageDir := cfg.StorageDir
	if storageDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("get home dir for cert storage: %w", err)
		}
		storageDir = filepath.Join(home, ".rcvd", "certs")
	}

	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return nil, fmt.Errorf("create cert storage dir %s: %w", storageDir, err)
	}

	// Configure certmagic storage (file-based)
	storage := &certmagic.FileStorage{Path: storageDir}

	// Route certmagic's own (zap) logs into the same destination as the rcvd logger,
	// so ACME/DNS-01 issuance errors are actually visible. Without this certmagic uses
	// its default logger (its own stderr sink), and under OpenRC that output is lost —
	// which is why a stuck DNS-01 challenge produced no diagnosable line anywhere.
	zapLogger := newZapLogger(logger)

	// Use a pointer so the cache callback can reference magic after it's created.
	var magic *certmagic.Config

	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
	})

	magic = certmagic.New(cache, certmagic.Config{
		Storage: storage,
		Logger:  zapLogger,
	})

	// Configure ACME issuer. Default uses the inbound challenges (HTTP-01 /
	// TLS-ALPN-01). When Challenge == "dns01", wire a libdns-backed DNS-01 solver
	// and disable the inbound challenges so issuance needs no inbound port —
	// works behind Cloudflare tunnels, CGNAT, and firewalls.
	acmeTemplate := certmagic.ACMEIssuer{
		Email:                   cfg.Email,
		Agreed:                  true, // ACME Terms of Service
		DisableHTTPChallenge:    false,
		DisableTLSALPNChallenge: false,
		Logger:                  zapLogger, // surface ACME challenge/order errors (see storage comment)
	}

	if cfg.Challenge == "dns01" {
		solver, err := newNoCleartextDNS01Solver(cfg)
		if err != nil {
			return nil, err
		}
		acmeTemplate.DNS01Solver = solver
		acmeTemplate.DisableHTTPChallenge = true
		acmeTemplate.DisableTLSALPNChallenge = true
		logger.Printf("TLS automation: using DNS-01 challenge via %q provider (no inbound port required)", cfg.DNSProvider)
	}

	issuer := certmagic.NewACMEIssuer(magic, acmeTemplate)
	if cfg.Staging {
		issuer.CA = certmagic.LetsEncryptStagingCA
		issuer.TestCA = certmagic.LetsEncryptStagingCA
		logger.Println("TLS automation: using Let's Encrypt staging (certificates are untrusted)")
	} else {
		issuer.CA = certmagic.LetsEncryptProductionCA
	}
	magic.Issuers = []certmagic.Issuer{issuer}

	m := &Manager{
		cfg:    cfg,
		magic:  magic,
		logger: logger,
	}

	// Wire on-demand config with domain allowlist as DecisionFunc.
	// This prevents certmagic from fetching certs for arbitrary domains
	// presented during TLS handshake. Critical to avoid ACME abuse.
	if cfg.OnDemand {
		magic.OnDemand = &certmagic.OnDemandConfig{
			DecisionFunc: m.IsAllowed,
		}
	}

	return m, nil
}

// GetTLSConfig returns a *tls.Config with certmagic GetCertificate wired in.
// Pass this to DoH/DoT/DoQ listeners instead of loading cert files manually.
//
// On-demand mode: certificate is fetched from Let's Encrypt on first TLS
// handshake for a domain, then cached and auto-renewed.
//
// Pre-loaded mode: certificates for AllowedDomains are fetched eagerly at
// startup. Useful when domains are known ahead of time.
func (m *Manager) GetTLSConfig() *tls.Config {
	if m.cfg.OnDemand {
		return m.magic.TLSConfig()
	}

	// Build TLS config with GetCertificate only (no on-demand).
	//
	// Divergence from certmagic's default (see the package doc): a general web server negotiates
	// down to HTTP/1.1 freely. rcvd does not — it serves DoH strictly over h2/h3, DoT/DoQ over
	// their own ALPN, and never HTTP/1.1. NextProtos here is only a base default — every Mode-2
	// listener overrides it
	// for its own transport: the DoQ listener clones + pins ["doq"] (RFC 9250 §4.1),
	// the DoH TCP listener pins ["h2"] and hard-rejects non-h2 offers (Issue 26),
	// and DoH3/QUIC gets "h3" from quic-go. So this base must not advertise
	// "http/1.1" (rcvd serves DoH strictly over h2/h3 — see internal/upstream/doh.go)
	// nor "doq" over a TCP config. Keep it to "h2" so any code path that ever served
	// this config unmodified cannot silently expose HTTP/1.1 or a bogus transport.
	return &tls.Config{
		GetCertificate: m.magic.GetCertificate,
		NextProtos:     []string{"h2"},
	}
}

// ManageDomains proactively fetches and caches certificates for all AllowedDomains. Call
// this at startup for pre-loaded (non-on-demand) mode; it blocks until all certificates are
// obtained or the context is cancelled.
//
// Divergence from certmagic's default (see the package doc): Caddy leans on on-demand issuance
// at the first TLS handshake so a web server can come up before its certs exist. A resolver
// that boots "successfully" but then hangs every handshake is worse than one that refuses to
// start, so for pre-issue rcvd blocks and fails loudly (ManageSync) instead.
func (m *Manager) ManageDomains(ctx context.Context) error {
	if len(m.cfg.AllowedDomains) == 0 {
		return nil
	}
	// On-demand: issuance is deferred to the first TLS handshake (per domain), so
	// ManageAsync is correct — it only registers the allowlist and returns before any
	// ACME work. Errors then surface later, on the handshake, in certmagic's own log.
	//
	// Pre-issue (on_demand=false): use ManageSync so startup blocks until every cert is
	// actually obtained and returns the first ACME error immediately. This is the "fail
	// loudly" path — a bad token or a stuck DNS-01 challenge aborts Start() with a real
	// error instead of the old fire-and-forget behavior, which logged "certificates
	// ready" while nothing had been issued and then hung every handshake.
	if m.cfg.OnDemand {
		m.logger.Printf("TLS automation: registering %d on-demand domain(s) (issued on first handshake)", len(m.cfg.AllowedDomains))
		if err := m.magic.ManageAsync(ctx, m.cfg.AllowedDomains); err != nil {
			return fmt.Errorf("manage TLS domains (on-demand): %w", err)
		}
		return nil
	}

	m.logger.Printf("TLS automation: pre-issuing certificates for %d domain(s) (blocking)", len(m.cfg.AllowedDomains))
	if err := m.magic.ManageSync(ctx, m.cfg.AllowedDomains); err != nil {
		return fmt.Errorf("obtain TLS certificate(s) for %v: %w", m.cfg.AllowedDomains, err)
	}
	m.logger.Printf("TLS automation: certificates obtained for %v", m.cfg.AllowedDomains)
	return nil
}

// newNoCleartextDNS01Solver builds a certmagic DNS-01 solver backed by the configured
// libdns provider. DNS-01 satisfies the ACME challenge by writing a TXT record via the
// provider's API, so no inbound port to rcvd is required.
//
// Divergence from certmagic's default (see the package doc): the solver returned here has
// its propagation self-check disabled, because that check queries the authoritative
// nameserver over cleartext UDP :53 — which rcvd must never do. The self-check is a
// convenience, not a correctness requirement (the CA does its own authoritative lookup),
// so dropping it costs nothing but the cleartext query. See the PropagationTimeout /
// PropagationDelay fields below for the mechanics.
func newNoCleartextDNS01Solver(cfg *AutomationConfig) (*certmagic.DNS01Solver, error) {
	var provider certmagic.DNSProvider
	switch cfg.DNSProvider {
	case "cloudflare":
		provider = &cloudflare.Provider{APIToken: cfg.DNSAPIToken}
	default:
		return nil, fmt.Errorf("unsupported dns_provider %q (supported: %s)",
			cfg.DNSProvider, strings.Join(config.SupportedDNSProviders, ", "))
	}
	return &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: provider,

			// Zero-cleartext invariant (a founding principle — see CLAUDE.md "Non-Negotiable
			// Design Principles" and the whitepaper): rcvd must never emit a cleartext DNS
			// query. certmagic's default DNS-01 flow includes a propagation self-check that
			// queries the zone's authoritative nameserver directly over cleartext UDP :53 to
			// confirm the _acme-challenge TXT is visible before telling the CA to validate.
			// That probe is a cleartext DNS query originating from rcvd itself. Setting
			// PropagationTimeout = -1 disables the self-check entirely and unconditionally, so
			// rcvd never makes that query regardless of how the host is otherwise configured.
			//
			// Correctness is unaffected: rcvd still writes the challenge TXT via the provider's
			// HTTPS API (api.cloudflare.com), and Let's Encrypt performs its own authoritative
			// lookup from the public internet before issuing. Skipping rcvd's local pre-check
			// only removes a redundant probe that the CA repeats anyway. Because we no longer
			// poll for propagation, PropagationDelay below gives the record a fixed head start.
			//
			// Regression history: the self-check went unnoticed for a long time because it only
			// misbehaves where outbound cleartext :53 is permitted — a permissive environment
			// simply let the query out and issuance appeared to "just work." The leak was real
			// the whole time; it only became visible once outbound cleartext :53 was blocked.
			// Do not remove this.
			PropagationTimeout: -1,

			// Fixed wait between writing the TXT and asking the CA to validate. This replaces
			// the (now-disabled) propagation polling with a delay that involves no DNS query at
			// all, so it costs nothing against the zero-cleartext invariant. Cloudflare's anycast
			// nameservers need a few seconds to serve a freshly written record from every edge;
			// without this, the CA can query an edge that has not caught up yet and fail with
			// "No TXT record found." 30s is comfortably above Cloudflare's observed propagation.
			PropagationDelay: 30 * time.Second,
		},
	}, nil
}

// IsAllowed reports whether certmagic should fetch a certificate for the given
// domain. Used as the OnDemandConfig.DecisionFunc to prevent abuse.
func (m *Manager) IsAllowed(ctx context.Context, name string) error {
	for _, allowed := range m.cfg.AllowedDomains {
		if name == allowed {
			return nil
		}
	}
	return fmt.Errorf("domain %q not in allowed_domains list", name)
}
