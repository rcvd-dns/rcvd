// SPDX-License-Identifier: MIT
// Package tls provides TLS certificate automation for RCVD upstream service.
// Uses certmagic (Apache 2.0) for automatic ACME certificate management,
// enabling production-ready DoH/DoT/DoQ without manual cert setup.
package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"

	"github.com/rcvd-dns/rcvd/internal/config"
)

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
	// requires inbound :80/:443) or "dns01" (DNS-01 via a libdns provider, NO inbound
	// port — works behind tunnels/CGNAT). When "dns01", DNSProvider+DNSAPIToken required.
	Challenge string

	// DNSProvider names the libdns provider for DNS-01 (currently: "cloudflare").
	DNSProvider string

	// DNSAPIToken is the DNS provider API token used to write the _acme-challenge TXT
	// record. SECURITY: scope to a single zone where possible.
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

	// Use a pointer so the cache callback can reference magic after it's created.
	var magic *certmagic.Config

	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
	})

	magic = certmagic.New(cache, certmagic.Config{
		Storage: storage,
	})

	// Configure ACME issuer. Default uses the inbound challenges (HTTP-01 /
	// TLS-ALPN-01). When Challenge == "dns01", wire a libdns-backed DNS-01 solver
	// and disable the inbound challenges so issuance needs NO inbound port —
	// works behind Cloudflare tunnels, CGNAT, and firewalls.
	acmeTemplate := certmagic.ACMEIssuer{
		Email:                   cfg.Email,
		Agreed:                  true, // ACME Terms of Service
		DisableHTTPChallenge:    false,
		DisableTLSALPNChallenge: false,
	}

	if cfg.Challenge == "dns01" {
		solver, err := newDNS01Solver(cfg)
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
	// NextProtos here is only a BASE default — every Mode-2 listener OVERRIDES it
	// for its own transport: the DoQ listener clones + pins ["doq"] (RFC 9250 §4.1),
	// the DoH TCP listener pins ["h2"] and hard-rejects non-h2 offers (Issue 26),
	// and DoH3/QUIC gets "h3" from quic-go. So this base MUST NOT advertise
	// "http/1.1" (rcvd serves DoH strictly over h2/h3 — see internal/upstream/doh.go)
	// nor "doq" over a TCP config. Keep it to "h2" so any code path that ever served
	// this config unmodified cannot silently expose HTTP/1.1 or a bogus transport.
	return &tls.Config{
		GetCertificate: m.magic.GetCertificate,
		NextProtos:     []string{"h2"},
	}
}

// ManageDomains proactively fetches and caches certificates for all
// AllowedDomains. Call this at startup for pre-loaded (non-on-demand) mode.
// Blocks until all certificates are obtained or context is cancelled.
func (m *Manager) ManageDomains(ctx context.Context) error {
	if len(m.cfg.AllowedDomains) == 0 {
		return nil
	}
	m.logger.Printf("TLS automation: fetching certificates for %d domain(s)", len(m.cfg.AllowedDomains))
	if err := m.magic.ManageAsync(ctx, m.cfg.AllowedDomains); err != nil {
		return fmt.Errorf("manage TLS domains: %w", err)
	}
	m.logger.Printf("TLS automation: certificates ready for %v", m.cfg.AllowedDomains)
	return nil
}

// newDNS01Solver builds a certmagic DNS-01 solver backed by the configured
// libdns provider. DNS-01 satisfies the ACME challenge by writing a TXT record
// via the provider's API, so no inbound port to rcvd is required.
func newDNS01Solver(cfg *AutomationConfig) (*certmagic.DNS01Solver, error) {
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
