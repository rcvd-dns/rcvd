// SPDX-License-Identifier: MIT

// Package upstream implements Mode 2 (the encrypted upstream service).
//
// It binds the client-facing encrypted DNS endpoints. DoH (over HTTP/2, and DoH3
// over HTTP/3), DoT, and DoQ — that other resolvers and web browsers query
// directly, then resolves each query upstream over an encrypted transport via the
// resolver package (sharing Mode 1's cache when both run in one process). The name
// "upstream" reflects that rcvd is the upstream service other clients point at;
// this is the "Mode 2" role in rcvd's two-mode model. The plaintext-side forwarder
// role ("Mode 1") lives in the server package.
// Note: the package's primary type is 'Service', which is the role's clearer name.
package upstream

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/rcvd-dns/rcvd/internal/cache"
	"github.com/rcvd-dns/rcvd/internal/config"
	"github.com/rcvd-dns/rcvd/internal/dnssec"
	applog "github.com/rcvd-dns/rcvd/internal/logger"
	rcvd_tls "github.com/rcvd-dns/rcvd/internal/rcvd_tls"
	"github.com/rcvd-dns/rcvd/internal/resolver"
	"github.com/rcvd-dns/rcvd/internal/statistics"
)

// ednsUDPBufSize is the EDNS0 UDP payload size the Mode-2 listeners advertise on the
// query sent upstream and the response returned to the client. Matches Mode 1's value
// (DNS-flag-day 1232, RFC 6891) so behavior is identical on both sides (Issue 28).
const ednsUDPBufSize = 1232

// clientDNSSECOK reports whether the client's query carried EDNS0 with the DO bit set.
func clientDNSSECOK(query *dns.Msg) bool {
	opt := query.IsEdns0()
	return opt != nil && opt.Do()
}

// queryWithDO returns a copy of the query with a single EDNS0 OPT (DO=1) for the
// upstream, so rcvd's own DNSSEC validator receives RRSIGs regardless of the client's
// DO bit. The caller's original query is left untouched (its DO bit still drives the
// cache key). Any existing OPT is stripped first: dns.SetEdns0 APPENDS, and two OPT
// records is malformed (RFC 6891 §6.1.1) — the upstream answers FORMERR (Issue 28).
func queryWithDO(query *dns.Msg) *dns.Msg {
	up := query.Copy()
	stripOPT(up)
	up.SetEdns0(ednsUDPBufSize, true)
	return up
}

// stripOPT removes any EDNS0 OPT pseudo-records from msg.Extra in place (a message must
// carry at most one OPT, RFC 6891 §6.1.1). Callers re-adding an OPT via SetEdns0 must
// strip first, since SetEdns0 appends rather than replaces.
func stripOPT(msg *dns.Msg) {
	if len(msg.Extra) == 0 {
		return
	}
	kept := msg.Extra[:0]
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			kept = append(kept, rr)
		}
	}
	msg.Extra = kept
}

// ensureResponseEDNS normalizes the reply's EDNS0 OPT against the client's query per
// RFC 6891 §6.1.1: a requestor that included an OPT gets a well-formed OPT back (DO bit
// matching the request, standard bufsize) so a validating client does not downgrade its
// feature set (Issue 28); a requestor that sent NO OPT (a non-EDNS query) gets a NON-EDNS
// response, i.e. no OPT at all. rcvd previously always appended an OPT even to a non-EDNS
// query — strict mobile native-DoH stacks (iOS 18 DNSecure, modern Android) break on that
// unsolicited OPT and refuse the resolver (Issue 36); Google/Quad9/AdGuard omit it and work.
// Mirrors the Mode-1 helper of the same name.
func ensureResponseEDNS(response, query *dns.Msg) {
	if response == nil {
		return
	}
	queryOPT := query.IsEdns0()
	clientDO := queryOPT != nil && queryOPT.Do()
	// A client that did not set DO must not receive DNSSEC records (RFC 6840 §5.9). We
	// always query upstream with DO=1 (queryWithDO) so the validator has RRSIGs, so a reply
	// for a signed zone carries RRSIG/NSEC/NSEC3 the client never asked for. Clearing the OPT
	// DO bit below is not enough on its own — the records must go too, or a strict client
	// (Firefox in DoH-only mode, macOS mDNSResponder) rejects or stalls on the response. This
	// mirrors the Mode-1 fix (Issue 34); the Mode-2 path was missed when that fix first landed.
	if !clientDO {
		stripDNSSECRecords(response)
	}
	// Non-EDNS query → non-EDNS response: strip any OPT the upstream/validator left behind and
	// do not add one (RFC 6891 §6.1.1; Issue 36). We always dial upstream with DO=1, so the
	// response can carry an OPT the client never asked for — remove it here.
	if queryOPT == nil {
		stripOPT(response)
		return
	}
	if opt := response.IsEdns0(); opt != nil {
		opt.SetDo(clientDO)
		opt.SetUDPSize(ednsUDPBufSize)
		return
	}
	response.SetEdns0(ednsUDPBufSize, clientDO)
}

// stripDNSSECRecords removes DNSSEC meta-records (RRSIG, NSEC, NSEC3, DNSKEY, DS) from
// every section of the response in place, for a client that did not set the DO bit
// (RFC 6840 §5.9). The OPT pseudo-record is left alone — ensureResponseEDNS owns it. The
// AD bit is preserved: validation already happened, only the signature records are dropped.
func stripDNSSECRecords(msg *dns.Msg) {
	msg.Answer = filterDNSSEC(msg.Answer)
	msg.Ns = filterDNSSEC(msg.Ns)
	msg.Extra = filterDNSSEC(msg.Extra)
}

// filterDNSSEC returns rrs with DNSSEC meta-records removed, reusing the backing array.
// OPT is not a DNSSEC record and is kept (the DO bit, not the OPT's presence, signals intent).
func filterDNSSEC(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return rrs
	}
	kept := rrs[:0]
	for _, rr := range rrs {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeDNSKEY, dns.TypeDS:
			// drop the signature record
		default:
			kept = append(kept, rr)
		}
	}
	return kept
}

// Service exposes encrypted DNS endpoints (DoH, DoT, DoQ) for other tools.
// Mode 2: rcvd acts as an upstream DNS service (not a resolver listening for clients).
//
// ValidateFunc applies the FULL DNSSEC outcome to a response in place and reports only whether the
// response is BOGUS. It owns the three-way decision (RFC 4035 §4.3) so every listener stays simple
// and identical:
//   - SECURE   → sets the AD bit, counts validated, returns nil.
//   - INSECURE → clears the AD bit, counts unsigned, returns nil (serve it; it is not a failure —
//     e.g. a CNAME chain whose signed head validates but whose tail is unsigned, Issue 30).
//   - BOGUS    → returns a non-nil error; the listener replaces the response with SERVFAIL.
//
// Returning nil therefore means "serve this response as adjusted" (secure or insecure); an error
// means "fail closed". Listeners must not set the AD bit themselves — the callback already has.
type ValidateFunc func(msg *dns.Msg) error

type Service struct {
	cfg           *config.UpstreamConfig
	advertiseHost string            // cert hostname advertised in DDR (RFC 9462); "" disables DDR
	resolv        resolver.Resolver // Resolver to use for queries (typically fallback resolver)
	cache         *cache.Cache      // SHARED with Mode 1 — one cache for the whole instance (may be nil)
	validator     *dnssec.Validator // optional DNSSEC validator
	stats         *statistics.Stats // optional runtime statistics
	tlsConfig     *tls.Config
	tlsManager    *rcvd_tls.Manager // certmagic automation manager (if enabled)
	logger        *log.Logger
	debugLog      *applog.Logger // optional leveled logger, forwarded to the DoQ listener so its
	// benign-idle server-side lines log at debug (see DOQListener.SetDebugLogger). nil = prior behavior.

	// Active listeners
	dohListener *dohListener
	dotListener *dotListener
	doqListener *doqListener

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a new upstream DNS service.
// fullConfig is needed to access TLSAutomationConfig; upstreamCfg is just the upstream_service section.
func New(upstreamCfg *config.UpstreamConfig, fullConfig *config.Config, resolv resolver.Resolver, dnsCache *cache.Cache, validator *dnssec.Validator, stats *statistics.Stats, logger *log.Logger) (*Service, error) {
	if !upstreamCfg.Enabled {
		return nil, fmt.Errorf("upstream service not enabled")
	}

	s := &Service{
		cfg:       upstreamCfg,
		resolv:    resolv,
		cache:     dnsCache,
		validator: validator,
		stats:     stats,
		logger:    logger,
	}

	// DDR (RFC 9462) self-advertisement identity: the cert subject rcvd serves DoH under.
	// This is the hostname clients must reach rcvd's DoH endpoint by, so it's the one we
	// advertise in the SVCB Target for _dns.resolver.arpa. Same idiom as cmd/rcvd/main.go.
	// Left empty when no automated cert domain is configured — DDR then stays off.
	if len(fullConfig.TLSAutomation.AllowedDomains) > 0 {
		s.advertiseHost = fullConfig.TLSAutomation.AllowedDomains[0]
	}

	// Load or generate TLS certificate
	tlsConfig, tlsManager, err := s.setupTLS(fullConfig)
	if err != nil {
		return nil, fmt.Errorf("setup TLS: %w", err)
	}
	s.tlsConfig = tlsConfig
	s.tlsManager = tlsManager

	return s, nil
}

// setupTLS loads TLS certificate, generates self-signed, or sets up certmagic automation.
// Returns (tlsConfig, tlsManager, error).
// tlsManager is non-nil only if automation is enabled; caller should invoke ManageDomains() in Start().
func (s *Service) setupTLS(fullConfig *config.Config) (*tls.Config, *rcvd_tls.Manager, error) {
	// Priority 1: TLS Automation (Let's Encrypt via certmagic)
	if s.cfg.TLSAutomation {
		automationCfg := &rcvd_tls.AutomationConfig{
			OnDemand:       fullConfig.TLSAutomation.OnDemand,
			AllowedDomains: fullConfig.TLSAutomation.AllowedDomains,
			StorageDir:     fullConfig.TLSAutomation.StorageDir,
			Email:          fullConfig.TLSAutomation.Email,
			Staging:        fullConfig.TLSAutomation.Staging,
			Challenge:      fullConfig.TLSAutomation.Challenge,
			DNSProvider:    fullConfig.TLSAutomation.DNSProvider,
			DNSAPIToken:    fullConfig.TLSAutomation.DNSAPIToken,
		}

		manager, err := rcvd_tls.NewManager(automationCfg, s.logger)
		if err != nil {
			return nil, nil, fmt.Errorf("create TLS automation manager: %w", err)
		}

		s.logger.Printf("TLS automation enabled: on_demand=%v, domains=%v, staging=%v",
			automationCfg.OnDemand, automationCfg.AllowedDomains, automationCfg.Staging)

		return manager.GetTLSConfig(), manager, nil
	}

	// Priority 2: Self-signed certificate (for testing/development)
	if s.cfg.TLSCertAutoGen {
		// Build the SAN list from the configured Mode-2 listen addresses so the cert
		// actually matches the address clients connect to (not just loopback). Without
		// this a LAN-facing endpoint like 192.0.2.1:8443 gets a localhost-only cert that
		// no remote client can validate.
		hosts := autogenSANHosts(s.cfg)
		cert, key, err := generateSelfSignedCert(hosts)
		if err != nil {
			return nil, nil, fmt.Errorf("generate self-signed cert: %w", err)
		}

		tlsCert, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, nil, fmt.Errorf("load generated cert: %w", err)
		}

		s.logger.Printf("TLS: using auto-generated self-signed certificate for %v", hosts)
		return &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		}, nil, nil
	}

	// Priority 3: Load certificate from files
	if s.cfg.TLSCert == "" || s.cfg.TLSKey == "" {
		return nil, nil, fmt.Errorf("TLS cert and key required (or enable tls_cert_autogen or tls_automation)")
	}

	tlsCert, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
	if err != nil {
		return nil, nil, fmt.Errorf("load TLS cert/key: %w", err)
	}

	s.logger.Printf("TLS: loaded certificate from %s", s.cfg.TLSCert)
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}, nil, nil
}

// SetDebugLogger wires an optional leveled logger, forwarded to the DoQ listener at Start so its
// benign-idle server-side lines log at debug rather than unconditionally. Must be called before
// Start (the listener is created there). nil / unset keeps the prior always-on behavior.
func (s *Service) SetDebugLogger(l *applog.Logger) { s.debugLog = l }

// Start begins listening on configured endpoints.
func (s *Service) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)

	// If TLS automation is enabled, eagerly fetch certificates for allowed domains.
	// This blocks until all certs are obtained or context is cancelled.
	if s.tlsManager != nil {
		if err := s.tlsManager.ManageDomains(s.ctx); err != nil {
			return fmt.Errorf("manage TLS domains: %w", err)
		}
	}

	// Build validate callback from DNSSEC validator (nil-safe). The callback applies the full
	// three-way DNSSEC outcome (AD bit + stats) in place and returns an error only for bogus — see
	// ValidateFunc. Centralizing it here keeps the DoQ/DoT/DoH listeners identical and prevents an
	// insecure answer (Issue 30) from being mistaken for a validation failure and turned into SERVFAIL.
	var validateFunc ValidateFunc
	if s.validator != nil {
		validator := s.validator
		stats := s.stats
		validateFunc = func(msg *dns.Msg) error {
			err := validator.ValidateResponse(msg)
			switch {
			case err == nil:
				msg.AuthenticatedData = true // SECURE (RFC 4035 §3.2.3)
				if stats != nil {
					atomic.AddInt64(&stats.DnssecValidated, 1)
				}
				return nil
			case dnssec.IsInsecure(err):
				msg.AuthenticatedData = false // INSECURE — serve without AD, not a failure
				if stats != nil {
					atomic.AddInt64(&stats.DnssecUnsigned, 1)
				}
				return nil
			default:
				return err // BOGUS — listener fails closed to SERVFAIL
			}
		}
	}

	// Build the DDR (RFC 9462) zone ONCE, then share it with every listener. It enumerates
	// each encrypted transport rcvd actually serves, priority-ordered (RFC 9462 §3), so a
	// client discovering over any one transport learns about all of them. Every listener
	// also serves the resolver.arpa zone itself — see ddr.go for the §6.4 containment rule.
	ddr := newDDRZone(s.advertiseHost, s.cfg.ListenDoH, s.cfg.ListenDoT, s.cfg.ListenDoQ,
		s.cfg.DoH3, s.cfg.AdvertiseIPs)

	switch {
	case ddr.advertises():
		for _, d := range ddr.designations {
			s.logger.Printf("DDR (RFC 9462) designation: _dns.resolver.arpa SVCB %d %s port=%d alpn=%v",
				d.priority, s.advertiseHost, d.port, d.alpn)
		}
		s.logger.Printf("DDR hints: ipv4hint=%v ipv6hint=%v", ddr.v4, ddr.v6)

		// A hintless advert is spec-legal but Android's native resolver rejects it outright and
		// falls back to DoT on :853 — silently, from the client side, so the operator sees a
		// working DoH endpoint that phones simply never use. Warn loudly rather than fail: DDR
		// is still useful to spec-conformant clients, and plenty of deployments have no mobile
		// clients at all. Set advertise_ips to the public address(es) to close this.
		if len(ddr.v4) == 0 && len(ddr.v6) == 0 {
			s.logger.Printf("DDR warning: no ipv4hint/ipv6hint in the advert (the listen address is a " +
				"wildcard or non-IP bind and advertise_ips is unset) — Android native Private DNS requires " +
				"the hints and will ignore this record, falling back to DoT; set " +
				"upstream_service.advertise_ips to the public address(es) clients dial")
		}
	default:
		// No cert hostname means no conformant way to name an endpoint, so rcvd designates
		// nothing. It still serves resolver.arpa: RFC 9462 §4 wants an explicit NODATA rather
		// than a forwarded query, so clients get an accurate "no designation" signal.
		s.logger.Printf("DDR (RFC 9462): no designations advertised (no tls_automation domain " +
			"configured); serving resolver.arpa as a locally served zone (NODATA)")
	}

	// Start DoH listener if configured. When cfg.DoH3 is set, the same listener
	// ALSO serves DoH3 (HTTP/3 over QUIC/UDP) on the same address, alongside the
	// always-on HTTP/2-over-TCP DoH.
	if s.cfg.ListenDoH != "" {
		dohList, err := newDOHListener(s.cfg.ListenDoH, s.tlsConfig, s.resolv, s.cache, validateFunc, s.stats, s.logger, s.cfg.DoH3)
		if err != nil {
			return fmt.Errorf("start DoH listener: %w", err)
		}
		dohList.ddr = ddr
		s.dohListener = dohList
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			dohList.serve(s.ctx)
		}()
		if s.cfg.DoH3 {
			s.logger.Printf("DoH endpoint listening on %s (HTTP/2 over TCP + DoH3/HTTP/3 over QUIC)", s.cfg.ListenDoH)
		} else {
			s.logger.Printf("DoH endpoint listening on %s (HTTP/2 over TCP)", s.cfg.ListenDoH)
		}
	}

	// Start DoT listener if configured
	if s.cfg.ListenDoT != "" {
		dotList, err := newDOTListener(s.cfg.ListenDoT, s.tlsConfig, s.resolv, s.cache, validateFunc, s.stats, s.logger)
		if err != nil {
			return fmt.Errorf("start DoT listener: %w", err)
		}
		dotList.ddr = ddr
		s.dotListener = dotList
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			dotList.Serve(s.ctx)
		}()
		s.logger.Printf("DoT endpoint listening on %s", s.cfg.ListenDoT)
	}

	// Start DoQ listener if configured
	if s.cfg.ListenDoQ != "" {
		doqList, err := newDOQListener(s.cfg.ListenDoQ, s.tlsConfig, s.resolv, s.cache, validateFunc, s.stats, s.logger)
		if err != nil {
			return fmt.Errorf("start DoQ listener: %w", err)
		}
		doqList.ddr = ddr
		// Forward the leveled logger (if wired) so the DoQ listener's benign-idle server-side
		// lines (client-closed write, idle accept close) log at debug instead of flooding.
		if s.debugLog != nil {
			doqList.SetDebugLogger(s.debugLog)
		}
		s.doqListener = doqList
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			doqList.serve(s.ctx)
		}()
		s.logger.Printf("DoQ endpoint listening on %s", s.cfg.ListenDoQ)
	}

	return nil
}

// Stop gracefully shuts down the upstream service.
func (s *Service) Stop(timeout time.Duration) error {
	s.logger.Println("stopping upstream service...")
	s.cancel()

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Println("upstream service stopped gracefully")
	case <-time.After(timeout):
		s.logger.Printf("upstream service stop timeout (%v), force closing", timeout)
	}

	// Close listeners
	if s.dohListener != nil {
		s.dohListener.close()
	}
	if s.dotListener != nil {
		s.dotListener.close()
	}
	if s.doqListener != nil {
		s.doqListener.close()
	}

	return nil
}

// BoundAddrs reports which Mode-2 endpoints are live, for the --audit live view. A non-empty
// address means Start() created that listener (DoT/DoQ bind in their constructor, so this is a
// true bind; DoH binds on serve, so this reflects "listener created and serving"). An empty
// string means that endpoint is not active. No self-dialing — reads only the Service's own
// listener handles + their configured addresses.
func (s *Service) BoundAddrs() (doh, dot, doq string) {
	if s.dohListener != nil {
		doh = s.cfg.ListenDoH
	}
	if s.dotListener != nil {
		dot = s.cfg.ListenDoT
	}
	if s.doqListener != nil {
		doq = s.cfg.ListenDoQ
	}
	return doh, dot, doq
}

// dohListener is an alias for DOHListener (internal implementation detail).
type dohListener = DOHListener

// newDOHListener creates a new DoH listener. enableH3 also serves DoH3 (HTTP/3 over QUIC).
func newDOHListener(addr string, tlsConfig *tls.Config, resolv resolver.Resolver, dnsCache *cache.Cache, validateFunc ValidateFunc, stats *statistics.Stats, logger *log.Logger, enableH3 bool) (*dohListener, error) {
	return NewDOHListener(addr, tlsConfig, resolv, dnsCache, validateFunc, stats, logger, enableH3)
}

func (d *dohListener) serve(ctx context.Context) {
	if err := d.Serve(ctx); err != nil {
		d.logger.Printf("DoH server error: %v", err)
	}
}

func (d *dohListener) close() error {
	return d.Close()
}

// dotListener is an alias for DOTListener (internal implementation detail).
type dotListener = DOTListener

// newDOTListener creates a new DoT listener.
func newDOTListener(addr string, tlsConfig *tls.Config, resolv resolver.Resolver, dnsCache *cache.Cache, validateFunc ValidateFunc, stats *statistics.Stats, logger *log.Logger) (*dotListener, error) {
	return NewDOTListener(addr, tlsConfig, resolv, dnsCache, validateFunc, stats, logger)
}

func (d *dotListener) serve(ctx context.Context) {
	if err := d.Serve(ctx); err != nil {
		d.logger.Printf("DoT server error: %v", err)
	}
}

func (d *dotListener) close() error {
	return d.Close()
}

// doqListener is an alias for DOQListener (internal implementation detail).
type doqListener = DOQListener

// newDOQListener creates a new DoQ listener.
func newDOQListener(addr string, tlsConfig *tls.Config, resolv resolver.Resolver, dnsCache *cache.Cache, validateFunc ValidateFunc, stats *statistics.Stats, logger *log.Logger) (*doqListener, error) {
	return NewDOQListener(addr, tlsConfig, resolv, dnsCache, validateFunc, stats, logger)
}

func (d *doqListener) serve(ctx context.Context) {
	if err := d.Serve(ctx); err != nil {
		d.logger.Printf("DoQ server error: %v", err)
	}
}

func (d *doqListener) close() error {
	return d.Close()
}

// autogenSANHosts collects the host portions of the configured Mode-2 listen addresses
// (DoH/DoT/DoQ) so the auto-generated self-signed cert covers the address clients actually
// connect to. Loopback is always included as a fallback. An unspecified bind (0.0.0.0 / ::)
// can't be put in a SAN meaningfully, so it is skipped (the operator should front it with a
// real hostname/cert); loopback still covers local testing.
func autogenSANHosts(cfg *config.UpstreamConfig) []string {
	seen := map[string]bool{}
	var hosts []string
	add := func(h string) {
		if h == "" || seen[h] {
			return
		}
		// Skip unspecified addresses — not meaningful in a SAN.
		if ip := net.ParseIP(h); ip != nil && ip.IsUnspecified() {
			return
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	for _, addr := range []string{cfg.ListenDoH, cfg.ListenDoT, cfg.ListenDoQ} {
		if addr == "" {
			continue
		}
		if h, _, err := net.SplitHostPort(addr); err == nil {
			add(h)
		}
	}
	// Operator-configured extra SAN entries (tunnel/LAN hostnames, extra IPs) that aren't the
	// bind address — e.g. a client reaching a public hostname that fronts a wildcard bind.
	for _, h := range cfg.TLSCertHosts {
		add(h)
	}
	// Always include loopback so local testing / health checks validate.
	add("127.0.0.1")
	add("localhost")
	return hosts
}

// generateSelfSignedCert generates a self-signed TLS certificate whose SAN covers the given
// hosts (IP literals go in IPAddresses, names in DNSNames). Returns PEM-encoded cert and key.
// Valid for 365 days. The first host is used as the Subject CommonName.
func generateSelfSignedCert(hosts []string) ([]byte, []byte, error) {
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1", "localhost"}
	}

	// Generate RSA private key (2048-bit)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate private key: %w", err)
	}

	// Split hosts into IP SANs vs DNS-name SANs.
	var dnsNames []string
	var ipAddrs []net.IP
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}

	// Create certificate template
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: hosts[0],
		},
		NotBefore: now,
		NotAfter:  now.AddDate(1, 0, 0), // Valid for 365 days
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    dnsNames,
		IPAddresses: ipAddrs,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyDER,
	})

	return certPEM, keyPEM, nil
}
