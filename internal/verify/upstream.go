// SPDX-License-Identifier: MIT
package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"crypto/x509"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rcvd-dns/rcvd/internal/config"
)

// UpstreamResult holds the verification outcome for one upstream server.
type UpstreamResult struct {
	Name          string
	Host          string
	Port          int
	Protocol      string // "DoQ", "DoT", "DoH"
	Success       bool
	Error         string
	TLSVersion    string
	ALPN          string
	CipherSuite   string
	Certs         []CertInfo
	ChainValid    bool
	HostnameValid bool
	DaysRemaining int
	Pinned        bool // this upstream has a pinned_pubkey configured
}

// CertInfo holds human-readable certificate details.
type CertInfo struct {
	Subject      string
	Issuer       string
	SANs         []string
	NotBefore    time.Time
	NotAfter     time.Time
	KeyAlgorithm string
	KeyDetail    string // e.g. "P-256", "RSA 2048"
	Fingerprint  string // SHA256 colon-hex
	SPKIPin      string // "sha256//BASE64" — ready to paste into a client's pinned_pubkey
}

// VerifyUpstreams probes each configured upstream and returns formatted output.
func VerifyUpstreams(ctx context.Context, configPath string, upstreams []config.UpstreamServer) (string, bool) {
	var results []UpstreamResult

	for _, up := range upstreams {
		var result *UpstreamResult
		var err error

		probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		dialHost := up.DialHost()

		if up.DoQ {
			result, err = probeDoQ(probeCtx, up.Host, dialHost, up.Port)
		} else if up.DoT {
			result, err = probeDoT(probeCtx, up.Host, dialHost, up.Port)
		} else if up.DoH {
			result, err = probeDoH(probeCtx, up.Host, dialHost, up.Port)
		}
		cancel()

		if err != nil {
			result = &UpstreamResult{
				Success: false,
				Error:   err.Error(),
			}
		}

		result.Name = up.Name
		result.Host = up.Host
		result.Port = up.Port
		result.Pinned = up.PinnedPubKey != ""

		results = append(results, *result)
	}

	allOK := true
	for _, r := range results {
		if !r.Success {
			allOK = false
			break
		}
	}

	return formatResults(configPath, results), allOK
}

// probeDoT connects via TLS (RFC 7858) and extracts the certificate chain.
// host is TLS ServerName for SNI; dialHost is the connection target (IP or hostname).
func probeDoT(ctx context.Context, host, dialHost string, port int) (*UpstreamResult, error) {
	addr := net.JoinHostPort(dialHost, fmt.Sprintf("%d", port))
	tlsConf := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config:    tlsConf,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TLS dial: %w", err)
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()

	return buildResult("DoT", host, port, state), nil
}

// probeDoQ connects via QUIC+TLS 1.3 (RFC 9250) and extracts the certificate chain.
// host is TLS ServerName for SNI; dialHost is the connection target (IP or hostname).
func probeDoQ(ctx context.Context, host, dialHost string, port int) (*UpstreamResult, error) {
	addr := net.JoinHostPort(dialHost, fmt.Sprintf("%d", port))
	tlsConf := &tls.Config{
		ServerName: host,
		NextProtos: []string{"doq"},
		MinVersion: tls.VersionTLS13,
	}

	quicConf := &quic.Config{
		MaxIdleTimeout: 10 * time.Second,
	}

	conn, err := quic.DialAddr(ctx, addr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}
	defer func() {
		_ = conn.CloseWithError(0, "verify complete")
	}()

	state := conn.ConnectionState().TLS

	return buildResult("DoQ", host, port, state), nil
}

// probeDoH connects via TLS to the HTTPS port and extracts the certificate chain.
// We only need the TLS handshake — no HTTP request is sent.
// host is TLS ServerName for SNI; dialHost is the connection target (IP or hostname).
func probeDoH(ctx context.Context, host, dialHost string, port int) (*UpstreamResult, error) {
	addr := net.JoinHostPort(dialHost, fmt.Sprintf("%d", port))
	tlsConf := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config:    tlsConf,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TLS dial: %w", err)
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()

	return buildResult("DoH", host, port, state), nil
}

// buildResult constructs an UpstreamResult from a tls.ConnectionState.
func buildResult(protocol, host string, port int, state tls.ConnectionState) *UpstreamResult {
	result := &UpstreamResult{
		Host:       host,
		Port:       port,
		Protocol:   protocol,
		Success:    true,
		TLSVersion: tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}

	if state.NegotiatedProtocol != "" {
		result.ALPN = state.NegotiatedProtocol
	}

	// Extract certificate info
	result.Certs = extractCerts(state.PeerCertificates)

	// Chain validation — Go already verified this during handshake (InsecureSkipVerify=false),
	// but we verify again explicitly for the human-readable output.
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]

		// Build intermediate pool from chain
		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}

		_, verifyErr := leaf.Verify(x509.VerifyOptions{
			DNSName:       host,
			Roots:         roots,
			Intermediates: intermediates,
		})
		result.ChainValid = verifyErr == nil
		result.HostnameValid = leaf.VerifyHostname(host) == nil

		daysRemaining := time.Until(leaf.NotAfter).Hours() / 24
		result.DaysRemaining = int(math.Max(0, daysRemaining))
	}

	return result
}

// extractCerts parses x509 certificates into human-readable CertInfo structs.
func extractCerts(certs []*x509.Certificate) []CertInfo {
	var infos []CertInfo
	for _, cert := range certs {
		info := CertInfo{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			KeyAlgorithm: cert.PublicKeyAlgorithm.String(),
			Fingerprint:  fingerprint(cert),
			SPKIPin:      config.SPKIPin(cert),
		}

		// SANs: DNS names + IP addresses
		for _, dns := range cert.DNSNames {
			info.SANs = append(info.SANs, dns)
		}
		for _, ip := range cert.IPAddresses {
			info.SANs = append(info.SANs, ip.String())
		}

		// Key details
		switch pub := cert.PublicKey.(type) {
		case *ecdsa.PublicKey:
			info.KeyDetail = pub.Curve.Params().Name
		case *rsa.PublicKey:
			info.KeyDetail = fmt.Sprintf("RSA %d", pub.N.BitLen())
		default:
			info.KeyDetail = cert.PublicKeyAlgorithm.String()
		}

		infos = append(infos, info)
	}
	return infos
}

// fingerprint returns the SHA256 fingerprint of a DER-encoded certificate as base64.
// Matches the format used by OpenSSH since 6.8 (2015).
func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// formatResults renders verification results as human-readable text.
func formatResults(configPath string, results []UpstreamResult) string {
	var b strings.Builder

	b.WriteString("RCVD Upstream TLS Verification\n")
	b.WriteString(fmt.Sprintf("  Config: %s\n", configPath))
	b.WriteByte('\n')

	for i, r := range results {
		// Index is 0-based and matches the [[upstreams]] order — it is the value an
		// operator passes to the planned `--verify-upstream-key <index>` (see TODO.md).
		b.WriteString(fmt.Sprintf("Upstream %d: %s [%s] %s:%d\n", i, r.Name, r.Protocol, r.Host, r.Port))

		if !r.Success {
			b.WriteString(fmt.Sprintf("  Connection:  FAILED — %s\n", r.Error))
			// This upstream is pin-verified in production (InsecureSkipVerify + SPKI
			// compare, resolver/pin.go), NOT CA-verified — so a CA-chain failure here
			// is EXPECTED for a pin-only self-signed leg and does NOT mean the live
			// path is broken. Steer the operator to the verb that asks the right
			// question. --verify-upstream itself stays deliberately CA-only (TODO.md).
			if r.Pinned {
				b.WriteString("               (this upstream sets pinned_pubkey — it is verified by SPKI pin,\n")
				b.WriteString("                not CA chain; use --verify-pin to validate the configured pin)\n")
			}
			b.WriteByte('\n')
			continue
		}

		// Protocol line
		switch r.Protocol {
		case "DoQ":
			b.WriteString(fmt.Sprintf("  Protocol:       QUIC + %s (DoQ, RFC 9250)\n", r.TLSVersion))
		case "DoT":
			b.WriteString(fmt.Sprintf("  Protocol:       TCP + %s (DoT, RFC 7858)\n", r.TLSVersion))
		case "DoH":
			b.WriteString(fmt.Sprintf("  Protocol:       TCP + %s (DoH, RFC 8484)\n", r.TLSVersion))
		}

		if r.ALPN != "" {
			b.WriteString(fmt.Sprintf("  ALPN:           %s\n", r.ALPN))
		}
		b.WriteString(fmt.Sprintf("  Cipher Suite:   %s\n", r.CipherSuite))

		// Certificates
		for i, cert := range r.Certs {
			b.WriteByte('\n')

			label := "Intermediate"
			if i == 0 {
				label = "Leaf"
			}
			b.WriteString(fmt.Sprintf("  [%d] %s\n", i, label))
			b.WriteString(fmt.Sprintf("      Subject:      %s\n", cert.Subject))
			b.WriteString(fmt.Sprintf("      Issuer:       %s\n", cert.Issuer))

			if len(cert.SANs) > 0 {
				b.WriteString(fmt.Sprintf("      SANs:         %s\n", strings.Join(cert.SANs, ", ")))
			}

			daysRemaining := int(math.Max(0, time.Until(cert.NotAfter).Hours()/24))
			b.WriteString(fmt.Sprintf("      Valid:        %s — %s (%d days remaining)\n",
				cert.NotBefore.Format("2006-01-02"),
				cert.NotAfter.Format("2006-01-02"),
				daysRemaining,
			))

			b.WriteString(fmt.Sprintf("      Key:          %s %s\n", cert.KeyAlgorithm, cert.KeyDetail))

			if i == 0 {
				b.WriteString(fmt.Sprintf("      Fingerprint:  %s\n", cert.Fingerprint))
				// SPKI pin of the leaf key. Only shown when this upstream actually has a
				// pinned_pubkey configured — for an unpinned public resolver (e.g. 9.9.9.9)
				// printing a computed pin misleadingly implies pinning is in force when it
				// is not. To obtain a pin for MANUAL pinning of a currently-unpinned
				// upstream, a dedicated key-only command is planned (see TODO). When shown,
				// this survives cert re-issue with the same keypair.
				if r.Pinned {
					b.WriteString(fmt.Sprintf("      SPKI pin:     %s\n", cert.SPKIPin))
				}
			}
		}

		// Summary assertions
		b.WriteByte('\n')
		if r.ChainValid {
			b.WriteString("  Chain:     Verified against system CA bundle\n")
		} else {
			b.WriteString("  Chain:     FAILED — certificate chain does not verify\n")
		}
		if r.HostnameValid {
			b.WriteString(fmt.Sprintf("  Hostname:  %s matches certificate SANs\n", r.Host))
		} else {
			b.WriteString(fmt.Sprintf("  Hostname:  FAILED — %s does not match certificate SANs\n", r.Host))
		}
		if r.DaysRemaining > 30 {
			b.WriteString(fmt.Sprintf("  Expiry:    %d days remaining\n", r.DaysRemaining))
		} else if r.DaysRemaining > 0 {
			b.WriteString(fmt.Sprintf("  Expiry:    WARNING — only %d days remaining\n", r.DaysRemaining))
		} else {
			b.WriteString("  Expiry:    EXPIRED\n")
		}

		b.WriteByte('\n')
	}

	return b.String()
}

// protocolLabel returns a human-readable label for a protocol.
func protocolLabel(protocol string) string {
	switch protocol {
	case "DoQ":
		return "QUIC + TLS 1.3 (DoQ, RFC 9250)"
	case "DoT":
		return "TCP + TLS (DoT, RFC 7858)"
	case "DoH":
		return "TCP + TLS (DoH, RFC 8484)"
	default:
		return protocol
	}
}
