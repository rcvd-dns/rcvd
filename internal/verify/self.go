// SPDX-License-Identifier: MIT
package verify

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rcvd-dns/rcvd/internal/config"
)

// VerifySelf probes THIS instance's own Mode-2 listeners (DoH/DoT/DoQ) and reports the
// certificate each one actually presents to clients — the inward-looking mirror of
// VerifyUpstreams. It is the answer to "what am I presenting, is it valid, when does it
// expire, and is it the real CA-issued cert or still the self-signed autogen?".
//
// It works by performing a real TLS handshake against the running listener, so it sees the
// cert that is genuinely served regardless of source: an in-memory `tls_cert_autogen`
// self-signed cert, a certmagic/ACME cert materialized on first handshake, or a
// bring-your-own `tls_cert`/`tls_key`. Reading config or files cannot reveal the first two.
//
// serverNameOverride sets the TLS SNI for the probe; when empty, the SNI is derived from each
// listener's configured host (falling back to "localhost", which the autogen SAN always
// covers). certmagic on-demand only issues for an allowed domain, so a real public deployment
// should pass its DoH hostname via the override to exercise the on-demand path.
//
// Returns the formatted report and a bool that is true only if every probed endpoint
// succeeded (TLS handshake completed and a leaf cert was presented).
func VerifySelf(ctx context.Context, configPath string, cfg *config.UpstreamConfig, serverNameOverride string) (string, bool) {
	if !cfg.Enabled {
		return "RCVD Self (Mode-2) TLS Verification\n" +
			fmt.Sprintf("  Config: %s\n\n", configPath) +
			"  Mode 2 (upstream service) is not enabled in this config — nothing to verify.\n" +
			"  (--verify-self inspects the cert THIS instance presents on its DoH/DoT/DoQ listeners.)\n", false
	}

	endpoints := selfEndpoints(cfg)
	if len(endpoints) == 0 {
		return "RCVD Self (Mode-2) TLS Verification\n" +
			fmt.Sprintf("  Config: %s\n\n", configPath) +
			"  Mode 2 is enabled but no listener address is configured (listen_doh/listen_dot/listen_doq).\n", false
	}

	var results []UpstreamResult
	for _, ep := range endpoints {
		serverName := serverNameOverride
		if serverName == "" {
			serverName = ep.sni
		}

		probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		result, err := probeSelf(probeCtx, ep.protocol, serverName, ep.dialHost, ep.port)
		cancel()

		if err != nil {
			result = &UpstreamResult{Success: false, Error: err.Error()}
		}
		// Label with the listen address + SNI used, not an upstream name.
		result.Name = "Mode-2 " + ep.protocol
		result.Host = serverName
		result.Port = ep.port
		results = append(results, *result)
	}

	allOK := true
	for _, r := range results {
		if !r.Success {
			allOK = false
			break
		}
	}

	return formatSelfResults(configPath, results), allOK
}

// probeSelf performs a TLS handshake against THIS instance's own listener and returns the cert
// it presents. Two things differ deliberately from the upstream probes:
//
//   - InsecureSkipVerify is TRUE. The whole point is to RETRIEVE and report the served cert,
//     including a self-signed `tls_cert_autogen` one — which would fail chain verification and
//     abort the handshake before we could inspect it. We are not deciding to TRUST the cert
//     (that's a client's job against the public PKI); we are reporting WHAT is being served, and
//     classifySelfCert() then labels it self-signed vs CA-issued from the chain itself.
//   - ALPN is set to what each Mode-2 listener requires: rcvd's DoH server STRICTLY requires
//     "h2" (ISSUES 26 hard-close) and will fail the handshake otherwise; DoQ uses "doq"
//     (RFC 9250); DoT needs no specific ALPN.
func probeSelf(ctx context.Context, protocol, serverName, dialHost string, port int) (*UpstreamResult, error) {
	addr := net.JoinHostPort(dialHost, fmt.Sprintf("%d", port))

	switch protocol {
	case "DoQ":
		tlsConf := &tls.Config{
			ServerName:         serverName,
			NextProtos:         []string{"doq"},
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, //nolint:gosec // retrieve-don't-trust: we report the cert, not trust it
		}
		conn, err := quic.DialAddr(ctx, addr, tlsConf, &quic.Config{MaxIdleTimeout: 10 * time.Second})
		if err != nil {
			return nil, fmt.Errorf("QUIC dial: %w", err)
		}
		defer func() { _ = conn.CloseWithError(0, "verify complete") }()
		return buildResult("DoQ", serverName, port, conn.ConnectionState().TLS), nil

	case "DoH":
		return dialTCPSelf(ctx, "DoH", serverName, addr, port, []string{"h2"})

	default: // DoT
		return dialTCPSelf(ctx, "DoT", serverName, addr, port, nil)
	}
}

// dialTCPSelf is the shared TCP+TLS handshake for the DoH/DoT self-probes (skip-verify,
// optional ALPN), returning the presented cert chain.
func dialTCPSelf(ctx context.Context, protocol, serverName, addr string, port int, alpn []string) (*UpstreamResult, error) {
	tlsConf := &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         alpn,
		InsecureSkipVerify: true, //nolint:gosec // retrieve-don't-trust: we report the cert, not trust it
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
	return buildResult(protocol, serverName, port, conn.(*tls.Conn).ConnectionState()), nil
}

// selfEndpoint describes one Mode-2 listener to probe.
type selfEndpoint struct {
	protocol string // "DoH" | "DoT" | "DoQ"
	dialHost string // address to connect to (loopback substituted for an unspecified bind)
	port     int
	sni      string // default TLS SNI when no override is given
}

// selfEndpoints turns the configured Mode-2 listen addresses into probe targets. An
// unspecified bind (0.0.0.0 / ::) is dialed on loopback, since the listener accepts there;
// the default SNI for an IP/unspecified bind is "localhost" (always in the autogen SAN).
func selfEndpoints(cfg *config.UpstreamConfig) []selfEndpoint {
	var eps []selfEndpoint
	add := func(addr, proto string) {
		if addr == "" {
			return
		}
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return
		}
		port := 0
		fmt.Sscanf(portStr, "%d", &port)

		dialHost := host
		sni := host
		if ip := net.ParseIP(host); ip != nil {
			if ip.IsUnspecified() {
				dialHost = "127.0.0.1"
				sni = "localhost"
			} else {
				// An IP literal isn't a useful SNI; default to localhost which the
				// autogen SAN covers. An operator with a real cert passes -server-name.
				sni = "localhost"
			}
		}
		eps = append(eps, selfEndpoint{protocol: proto, dialHost: dialHost, port: port, sni: sni})
	}
	add(cfg.ListenDoH, "DoH")
	add(cfg.ListenDoT, "DoT")
	add(cfg.ListenDoQ, "DoQ")
	return eps
}

// formatSelfResults renders the self-verification report. It reuses the per-cert detail layout
// of the upstream report but frames the summary inward ("what I present") and adds an explicit
// self-signed-vs-CA classification — the single most useful line for a Mode-2 operator.
func formatSelfResults(configPath string, results []UpstreamResult) string {
	var b strings.Builder

	b.WriteString("RCVD Self (Mode-2) TLS Verification\n")
	fmt.Fprintf(&b, "  Config: %s\n", configPath)
	b.WriteString("  Probes THIS instance's listeners for the cert it presents to clients.\n")
	b.WriteByte('\n')

	for _, r := range results {
		fmt.Fprintf(&b, "Endpoint: %s   (SNI %s, port %d)\n", r.Name, r.Host, r.Port)

		if !r.Success {
			fmt.Fprintf(&b, "  Connection:  FAILED — %s\n", r.Error)
			b.WriteString("  (is this instance running with this Mode-2 listener enabled?)\n\n")
			continue
		}

		switch r.Protocol {
		case "DoQ":
			fmt.Fprintf(&b, "  Protocol:       QUIC + %s (DoQ, RFC 9250)\n", r.TLSVersion)
		case "DoT":
			fmt.Fprintf(&b, "  Protocol:       TCP + %s (DoT, RFC 7858)\n", r.TLSVersion)
		case "DoH":
			fmt.Fprintf(&b, "  Protocol:       TCP + %s (DoH, RFC 8484)\n", r.TLSVersion)
		}
		if r.ALPN != "" {
			fmt.Fprintf(&b, "  ALPN:           %s\n", r.ALPN)
		}
		fmt.Fprintf(&b, "  Cipher Suite:   %s\n", r.CipherSuite)

		for i, cert := range r.Certs {
			b.WriteByte('\n')
			label := "Intermediate"
			if i == 0 {
				label = "Leaf"
			}
			fmt.Fprintf(&b, "  [%d] %s\n", i, label)
			fmt.Fprintf(&b, "      Subject:      %s\n", cert.Subject)
			fmt.Fprintf(&b, "      Issuer:       %s\n", cert.Issuer)
			if len(cert.SANs) > 0 {
				fmt.Fprintf(&b, "      SANs:         %s\n", strings.Join(cert.SANs, ", "))
			}
			daysRemaining := int(math.Max(0, time.Until(cert.NotAfter).Hours()/24))
			fmt.Fprintf(&b, "      Valid:        %s — %s (%d days remaining)\n",
				cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"), daysRemaining)
			fmt.Fprintf(&b, "      Key:          %s %s\n", cert.KeyAlgorithm, cert.KeyDetail)
			if i == 0 {
				fmt.Fprintf(&b, "      Fingerprint:  %s\n", cert.Fingerprint)
				// The SPKI pin is the value a CLIENT pins via [[upstreams]] pinned_pubkey.
				// Printing it here (server side) so an operator managing BOTH ends can copy it
				// straight from --verify-self into the client config, then confirm with
				// --verify-pin — same "sha256//…" form on both sides, no format conversion.
				fmt.Fprintf(&b, "      SPKI pin:     %s\n", cert.SPKIPin)
			}
		}

		// Inward-facing summary: the cert SOURCE classification is what a Mode-2 operator
		// most needs ("am I still on the self-signed autogen, or a real CA cert?").
		b.WriteByte('\n')
		fmt.Fprintf(&b, "  Cert source:  %s\n", classifySelfCert(r.Certs))
		if r.DaysRemaining > 30 {
			fmt.Fprintf(&b, "  Expiry:       %d days remaining\n", r.DaysRemaining)
		} else if r.DaysRemaining > 0 {
			fmt.Fprintf(&b, "  Expiry:       WARNING — only %d days remaining\n", r.DaysRemaining)
		} else {
			b.WriteString("  Expiry:       EXPIRED\n")
		}
		b.WriteByte('\n')
	}

	return b.String()
}

// classifySelfCert inspects the presented chain and describes where the cert came from, in the
// terms a Mode-2 operator cares about: a self-signed cert (the tls_cert_autogen path — leaf is
// its own issuer, no chain) versus a CA-issued cert (a chain is present / issuer differs), with
// a best-effort issuer name. This is deliberately heuristic and descriptive, not a trust verdict
// — trust against the public PKI is what a real client does; here we just tell the operator what
// they are serving.
func classifySelfCert(certs []CertInfo) string {
	if len(certs) == 0 {
		return "unknown (no certificate presented)"
	}
	leaf := certs[0]
	selfSigned := leaf.Subject == leaf.Issuer && len(certs) == 1
	if selfSigned {
		return "SELF-SIGNED (tls_cert_autogen or self-signed file) — NOT a public-CA cert; " +
			"browsers/standards clients will reject it unless they trust it explicitly"
	}
	issuer := issuerCommonName(leaf.Issuer)
	if issuer == "" {
		issuer = leaf.Issuer
	}
	return fmt.Sprintf("CA-ISSUED — issuer %q (chain length %d)", issuer, len(certs))
}

// issuerCommonName pulls the CN out of an RFC 2253 issuer DN string ("CN=...,O=...") for a
// compact label; returns "" if there is no CN component.
func issuerCommonName(issuer string) string {
	for _, part := range strings.Split(issuer, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return ""
}
