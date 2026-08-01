// SPDX-License-Identifier: MIT
package verify

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rcvd-dns/rcvd/internal/config"
)

// VerifyPins validates each upstream's CONFIGURED pinned_pubkey against the
// certificate the server presents RIGHT NOW — dialing the way the live resolver
// path does (InsecureSkipVerify=true + manual SPKI compare, mirroring
// internal/resolver/pin.go), NOT the CA-validating way --verify-upstream dials.
//
// This is the audit half of the SPKI-pin lifecycle (bootstrap: --verify-upstream's
// gated pin print; config: pinned_pubkey; audit: --verify-pin). It answers ONE
// unambiguous question per pinned upstream: does the configured pin still MATCH
// what the server presents? — so it correctly reports OK for a pin-only, self-
// signed leg (posture 3, the encrypted LAN leg) that --verify-upstream FALSE-fails
// with "certificate signed by unknown authority". See repos/rcvd/TODO.md.
//
// Upstreams with NO pin configured are skipped (with a note) so the two verbs never
// overlap in meaning. Returns formatted output and allOK (true only if every pinned
// upstream matched); exit-code-friendly for cron/monitoring of far-end key rotation.
func VerifyPins(ctx context.Context, configPath string, upstreams []config.UpstreamServer) (string, bool) {
	type pinResult struct {
		name, host string
		port       int
		protocol   string
		pinned     bool
		ok         bool
		observed   string // the pin the server actually presented (for MISMATCH diagnosis)
		err        string
	}

	var results []pinResult
	for _, up := range upstreams {
		r := pinResult{name: up.Name, host: up.Host, port: up.Port, pinned: up.PinnedPubKey != ""}
		switch {
		case up.DoQ:
			r.protocol = "DoQ"
		case up.DoT:
			r.protocol = "DoT"
		case up.DoH:
			r.protocol = "DoH"
		}

		if !r.pinned {
			results = append(results, r)
			continue
		}

		probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		leaf, err := probePinLeaf(probeCtx, &up)
		cancel()
		if err != nil {
			r.err = err.Error()
			results = append(results, r)
			continue
		}

		// Compute the observed pin and constant-time compare against configured.
		want, perr := config.ParsePin(up.PinnedPubKey)
		if perr != nil {
			// Should be impossible (validated at config load), but never claim a
			// match we couldn't actually check.
			r.err = fmt.Sprintf("configured pin unparseable: %v", perr)
			results = append(results, r)
			continue
		}
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		r.observed = config.SPKIPin(leaf)
		r.ok = subtle.ConstantTimeCompare(sum[:], want) == 1
		results = append(results, r)
	}

	var b strings.Builder
	b.WriteString("RCVD Upstream Pin Verification\n")
	fmt.Fprintf(&b, "  Config: %s\n\n", configPath)

	allOK := true
	pinnedCount := 0
	for i, r := range results {
		label := r.name
		if label == "" {
			label = "(unnamed)"
		}
		fmt.Fprintf(&b, "Upstream %d: %s [%s] %s:%d\n", i, label, r.protocol, r.host, r.port)
		switch {
		case !r.pinned:
			b.WriteString("  Pin: (none configured) — use --verify-upstream for CA validation\n")
		case r.err != "":
			allOK = false
			pinnedCount++
			fmt.Fprintf(&b, "  Pin: FAILED — %s\n", r.err)
		case r.ok:
			pinnedCount++
			fmt.Fprintf(&b, "  Pin: OK — matches configured pinned_pubkey\n       %s\n", r.observed)
		default:
			allOK = false
			pinnedCount++
			b.WriteString("  Pin: MISMATCH — server key does NOT match configured pinned_pubkey\n")
			fmt.Fprintf(&b, "       configured: %s\n", up_pin(upstreams, i))
			fmt.Fprintf(&b, "       observed:   %s\n", r.observed)
		}
		b.WriteString("\n")
	}

	if pinnedCount == 0 {
		b.WriteString("No upstreams have a pinned_pubkey configured — nothing to verify.\n")
	}

	return b.String(), allOK
}

// up_pin returns the configured pin for the upstream at index i (helper for the
// MISMATCH diagnostic; kept out of the result struct so we don't copy secrets around).
func up_pin(upstreams []config.UpstreamServer, i int) string {
	if i >= 0 && i < len(upstreams) {
		return upstreams[i].PinnedPubKey
	}
	return ""
}

// probePinLeaf dials the upstream with CA validation DISABLED (as the live pinned
// resolver path does) and returns the peer LEAF certificate, WITHOUT judging the
// pin — the caller does the SPKI compare. We do NOT VerifyHostname here: the pin,
// not the name, is the trust root on this path, and requiring a hostname match
// would re-introduce exactly the CA-shaped failure --verify-pin exists to avoid
// for an IP-reached self-signed leg.
func probePinLeaf(ctx context.Context, up *config.UpstreamServer) (*x509.Certificate, error) {
	dialHost := up.DialHost()
	addr := net.JoinHostPort(dialHost, fmt.Sprintf("%d", up.Port))

	tlsConf := &tls.Config{
		ServerName:         up.Host,
		InsecureSkipVerify: true, // pin is the trust root here; we compare the key ourselves
		MinVersion:         tls.VersionTLS12,
	}

	if up.DoQ {
		tlsConf.NextProtos = []string{"doq"}
		tlsConf.MinVersion = tls.VersionTLS13
		quicConf := &quic.Config{MaxIdleTimeout: 10 * time.Second}
		conn, err := quic.DialAddr(ctx, addr, tlsConf, quicConf)
		if err != nil {
			return nil, fmt.Errorf("QUIC dial: %w", err)
		}
		defer func() { _ = conn.CloseWithError(0, "verify-pin complete") }()
		return leafFrom(conn.ConnectionState().TLS)
	}

	// DoT and DoH both terminate as a plain TLS handshake to the listener port.
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config:    tlsConf,
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TLS dial: %w", err)
	}
	defer conn.Close()
	return leafFrom(conn.(*tls.Conn).ConnectionState())
}

func leafFrom(state tls.ConnectionState) (*x509.Certificate, error) {
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificate presented")
	}
	return state.PeerCertificates[0], nil
}
