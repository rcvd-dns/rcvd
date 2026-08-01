// SPDX-License-Identifier: MIT
package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rcvd-dns/rcvd/internal/statistics"
	"golang.org/x/net/http2"
)

// HTTPResolver handles DNS-over-HTTPS (DoH) queries per RFC 8484.
// Key RFC 8484 points:
// - POST request to /dns-query endpoint (or configurable path)
// - Content-Type: application/dns-message
// - Accept: application/dns-message
// - Response: application/dns-message (binary DNS message)
//
// TRANSPORT NOTE — the underlying HTTP version is selectable:
//   - HTTP/2 over TCP   (default): classic DoH. Uses the stdlib http.Transport.
//   - HTTP/3 over QUIC  ("DoH3"):  uses the quic-go http3.Transport (RoundTripper).
//
// The request/response logic in Resolve() is identical for both; only the
// http.RoundTripper held by `client.Transport` differs.
type HTTPResolver struct {
	endpoint string // e.g., "https://dns.quad9.net:443/dns-query"
	client   *http.Client
	h3rt     *http3.Transport  // non-nil only when DoH3 (HTTP/3) is in use; kept for Close()
	stats    *statistics.Stats // optional, nil if stats disabled
}

// NewHTTPResolver creates a new DoH resolver.
// host is the TLS ServerName for SNI. dialHost is the address to dial (IP preferred).
// path is the HTTP path (default: /dns-query).
// useH3 selects the transport: false = HTTP/2 over TCP (classic DoH);
// true = HTTP/3 over QUIC (DoH3).
// pin, if non-empty, is an SPKI public-key pin ("sha256//BASE64") that replaces CA
// chain validation for this upstream (see pin.go); "" keeps normal CA validation.
// It applies to both the HTTP/2 and HTTP/3 transports (both share tlsConf).
func NewHTTPResolver(host, dialHost string, port int, path string, useH3 bool, pin string, stats *statistics.Stats) (*HTTPResolver, error) {
	endpoint := fmt.Sprintf("https://%s:%d%s", host, port, path)

	// Validate URL
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("DoH invalid endpoint: %w", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("DoH requires HTTPS, got: %s", parsedURL.Scheme)
	}

	// TLS config shared by both transports: SNI is always the hostname, even when
	// we dial an IP directly (bootstrap safety / avoiding a DNS lookup).
	tlsConf := &tls.Config{
		ServerName: host,
		// TLS 1.3 only (audit M5), matching the DoQ leg: keeps 1.3's downgrade
		// resistance and preserves the Go-default X25519MLKEM768 hybrid post-quantum
		// key exchange (a 1.3-only mechanism — rcvd's harvest-now-decrypt-later
		// defense). Do NOT set CurvePreferences: that would silently strip MLKEM768
		// (see repos/CLAUDE.md).
		MinVersion: tls.VersionTLS13,
	}
	// Apply SPKI pin verification when configured (no-op when pin == ""). Shared by
	// both the HTTP/2 and HTTP/3 transports below.
	tlsConf = pinnedTLSConfig(tlsConf, host, pin)
	dialAddr := net.JoinHostPort(dialHost, fmt.Sprintf("%d", port))

	r := &HTTPResolver{endpoint: endpoint, stats: stats}

	if useH3 {
		// --- HTTP/3 over QUIC (DoH3) ---
		// The Dial hook lets us connect to the pinned IP (dialHost) while keeping
		// the TLS ServerName as the hostname for SNI — the QUIC analogue of the
		// HTTP/2 DialContext override below.
		h3rt := &http3.Transport{
			TLSClientConfig: tlsConf,
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				// Ignore the address http3 wants to dial; use our pinned IP:port.
				udpAddr, err := net.ResolveUDPAddr("udp", dialAddr)
				if err != nil {
					return nil, err
				}
				udpConn, err := net.ListenUDP("udp", nil)
				if err != nil {
					return nil, err
				}
				return quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)
			},
		}
		r.h3rt = h3rt
		r.client = &http.Client{Transport: h3rt, Timeout: 30 * time.Second}
	} else {
		// --- HTTP/2 over TCP (classic DoH) ---
		// DialContext overrides the dial target to the pinned IP while TLS SNI
		// stays the hostname.
		//
		// STRICT HTTP/2 (mirrors the DoH SERVER's h2-only posture, ISSUES 26/32).
		// Go's http.Transport only auto-negotiates HTTP/2 when it dials the TLS
		// connection ITSELF; the moment a custom DialContext is set (as here, to reach
		// the pinned IP) the stdlib DISABLES its implicit h2 wiring and the transport
		// silently speaks HTTP/1.1. Against an HTTP/2-only upstream (e.g. Mullvad,
		// Quad9) that means every request fails: the server answers with an h2 SETTINGS
		// frame, which the h1 client parser reads as a "malformed HTTP response"
		// (\x00\x00\x06\x04… = length 6, type 0x04 SETTINGS). rcvd does NOT do cleartext
		// HTTP/1.1 DoH, so we force h2 two ways: advertise ONLY "h2" in ALPN (no
		// http/1.1 offer, so a mismatch fails the TLS handshake instead of downgrading),
		// and ConfigureTransport to attach the h2 protocol handler despite the custom dial.
		tlsConf.NextProtos = []string{"h2"}
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		transport := &http.Transport{
			TLSClientConfig:     tlsConf,
			ForceAttemptHTTP2:   true, // keep h2 negotiation on even with a custom DialContext
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     30 * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, dialAddr)
			},
		}
		// Explicitly wire Go's HTTP/2 onto this transport. ForceAttemptHTTP2 alone is not
		// sufficient once DialContext is set — ConfigureTransport installs the h2 handler
		// so the ALPN-negotiated "h2" is actually used (the client analogue of the server's
		// http2.ConfigureServer). Errors here are a programming error, not runtime.
		if err := http2.ConfigureTransport(transport); err != nil {
			return nil, fmt.Errorf("DoH HTTP/2 configure transport: %w", err)
		}
		r.client = &http.Client{Transport: transport, Timeout: 30 * time.Second}
	}

	return r, nil
}

// Resolve sends a DNS query over HTTPS and returns the response.
// Returns an error if:
// - HTTP request fails
// - Server returns non-200 status
// - Response body is invalid DNS message
// On error, callers should NOT fall back to cleartext. Instead, return SERVFAIL.
func (h *HTTPResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if h.stats != nil {
		atomic.AddInt64(&h.stats.DoHQueries, 1)
	}
	// Encode DNS message
	msgBytes, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("DoH pack: %w", err)
	}

	// Create POST request with DNS message as body
	req, err := http.NewRequestWithContext(ctx, "POST", h.endpoint, bytes.NewReader(msgBytes))
	if err != nil {
		return nil, fmt.Errorf("DoH request creation: %w", err)
	}

	// Set headers per RFC 8484
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// Send request
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server error: HTTP %d", resp.StatusCode)
	}

	// Read response body, bounded to prevent memory-exhaustion DoS from a
	// malicious or compromised upstream streaming an oversized body. A valid DNS
	// message never exceeds dns.MaxMsgSize (65535); a body capped at the limit
	// that isn't a valid DNS message will fail Unpack below and be rejected.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, fmt.Errorf("DoH read response: %w", err)
	}

	// Decode DNS response
	respMsg := &dns.Msg{}
	if err := respMsg.Unpack(respBody); err != nil {
		return nil, fmt.Errorf("DoH unpack response: %w", err)
	}

	return respMsg, nil
}

// Close closes the resolver (HTTP client cleanup). Handles both transports:
// the HTTP/2 stdlib transport and the HTTP/3 (DoH3) quic-go transport.
func (h *HTTPResolver) Close() error {
	if h.h3rt != nil {
		// HTTP/3 over QUIC (DoH3)
		return h.h3rt.Close()
	}
	if h.client != nil && h.client.Transport != nil {
		// HTTP/2 over TCP
		if t, ok := h.client.Transport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	}
	return nil
}
