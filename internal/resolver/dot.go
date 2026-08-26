// SPDX-License-Identifier: MIT
package resolver

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/rcvd-dns/rcvd/internal/statistics"
)

// TLSResolver handles DNS-over-TLS (DoT) queries per RFC 7858.
// Key RFC 7858 points:
// - Connection on TCP port 853 (or 53 via cleartext + STARTTLS, not supported here)
// - TLS 1.2+ required
// - RFC 1035 DNS message format (2-byte length prefix + message)
// - Keep-alive: connections can be reused for multiple queries
// - Server name indication (SNI) for virtual hosting
type TLSResolver struct {
	host     string // TLS ServerName (SNI) for certificate validation
	dialHost string // address to dial (IP or hostname)
	port     int
	pin      string            // optional SPKI pin ("sha256//..."); "" = normal CA validation
	stats    *statistics.Stats // optional, nil if stats disabled

	// Connection pooling
	mu   sync.Mutex
	conn *tls.Conn

	// exchMu serializes a whole write→read exchange on the single pooled conn.
	// The DoT pool holds exactly one connection with no in-flight ID demux, so
	// two concurrent queries would otherwise interleave their writes/reads and
	// read each other's replies (the "question does not match query" symptom).
	exchMu sync.Mutex
}

// NewTLSResolver creates a new DoT resolver.
// host is the TLS ServerName for SNI. dialHost is the address to dial (IP preferred).
// pin, if non-empty, is an SPKI public-key pin ("sha256//BASE64") that replaces CA
// chain validation for this upstream (see pin.go); "" keeps normal CA validation.
func NewTLSResolver(host, dialHost string, port int, pin string, stats *statistics.Stats) *TLSResolver {
	return &TLSResolver{
		host:     host,
		dialHost: dialHost,
		port:     port,
		pin:      pin,
		stats:    stats,
	}
}

// Resolve sends a DNS query over TLS and returns the response.
// Returns an error if:
// - Connection fails (network error, timeout, TLS handshake)
// - Protocol error (invalid response format)
// - Query encoding fails
// On error, callers should NOT fall back to cleartext. Instead, return SERVFAIL.
//
// If a pooled connection is stale (broken pipe, EOF), the connection is discarded
// and the query is retried once on a fresh connection.
func (t *TLSResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if t.stats != nil {
		atomic.AddInt64(&t.stats.DoTQueries, 1)
	}
	// Capture pooled-ness BEFORE the first attempt: resolveOnce discards the
	// connection on every error path (broken pipe, EOF, short read, ID mismatch),
	// so checking t.isPooled() afterwards is always false and the retry never
	// fires. A pooled conn can go stale server-side after an idle gap (Mullvad
	// closes idle DoT conns); with a single upstream that first dead-conn write
	// is instantly "all upstreams failed" → SERVFAIL. Retry once on a fresh dial.
	pooledBefore := t.isPooled()
	resp, err := t.resolveOnce(ctx, msg)
	if err != nil && pooledBefore {
		return t.resolveOnce(ctx, msg)
	}
	return resp, err
}

// isPooled returns true if there is a cached connection in the pool.
func (t *TLSResolver) isPooled() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn != nil
}

// resolveOnce performs a single DNS query over TLS.
func (t *TLSResolver) resolveOnce(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// One in-flight exchange per pooled conn (see exchMu). Held across the whole
	// write→read so concurrent queries can't cross-wire on the shared connection.
	t.exchMu.Lock()
	defer t.exchMu.Unlock()

	conn, err := t.getConnection(ctx)
	if err != nil {
		return nil, fmt.Errorf("DoT connection: %w", err)
	}

	// Encode DNS message
	msgBytes, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("DoT pack: %w", err)
	}

	// Write length-prefixed DNS message (RFC 1035 §4.2.2)
	lengthPrefix := []byte{byte(len(msgBytes) >> 8), byte(len(msgBytes))}
	if _, err := conn.Write(lengthPrefix); err != nil {
		t.closeConnection()
		return nil, fmt.Errorf("DoT write length: %w", err)
	}
	if _, err := conn.Write(msgBytes); err != nil {
		t.closeConnection()
		return nil, fmt.Errorf("DoT write msg: %w", err)
	}

	// Read response length. io.ReadFull, not conn.Read: a split TCP segment can
	// deliver fewer than 2 bytes on a single Read, which would misparse the length.
	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		t.closeConnection()
		return nil, fmt.Errorf("DoT read length: %w", err)
	}

	respLen := int(lengthBuf[0])<<8 | int(lengthBuf[1])
	if respLen == 0 || respLen > 65535 {
		t.closeConnection()
		return nil, fmt.Errorf("DoT invalid response length: %d", respLen)
	}

	// Read DNS response (io.ReadFull to handle a body split across TCP segments)
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		t.closeConnection()
		return nil, fmt.Errorf("DoT read msg: %w", err)
	}

	// Decode DNS response
	resp := &dns.Msg{}
	if err := resp.Unpack(respBuf); err != nil {
		t.closeConnection()
		return nil, fmt.Errorf("DoT unpack: %w", err)
	}

	// Response-ID sanity check: a mismatch means the pooled conn is out of sync
	// (a stale reply from an earlier query is buffered ahead of ours). Discard
	// the conn so the retry in Resolve gets a clean dial. Cheap correlation
	// defense in the spirit of the Issue 31 DoQ fix; the fallback layer's
	// question-match check remains the outer guard.
	if resp.Id != msg.Id {
		t.closeConnection()
		return nil, fmt.Errorf("DoT response ID mismatch: got %d, want %d", resp.Id, msg.Id)
	}

	return resp, nil
}

// getConnection returns a reusable TLS connection, creating one if needed.
func (t *TLSResolver) getConnection(ctx context.Context) (*tls.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if existing connection is still open
	if t.conn != nil {
		// Verify connection is alive (no errors on read/write)
		// Simple check: if conn exists, try to use it
		return t.conn, nil
	}

	// Create new TLS connection
	addr := net.JoinHostPort(t.dialHost, fmt.Sprintf("%d", t.port))

	tlsConf := &tls.Config{
		ServerName: t.host, // TLS SNI — always the hostname, even when dialing by IP
		// TLS 1.3 only (audit M5), matching the DoQ leg: keeps 1.3's downgrade
		// resistance and preserves the Go-default X25519MLKEM768 hybrid post-quantum
		// key exchange (a 1.3-only mechanism — rcvd's harvest-now-decrypt-later
		// defense). Do NOT set CurvePreferences: that would silently strip MLKEM768
		// (see repos/CLAUDE.md).
		MinVersion: tls.VersionTLS13,
	}
	// Apply SPKI pin verification when configured (no-op when t.pin == "").
	tlsConf = pinnedTLSConfig(tlsConf, t.host, t.pin)

	// TLS dial with context timeout
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	tlsConn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConf)
	if err != nil {
		return nil, fmt.Errorf("DoT TLS dial: %w", err)
	}

	t.conn = tlsConn
	return tlsConn, nil
}

// closeConnection closes and discards the current connection.
func (t *TLSResolver) closeConnection() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
}

// Close closes the resolver and any open connections.
func (t *TLSResolver) Close() error {
	t.closeConnection()
	return nil
}
