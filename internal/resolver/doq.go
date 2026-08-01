// SPDX-License-Identifier: MIT
package resolver

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/rcvd-dns/rcvd/internal/statistics"
)

// DoQResolver handles DNS-over-QUIC (DoQ) queries per RFC 9250.
// Key RFC 9250 points:
// - ALPN: "doq"
// - DNS Message ID must be 0 on the wire
// - Each query uses a separate bidirectional stream on the connection (§4.2)
// - 2-byte big-endian length prefix before each DNS message (§4.2)
// - Connection reuse: clients SHOULD reuse connections (§5.5.1)
// - Idle timeout: close and reconnect when idle time approaches timeout (§4.4)
type DoQResolver struct {
	host     string // TLS ServerName (SNI) for certificate validation
	dialHost string // address to dial (IP or hostname)
	port     int
	pin      string            // optional SPKI pin ("sha256//..."); "" = normal CA validation
	stats    *statistics.Stats // optional, nil if stats disabled
	logger   *log.Logger       // optional, nil = no retry-path logging (Issue 31)

	// TLS session resumption cache (RFC 9250 §5.5.3). Created once and reused
	// across dials so re-connections after idle-close resume at 1-RTT instead of
	// paying a full handshake. This does NOT enable 0-RTT early data (see §7.1
	// replay risk) — resumption only accepts the §7.2 linkability tradeoff.
	sessionCache tls.ClientSessionCache

	// Connection pooling per RFC 9250 §5.5.1
	mu       sync.Mutex
	conn     *quic.Conn
	lastUsed time.Time
}

// NewDoQResolver creates a new DoQ resolver.
// host is the TLS ServerName for SNI. dialHost is the address to dial (IP preferred).
// pin, if non-empty, is an SPKI public-key pin ("sha256//BASE64") that replaces CA
// chain validation for this upstream (see pin.go); "" keeps normal CA validation.
func NewDoQResolver(host, dialHost string, port int, pin string, stats *statistics.Stats) *DoQResolver {
	return &DoQResolver{
		host:     host,
		dialHost: dialHost,
		port:     port,
		pin:      pin,
		stats:    stats,
		// Small LRU is sufficient: a single upstream needs only a handful of
		// resumption tickets in flight. Persists for the resolver's lifetime.
		sessionCache: tls.NewLRUClientSessionCache(8),
	}
}

// SetLogger wires an optional logger for retry-path diagnostics (Issue 31). When set,
// a retried exchange logs which failure triggered the retry — an idle-gap read failure
// (benign, expected) vs. a response-question mismatch (rare, signals cross-wiring). Kept
// off the constructor so existing callers/tests are undisturbed; nil = silent.
func (q *DoQResolver) SetLogger(l *log.Logger) { q.logger = l }

// logRetry emits one retry-path line if a logger is wired. cause is the classified reason.
func (q *DoQResolver) logRetry(cause string, err error) {
	if q.logger != nil {
		q.logger.Printf("DoQ retry: %s — %v", cause, err)
	}
}

// Resolve sends a DNS query over QUIC and returns the response.
// On error, callers should NOT fall back to cleartext. Instead, return SERVFAIL.
//
// A single exchange runs via exchangeOnce. Any STREAM-scoped failure — a read
// failure on a reused-but-stale connection, or a response-question mismatch — is
// retried EXACTLY ONCE on a freshly dialed connection before giving up (Issue 31).
// This absorbs the dominant field failure: when the router closes an idle connection
// at 30s and a batch of concurrent queries reuse it, the first read on each fails at
// once — a burst of same-second SERVFAILs that a single re-dial + re-ask silences.
// Bounded to one retry so a genuinely down leg still fails fast (no retry storm).
func (q *DoQResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if q.stats != nil {
		atomic.AddInt64(&q.stats.DoQQueries, 1)
	}

	resp, retryable, err := q.exchangeOnce(ctx, msg)
	if err == nil {
		return resp, nil
	}
	// Only stream-scoped failures are safe to retry — a connection-level failure
	// (dial/getConnection) already tried a fresh conn inside exchangeOnce.
	if !retryable {
		return nil, err
	}

	// Classify for the log: a question mismatch is rare and signals residual cross-wiring;
	// everything else here is the benign idle-gap read failure we expect under load.
	if err != nil && err == errDoQQuestionMismatch {
		q.logRetry("response question mismatch (rare — investigate cross-wiring)", err)
	} else {
		q.logRetry("stale-conn read failure (idle gap)", err)
	}

	// One retry on a guaranteed-fresh connection.
	resp, _, err = q.exchangeOnce(ctx, msg)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// errDoQQuestionMismatch marks the correlation-guard failure so the retry path can log it
// distinctly. Sentinel (not wrapped with %w) — callers compare identity, not chains.
var errDoQQuestionMismatch = fmt.Errorf("DoQ response question does not match query")

// exchangeOnce performs one full DoQ request/response on the pooled connection.
// Returns (response, retryable, error). retryable is true when the failure is
// stream-scoped (read/unpack/correlation) and a re-ask on a fresh connection could
// succeed; it is false for pack errors (the query itself is bad) and connection
// failures (already retried internally). On any stream-scoped failure it recycles the
// exact connection it used (identity-checked, so a sibling's fresh conn is never torn
// down — the original Issue 31 shared-teardown fix, preserved).
func (q *DoQResolver) exchangeOnce(ctx context.Context, msg *dns.Msg) (*dns.Msg, bool, error) {
	conn, err := q.getConnection(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("DoQ connection: %w", err)
	}

	// Each query gets its own stream per RFC 9250 §4.2. The connection is shared across
	// all concurrent Resolve() calls — QUIC multiplexes streams safely, so opening/reading
	// our own stream never disturbs a sibling's. What we must not do is tear the shared
	// connection down out from under in-flight siblings: every teardown below is scoped to
	// the exact *conn we used (recycleConn), so a stale/racing close can't kill a connection
	// a sibling already replaced (ISSUES 31 — shared-connection teardown race).
	stream, err := q.openStream(ctx, conn)
	if err != nil {
		// This connection is unusable (server closed it, or it idled out). Recycle this
		// conn (only if it's still the pooled one) and dial a fresh one. A stream that
		// cannot even be opened means the outer retry has nothing to add, so this local
		// re-dial is kept — but classified non-retryable to avoid a third attempt.
		q.recycleConn(conn)
		conn, err = q.getConnection(ctx)
		if err != nil {
			return nil, false, fmt.Errorf("DoQ reconnect: %w", err)
		}
		stream, err = q.openStream(ctx, conn)
		if err != nil {
			q.recycleConn(conn)
			return nil, false, fmt.Errorf("DoQ stream: %w", err)
		}
	}

	// Bound the whole exchange with a stream deadline. QUIC stream reads honor the stream's
	// deadline, NOT the context — without this, a read on a silently-dead pooled connection
	// blocks until the 30s MaxIdleTimeout (the 25.9s+ max-latency outlier, Issue 31). With it,
	// a stale conn's read fails in streamExchangeTimeout and the exchange retry re-dials fast.
	// If the caller's ctx deadline is sooner, honor that instead.
	deadline := time.Now().Add(streamExchangeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	stream.SetDeadline(deadline)

	// Encode DNS message. A pack failure is the query's fault, not the connection's — not
	// retryable.
	msgBytes, err := msg.Pack()
	if err != nil {
		stream.Close()
		return nil, false, fmt.Errorf("DoQ pack: %w", err)
	}

	// Write length-prefixed DNS message (RFC 9250 §4.2)
	lengthPrefix := []byte{byte(len(msgBytes) >> 8), byte(len(msgBytes))}
	if _, err := stream.Write(lengthPrefix); err != nil {
		stream.Close()
		q.recycleConn(conn)
		return nil, true, fmt.Errorf("DoQ write length: %w", err)
	}
	if _, err := stream.Write(msgBytes); err != nil {
		stream.Close()
		q.recycleConn(conn)
		return nil, true, fmt.Errorf("DoQ write msg: %w", err)
	}

	// Close write side of stream (sends FIN) — signal end of request
	// In quic-go, stream.Close() only closes the send side, reads remain open
	stream.Close()

	// Read response length prefix (2 bytes). A read failure here is stream-scoped (this
	// query's stream), not proof the shared connection is dead — recycleConn only recycles
	// if this conn is still the pooled one, so a sibling reading a healthy stream is never
	// disturbed. Marked retryable: on a reused-but-stale conn this is exactly the idle-gap
	// failure the outer retry silences.
	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lengthBuf); err != nil {
		q.recycleConn(conn)
		return nil, true, fmt.Errorf("DoQ read length: %w", err)
	}

	respLen := int(lengthBuf[0])<<8 | int(lengthBuf[1])
	if respLen == 0 || respLen > 65535 {
		q.recycleConn(conn)
		return nil, true, fmt.Errorf("DoQ invalid response length: %d", respLen)
	}

	// Read exactly respLen bytes of DNS response
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(stream, respBuf); err != nil {
		q.recycleConn(conn)
		return nil, true, fmt.Errorf("DoQ read msg: %w", err)
	}

	// Decode DNS response
	resp := &dns.Msg{}
	if err := resp.Unpack(respBuf); err != nil {
		q.recycleConn(conn)
		return nil, true, fmt.Errorf("DoQ unpack: %w", err)
	}

	// Transport-layer correlation guard (defense in depth, ISSUES 31). Each DoQ query has
	// its own stream, so the response read off this stream is by construction the answer to
	// this query — but we refuse to return a message whose question does not match what we
	// sent rather than ever hand a caller a foreign answer. RFC 9250 forces the wire ID to 0,
	// so the ID is not a usable discriminator — the question section is. Retryable, and
	// logged distinctly by the caller since a mismatch is the rare, serious case.
	if !doqResponseMatchesQuery(msg, resp) {
		q.recycleConn(conn)
		return nil, true, errDoQQuestionMismatch
	}

	// Update last-used time for idle timeout tracking
	q.mu.Lock()
	q.lastUsed = time.Now()
	q.mu.Unlock()

	return resp, false, nil
}

// openStreamTimeout bounds how long we wait to open a stream on a pooled connection.
// A QUIC peer that vanished SILENTLY (suspend, cable pull — no CONNECTION_CLOSE frame)
// leaves the conn looking alive until our 30s MaxIdleTimeout fires, so OpenStreamSync
// would otherwise block the full 30s (this is the 25.9s+ max-latency outlier in the
// field stats, Issue 31). Capping it here lets recycleConn + the exchange retry re-dial
// in a couple seconds instead. A healthy conn opens a stream in microseconds, so this
// never trips in the normal case.
const openStreamTimeout = 2 * time.Second

// streamExchangeTimeout bounds the write+read of a single DoQ exchange via the stream
// deadline (QUIC stream I/O honors the deadline, not the context). Deliberately well under
// a caller's typical 5s query budget so that when the FIRST attempt trips this on a stale
// conn, there is still budget left for the exchange retry to re-dial and succeed (Issue 31).
// Sized for a LAN leg with sub-ms RTT plus upstream slack; trips instead of hanging to the
// 30s idle timeout. The caller's ctx deadline still wins when it is sooner.
const streamExchangeTimeout = 2 * time.Second

// openStream opens a bidirectional stream on conn, bounded by openStreamTimeout so a
// silently-dead pooled connection is detected quickly rather than after the idle timeout.
func (q *DoQResolver) openStream(ctx context.Context, conn *quic.Conn) (*quic.Stream, error) {
	osCtx, cancel := context.WithTimeout(ctx, openStreamTimeout)
	defer cancel()
	return conn.OpenStreamSync(osCtx)
}

// getConnection returns a reusable QUIC connection per RFC 9250 §5.5.1.
// Creates a new connection if none exists or if the idle time approaches the timeout.
func (q *DoQResolver) getConnection(ctx context.Context) (*quic.Conn, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Reuse existing connection only while comfortably inside the idle timeout (§4.4).
	// Margin widened from 5s to 10s (Issue 31): the peer's 30s MaxIdleTimeout and ours
	// can disagree by a keepalive interval, and clock/scheduling slop near the edge meant
	// a "reused" conn was sometimes already half-closed on the server — the first read
	// then failed for a whole batch of concurrent queries at once. Reconnecting at 20s
	// keeps reuse (the common case is sub-second gaps) while staying clear of the cliff;
	// the exchange-level retry is the backstop for the races this doesn't cover.
	if q.conn != nil {
		idleTime := time.Since(q.lastUsed)
		if idleTime < 20*time.Second { // 10s margin before 30s idle timeout
			return q.conn, nil
		}
		// Too close to idle timeout, close and reconnect
		q.conn.CloseWithError(0, "idle timeout approaching")
		q.conn = nil
	}

	conn, err := q.dial(ctx)
	if err != nil {
		return nil, err
	}

	q.conn = conn
	q.lastUsed = time.Now()
	return conn, nil
}

// dial creates a new QUIC connection to the upstream server.
func (q *DoQResolver) dial(ctx context.Context) (*quic.Conn, error) {
	addr := net.JoinHostPort(q.dialHost, fmt.Sprintf("%d", q.port))
	tlsConf := &tls.Config{
		ServerName:         q.host,          // TLS SNI — always the hostname, even when dialing by IP
		NextProtos:         []string{"doq"}, // RFC 9250: ALPN must be "doq"
		MinVersion:         tls.VersionTLS13,
		ClientSessionCache: q.sessionCache, // 1-RTT resume on re-dial (RFC 9250 §5.5.3)
	}
	// Apply SPKI pin verification when configured (no-op when q.pin == "").
	tlsConf = pinnedTLSConfig(tlsConf, q.host, q.pin)

	quicConf := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 5 * time.Second,
		// Fail a dial to a truly-down peer fast instead of hanging (Issue 31): without
		// this a fresh dial to a vanished router could block far longer than a caller's
		// query budget. Kept short since the LAN leg's RTT is sub-millisecond.
		HandshakeIdleTimeout:   5 * time.Second,
		MaxStreamReceiveWindow: 8 * 1024 * 1024,
	}

	conn, err := quic.DialAddr(ctx, addr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("DoQ dial: %w", err)
	}

	return conn, nil
}

// closeConnection closes and discards the current pooled connection.
func (q *DoQResolver) closeConnection() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.conn != nil {
		q.conn.CloseWithError(0, "connection reset")
		q.conn = nil
	}
}

// recycleConn discards a specific connection that a query found unusable, but ONLY if it
// is still the pooled connection — the crux of the ISSUES 31 fix. The connection is shared
// by every concurrent Resolve(); if query A's stream errored on conn X, A must not tear down
// whatever q.conn is NOW, because a sibling may already have replaced X with a fresh conn Y
// that other queries are happily using. Comparing identity (bad == q.conn) means only the
// FIRST caller to notice conn X is bad clears it; everyone else's recycleConn(X) is a no-op.
// The QUIC connection is reference-safe to CloseWithError more than once, but we avoid
// closing the live pooled conn a sibling still needs.
func (q *DoQResolver) recycleConn(bad *quic.Conn) {
	if bad == nil {
		return
	}
	q.mu.Lock()
	if q.conn == bad {
		q.conn = nil
	}
	q.mu.Unlock()
	// Close the bad connection itself regardless (idempotent); we only guarded the POOL
	// pointer above so we don't strand a sibling's freshly-dialed replacement.
	bad.CloseWithError(0, "connection reset")
}

// doqResponseMatchesQuery reports whether resp answers exactly the single question in
// query, comparing QTYPE, QCLASS, and a case-insensitive QNAME (RFC 4343). Mirrors the
// FallbackResolver guard; kept local so the DoQ client is self-correct without importing it.
func doqResponseMatchesQuery(query, resp *dns.Msg) bool {
	if len(query.Question) != 1 || len(resp.Question) != 1 {
		return false
	}
	a, b := query.Question[0], resp.Question[0]
	return a.Qtype == b.Qtype &&
		a.Qclass == b.Qclass &&
		dns.CanonicalName(a.Name) == dns.CanonicalName(b.Name)
}

// Close closes the resolver and any open connections.
func (q *DoQResolver) Close() error {
	q.closeConnection()
	return nil
}
