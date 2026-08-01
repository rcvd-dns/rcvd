// SPDX-License-Identifier: MIT
package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/rcvd-dns/rcvd/internal/cache"
	"github.com/rcvd-dns/rcvd/internal/resolver"
	"github.com/rcvd-dns/rcvd/internal/statistics"
)

// DOQListener handles DNS-over-QUIC (DoQ) connections.
// RFC 9250: DNS over QUIC (DoQ)
// Accepts QUIC connections and handles DNS messages with 2-byte length prefix per stream.
type DOQListener struct {
	addr         string
	tlsConfig    *tls.Config
	resolv       resolver.Resolver
	cache        *cache.Cache      // SHARED instance cache (may be nil)
	validateFunc ValidateFunc      // optional DNSSEC validation callback
	stats        *statistics.Stats // optional runtime statistics
	logger       *log.Logger
	listener     *quic.Listener
	udpConn      net.PacketConn
	closeOnce    sync.Once // guards Close (idempotent without racing Serve's field reads)
}

// NewDOQListener creates a new DoQ listener.
func NewDOQListener(addr string, tlsConfig *tls.Config, resolv resolver.Resolver, dnsCache *cache.Cache, validateFunc ValidateFunc, stats *statistics.Stats, logger *log.Logger) (*DOQListener, error) {
	// Parse address
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP addr: %w", err)
	}

	// Create UDP listener
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	// DoQ REQUIRES the "doq" ALPN token (RFC 9250 §4.1). The TLS config handed in is
	// SHARED with the DoT/DoH listeners (which don't set NextProtos), so a QUIC server
	// built from it directly advertises NO ALPN and the handshake fails with
	// "server did not select an ALPN protocol". Clone it and pin NextProtos=["doq"]
	// locally so we don't mutate the shared config the other listeners use.
	if tlsConfig != nil {
		tlsConfig = tlsConfig.Clone()
		tlsConfig.NextProtos = []string{"doq"}
	}

	// Create QUIC listener
	quicConfig := &quic.Config{
		MaxIdleTimeout:          30 * time.Second,
		KeepAlivePeriod:         15 * time.Second,
		DisablePathMTUDiscovery: false,
	}

	quicListener, err := quic.Listen(udpConn, tlsConfig, quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("listen QUIC: %w", err)
	}

	return &DOQListener{
		addr:         addr,
		tlsConfig:    tlsConfig,
		resolv:       resolv,
		cache:        dnsCache,
		validateFunc: validateFunc,
		stats:        stats,
		logger:       logger,
		listener:     quicListener,
		udpConn:      udpConn,
	}, nil
}

// Serve accepts and handles DoQ connections.
// Blocks until context is cancelled.
func (d *DOQListener) Serve(ctx context.Context) error {
	if d.listener == nil {
		return fmt.Errorf("listener not initialized")
	}

	d.logger.Printf("DoQ server listening on %s", d.addr)

	// Use a channel to handle context cancellation
	doneChan := make(chan error, 1)

	go func() {
		for {
			// Accept new QUIC connection
			conn, err := d.listener.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil {
					doneChan <- nil
					return
				}
				doneChan <- fmt.Errorf("accept error: %w", err)
				return
			}

			// Handle connection in goroutine
			go d.handleConnection(ctx, conn)
		}
	}()

	// Wait for context cancellation or accept error
	return <-doneChan
}

// handleConnection processes a single DoQ QUIC connection.
// Accepts multiple DNS queries on different streams.
func (d *DOQListener) handleConnection(ctx context.Context, conn *quic.Conn) {
	defer conn.CloseWithError(0, "")

	for {
		stream, err := d.acceptStream(ctx, conn)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// The connection itself is dead (peer suspended/vanished → quic-go cancels
			// conn.Context() when the connection closes). MUST return, not continue: a
			// closed connection yields AcceptStream errors immediately and forever, so a
			// continue here spins a whole core with no I/O (Issue 29). Check this BEFORE
			// isNonCriticalNetErr, whose timeout classification would otherwise swallow the
			// terminal *quic.IdleTimeoutError (Timeout()==true, Unwrap()==net.ErrClosed).
			if conn.Context().Err() != nil {
				return
			}
			// Our OWN 30s acceptStream deadline on a still-live idle connection — not an
			// error, loop again and wait for the next stream.
			if isNonCriticalNetErr(err) {
				continue
			}
			d.logger.Printf("DoQ accept stream error: %v", err)
			return
		}

		// Handle stream in goroutine
		go d.handleStream(ctx, stream)
	}
}

// acceptStream accepts a single stream with an idle timeout deadline.
// quic-go's AcceptStream can get stuck even when ctx is canceled (upstream bug);
// the explicit ctx.Done() check before calling it is a known mitigation.
func (d *DOQListener) acceptStream(ctx context.Context, conn *quic.Conn) (*quic.Stream, error) {
	acceptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Explicit pre-check: AcceptStream can get stuck after ctx cancellation.
	// See: AdguardTeam/dnsproxy commit 8146535 (AG-53944-add-quic-timeouts)
	select {
	case <-acceptCtx.Done():
		return nil, fmt.Errorf("accept stream ctx: %w", acceptCtx.Err())
	default:
	}

	return conn.AcceptStream(acceptCtx)
}

// isNonCriticalNetErr returns true for deadline/timeout errors that should
// not terminate the accept loop — they indicate an idle connection, not a failure.
func isNonCriticalNetErr(err error) bool {
	// A CLOSED connection is terminal, never "just idle" — the accept loop must return, not
	// continue, or it spins a core (Issue 29). quic-go's *IdleTimeoutError ("peer went away
	// unexpectedly") reports Timeout()==true and Unwraps to net.ErrClosed, so it would slip
	// through the net.Error timeout check below; exclude both explicitly here.
	var idleTimeout *quic.IdleTimeoutError
	if errors.As(err, &idleTimeout) || errors.Is(err, net.ErrClosed) {
		return false
	}
	// Our own acceptStream deadline (WithTimeout) on a still-live idle connection: keep looping.
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// handleStream processes a single DoQ stream.
// Reads a DNS query and sends a response per RFC 9250.
func (d *DOQListener) handleStream(ctx context.Context, stream *quic.Stream) {
	defer stream.Close()

	// Read 2-byte length prefix (RFC 1035)
	lenBuf := make([]byte, 2)
	_, err := io.ReadFull(stream, lenBuf)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// Client closed stream
			return
		}
		d.logger.Printf("DoQ read length error: %v", err)
		return
	}

	msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if msgLen == 0 || msgLen > 65535 {
		d.logger.Printf("DoQ invalid message length: %d", msgLen)
		return
	}

	// Read DNS message
	msgBuf := make([]byte, msgLen)
	_, err = io.ReadFull(stream, msgBuf)
	if err != nil {
		d.logger.Printf("DoQ read message error: %v", err)
		return
	}

	// Parse DNS query
	query := &dns.Msg{}
	if err := query.Unpack(msgBuf); err != nil {
		d.logger.Printf("DoQ parse error: %v", err)
		return
	}

	// INGRESS counters — count every accepted/parsed query once, here, BEFORE any
	// cache/upstream decision, so TotalQueries is positionally consistent with Mode 1.
	if d.stats != nil {
		atomic.AddInt64(&d.stats.DoQServed, 1)
		atomic.AddInt64(&d.stats.TotalQueries, 1)
	}

	// Client-facing service timer: request parsed → response sent (recorded at the send
	// point below). Hits ~0; misses include the upstream fetch. See dot.go for rationale.
	servedStart := time.Now()

	// Reject any query that does not carry exactly ONE question (audit M3) — FORMERR,
	// never forwarded upstream. The shared cache keys off Question[0] only, and a
	// degenerate message must never reach the upstream leg. The reply flows through
	// the shared send path below.
	var response *dns.Msg
	if len(query.Question) != 1 {
		response = &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:       query.Id,
				Response: true,
				Rcode:    dns.RcodeFormatError,
			},
			Question: query.Question,
		}
	}

	// SHARED CACHE check (same object as Mode 1) — serve a cached answer without an
	// upstream round-trip if present.
	if response == nil && d.cache != nil {
		if cached, found := d.cache.Get(query); found {
			cached.Id = query.Id
			response = cached
			if d.stats != nil {
				atomic.AddInt64(&d.stats.CacheHits, 1)
			}
		} else if d.stats != nil {
			atomic.AddInt64(&d.stats.CacheMisses, 1)
		}
	}

	// Neither rejected nor served from cache — go upstream.
	if response == nil {
		// Resolve via upstream. UpstreamQueries counted HERE (only queries that go upstream).
		// Aggregate Success/SERVFAIL/UpstreamErrors — fixes Mode-1-only wiring (ISSUES 4 / 3.4.2).
		if d.stats != nil {
			atomic.AddInt64(&d.stats.UpstreamQueries, 1)
		}
		queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		resp, err := d.resolv.Resolve(queryCtx, queryWithDO(query))
		cancel()
		response = resp

		if err != nil {
			// Upstream failed: return SERVFAIL
			d.logger.Printf("DoQ resolve error: %v", err)
			if d.stats != nil {
				atomic.AddInt64(&d.stats.UpstreamErrors, 1)
			}
			response = &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:       query.Id,
					Response: true,
					Rcode:    dns.RcodeServerFailure,
				},
				Question: query.Question,
			}
		} else if d.validateFunc != nil {
			// validateFunc applies the full DNSSEC outcome in place (AD bit + validated/unsigned
			// stats) and returns an error ONLY when the response is BOGUS — an INSECURE answer
			// (e.g. a CNAME chain crossing into an unsigned zone, Issue 30) returns nil and is
			// served without AD, never SERVFAIL.
			if err := d.validateFunc(response); err != nil {
				d.logger.Printf("DoQ DNSSEC validation failed: %v", err)
				if d.stats != nil {
					atomic.AddInt64(&d.stats.DnssecFailed, 1)
				}
				response = &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id:       query.Id,
						Response: true,
						Rcode:    dns.RcodeServerFailure,
					},
					Question: query.Question,
				}
			}
		}

		// Cache successful responses into the SHARED cache.
		if d.cache != nil && len(query.Question) > 0 && response.Rcode == dns.RcodeSuccess {
			d.cache.Put(query, response)
		}
	}

	// Normalize EDNS0 so a validating client does not downgrade (Issue 28).
	ensureResponseEDNS(response, clientDNSSECOK(query))

	// Encode response
	respBuf, err := response.Pack()
	if err != nil {
		d.logger.Printf("DoQ pack error: %v", err)
		return
	}

	// Write response with length prefix
	respLen := []byte{byte(len(respBuf) >> 8), byte(len(respBuf))}
	if _, err := stream.Write(respLen); err != nil {
		d.logger.Printf("DoQ write length error: %v", err)
		return
	}
	if _, err := stream.Write(respBuf); err != nil {
		d.logger.Printf("DoQ write message error: %v", err)
		return
	}
	// Single response-bucket accounting point, keyed on rcode (Issue 27).
	// Client-facing service time recorded here too — response is fully written.
	if d.stats != nil {
		d.stats.RecordResponse(response.Rcode)
		d.stats.RecordMode2Latency(time.Since(servedStart).Microseconds())
	}
}

// Close gracefully closes the DoQ listener.
// Idempotent via sync.Once. Deliberately does NOT nil the fields: Serve's accept
// goroutine reads d.listener concurrently (doq.go Serve → d.listener.Accept), so the
// old nil-out "mark as closed" pattern was a data race — and a latent nil-deref if
// the accept loop iterated mid-Close. Closing the listener is what unblocks Accept;
// the Once provides the double-close safety the nil-marker was for.
func (d *DOQListener) Close() error {
	d.closeOnce.Do(func() {
		if d.listener != nil {
			d.listener.Close()
		}
		if d.udpConn != nil {
			d.udpConn.Close()
		}
	})
	return nil
}
