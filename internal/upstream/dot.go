// SPDX-License-Identifier: MIT
package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/rcvd-dns/rcvd/internal/cache"
	"github.com/rcvd-dns/rcvd/internal/resolver"
	"github.com/rcvd-dns/rcvd/internal/statistics"
)

// DOTListener handles DNS-over-TLS (DoT) connections.
// RFC 7858: DNS over TLS
// Accepts TLS connections on TCP, handles DNS messages with 2-byte length prefix.
type DOTListener struct {
	addr         string
	tlsConfig    *tls.Config
	resolv       resolver.Resolver
	cache        *cache.Cache      // SHARED instance cache (may be nil)
	validateFunc ValidateFunc      // optional DNSSEC validation callback
	stats        *statistics.Stats // optional runtime statistics
	logger       *log.Logger
	listener     net.Listener
	done         chan struct{}
	closeOnce    sync.Once // guards Close (idempotent without racing Serve's field reads)
}

// NewDOTListener creates a new DoT listener.
func NewDOTListener(addr string, tlsConfig *tls.Config, resolv resolver.Resolver, dnsCache *cache.Cache, validateFunc ValidateFunc, stats *statistics.Stats, logger *log.Logger) (*DOTListener, error) {
	// Create TCP listener
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve TCP addr: %w", err)
	}

	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen TCP: %w", err)
	}

	// Wrap with TLS
	tlsListener := tls.NewListener(tcpListener, tlsConfig)

	return &DOTListener{
		addr:         addr,
		tlsConfig:    tlsConfig,
		resolv:       resolv,
		cache:        dnsCache,
		validateFunc: validateFunc,
		stats:        stats,
		logger:       logger,
		listener:     tlsListener,
		done:         make(chan struct{}),
	}, nil
}

// Serve accepts and handles DoT connections.
// Blocks until context is cancelled.
func (d *DOTListener) Serve(ctx context.Context) error {
	defer d.listener.Close()

	// Track active connections
	var connWg sync.WaitGroup

	// Use a ticker to periodically check for context cancellation
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Create a channel for accepting connections in a non-blocking way
	acceptChan := make(chan net.Conn)
	acceptErrChan := make(chan error)

	// Goroutine to accept connections
	go func() {
		for {
			conn, err := d.listener.Accept()
			if err != nil {
				acceptErrChan <- err
				return
			}
			acceptChan <- conn
		}
	}()

	for {
		select {
		case <-ctx.Done():
			// Wait for active connections to finish (with timeout)
			done := make(chan struct{})
			go func() {
				connWg.Wait()
				close(done)
			}()

			select {
			case <-done:
				d.logger.Println("DoT listener: all connections closed")
				return nil
			case <-time.After(5 * time.Second):
				d.logger.Println("DoT listener: timeout waiting for connections, closing")
				return nil
			}

		case conn := <-acceptChan:
			// Handle connection in goroutine
			connWg.Add(1)
			go func() {
				defer connWg.Done()
				d.handleConnection(conn, ctx)
			}()

		case err := <-acceptErrChan:
			if ctx.Err() != nil {
				return nil
			}
			d.logger.Printf("DoT accept error: %v", err)
			return err

		case <-ticker.C:
			// Periodically check context
			select {
			case <-ctx.Done():
				// Will be caught by the case above
			default:
			}
		}
	}
}

// handleConnection processes a single DoT client connection.
// Accepts multiple DNS queries on the same TLS connection.
func (d *DOTListener) handleConnection(conn net.Conn, ctx context.Context) {
	defer conn.Close()

	// Keep connection open for multiple queries
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set read deadline
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// Read 2-byte length prefix (RFC 1035)
		lenBuf := make([]byte, 2)
		_, err := io.ReadFull(conn, lenBuf)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				// Client closed connection
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout is normal for idle connections
				return
			}
			d.logger.Printf("DoT read length error: %v", err)
			return
		}

		msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		if msgLen == 0 || msgLen > 65535 {
			d.logger.Printf("DoT invalid message length: %d", msgLen)
			return
		}

		// Read DNS message
		msgBuf := make([]byte, msgLen)
		_, err = io.ReadFull(conn, msgBuf)
		if err != nil {
			d.logger.Printf("DoT read message error: %v", err)
			return
		}

		// Parse DNS query
		query := &dns.Msg{}
		if err := query.Unpack(msgBuf); err != nil {
			d.logger.Printf("DoT parse error: %v", err)
			// Continue to next message instead of closing
			continue
		}

		// INGRESS counters — count every accepted/parsed query once, here, BEFORE any
		// cache/upstream decision, so TotalQueries is positionally consistent with Mode 1.
		if d.stats != nil {
			atomic.AddInt64(&d.stats.DoTServed, 1)
			atomic.AddInt64(&d.stats.TotalQueries, 1)
		}

		// Start the CLIENT-FACING service timer: request parsed → response sent. Recorded
		// just before the write below. Cache hits land near 0; misses include the upstream
		// fetch. This is the "what a pinned LAN client experiences" number (not the WAN leg).
		servedStart := time.Now()

		// Reject any query that does not carry exactly ONE question (audit M3) —
		// FORMERR, never forwarded upstream. The shared cache keys off Question[0]
		// only, and a degenerate message must never reach the upstream leg. The
		// reply flows through the shared send path below.
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

		// SHARED CACHE check (same object as Mode 1).
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
				d.logger.Printf("DoT resolve error: %v", err)
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
				// stats) and returns an error ONLY when BOGUS — an INSECURE answer (Issue 30) returns
				// nil and is served without AD, never SERVFAIL.
				if err := d.validateFunc(response); err != nil {
					d.logger.Printf("DoT DNSSEC validation failed: %v", err)
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
			d.logger.Printf("DoT pack error: %v", err)
			return
		}

		// Write response with length prefix
		respLen := []byte{byte(len(respBuf) >> 8), byte(len(respBuf))}
		if _, err := conn.Write(respLen); err != nil {
			d.logger.Printf("DoT write length error: %v", err)
			return
		}
		if _, err := conn.Write(respBuf); err != nil {
			d.logger.Printf("DoT write message error: %v", err)
			return
		}
		// Single response-bucket accounting point, keyed on rcode (Issue 27).
		// Client-facing service time recorded here too — response is fully written.
		if d.stats != nil {
			d.stats.RecordResponse(response.Rcode)
			d.stats.RecordMode2Latency(time.Since(servedStart).Microseconds())
		}
	}
}

// Close gracefully closes the DoT listener.
// Idempotent via sync.Once. Deliberately does NOT nil the field: Serve's accept
// goroutine reads d.listener concurrently, so the old nil-out "mark as closed"
// pattern was a data race. Closing the listener is what unblocks Accept; the
// Once provides the double-close safety the nil-marker was for.
func (d *DOTListener) Close() error {
	d.closeOnce.Do(func() {
		if d.listener != nil {
			d.listener.Close()
		}
	})
	return nil
}
