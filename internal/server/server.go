// SPDX-License-Identifier: MIT

// Package server implements Mode 1 (the plaintext-side forwarder).
//
// It binds the local/LAN-facing UDP and TCP DNS listeners (port 53 / 5300),
// accepts ordinary cleartext DNS from stub resolvers and LAN clients, applies
// blocklist/cache/DNSSEC logic, and forwards cache-miss queries upstream over an
// encrypted transport via the resolver package. Despite the name, this is the
// "Mode 1" role in rcvd's two-mode model; the encrypted-endpoint role ("Mode 2")
// lives in the upstream package.
package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/rcvd-dns/rcvd/internal/blocklist"
	"github.com/rcvd-dns/rcvd/internal/cache"
	"github.com/rcvd-dns/rcvd/internal/config"
	"github.com/rcvd-dns/rcvd/internal/dnssec"
	"github.com/rcvd-dns/rcvd/internal/statistics"
)

// dnsUDPBufSize is the EDNS0 UDP payload size rcvd advertises on both the query it
// sends upstream and the response it returns to the client. 1232 is the DNS-flag-day
// recommended value (fits within common path MTUs to avoid IP fragmentation, RFC 6891);
// it also replaces the nonstandard 0-byte bufsize that previously irritated stub-resolver
// EDNS probes (Issue 28).
const dnsUDPBufSize = 1232

// Server listens for incoming DNS queries on UDP/TCP and forwards them to resolvers.
// CRITICAL: No cleartext DNS responses allowed. If all resolvers fail, return SERVFAIL.
// Queries are cached per TTL; cache can be disabled via config.
// Blocked domains return NXDOMAIN (domain does not exist).
type Server struct {
	cfg       *config.Config
	resolver  Resolver             // abstraction for DoQ/DoT/DoH
	cache     *cache.Cache         // optional DNS response cache
	blocklist *blocklist.Blocklist // optional blocklist for domain filtering
	validator *dnssec.Validator    // optional DNSSEC validator
	stats     *statistics.Stats    // optional runtime statistics
	logger    *log.Logger
	udpConn   *net.UDPConn
	tcpList   net.Listener
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// Resolver interface abstracts over DoQ, DoT, DoH resolvers.
type Resolver interface {
	Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
	Close() error
}

// NewServer creates a DNS server for the given config.
// Pass nil for cache, blocklist, validator, or stats if they are disabled.
func NewServer(cfg *config.Config, resolver Resolver, dnsCache *cache.Cache, dnsBlocklist *blocklist.Blocklist, dnsValidator *dnssec.Validator, stats *statistics.Stats, logger *log.Logger) *Server {
	return &Server{
		cfg:       cfg,
		resolver:  resolver,
		cache:     dnsCache,
		blocklist: dnsBlocklist,
		validator: dnsValidator,
		stats:     stats,
		logger:    logger,
	}
}

// Start begins listening for DNS queries on the configured address.
func (s *Server) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)

	if !s.cfg.Resolver.Enabled {
		return fmt.Errorf("resolver mode not enabled")
	}

	addr := s.cfg.Resolver.Listen

	// Start UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve UDP addr: %w", err)
	}

	s.udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}

	s.logger.Printf("listening on UDP %s", addr)

	// Start TCP listener
	tcpList, err := net.Listen("tcp", addr)
	if err != nil {
		s.udpConn.Close()
		return fmt.Errorf("listen TCP: %w", err)
	}
	s.tcpList = tcpList

	s.logger.Printf("listening on TCP %s", addr)

	// Accept UDP queries
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.serveUDP()
	}()

	// Accept TCP queries
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.serveTCP()
	}()

	return nil
}

// serveUDP handles incoming UDP DNS queries.
func (s *Server) serveUDP() {
	defer s.udpConn.Close()

	buf := make([]byte, 65535)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		s.udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, remoteAddr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if s.ctx.Err() != nil {
				return
			}
			s.logger.Printf("UDP read error: %v", err)
			continue
		}

		// Handle query in goroutine
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleDNSQuery(buf[:n], remoteAddr)
		}()
	}
}

// serveTCP handles incoming TCP DNS queries.
func (s *Server) serveTCP() {
	defer s.tcpList.Close()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.tcpList.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			s.logger.Printf("TCP accept error: %v", err)
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleTCPConnection(conn)
		}()
	}
}

// clientDNSSECOK reports whether the client's query asked for DNSSEC records,
// i.e. it carried an EDNS0 OPT record with the DO (DNSSEC OK) bit set (RFC 4035 §3.2.1).
// A stub resolver like systemd-resolved sets DO when it probes/validates.
func clientDNSSECOK(query *dns.Msg) bool {
	opt := query.IsEdns0()
	return opt != nil && opt.Do()
}

// queryWithDO returns a query to send upstream that always requests DNSSEC records
// (EDNS0 OPT with DO=1, RFC 4035 §3.2.1). We validate DNSSEC ourselves, so we must
// receive RRSIGs from the upstream regardless of whether the client asked for them.
// The returned message is a copy — the caller's original query is left untouched so
// the cache key (which is DO-sensitive) and response synthesis still reflect the
// CLIENT's DO intent, not our normalized upstream one.
//
// NOTE: dns.SetEdns0 APPENDS an OPT; it does NOT replace an existing one. A query from
// a DNSSEC-aware stub (dig +dnssec, systemd-resolved) already carries an OPT, so we must
// strip any existing OPT first — two OPT records is malformed (RFC 6891 §6.1.1) and the
// upstream answers FORMERR (Issue 28).
func queryWithDO(query *dns.Msg) *dns.Msg {
	up := query.Copy()
	stripOPT(up)
	up.SetEdns0(dnsUDPBufSize, true) // exactly one OPT: bufsize + DO=1
	return up
}

// stripOPT removes any EDNS0 OPT pseudo-records from msg.Extra in place. A DNS message
// must carry at most one OPT (RFC 6891 §6.1.1); callers that (re)add an OPT with SetEdns0
// must strip first, since SetEdns0 appends rather than replaces.
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

// ensureResponseEDNS guarantees the response we hand back to the client carries a
// well-formed EDNS0 OPT record, with its DO bit matching what the CLIENT requested
// and a standard UDP payload size advertised.
//
// Why this matters: without it, a synthesized response (blocklist NXDOMAIN, SERVFAIL)
// or an upstream reply that lost its OPT record goes back with NO EDNS0 and DO=0.
// A validating stub resolver (systemd-resolved) that sent a DO=1 probe then concludes
// the server is not EDNS/DNSSEC-capable, DOWNGRADES its feature set, and retries —
// burning a ~5s feature-detection timer on every lookup (Issue 28). Echoing an OPT
// with DO set tells resolved "yes, I speak EDNS0 + DNSSEC," so it stops downgrading.
func ensureResponseEDNS(response *dns.Msg, clientDO bool) {
	if response == nil {
		return
	}
	opt := response.IsEdns0()
	if opt == nil {
		// No OPT survived (synthesized reply, or upstream dropped it) — add one.
		response.SetEdns0(dnsUDPBufSize, clientDO)
		return
	}
	// Preserve the upstream OPT but normalize the fields resolved keys off of.
	opt.SetDo(clientDO)
	opt.SetUDPSize(dnsUDPBufSize)
}

// applyDNSSEC runs the validator over an upstream response and applies the three-way DNSSEC
// outcome, returning the response to serve. There are exactly three states (RFC 4035 §4.3):
//
//   - SECURE   → validation returned nil: set the AD bit, count validated.
//   - INSECURE → validation returned an insecure signal (dnssec.IsInsecure): serve the answer as-is
//     WITHOUT the AD bit, count unsigned. This covers a proven no-DS delegation AND a CNAME chain
//     whose signed head validates but whose tail is unsigned (Issue 30). It is NOT a failure — the
//     signed portion checked out, the unsigned portion simply can't be authenticated, so we must
//     neither claim AD nor SERVFAIL.
//   - BOGUS    → any other error: replace with SERVFAIL, count failed. NEVER cleartext, never AD.
//
// tag prefixes the log line so UDP/TCP paths stay distinguishable. Both transports call this so the
// three-way logic lives in exactly one place.
func (s *Server) applyDNSSEC(response *dns.Msg, query *dns.Msg, tag string) *dns.Msg {
	err := s.validator.ValidateResponse(response)
	switch {
	case err == nil:
		// SECURE — set AD flag (RFC 4035 §3.2.3).
		response.AuthenticatedData = true
		if s.stats != nil {
			atomic.AddInt64(&s.stats.DnssecValidated, 1)
		}
		return response
	case dnssec.IsInsecure(err):
		// INSECURE — serve without AD. Belt-and-suspenders: strip AD in case the upstream set it.
		response.AuthenticatedData = false
		if s.stats != nil {
			atomic.AddInt64(&s.stats.DnssecUnsigned, 1)
		}
		return response
	default:
		// BOGUS — fail closed. Privacy: never log the queried name — event + error only.
		s.logger.Printf("%sDNSSEC validation failed: %v", tag, err)
		if s.stats != nil {
			atomic.AddInt64(&s.stats.DnssecFailed, 1)
		}
		return s.upstreamFailureResponse(query)
	}
}

// formErrResponse builds the FORMERR reply for a query whose QDCOUNT != 1 (audit M3).
// A DNS query carries exactly one question in practice; blocklist and cache key off
// Question[0] only, so a multi-question message could smuggle a blocked name past the
// filter in Question[1], and a zero-question message would otherwise be forwarded
// upstream as-is. Rejecting at ingress (never forwarded) closes both, matching common
// resolver practice for a malformed QDCOUNT. The fallback resolver carries the same
// guard as a backstop (fallback.go).
func formErrResponse(query *dns.Msg) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:       query.Id,
			Response: true,
			Rcode:    dns.RcodeFormatError,
		},
		Question: query.Question,
	}
}

// handleDNSQuery processes a single DNS query from the network.
// Query comes in via UDP, parsed, checked against blocklist, forwarded to resolver, response sent back.
// CRITICAL: If resolver fails, return SERVFAIL (never cleartext).
// Blocked domains return NXDOMAIN.
func (s *Server) handleDNSQuery(queryBuf []byte, remoteAddr net.Addr) {
	// Parse incoming DNS query
	query := &dns.Msg{}
	if err := query.Unpack(queryBuf); err != nil {
		s.logger.Printf("parse query error: %v", err)
		return
	}

	if s.stats != nil {
		atomic.AddInt64(&s.stats.TotalQueries, 1)
	}

	// Reject any query that does not carry exactly ONE question (audit M3) — FORMERR,
	// never forwarded upstream. See formErrResponse for why.
	if len(query.Question) != 1 {
		response := formErrResponse(query)
		ensureResponseEDNS(response, clientDNSSECOK(query))
		respBuf, err := response.Pack()
		if err != nil {
			s.logger.Printf("pack FORMERR response error: %v", err)
			return
		}
		if udpAddr, ok := remoteAddr.(*net.UDPAddr); ok {
			if _, err := s.udpConn.WriteToUDP(respBuf, udpAddr); err != nil {
				s.logger.Printf("UDP write FORMERR error: %v", err)
			}
		}
		if s.stats != nil {
			s.stats.RecordResponse(response.Rcode)
		}
		return
	}

	// Check blocklist before cache/resolver
	if s.blocklist != nil && len(query.Question) > 0 {
		domain := query.Question[0].Name
		if s.blocklist.IsBlocked(domain) {
			if s.stats != nil {
				atomic.AddInt64(&s.stats.BlockedQueries, 1)
			}
			// Return NXDOMAIN (domain does not exist)
			response := &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:       query.Id,
					Response: true,
					Rcode:    dns.RcodeNameError, // NXDOMAIN
				},
				Question: query.Question,
			}
			// Echo EDNS0 so a DNSSEC-probing stub resolver sees an EDNS-capable
			// server and does not downgrade (Issue 28).
			ensureResponseEDNS(response, clientDNSSECOK(query))
			respBuf, err := response.Pack()
			if err != nil {
				s.logger.Printf("pack NXDOMAIN response error: %v", err)
				return
			}
			udpAddr, ok := remoteAddr.(*net.UDPAddr)
			if ok {
				_, err = s.udpConn.WriteToUDP(respBuf, udpAddr)
				if err != nil {
					s.logger.Printf("UDP write NXDOMAIN error: %v", err)
				}
			}
			if s.stats != nil {
				s.stats.RecordResponse(response.Rcode)
			}
			return
		}
	}

	// Check cache (before querying upstream)
	if s.cache != nil && len(query.Question) > 0 {
		if cached, found := s.cache.Get(query); found {
			if s.stats != nil {
				atomic.AddInt64(&s.stats.CacheHits, 1)
			}
			// Cache hit: return cached response with original query ID
			cached.Id = query.Id
			// Normalize EDNS0 to this client's DO request (the cache key already
			// separates DO/non-DO entries, but re-assert OPT+bufsize for Issue 28).
			ensureResponseEDNS(cached, clientDNSSECOK(query))
			// Encode and send cached response
			respBuf, err := cached.Pack()
			if err != nil {
				s.logger.Printf("pack cached response error: %v", err)
				return
			}
			udpAddr, ok := remoteAddr.(*net.UDPAddr)
			if ok {
				_, err = s.udpConn.WriteToUDP(respBuf, udpAddr)
				if err != nil {
					s.logger.Printf("UDP write cached response error: %v", err)
				}
			}
			if s.stats != nil {
				s.stats.RecordResponse(cached.Rcode)
			}
			return
		}
	}

	// Cache miss: resolve via upstream (DoQ → DoT → DoH with fallback)
	if s.stats != nil {
		atomic.AddInt64(&s.stats.CacheMisses, 1)
		atomic.AddInt64(&s.stats.UpstreamQueries, 1)
	}
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	queryStart := time.Now()
	// Always request DNSSEC records upstream (DO=1) so our validator has RRSIGs to
	// check, independent of whether the client set DO. The original query is preserved
	// for the DO-sensitive cache key + response synthesis.
	response, err := s.resolver.Resolve(ctx, queryWithDO(query))
	if err == nil && s.stats != nil {
		s.stats.RecordLatency(time.Since(queryStart).Microseconds())
	}
	if err != nil {
		// Upstream failed: return SERVFAIL (never cleartext)
		// Privacy: never log the queried name — log the event + error only.
		s.logger.Printf("resolve error: %v", err)
		if s.stats != nil {
			atomic.AddInt64(&s.stats.UpstreamErrors, 1)
		}
		response = s.upstreamFailureResponse(query)
	} else {
		// Validate DNSSEC if enabled (three-way: secure→AD, insecure→no-AD, bogus→SERVFAIL)
		if s.validator != nil {
			response = s.applyDNSSEC(response, query, "")
		}
		// Cache successful response (only if not overridden by DNSSEC failure)
		if s.cache != nil && len(query.Question) > 0 && s.cacheableResponse(response) {
			s.cache.Put(query, response)
		}
	}

	// Normalize EDNS0 on the outgoing reply (OPT present, DO matches the client's
	// request, standard bufsize) so a validating stub resolver does not downgrade
	// its feature set and stall (Issue 28).
	ensureResponseEDNS(response, clientDNSSECOK(query))

	// Encode response
	respBuf, err := response.Pack()
	if err != nil {
		s.logger.Printf("pack response error: %v", err)
		return
	}

	// Send response back to client
	udpAddr, ok := remoteAddr.(*net.UDPAddr)
	if ok {
		_, err = s.udpConn.WriteToUDP(respBuf, udpAddr)
		if err != nil {
			s.logger.Printf("UDP write error: %v", err)
		}
	}
	// Account exactly one response bucket per sent reply, keyed on rcode (Issue 27).
	if s.stats != nil {
		s.stats.RecordResponse(response.Rcode)
	}
}

// upstreamFailureResponse builds the response to return when an upstream resolve or
// DNSSEC validation fails. If serve-stale is enabled (cache mode "aggressive") and a
// bounded-stale entry exists, it serves that previously-validated answer instead of
// SERVFAIL — a resilience fallback that NEVER emits cleartext (the stale answer was
// already DNSSEC-validated and arrived over an encrypted upstream; only freshness is
// relaxed). Every served-stale response increments stats.StaleServed so it is observable.
// Otherwise it returns a SERVFAIL (fail-closed). Response bucketing (Success for a
// stale answer, SERVFAIL otherwise) is NOT done here — the caller's single send-point
// RecordResponse(response.Rcode) handles it (Issue 27); this only tracks StaleServed.
func (s *Server) upstreamFailureResponse(query *dns.Msg) *dns.Msg {
	if s.cache != nil {
		if stale, ok := s.cache.GetStale(query); ok {
			// GetStale (like Get) returns a private copy — safe to mutate directly.
			resp := stale
			resp.Id = query.Id
			if s.stats != nil {
				atomic.AddInt64(&s.stats.StaleServed, 1)
			}
			// Privacy: never log the queried name — log the event only.
			s.logger.Printf("serving stale (bounded) — all upstreams failed")
			return resp
		}
	}
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:       query.Id,
			Response: true,
			Rcode:    dns.RcodeServerFailure, // SERVFAIL — fail closed, never cleartext
		},
		Question: query.Question,
	}
}

// cacheableResponse reports whether resp should be stored in the cache: a positive
// success (NOERROR with answers) always, OR a negative answer (NXDOMAIN/NODATA) when
// negative caching is enabled. The cache itself enforces TTL bounds; this gates which
// rcodes are eligible. DNSSEC-failure SERVFAILs (synthesized locally) are never cached.
func (s *Server) cacheableResponse(resp *dns.Msg) bool {
	if resp == nil {
		return false
	}
	if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
		return true
	}
	// Negative (NXDOMAIN / NODATA) — only when negative caching is on.
	if s.cache != nil && s.cache.NegativeCachingEnabled() {
		if resp.Rcode == dns.RcodeNameError ||
			(resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0) {
			return true
		}
	}
	return false
}

// handleTCPConnection handles a single TCP client connection.
// TCP DNS: 2-byte length prefix followed by DNS message (RFC 1035).
func (s *Server) handleTCPConnection(conn net.Conn) {
	defer conn.Close()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		// Read 2-byte length prefix. io.ReadFull, NOT a bare conn.Read (audit M1):
		// TCP may legally return a short read, which would mis-size the body read
		// below and misparse the message. Matches the Mode-2 DoT/DoQ readers.
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			if err == io.EOF {
				return // client closed the connection between queries — normal
			}
			s.logger.Printf("TCP read length error: %v", err)
			return
		}

		msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		if msgLen == 0 || msgLen > 65535 {
			s.logger.Printf("TCP invalid message length: %d", msgLen)
			return
		}

		// Read DNS message (io.ReadFull — the body may span multiple TCP segments)
		msgBuf := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msgBuf); err != nil {
			s.logger.Printf("TCP read message error: %v", err)
			return
		}

		// Parse and handle query
		query := &dns.Msg{}
		if err := query.Unpack(msgBuf); err != nil {
			s.logger.Printf("TCP parse error: %v", err)
			continue
		}

		if s.stats != nil {
			atomic.AddInt64(&s.stats.TotalQueries, 1)
		}

		// Reject malformed QDCOUNT before blocklist/cache/upstream (audit M3); see
		// formErrResponse. The reply flows through the shared send path below.
		var response *dns.Msg
		if len(query.Question) != 1 {
			response = formErrResponse(query)
		}

		// Check blocklist first
		if response == nil && s.blocklist != nil && len(query.Question) > 0 {
			domain := query.Question[0].Name
			if s.blocklist.IsBlocked(domain) {
				if s.stats != nil {
					atomic.AddInt64(&s.stats.BlockedQueries, 1)
				}
				// Return NXDOMAIN (domain does not exist)
				response = &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id:       query.Id,
						Response: true,
						Rcode:    dns.RcodeNameError, // NXDOMAIN
					},
					Question: query.Question,
				}
			}
		}

		// Check cache (before querying upstream)
		if response == nil && s.cache != nil && len(query.Question) > 0 {
			if cached, found := s.cache.Get(query); found {
				if s.stats != nil {
					atomic.AddInt64(&s.stats.CacheHits, 1)
				}
				cached.Id = query.Id
				response = cached
			}
		}

		// If not blocked and not cached, resolve via upstream
		if response == nil {
			if s.stats != nil {
				atomic.AddInt64(&s.stats.CacheMisses, 1)
				atomic.AddInt64(&s.stats.UpstreamQueries, 1)
			}
			ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
			var err error
			queryStart := time.Now()
			// Always request DNSSEC records upstream (DO=1); see the UDP path.
			response, err = s.resolver.Resolve(ctx, queryWithDO(query))
			if err == nil && s.stats != nil {
				s.stats.RecordLatency(time.Since(queryStart).Microseconds())
			}
			cancel()

			if err != nil {
				// Upstream failed: return SERVFAIL
				s.logger.Printf("TCP resolve error: %v", err)
				if s.stats != nil {
					atomic.AddInt64(&s.stats.UpstreamErrors, 1)
				}
				response = s.upstreamFailureResponse(query)
			} else {
				// Validate DNSSEC if enabled (three-way: secure→AD, insecure→no-AD, bogus→SERVFAIL)
				if s.validator != nil {
					response = s.applyDNSSEC(response, query, "TCP ")
				}
				// Cache successful response
				if s.cache != nil && len(query.Question) > 0 && s.cacheableResponse(response) {
					s.cache.Put(query, response)
				}
			}
		}

		// Normalize EDNS0 on the outgoing reply (covers blocklist NXDOMAIN, cache
		// hit, and upstream reply) so a validating stub resolver does not downgrade
		// and stall (Issue 28).
		ensureResponseEDNS(response, clientDNSSECOK(query))

		// Encode and send response with length prefix
		respBuf, err := response.Pack()
		if err != nil {
			s.logger.Printf("TCP pack error: %v", err)
			return
		}

		respLen := []byte{byte(len(respBuf) >> 8), byte(len(respBuf))}
		if _, err := conn.Write(respLen); err != nil {
			s.logger.Printf("TCP write length error: %v", err)
			return
		}
		if _, err := conn.Write(respBuf); err != nil {
			s.logger.Printf("TCP write message error: %v", err)
			return
		}
		// Account exactly one response bucket per sent reply, keyed on rcode (Issue 27).
		if s.stats != nil {
			s.stats.RecordResponse(response.Rcode)
		}
	}
}

// UDPAddr returns the local UDP listen address. Useful in tests with port :0.
func (s *Server) UDPAddr() net.Addr {
	if s.udpConn == nil {
		return nil
	}
	return s.udpConn.LocalAddr()
}

// TCPAddr returns the local TCP listen address, or nil if the TCP listener is not bound.
// Used by --audit to report the actually-bound Mode-1 TCP listener.
func (s *Server) TCPAddr() net.Addr {
	if s.tcpList == nil {
		return nil
	}
	return s.tcpList.Addr()
}

// Stop gracefully shuts down the server.
// Waits for in-flight queries (up to 5s timeout).
func (s *Server) Stop(timeout time.Duration) error {
	s.logger.Println("stopping server...")
	s.cancel()

	// Close the listeners BEFORE waiting on the WaitGroup. The serveUDP/serveTCP
	// loops park in ReadFromUDP (5s deadline) / Accept (no deadline) and cannot
	// observe ctx cancellation while blocked there — closing the socket is what
	// unblocks them. They then see s.ctx.Err() != nil and return immediately
	// (server.go serveUDP/serveTCP). Closing first turns a guaranteed ~5s
	// timeout-kill into a sub-millisecond graceful stop. (Issue 15)
	if s.udpConn != nil {
		s.udpConn.Close()
	}
	if s.tcpList != nil {
		s.tcpList.Close()
	}

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Println("server stopped gracefully")
	case <-time.After(timeout):
		s.logger.Printf("server stop timeout (%v), force closing", timeout)
	}

	// Close upstream connections (QUIC/TLS) after the read loops have drained.
	if s.resolver != nil {
		s.resolver.Close()
	}

	return nil
}
