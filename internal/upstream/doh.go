// SPDX-License-Identifier: MIT
package upstream

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
	"github.com/rcvd-dns/rcvd/internal/cache"
	"github.com/rcvd-dns/rcvd/internal/resolver"
	"github.com/rcvd-dns/rcvd/internal/statistics"
	"golang.org/x/net/http2"
)

// DOHListener handles DNS-over-HTTPS (DoH) connections per RFC 8484.
//
// TRANSPORT NOTE — this listener can serve DoH over BOTH HTTP transports:
//   - HTTP/2 over TCP (the baseline): the classic DoH transport, per RFC 8484 §5.2
//     which recommends HTTP/2 as the minimum. Handled by the stdlib net/http.Server
//     in the `h2server` field. (Incidentally, because we don't disable the stdlib's
//     default ALPN set, an HTTP/1.1-only client would still be accepted via fallback;
//     this is not a targeted transport — see the HTTP/1.1 audit item in TODO.md.)
//   - HTTP/3 over QUIC (optional, "DoH3"): DoH carried on HTTP/3, which runs on
//     QUIC/UDP. Handled by the quic-go http3.Server in the `h3server` field.
//
// Both servers share ONE http.Handler (the same /dns-query mux), so the request
// handling logic (handleDNSQuery / writeResponse) is identical regardless of
// whether a request arrived over HTTP/2 or HTTP/3. Only the listener/serving
// plumbing differs between the two transports.
type DOHListener struct {
	addr         string
	tlsConfig    *tls.Config // shared base config (used by the h3/QUIC server as-is)
	h2TLSConfig  *tls.Config // TCP-listener config with NextProtos=["h2"] (strict HTTP/2 ALPN)
	resolv       resolver.Resolver
	cache        *cache.Cache      // SHARED instance cache (may be nil)
	validateFunc ValidateFunc      // optional DNSSEC validation callback
	stats        *statistics.Stats // optional runtime statistics
	logger       *log.Logger

	handler   http.Handler  // shared by both the HTTP/2 and HTTP/3 servers
	h2server  *http.Server  // HTTP/2 over TCP (classic DoH) — the baseline listener, always created
	h3server  *http3.Server // HTTP/3 over QUIC ("DoH3") — created only when enableH3
	enableH3  bool          // whether to also serve DoH3 (HTTP/3 over QUIC/UDP)
	closeOnce sync.Once     // guards Close (idempotent without racing Serve's field reads)
}

// NewDOHListener creates a new DoH listener.
//
// enableH3 controls whether DoH3 (HTTP/3 over QUIC) is served IN ADDITION to the
// baseline HTTP/2-over-TCP DoH. Both transports listen on the same `addr`
// (TCP for HTTP/2, UDP for HTTP/3) and share the same /dns-query handler.
func NewDOHListener(addr string, tlsConfig *tls.Config, resolv resolver.Resolver, dnsCache *cache.Cache, validateFunc ValidateFunc, stats *statistics.Stats, logger *log.Logger, enableH3 bool) (*DOHListener, error) {
	d := &DOHListener{
		addr:         addr,
		tlsConfig:    tlsConfig,
		resolv:       resolv,
		cache:        dnsCache,
		validateFunc: validateFunc,
		stats:        stats,
		logger:       logger,
		enableH3:     enableH3,
	}

	// ONE shared handler/mux serves both HTTP/2 and HTTP/3 requests.
	// Register the exact path AND the trailing-slash variant: Go's ServeMux treats a
	// bare "/dns-query" as an exact match only, so a client that requests "/dns-query/"
	// (some browsers/configs append the slash) would otherwise get a 404. Both forms map
	// to the same handler so DoH works regardless of the trailing slash.
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", d.handleDNSQuery)
	mux.HandleFunc("/dns-query/", d.handleDNSQuery)
	d.handler = mux

	// HTTP/2 server (over TCP). This is the always-on, classic DoH transport.
	// When DoH3 is enabled we wrap the handler so HTTP/2 responses advertise the
	// HTTP/3 endpoint via an Alt-Svc header (RFC 9114 §3.1.1), letting capable
	// clients upgrade to DoH3 on subsequent requests.
	h2handler := d.handler
	if enableH3 {
		h2handler = d.withAltSvc(d.handler)
	}

	// Dedicated TLS config for the TCP listener that advertises HTTP/2 via ALPN.
	// rcvd serves DoH STRICTLY over HTTP/2 on TCP — NextProtos = ["h2"] only (no
	// "http/1.1" fallback). The shared tlsConfig has no NextProtos, and serving a
	// pre-TLS-wrapped listener via http.Server.Serve does NOT auto-enable HTTP/2, so
	// without this every client ALPN-negotiated nothing and silently fell back to
	// HTTP/1.1 (the "HTTP/2 over TCP" listener was really serving h1.1). We clone the
	// shared config (NOT mutate it) because the h3server shares it and QUIC needs its
	// own "h3" ALPN, which quic-go sets internally. See ISSUES 26.
	d.h2TLSConfig = tlsConfig.Clone()

	d.h2server = &http.Server{
		Addr:      addr,
		TLSConfig: d.h2TLSConfig,
		Handler:   h2handler,
	}
	// Wire Go's HTTP/2 protocol handler onto the server explicitly. ConfigureServer
	// is required because we Serve a manually TLS-wrapped listener (the automatic h2
	// setup only happens via ServeTLS/ListenAndServeTLS).
	if err := http2.ConfigureServer(d.h2server, &http2.Server{}); err != nil {
		return nil, fmt.Errorf("DoH HTTP/2 configure: %w", err)
	}
	// IMPORTANT: ConfigureServer APPENDS "h2" to NextProtos but leaves (or adds)
	// "http/1.1" too. rcvd serves DoH STRICTLY over HTTP/2 on TCP, so pin NextProtos to
	// ["h2"] AFTER ConfigureServer. (DoH3/h3 is unaffected — it uses the separate base
	// tlsConfig; quic-go sets "h3".)
	d.h2TLSConfig.NextProtos = []string{"h2"}

	// HARD-CLOSE HTTP/1.1: pinning NextProtos to ["h2"] is NOT sufficient on its own —
	// Go's TLS server treats an ALPN mismatch as NON-fatal and completes the handshake
	// with NO negotiated protocol, after which http.Server falls through to serving
	// HTTP/1.1. That leaves an unintended, untested h1.1 code path reachable (a downgrade
	// / attack surface). To genuinely reject it we install GetConfigForClient and fail the
	// handshake when the client's ALPN offer does not include "h2". An h1.1-only client now
	// gets a TLS handshake error and never reaches the DoH handler — only h2 (this listener)
	// and h3 (the QUIC listener) are reachable, and both are tested. See ISSUES 26.
	enforced := d.h2TLSConfig
	enforced.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		// Empty SupportedProtos means the client sent no ALPN extension at all — reject
		// too (rcvd requires an explicit h2 offer; no implicit-h1.1 clients).
		for _, p := range chi.SupportedProtos {
			if p == "h2" {
				return nil, nil // h2 offered → proceed with the pinned config
			}
		}
		return nil, fmt.Errorf("DoH: rejecting TLS connection from %s — client did not offer HTTP/2 (ALPN %v); rcvd serves DoH over h2/h3 only", chi.Conn.RemoteAddr(), chi.SupportedProtos)
	}

	// HTTP/3 server (over QUIC/UDP) — "DoH3". Only created when requested.
	// It reuses the exact same handler as HTTP/2; only the transport differs.
	if enableH3 {
		d.h3server = &http3.Server{
			Addr:      addr,
			TLSConfig: tlsConfig,
			Handler:   d.handler,
		}
	}

	return d, nil
}

// withAltSvc wraps an HTTP/2 handler so its responses carry an Alt-Svc header
// advertising the HTTP/3 (DoH3) endpoint on the same authority/port. Clients
// that understand HTTP/3 may then switch to QUIC for later DoH requests.
// This is set ONLY on the HTTP/2 path; the HTTP/3 server does not need it.
func (d *DOHListener) withAltSvc(next http.Handler) http.Handler {
	// Advertise h3 on the same port the listener binds (the UDP port mirrors
	// the TCP port for DoH3).
	altSvc := fmt.Sprintf(`h3=":%s"; ma=86400`, portOf(d.addr))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", altSvc)
		next.ServeHTTP(w, r)
	})
}

// portOf extracts the port from a "host:port" listen address; returns the input
// unchanged if it has no parseable port.
func portOf(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return addr
}

// handleDNSQuery handles DoH requests to /dns-query (RFC 8484 §4.1).
// Both methods are supported:
//   - POST: DNS wire message in the request body (Content-Type application/dns-message)
//   - GET:  DNS wire message base64url-encoded (no padding) in the ?dns= query parameter
//
// Browsers (Firefox, Chrome) default to GET for HTTP-cache friendliness, so GET support
// is required for browser DoH. CLI tools (kdig) typically use POST.
func (d *DOHListener) handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	var body []byte

	switch r.Method {
	case http.MethodPost:
		// Read DNS message from request body, bounded to prevent memory-exhaustion
		// DoS from a malicious client streaming an oversized body. A DNS message can
		// never exceed dns.MaxMsgSize (65535); read one byte past that so we can
		// detect and reject anything larger rather than silently truncating.
		b, err := io.ReadAll(io.LimitReader(r.Body, dns.MaxMsgSize+1))
		if err != nil {
			d.logger.Printf("DoH read body error: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		body = b

	case http.MethodGet:
		// RFC 8484 §4.1: the DNS message is base64url-encoded (unpadded) in ?dns=.
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		b, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			d.logger.Printf("DoH GET ?dns= base64url decode error: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body = b

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate message size (max 65535 bytes per RFC 1035). len(body) >
	// dns.MaxMsgSize here means the message was at least MaxMsgSize+1 (too large).
	if len(body) == 0 || len(body) > dns.MaxMsgSize {
		d.logger.Printf("DoH invalid message size: %d", len(body))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Parse DNS query
	query := &dns.Msg{}
	if err := query.Unpack(body); err != nil {
		d.logger.Printf("DoH parse error: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// INGRESS counters — count every accepted/parsed query once, here, BEFORE any
	// cache/upstream decision, so TotalQueries means the same thing as in Mode 1.
	if d.stats != nil {
		atomic.AddInt64(&d.stats.DoHServed, 1)
		atomic.AddInt64(&d.stats.TotalQueries, 1)
	}

	// Client-facing service timer: request parsed → response sent. Passed into
	// writeResponse (both the cache-hit and main paths funnel through it), recorded there.
	// Hits ~0; misses include the upstream fetch. See dot.go for rationale.
	servedStart := time.Now()

	// Reject any query that does not carry exactly ONE question (audit M3) — FORMERR,
	// never forwarded upstream. The shared cache keys off Question[0] only, and a
	// degenerate message must never reach the upstream leg.
	if len(query.Question) != 1 {
		response := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:       query.Id,
				Response: true,
				Rcode:    dns.RcodeFormatError,
			},
			Question: query.Question,
		}
		ensureResponseEDNS(response, clientDNSSECOK(query))
		d.writeResponse(w, response, servedStart)
		return
	}

	// SHARED CACHE (same object used by Mode 1). Check before going upstream — a
	// browser query whose answer is already cached (by this Mode-2 server OR by a
	// Mode-1 client in a dual-mode instance) is served instantly with no upstream hit.
	if d.cache != nil && len(query.Question) > 0 {
		if cached, found := d.cache.Get(query); found {
			cached.Id = query.Id
			if d.stats != nil {
				atomic.AddInt64(&d.stats.CacheHits, 1)
			}
			// Normalize EDNS0 to the client's DO request (Issue 28).
			ensureResponseEDNS(cached, clientDNSSECOK(query))
			d.writeResponse(w, cached, servedStart)
			return
		}
		if d.stats != nil {
			atomic.AddInt64(&d.stats.CacheMisses, 1)
		}
	}

	// Resolve query via upstream resolver. UpstreamQueries is counted HERE (not at
	// ingress) because it must only count queries that actually go upstream — cache
	// hits above already returned. Aggregate counters fix the Mode-1-only wiring
	// (see ISSUES 4 / PLAN.md 3.4.2).
	if d.stats != nil {
		atomic.AddInt64(&d.stats.UpstreamQueries, 1)
	}
	response, err := d.resolv.Resolve(r.Context(), queryWithDO(query))
	if err != nil {
		// Upstream failed: return SERVFAIL
		d.logger.Printf("DoH resolve error: %v", err)
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
		// validateFunc applies the full DNSSEC outcome in place (AD bit + validated/unsigned stats)
		// and returns an error ONLY when BOGUS — an INSECURE answer (Issue 30) returns nil and is
		// served without AD, never SERVFAIL.
		if err := d.validateFunc(response); err != nil {
			d.logger.Printf("DoH DNSSEC validation failed: %v", err)
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
	// Response bucketing is done once at the send point (writeResponse), keyed on
	// rcode (Issue 27) — not coupled to the resolve/validate/cache branches above.

	// Cache successful responses into the SHARED cache so subsequent Mode-2 (and
	// Mode-1) queries for the same name are served without an upstream round-trip.
	if d.cache != nil && len(query.Question) > 0 && response.Rcode == dns.RcodeSuccess {
		d.cache.Put(query, response)
	}

	// Normalize EDNS0 so a validating client does not downgrade (Issue 28).
	ensureResponseEDNS(response, clientDNSSECOK(query))
	d.writeResponse(w, response, servedStart)
}

// writeResponse encodes a DNS message and writes it as application/dns-message.
// servedStart is the request-received instant, so the client-facing service time can be
// recorded once here (both the cache-hit and main handler paths funnel through this).
func (d *DOHListener) writeResponse(w http.ResponseWriter, msg *dns.Msg, servedStart time.Time) {
	respBuf, err := msg.Pack()
	if err != nil {
		d.logger.Printf("DoH pack error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(respBuf)))
	if _, err := w.Write(respBuf); err != nil {
		d.logger.Printf("DoH write error: %v", err)
	}
	// Single response-bucket accounting point for the Mode-2 DoH server (Issue 27).
	// Reached only after a successful Pack; a pack failure above returns early and is
	// correctly left unaccounted (a pre-send drop). Client-facing service time recorded
	// here too — response is fully written.
	if d.stats != nil {
		d.stats.RecordResponse(msg.Rcode)
		d.stats.RecordMode2Latency(time.Since(servedStart).Microseconds())
	}
}

// Serve starts the DoH server(s) and blocks until the context is cancelled.
//
// It always serves HTTP/2 over TCP. When DoH3 is enabled (enableH3), it ALSO
// serves HTTP/3 over QUIC/UDP on the same address, concurrently. The first of
// the two transports to error returns that error; context cancellation shuts
// both down gracefully.
func (d *DOHListener) Serve(ctx context.Context) error {
	if d.h2server == nil {
		return fmt.Errorf("server not initialized")
	}

	// errChan is buffered for both possible servers (HTTP/2 + HTTP/3) so neither
	// goroutine blocks on send if the other has already reported.
	errChan := make(chan error, 2)

	// --- HTTP/2 over TCP (classic DoH) ---
	tcpListener, err := net.Listen("tcp", d.addr)
	if err != nil {
		return fmt.Errorf("DoH HTTP/2 TCP listen: %w", err)
	}
	tlsListener := tls.NewListener(tcpListener, d.h2TLSConfig)
	go func() {
		d.logger.Printf("DoH (HTTP/2 over TCP) server starting on %s", d.addr)
		errChan <- d.h2server.Serve(tlsListener)
	}()

	// --- HTTP/3 over QUIC/UDP (DoH3) — only when enabled ---
	// We open the UDP packet conn ourselves so we can close it deterministically
	// on shutdown (http3.Server.Serve does not own the conn it is handed).
	var udpConn net.PacketConn
	if d.enableH3 && d.h3server != nil {
		udpAddr, err := net.ResolveUDPAddr("udp", d.addr)
		if err != nil {
			tlsListener.Close()
			return fmt.Errorf("DoH3 resolve UDP addr: %w", err)
		}
		uc, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			tlsListener.Close()
			return fmt.Errorf("DoH3 (HTTP/3 over QUIC) UDP listen: %w", err)
		}
		udpConn = uc
		go func() {
			d.logger.Printf("DoH3 (HTTP/3 over QUIC) server starting on %s (UDP)", d.addr)
			errChan <- d.h3server.Serve(uc)
		}()
	}

	// Wait for context cancellation or the first server error.
	select {
	case <-ctx.Done():
		// Context cancelled — fall through to graceful shutdown below.
	case err := <-errChan:
		// One transport failed — tear down both and report.
		tlsListener.Close()
		if udpConn != nil {
			udpConn.Close()
		}
		if d.h3server != nil {
			d.h3server.Close()
		}
		return err
	}

	// Graceful shutdown (both transports) with a shared timeout.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// HTTP/2: graceful drain.
	if d.h2server != nil {
		if err := d.h2server.Shutdown(shutdownCtx); err != nil {
			d.logger.Printf("DoH (HTTP/2) shutdown error: %v", err)
		}
	}
	// HTTP/3: close the server, then the UDP conn we own.
	if d.h3server != nil {
		if err := d.h3server.Close(); err != nil {
			d.logger.Printf("DoH3 (HTTP/3) shutdown error: %v", err)
		}
	}
	if udpConn != nil {
		udpConn.Close()
	}

	return nil
}

// Close gracefully closes the DoH listener (both HTTP/2 and HTTP/3 transports).
// Idempotent via sync.Once. Deliberately does NOT nil the fields: Serve's server
// goroutines read d.h2server/d.h3server concurrently, so the old nil-out "mark as
// closed" pattern was a data race. http.Server.Close / http3.Server.Close are what
// unblock Serve; the Once provides the double-close safety the nil-marker was for.
func (d *DOHListener) Close() error {
	d.closeOnce.Do(func() {
		if d.h2server != nil {
			d.h2server.Close()
		}
		if d.h3server != nil {
			d.h3server.Close()
		}
	})
	return nil
}
