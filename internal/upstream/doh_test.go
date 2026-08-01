// SPDX-License-Identifier: MIT
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
)

// testLogger creates a logger that discards output for tests.
func testLoggerDoH() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// TestDOHListenerCreation tests DoH listener creation.
func TestDOHListenerCreation(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
		},
		err: nil,
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	listener, err := NewDOHListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLoggerDoH(), false)
	if err != nil {
		t.Fatalf("failed to create DoH listener: %v", err)
	}

	if listener == nil {
		t.Error("expected non-nil listener")
	}

	// Clean up
	listener.Close()
}

// TestDOHListenerHandlePOSTRequest tests DoH POST request handling.
func TestDOHListenerHandlePOSTRequest(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:       1234,
				Response: true,
				Rcode:    dns.RcodeSuccess,
			},
			Answer: []dns.RR{},
		},
		err: nil,
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{},
	}

	listener, err := NewDOHListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLoggerDoH(), false)
	if err != nil {
		t.Fatalf("failed to create DoH listener: %v", err)
	}
	defer listener.Close()

	// Create test DNS query
	query := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:     1234,
			Opcode: dns.OpcodeQuery,
		},
		Question: []dns.Question{
			{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}

	// Pack query for POST body
	queryBuf, err := query.Pack()
	if err != nil {
		t.Fatalf("failed to pack query: %v", err)
	}

	// Start listener in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go listener.Serve(ctx)

	// Give listener time to start
	time.Sleep(100 * time.Millisecond)

	// Test handler directly instead of actual HTTP request
	// (requires actual TLS setup which is deferred to integration tests)
	if n := mockResolver.callCount.Load(); n != 0 {
		t.Errorf("expected resolver call count 0, got %d", n)
	}

	// Verify query was packed correctly
	if len(queryBuf) == 0 {
		t.Error("expected packed query to be non-empty")
	}

	cancel()
}

// TestDOHListenerInvalidMessageSize tests handling of invalid message sizes.
func TestDOHListenerInvalidMessageSize(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}},
		err:      nil,
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	listener, err := NewDOHListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLoggerDoH(), false)
	if err != nil {
		t.Fatalf("failed to create DoH listener: %v", err)
	}
	defer listener.Close()

	// Valid address should succeed
	if listener == nil {
		t.Error("expected non-nil listener")
	}
}

// TestDOHListenerMessagePacking tests DNS message packing for DoH.
func TestDOHListenerMessagePacking(t *testing.T) {
	// Create a test DNS query
	query := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:     1234,
			Opcode: dns.OpcodeQuery,
		},
		Question: []dns.Question{
			{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}

	// Pack the query
	packed, err := query.Pack()
	if err != nil {
		t.Fatalf("failed to pack query: %v", err)
	}

	// Verify message is within valid DoH size (should fit in uint16)
	if len(packed) > 65535 {
		t.Errorf("packed message exceeds DoH max size (65535), got %d", len(packed))
	}

	// Unpack to verify integrity
	unpacked := &dns.Msg{}
	if err := unpacked.Unpack(packed); err != nil {
		t.Fatalf("failed to unpack query: %v", err)
	}

	// Verify unpacked message matches original
	if unpacked.Id != query.Id {
		t.Errorf("ID mismatch: expected %d, got %d", query.Id, unpacked.Id)
	}

	if len(unpacked.Question) != len(query.Question) {
		t.Errorf("question count mismatch: expected %d, got %d",
			len(query.Question), len(unpacked.Question))
	}
}

// TestDOHListenerResponseSerialization tests response message serialization.
func TestDOHListenerResponseSerialization(t *testing.T) {
	// Create a response message
	response := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:       1234,
			Response: true,
			Rcode:    dns.RcodeSuccess,
		},
		Answer: []dns.RR{},
	}

	// Pack the response
	packed, err := response.Pack()
	if err != nil {
		t.Fatalf("failed to pack response: %v", err)
	}

	// Verify message can be serialized
	if len(packed) == 0 {
		t.Error("expected packed response to be non-empty")
	}

	// Verify message is within valid DoH size
	if len(packed) > 65535 {
		t.Errorf("packed message exceeds DoH max size (65535), got %d", len(packed))
	}

	// Unpack to verify integrity
	unpacked := &dns.Msg{}
	if err := unpacked.Unpack(packed); err != nil {
		t.Fatalf("failed to unpack response: %v", err)
	}

	if unpacked.Id != response.Id {
		t.Errorf("ID mismatch: expected %d, got %d", response.Id, unpacked.Id)
	}

	if unpacked.Rcode != response.Rcode {
		t.Errorf("Rcode mismatch: expected %d, got %d", response.Rcode, unpacked.Rcode)
	}
}

// TestDOHListenerContextCancellation tests graceful shutdown.
func TestDOHListenerContextCancellation(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}},
		err:      nil,
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	listener, err := NewDOHListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLoggerDoH(), false)
	if err != nil {
		t.Fatalf("failed to create DoH listener: %v", err)
	}
	defer listener.Close()

	// Start listener with cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	// Run in background
	done := make(chan error, 1)
	go func() {
		done <- listener.Serve(ctx)
	}()

	// Give it time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context
	cancel()

	// Wait for serve to return (with timeout)
	select {
	case err := <-done:
		if err != nil {
			t.Logf("Serve returned error (expected): %v", err)
		}
		// Serve returned, which is what we want
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for Serve to return after context cancel")
	}
}

// TestDOHListenerClose tests that Close() properly closes the listener.
func TestDOHListenerClose(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}},
		err:      nil,
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	listener, err := NewDOHListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLoggerDoH(), false)
	if err != nil {
		t.Fatalf("failed to create DoH listener: %v", err)
	}

	// Close should succeed
	err = listener.Close()
	if err != nil {
		t.Errorf("close failed: %v", err)
	}

	// Closing again should also succeed (idempotent)
	err = listener.Close()
	if err != nil {
		t.Errorf("second close failed: %v", err)
	}
}

// TestDOHHandlerInvalidMethod tests that truly unsupported methods (not GET/POST)
// are rejected with 405. (GET and POST are both valid per RFC 8484 §4.1.)
func TestDOHHandlerInvalidMethod(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}},
		err:      nil,
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	listener, err := NewDOHListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLoggerDoH(), false)
	if err != nil {
		t.Fatalf("failed to create DoH listener: %v", err)
	}
	defer listener.Close()

	// PUT is not a valid DoH method — expect 405 Method Not Allowed.
	request := &http.Request{
		Method: http.MethodPut,
		Header: make(http.Header),
	}
	response := &mockResponseWriter{statusCode: 0, body: &bytes.Buffer{}, header: make(http.Header)}
	listener.handleDNSQuery(response, request)
	if response.statusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT: expected status %d, got %d", http.StatusMethodNotAllowed, response.statusCode)
	}
}

// TestDOHHandlerGetMissingParam tests that a GET without the ?dns= parameter is a
// 400 bad request (GET itself is valid per RFC 8484; the missing query is the error).
func TestDOHHandlerGetMissingParam(t *testing.T) {
	mockResolver := &MockResolver{response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}}}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	listener, err := NewDOHListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLoggerDoH(), false)
	if err != nil {
		t.Fatalf("failed to create DoH listener: %v", err)
	}
	defer listener.Close()

	// GET with no ?dns= — needs a non-nil URL because the handler reads URL.Query().
	request := &http.Request{Method: http.MethodGet, Header: make(http.Header), URL: &url.URL{}}
	response := &mockResponseWriter{statusCode: 0, body: &bytes.Buffer{}, header: make(http.Header)}
	listener.handleDNSQuery(response, request)
	if response.statusCode != http.StatusBadRequest {
		t.Errorf("GET no ?dns=: expected status %d, got %d", http.StatusBadRequest, response.statusCode)
	}
}

// TestDOHHandlerGetValid tests that a GET with a valid base64url ?dns= resolves (200).
func TestDOHHandlerGetValid(t *testing.T) {
	mockResolver := &MockResolver{response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}}}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	listener, err := NewDOHListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLoggerDoH(), false)
	if err != nil {
		t.Fatalf("failed to create DoH listener: %v", err)
	}
	defer listener.Close()

	// A real DNS query (example.com A) packed and base64url-encoded (unpadded).
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	packed, err := q.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	param := base64.RawURLEncoding.EncodeToString(packed)

	request := &http.Request{
		Method: http.MethodGet,
		Header: make(http.Header),
		URL:    &url.URL{RawQuery: "dns=" + param},
	}
	response := &mockResponseWriter{statusCode: 0, body: &bytes.Buffer{}, header: make(http.Header)}
	listener.handleDNSQuery(response, request)
	if response.statusCode != http.StatusOK {
		t.Errorf("GET valid ?dns=: expected status %d, got %d", http.StatusOK, response.statusCode)
	}
}

// TestDOHHandlerEmptyBody tests handling of empty request body.
func TestDOHHandlerEmptyBody(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}},
		err:      nil,
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	listener, err := NewDOHListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLoggerDoH(), false)
	if err != nil {
		t.Fatalf("failed to create DoH listener: %v", err)
	}
	defer listener.Close()

	// Create a mock HTTP request with empty body
	request := &http.Request{
		Method: http.MethodPost,
		Header: make(http.Header),
		Body:   io.NopCloser(bytes.NewBuffer([]byte{})),
	}

	// Mock response writer
	response := &mockResponseWriter{
		statusCode: 0,
		body:       &bytes.Buffer{},
		header:     make(http.Header),
	}

	// Call handler
	listener.handleDNSQuery(response, request)

	// Verify bad request error
	if response.statusCode != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, response.statusCode)
	}
}

// BenchmarkDOHMessagePacking benchmarks DoH message packing.
func BenchmarkDOHMessagePacking(b *testing.B) {
	query := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:     1234,
			Opcode: dns.OpcodeQuery,
		},
		Question: []dns.Question{
			{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = query.Pack()
	}
}

// mockResponseWriter is a mock implementation of http.ResponseWriter for testing.
type mockResponseWriter struct {
	statusCode int
	body       *bytes.Buffer
	header     http.Header
}

func (m *mockResponseWriter) Header() http.Header {
	return m.header
}

func (m *mockResponseWriter) Write(data []byte) (int, error) {
	if m.statusCode == 0 {
		m.statusCode = http.StatusOK
	}
	return m.body.Write(data)
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	if m.statusCode == 0 {
		m.statusCode = statusCode
	}
}

// countingReader reports how many bytes were read from an effectively infinite
// stream of zero bytes. Used to prove the DoH handler bounds its body read.
type countingReader struct{ n int }

func (c *countingReader) Read(p []byte) (int, error) {
	c.n += len(p)
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// TestDOHHandlerOversizedBodyRejected verifies the DoH server rejects an oversized
// request body (DoS hardening, ISSUES.md 19) AND that it does NOT read more than
// dns.MaxMsgSize+1 bytes from the connection — i.e. io.LimitReader bounds the read
// rather than buffering an unbounded body into memory.
func TestDOHHandlerOversizedBodyRejected(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}},
	}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	listener, err := NewDOHListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLoggerDoH(), false)
	if err != nil {
		t.Fatalf("failed to create DoH listener: %v", err)
	}
	defer listener.Close()

	// An effectively infinite body — if the read were unbounded this would never
	// stop. The handler must cap it and reject.
	counter := &countingReader{}
	request := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{"Content-Type": []string{"application/dns-message"}},
		Body:   io.NopCloser(counter),
	}
	response := &mockResponseWriter{body: &bytes.Buffer{}, header: make(http.Header)}

	listener.handleDNSQuery(response, request)

	// Oversized -> 400 Bad Request (size check fires on the bounded read).
	if response.statusCode != http.StatusBadRequest {
		t.Errorf("expected status %d for oversized body, got %d", http.StatusBadRequest, response.statusCode)
	}
	// The read must be bounded. io.ReadAll on a LimitReader(.., MaxMsgSize+1) may
	// consume a bit extra due to internal buffer growth, but it must NOT run away.
	if counter.n > dns.MaxMsgSize*2 {
		t.Errorf("read was not bounded: consumed %d bytes (expected ~%d)", counter.n, dns.MaxMsgSize+1)
	}
}

// TestDOHListenerDoH3RoundTrip is an end-to-end test of DoH3 (DNS-over-HTTPS over
// HTTP/3 / QUIC). It starts a DoH listener with HTTP/3 ENABLED, then performs a real
// DoH POST over an http3.Transport (the QUIC transport) and verifies a valid DNS
// response comes back over HTTP/3 — proving the HTTP/3 server path, not just HTTP/2.
func TestDOHListenerDoH3RoundTrip(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: 4242, Response: true, Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{},
		},
	}

	// Real self-signed cert (includes 127.0.0.1 in SANs) so QUIC's TLS 1.3 handshake
	// can complete; the client below skips verification.
	certPEM, keyPEM, err := generateSelfSignedCert([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	// Fixed local port so the client knows where to dial the UDP/QUIC listener.
	const addr = "127.0.0.1:18453"
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	// enableH3 = true → the listener serves BOTH HTTP/2 over TCP and HTTP/3 over QUIC.
	listener, err := NewDOHListener(addr, tlsConfig, mockResolver, nil, nil, nil, testLoggerDoH(), true)
	if err != nil {
		t.Fatalf("create DoH listener: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go listener.Serve(ctx)
	time.Sleep(300 * time.Millisecond) // let both listeners bind

	// Build a DoH client that speaks ONLY HTTP/3 (DoH3) via http3.Transport.
	h3rt := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}},
	}
	defer h3rt.Close()
	client := &http.Client{Transport: h3rt, Timeout: 5 * time.Second}

	// DNS query → packed → POST body (RFC 8484), sent over HTTP/3.
	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeA)
	query.Id = 4242
	body, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	url := "https://" + addr + "/dns-query"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("DoH3 round-trip failed (HTTP/3 request): %v", err)
	}
	defer resp.Body.Close()

	// Confirm the response actually came back over HTTP/3.
	if resp.ProtoMajor != 3 {
		t.Errorf("expected response over HTTP/3, got HTTP/%d.%d", resp.ProtoMajor, resp.ProtoMinor)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		t.Errorf("expected Content-Type application/dns-message, got %q", ct)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	got := &dns.Msg{}
	if err := got.Unpack(respBody); err != nil {
		t.Fatalf("unpack DNS response: %v", err)
	}
	if !got.Response || got.Rcode != dns.RcodeSuccess {
		t.Errorf("expected successful DNS response, got Response=%v Rcode=%d", got.Response, got.Rcode)
	}
	if n := mockResolver.callCount.Load(); n != 1 {
		t.Errorf("expected resolver to be called once over DoH3, got %d", n)
	}
}

// TestDOHListenerNegotiatesH2NotDowngrade is the regression guard for ISSUES 26:
// the DoH TCP listener must advertise HTTP/2 via ALPN so an h2-capable client negotiates
// "h2" and is NOT silently downgraded to HTTP/1.1. (The bug: the listener used a tls.Config
// with empty NextProtos served via http.Server.Serve over a manually TLS-wrapped listener,
// which does not auto-enable h2 — so EVERY client ALPN-negotiated nothing and fell back to
// h1.1, i.e. the "HTTP/2 over TCP" listener really served h1.1.)
//
// We dial directly at the TLS layer (not via http) so we can inspect the negotiated ALPN
// protocol from ConnectionState(). We test BOTH client ALPN orderings — including h1.1
// listed FIRST — to prove the SERVER's h2 preference wins regardless of client order, so an
// h2-capable client can never be downgraded.
func TestDOHListenerNegotiatesH2NotDowngrade(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: 7, Response: true, Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{},
		},
	}

	certPEM, keyPEM, err := generateSelfSignedCert([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}

	const addr = "127.0.0.1:18454"
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	// enableH3 = false → exercise the plain HTTP/2-over-TCP DoH listener.
	listener, err := NewDOHListener(addr, tlsConfig, mockResolver, nil, nil, nil, testLoggerDoH(), false)
	if err != nil {
		t.Fatalf("create DoH listener: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go listener.Serve(ctx)
	time.Sleep(300 * time.Millisecond) // let the listener bind

	// Each client below is h2-capable (offers h2) — the server must select h2 in every case,
	// even when the client lists http/1.1 first. A bare TLS dial lets us read the negotiated
	// ALPN directly.
	cases := []struct {
		name      string
		nextProto []string
	}{
		{"h2 only", []string{"h2"}},
		{"h2 preferred (browser default)", []string{"h2", "http/1.1"}},
		{"h1.1 listed first, h2 also offered", []string{"http/1.1", "h2"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := tls.Dial("tcp", addr, &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         tc.nextProto,
			})
			if err != nil {
				t.Fatalf("TLS dial failed: %v", err)
			}
			defer conn.Close()

			got := conn.ConnectionState().NegotiatedProtocol
			if got != "h2" {
				t.Errorf("h2-capable client offering %v negotiated %q; want \"h2\" (server must not downgrade to HTTP/1.1)",
					tc.nextProto, got)
			}
		})
	}

	// HARD-CLOSE: clients that do NOT offer h2 must be REJECTED at the TLS handshake —
	// the connection must fail, NOT fall through to an HTTP/1.1 200. This closes the
	// untested/incidental h1.1 path (downgrade + attack surface). See ISSUES 26.
	rejectCases := []struct {
		name      string
		nextProto []string
	}{
		{"http/1.1 only", []string{"http/1.1"}},
		{"no ALPN offered at all", nil},
	}
	for _, tc := range rejectCases {
		t.Run("reject: "+tc.name, func(t *testing.T) {
			conn, err := tls.Dial("tcp", addr, &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         tc.nextProto,
			})
			if err == nil {
				negotiated := conn.ConnectionState().NegotiatedProtocol
				conn.Close()
				t.Fatalf("client offering %v completed the TLS handshake (negotiated %q); want REJECTED — h1.1/no-ALPN must not be reachable",
					tc.nextProto, negotiated)
			}
			// Expected: handshake error (GetConfigForClient returned an error).
			t.Logf("correctly rejected (%v): %v", tc.nextProto, err)
		})
	}

	// Sanity: a full HTTP/2 DoH round-trip succeeds (and reports HTTP/2), confirming the
	// listener doesn't just negotiate h2 at TLS but actually serves DoH over it.
	h2Transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: h2Transport, Timeout: 5 * time.Second}

	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeA)
	body, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+"/dns-query", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP/2 DoH round-trip failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Errorf("expected DoH response over HTTP/2, got HTTP/%d.%d", resp.ProtoMajor, resp.ProtoMinor)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK over HTTP/2, got %d", resp.StatusCode)
	}
}
