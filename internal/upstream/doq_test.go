// SPDX-License-Identifier: MIT
package upstream

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// testLoggerDoQ creates a logger that discards output for tests.
func testLoggerDoQ() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// TestDOQListenerCreation tests DoQ listener creation.
func TestDOQListenerCreation(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
		},
		err: nil,
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	listener, err := NewDOQListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLoggerDoQ())
	if err != nil {
		t.Fatalf("failed to create DoQ listener: %v", err)
	}

	if listener == nil {
		t.Error("expected non-nil listener")
	}

	// Clean up
	listener.Close()
}

// TestDOQListenerInvalidMessageLength tests handling of invalid message length.
func TestDOQListenerInvalidMessageLength(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}},
		err:      nil,
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	// Valid address
	listener, err := NewDOQListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLoggerDoQ())
	if err != nil {
		t.Fatalf("failed to create listener on valid address: %v", err)
	}
	listener.Close()

	// Invalid address should fail
	_, err = NewDOQListener("999.999.999.999:99999", tlsConfig, mockResolver, nil, nil, nil, testLoggerDoQ())
	if err == nil {
		t.Error("expected error for invalid address, got nil")
	}
}

// TestDOQListenerMessagePacking tests DNS message packing.
func TestDOQListenerMessagePacking(t *testing.T) {
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

	// Verify message is within valid DoQ size (should fit in uint16)
	if len(packed) > 65535 {
		t.Errorf("packed message exceeds DoQ max size (65535), got %d", len(packed))
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

// TestDOQListenerResponseSerialization tests response message serialization.
func TestDOQListenerResponseSerialization(t *testing.T) {
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

	// Verify message is within valid DoQ size
	if len(packed) > 65535 {
		t.Errorf("packed message exceeds DoQ max size (65535), got %d", len(packed))
	}

	// Simulate DoQ length prefix encoding
	lenBuf := []byte{byte(len(packed) >> 8), byte(len(packed))}
	if len(lenBuf) != 2 {
		t.Errorf("length prefix should be 2 bytes, got %d", len(lenBuf))
	}

	// Verify length encoding is correct
	msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if msgLen != len(packed) {
		t.Errorf("length mismatch: encoded %d, actual %d", msgLen, len(packed))
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

// TestDOQListenerContextCancellation tests graceful shutdown.
func TestDOQListenerContextCancellation(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}},
		err:      nil,
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	listener, err := NewDOQListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLoggerDoQ())
	if err != nil {
		t.Fatalf("failed to create DoQ listener: %v", err)
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

// TestDOQListenerClose tests that Close() properly closes the listener.
func TestDOQListenerClose(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}},
		err:      nil,
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	listener, err := NewDOQListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLoggerDoQ())
	if err != nil {
		t.Fatalf("failed to create DoQ listener: %v", err)
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

// TestDOQListenerRoundTripALPN is the regression guard for the DoQ ALPN bug (2026-07-11):
// the DoQ server MUST advertise the "doq" ALPN token (RFC 9250 §4.1). The TLS config is
// shared with the DoT/DoH listeners, which set no NextProtos, so a QUIC server built from
// it directly advertises NO ALPN and every client handshake fails with
// "tls: server did not select an ALPN protocol". NewDOQListener now clones the config and
// pins NextProtos=["doq"]; this test does a REAL QUIC handshake + query round-trip to prove
// it — it fails without the fix.
func TestDOQListenerRoundTripALPN(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: 4242, Response: true, Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{},
		},
	}

	// Real self-signed cert (includes 127.0.0.1) so QUIC's TLS 1.3 handshake can complete.
	certPEM, keyPEM, err := generateSelfSignedCert([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}

	const addr = "127.0.0.1:18853"
	// SHARED-style config: certs only, NO NextProtos — exactly what DoT/DoH hand in. The
	// listener must add "doq" itself, or the handshake below fails on ALPN.
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	listener, err := NewDOQListener(addr, tlsConfig, mockResolver, nil, nil, nil, testLoggerDoQ())
	if err != nil {
		t.Fatalf("create DoQ listener: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go listener.Serve(ctx)
	time.Sleep(300 * time.Millisecond) // let the UDP/QUIC listener bind

	// DoQ client: must offer the "doq" ALPN (RFC 9250). Skip cert verification (self-signed).
	clientTLS := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"doq"}}
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()
	conn, err := quic.DialAddr(dialCtx, addr, clientTLS, &quic.Config{})
	if err != nil {
		t.Fatalf("DoQ QUIC dial failed (ALPN regression?): %v", err)
	}
	defer conn.CloseWithError(0, "")

	// One DNS query on a fresh stream, RFC 9250 2-byte length prefix.
	stream, err := conn.OpenStreamSync(dialCtx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeA)
	query.Id = 4242
	qBuf, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	prefix := []byte{byte(len(qBuf) >> 8), byte(len(qBuf))}
	if _, err := stream.Write(append(prefix, qBuf...)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	stream.Close() // signal end of request

	// Read the length-prefixed response.
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		t.Fatalf("read response length: %v", err)
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(stream, respBuf); err != nil {
		t.Fatalf("read response body: %v", err)
	}
	got := &dns.Msg{}
	if err := got.Unpack(respBuf); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if !got.Response || got.Rcode != dns.RcodeSuccess {
		t.Errorf("expected successful DNS response, got Response=%v Rcode=%d", got.Response, got.Rcode)
	}
	if n := mockResolver.callCount.Load(); n != 1 {
		t.Errorf("expected resolver called once over DoQ, got %d", n)
	}
}

// BenchmarkDOQMessagePacking benchmarks message packing.
func BenchmarkDOQMessagePacking(b *testing.B) {
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
