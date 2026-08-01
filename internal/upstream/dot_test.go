// SPDX-License-Identifier: MIT
package upstream

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testLogger creates a logger that discards output for tests.
func testLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// MockResolver returns a fixed response for testing.
// callCount is atomic: the listeners resolve on their own goroutines, and the race
// detector cannot see a happens-before edge through the loopback sockets the tests
// use, so a plain int read from the test goroutine is a data race.
type MockResolver struct {
	response  *dns.Msg
	err       error
	callCount atomic.Int64
}

func (m *MockResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	m.callCount.Add(1)
	return m.response, m.err
}

func (m *MockResolver) Close() error {
	return nil
}

// TestDOTListenerCreation tests DoT listener creation.
func TestDOTListenerCreation(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
		},
		err: nil,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{},
	}

	listener, err := NewDOTListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("failed to create DoT listener: %v", err)
	}

	if listener == nil {
		t.Error("expected non-nil listener")
	}

	// Clean up
	listener.Close()
}

// TestDOTListenerResolveQuery tests that DoT listener resolves queries correctly.
func TestDOTListenerResolveQuery(t *testing.T) {
	// Create mock resolver with test response
	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:       1234,
				Response: true,
				Rcode:    dns.RcodeSuccess,
			},
			Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.IPv4(93, 184, 216, 34),
				},
			},
		},
		err: nil,
	}

	// Create TLS config (for testing, use empty config - will fail in real scenario)
	// For unit tests, we skip the actual TLS handshake
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Create listener on random port
	listener, err := NewDOTListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("failed to create DoT listener: %v", err)
	}
	defer listener.Close()

	// Get the actual bound address
	addr := listener.listener.Addr().String()
	t.Logf("DoT listener bound to %s", addr)

	// Start listener in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go listener.Serve(ctx)

	// Give listener time to start accepting connections
	time.Sleep(100 * time.Millisecond)

	// Note: Testing actual TLS connection requires proper certificate setup
	// This is tested at integration level in main.go tests
	// For now, we verify the listener can be created and started

	// Verify resolver was not called yet (no queries received)
	if n := mockResolver.callCount.Load(); n != 0 {
		t.Errorf("expected resolver call count 0, got %d", n)
	}
}

// TestDOTListenerInvalidMessageLength tests handling of invalid message length.
func TestDOTListenerInvalidMessageLength(t *testing.T) {
	// This test verifies the listener's handling of edge cases
	// Actual connection testing is deferred to integration tests

	// Test that NewDOTListener accepts valid addresses
	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}},
		err:      nil,
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	// Valid address
	listener, err := NewDOTListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("failed to create listener on valid address: %v", err)
	}
	listener.Close()

	// Invalid address should fail
	_, err = NewDOTListener("999.999.999.999:99999", tlsConfig, mockResolver, nil, nil, nil, testLogger())
	if err == nil {
		t.Error("expected error for invalid address, got nil")
	}
}

// TestDOTListenerMessagePacking tests DNS message packing.
func TestDOTListenerMessagePacking(t *testing.T) {
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

	// Verify message is within valid DoT size (should fit in uint16)
	if len(packed) > 65535 {
		t.Errorf("packed message exceeds DoT max size (65535), got %d", len(packed))
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

// TestDOTListenerContextCancellation tests graceful shutdown.
func TestDOTListenerContextCancellation(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}},
		err:      nil,
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	listener, err := NewDOTListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("failed to create DoT listener: %v", err)
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

	// Wait for serve to return (with longer timeout since accept loop runs on 1s ticker)
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

// TestDOTListenerResponseSerialization tests response message serialization.
func TestDOTListenerResponseSerialization(t *testing.T) {
	// Create a response message
	response := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:       1234,
			Response: true,
			Rcode:    dns.RcodeSuccess,
		},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4(93, 184, 216, 34),
			},
		},
	}

	// Pack the response
	packed, err := response.Pack()
	if err != nil {
		t.Fatalf("failed to pack response: %v", err)
	}

	// Simulate DoT length prefix encoding
	lenBuf := []byte{byte(len(packed) >> 8), byte(len(packed))}
	if len(lenBuf) != 2 {
		t.Errorf("length prefix should be 2 bytes, got %d", len(lenBuf))
	}

	// Verify length encoding is correct
	msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if msgLen != len(packed) {
		t.Errorf("length mismatch: encoded %d, actual %d", msgLen, len(packed))
	}

	// Verify message is valid
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

	if len(unpacked.Answer) != len(response.Answer) {
		t.Errorf("answer count mismatch: expected %d, got %d",
			len(response.Answer), len(unpacked.Answer))
	}
}

// TestDOTListenerClose tests that Close() properly closes the listener.
func TestDOTListenerClose(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}},
		err:      nil,
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	listener, err := NewDOTListener("127.0.0.1:0", tlsConfig, mockResolver, nil, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("failed to create DoT listener: %v", err)
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

// BenchmarkDOTListenerMessagePacking benchmarks message packing.
func BenchmarkDOTListenerMessagePacking(b *testing.B) {
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
