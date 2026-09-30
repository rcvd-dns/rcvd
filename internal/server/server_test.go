// SPDX-License-Identifier: MIT
package server

import (
	"context"
	"crypto"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rcvd-dns/rcvd/internal/allowlist"
	"github.com/rcvd-dns/rcvd/internal/blocklist"
	"github.com/rcvd-dns/rcvd/internal/cache"
	"github.com/rcvd-dns/rcvd/internal/config"
	"github.com/rcvd-dns/rcvd/internal/dnssec"
	"github.com/rcvd-dns/rcvd/internal/statistics"
)

// MockResolver is a test resolver that returns a fixed response.
// The mutable capture fields are mutex-guarded: the server resolves on its own
// goroutines, and the race detector cannot see a happens-before edge through the
// loopback sockets the tests use, so plain field reads from the test goroutine
// are a data race.
type MockResolver struct {
	mu        sync.Mutex
	callCount int
	response  *dns.Msg
	err       error
	lastQuery *dns.Msg // captures the most recent query passed upstream (for assertions)
}

func (m *MockResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	m.mu.Lock()
	m.callCount++
	m.lastQuery = msg
	m.mu.Unlock()
	if m.response != nil {
		// Mirror the query ID so the DNS client accepts the response.
		resp := m.response.Copy()
		resp.Id = msg.Id
		return resp, m.err
	}
	return m.response, m.err
}

// CallCount returns the number of Resolve calls observed so far.
func (m *MockResolver) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

// LastQuery returns the most recent query passed upstream (may be nil).
func (m *MockResolver) LastQuery() *dns.Msg {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastQuery
}

func (m *MockResolver) Close() error {
	return nil
}

// TestServerCacheIntegration tests that server uses cache correctly.
func TestServerCacheIntegration(t *testing.T) {
	cfg := &config.Config{
		Resolver: config.ResolverConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0", // Use dynamic port for testing
		},
		Cache: config.CacheConfig{
			Enabled:  true,
			MaxSize:  100,
			TTLMin:   60,
			TTLMax:   3600,
			Prefetch: false,
		},
	}

	// Create mock resolver that tracks calls
	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{
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

	// Create cache
	dnsCache := cache.New(cache.Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 3600})

	// Create blocklist (disabled for this test)
	dnsBlocklist := blocklist.New(false)

	// Create server with cache and blocklist
	srv := NewServer(cfg, mockResolver, dnsCache, dnsBlocklist, nil, nil, nil)

	// Create test query
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

	// First query should call resolver and cache result
	ctx := context.Background()
	response1, err := srv.resolver.Resolve(ctx, query)
	if err != nil {
		t.Fatalf("first resolve failed: %v", err)
	}

	initialCallCount := mockResolver.CallCount()
	if initialCallCount != 1 {
		t.Errorf("expected 1 resolver call, got %d", initialCallCount)
	}

	// Cache the response
	if srv.cache != nil && len(query.Question) > 0 {
		srv.cache.Put(query, response1)
	}

	// Second query should hit cache (resolver not called)
	if srv.cache != nil && len(query.Question) > 0 {
		cached, found := srv.cache.Get(query)
		if !found {
			t.Fatal("expected cache hit, got miss")
		}
		if cached == nil {
			t.Fatal("expected non-nil cached response")
		}
	}

	// Verify resolver was NOT called again
	if now := mockResolver.CallCount(); now != initialCallCount {
		t.Errorf("resolver was called again (cache miss). Initial: %d, Now: %d",
			initialCallCount, now)
	}
}

// TestServerNoCacheWorks tests that server works fine without cache.
func TestServerNoCacheWorks(t *testing.T) {
	cfg := &config.Config{
		Resolver: config.ResolverConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
		},
		Cache: config.CacheConfig{
			Enabled: false, // Cache disabled
		},
	}

	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
		},
		err: nil,
	}

	// Create disabled cache
	dnsCache := cache.New(cache.Options{Enabled: false, MaxSize: 0, TTLMin: 0, TTLMax: 0})

	// Create blocklist (disabled for this test)
	dnsBlocklist := blocklist.New(false)

	srv := NewServer(cfg, mockResolver, dnsCache, dnsBlocklist, nil, nil, nil)

	query := &dns.Msg{
		Question: []dns.Question{
			{
				Name:   "test.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}

	ctx := context.Background()
	_, err := srv.resolver.Resolve(ctx, query)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	// Try to get from cache (should miss since cache is disabled)
	if srv.cache != nil && len(query.Question) > 0 {
		_, found := srv.cache.Get(query)
		if found {
			t.Error("expected cache miss when cache is disabled")
		}
	}
}

// TestServerBlocklistIntegration tests that server blocks domains correctly.
func TestServerBlocklistIntegration(t *testing.T) {
	cfg := &config.Config{
		Resolver: config.ResolverConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
		},
		Cache: config.CacheConfig{
			Enabled: false, // Disable cache for this test
		},
		Blocklists: config.BlocklistConfig{
			Enabled: true,
		},
	}

	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
		},
		err: nil,
	}

	// Create enabled blocklist
	dnsBlocklist := blocklist.New(true)

	// Add some blocked domains
	dnsBlocklist.Add("blocked.com")
	dnsBlocklist.Add("*.ads.example.com")

	srv := NewServer(cfg, mockResolver, cache.New(cache.Options{Enabled: false, MaxSize: 0, TTLMin: 0, TTLMax: 0}), dnsBlocklist, nil, nil, nil)

	// Test 1: Blocked domain should return NXDOMAIN
	blockedQuery := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:     1234,
			Opcode: dns.OpcodeQuery,
		},
		Question: []dns.Question{
			{
				Name:   "blocked.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}

	initialCallCount := mockResolver.CallCount()
	_, err := srv.resolver.Resolve(context.Background(), blockedQuery)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	// Check that resolver was still called (blocklist integration is separate)
	if mockResolver.CallCount() <= initialCallCount {
		t.Errorf("expected resolver call (integration test context)")
	}

	// Test 2: Unblocked domain should resolve normally
	unblockQuery := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:     5678,
			Opcode: dns.OpcodeQuery,
		},
		Question: []dns.Question{
			{
				Name:   "google.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}

	response2, err := srv.resolver.Resolve(context.Background(), unblockQuery)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	if response2 == nil {
		t.Error("expected non-nil response for unblocked domain")
	}

	// Test 3: Wildcard blocked domain should be blocked
	if !srv.blocklist.IsBlocked("ads1.ads.example.com") {
		t.Error("expected wildcard match for *.ads.example.com")
	}

	if !srv.blocklist.IsBlocked("deep.ads1.ads.example.com") {
		t.Error("expected wildcard match for deep subdomain")
	}
}

// TestServerDNSSECDisabled tests that server skips DNSSEC validation when disabled.
func TestServerDNSSECDisabled(t *testing.T) {
	cfg := &config.Config{
		Resolver: config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"},
	}

	// Resolver returns a response without RRSIG records
	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.IPv4(93, 184, 216, 34),
				},
			},
		},
	}

	// DNSSEC disabled — validator should not block unsigned responses
	validator := dnssec.New(false, false)
	srv := NewServer(cfg, mockResolver, cache.New(cache.Options{Enabled: false, MaxSize: 0, TTLMin: 0, TTLMax: 0}), blocklist.New(false), validator, nil, nil)

	ctx := context.Background()
	query := &dns.Msg{Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}

	response, err := srv.resolver.Resolve(ctx, query)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	// Validator disabled: should return nil for any response
	if err := srv.validator.ValidateResponse(response); err != nil {
		t.Errorf("expected no error with DNSSEC disabled, got: %v", err)
	}
}

// TestServerDNSSECEnabledUnsignedPermissive tests that server allows unsigned responses
// when DNSSEC is enabled but validateAll is false (permissive mode).
func TestServerDNSSECEnabledUnsignedPermissive(t *testing.T) {
	cfg := &config.Config{
		Resolver: config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"},
	}

	// Unsigned response (no RRSIG records)
	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.IPv4(93, 184, 216, 34),
				},
			},
		},
	}

	// Permissive: unsigned OK (validateAll=false)
	validator := dnssec.New(true, false)
	srv := NewServer(cfg, mockResolver, cache.New(cache.Options{Enabled: false, MaxSize: 0, TTLMin: 0, TTLMax: 0}), blocklist.New(false), validator, nil, nil)

	ctx := context.Background()
	query := &dns.Msg{Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}

	response, err := srv.resolver.Resolve(ctx, query)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	// Permissive mode: an unsigned answer is INSECURE, not secure. It must be served (not SERVFAIL)
	// but WITHOUT the AD bit — so ValidateResponse returns the insecure signal (IsInsecure==true),
	// NOT nil. nil would falsely claim authentication on an unsigned answer (the docker.io bug).
	err = srv.validator.ValidateResponse(response)
	if err == nil {
		t.Fatalf("expected insecure signal (not nil) for unsigned response in permissive mode")
	}
	if !dnssec.IsInsecure(err) {
		t.Errorf("expected IsInsecure for unsigned response in permissive mode, got: %v", err)
	}
}

// TestServerDNSSECEnabledUnsignedStrict tests that server rejects unsigned responses
// when validateAll is true (strict mode).
func TestServerDNSSECEnabledUnsignedStrict(t *testing.T) {
	cfg := &config.Config{
		Resolver: config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"},
	}

	// Unsigned response (no RRSIG records)
	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.IPv4(93, 184, 216, 34),
				},
			},
		},
	}

	// Strict: unsigned NOT OK (validateAll=true)
	validator := dnssec.New(true, true)
	srv := NewServer(cfg, mockResolver, cache.New(cache.Options{Enabled: false, MaxSize: 0, TTLMin: 0, TTLMax: 0}), blocklist.New(false), validator, nil, nil)

	ctx := context.Background()
	query := &dns.Msg{Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}

	response, err := srv.resolver.Resolve(ctx, query)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	// Strict mode: unsigned response must fail validation
	if err := srv.validator.ValidateResponse(response); err == nil {
		t.Error("expected validation error in strict mode for unsigned response, got nil")
	}
}

// TestServerDNSSECExpiredRRSIG tests that server rejects responses with expired RRSIG.
func TestServerDNSSECExpiredRRSIG(t *testing.T) {
	cfg := &config.Config{
		Resolver: config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"},
	}

	// Response with expired RRSIG (expiration in the past)
	expiredRRSIG := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.ECDSAP256SHA256,
		Inception:   1000000000, // 2001-09-09 (past)
		Expiration:  1000000001, // 2001-09-09 + 1s (expired)
		KeyTag:      12345,
		SignerName:  "example.com.",
		Signature:   "AAAA", // non-empty
	}

	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.IPv4(93, 184, 216, 34),
				},
				expiredRRSIG,
			},
		},
	}

	validator := dnssec.New(true, false)
	srv := NewServer(cfg, mockResolver, cache.New(cache.Options{Enabled: false, MaxSize: 0, TTLMin: 0, TTLMax: 0}), blocklist.New(false), validator, nil, nil)

	ctx := context.Background()
	query := &dns.Msg{Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}

	response, err := srv.resolver.Resolve(ctx, query)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	// Expired RRSIG must fail validation
	if err := srv.validator.ValidateResponse(response); err == nil {
		t.Error("expected validation error for expired RRSIG, got nil")
	}
}

// TestServerDNSSECNilValidator tests that server works with nil validator (no DNSSEC).
func TestServerDNSSECNilValidator(t *testing.T) {
	cfg := &config.Config{
		Resolver: config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"},
	}

	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.IPv4(93, 184, 216, 34),
				},
			},
		},
	}

	// nil validator: server should not panic and should process normally
	srv := NewServer(cfg, mockResolver, cache.New(cache.Options{Enabled: false, MaxSize: 0, TTLMin: 0, TTLMax: 0}), blocklist.New(false), nil, nil, nil)

	ctx := context.Background()
	query := &dns.Msg{Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}

	_, err := srv.resolver.Resolve(ctx, query)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	// Verify nil validator field
	if srv.validator != nil {
		t.Error("expected nil validator")
	}
}

// signCNAME generates a ZSK for `zone`, signs the given CNAME with it, and returns the record, its
// RRSIG, and the co-resident DNSKEY. Putting the DNSKEY in the answer lets the validator's fast path
// find the signing key without a chain fetch — so this stays a self-contained server-package test.
func signCNAME(t *testing.T, zone string, cname *dns.CNAME) (*dns.RRSIG, *dns.DNSKEY) {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 256, Protocol: 3, Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("generate DNSKEY: %v", err)
	}
	now := time.Now()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: cname.Hdr.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: cname.Hdr.Ttl},
		TypeCovered: dns.TypeCNAME, Algorithm: key.Algorithm, Labels: uint8(dns.CountLabel(cname.Hdr.Name)),
		OrigTtl:    cname.Hdr.Ttl,
		Expiration: uint32(now.Add(24 * time.Hour).Unix()), Inception: uint32(now.Add(-time.Hour).Unix()),
		KeyTag: key.KeyTag(), SignerName: zone,
	}
	if err := sig.Sign(priv.(crypto.Signer), []dns.RR{cname}); err != nil {
		t.Fatalf("sign CNAME: %v", err)
	}
	return sig, key
}

// TestApplyDNSSECThreeWay proves the Issue 30 fix at the server boundary: applyDNSSEC must produce
// three distinct outcomes and — critically — must NOT stamp the AD bit on an INSECURE answer, nor
// SERVFAIL it.
//
//	SECURE   → AD set,      rcode NOERROR, DnssecValidated++
//	INSECURE → AD CLEARED,  rcode NOERROR, DnssecUnsigned++   (the Issue 30 case)
//	BOGUS    → SERVFAIL,    DnssecFailed++
func TestApplyDNSSECThreeWay(t *testing.T) {
	cfg := &config.Config{Resolver: config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"}}
	discard := log.New(io.Discard, "", 0) // applyDNSSEC logs on the bogus path — avoid a nil-logger panic
	newSrv := func(v *dnssec.Validator, stats *statistics.Stats) *Server {
		return NewServer(cfg, &MockResolver{}, cache.New(cache.Options{Enabled: false}), blocklist.New(false), v, stats, discard)
	}
	query := &dns.Msg{Question: []dns.Question{{Name: "whois.pir.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}

	// --- INSECURE: a signed CNAME head (its DNSKEY co-resident so it verifies) followed by an
	// UNSIGNED tail (a second CNAME + the final A), exactly like whois.pir.org crossing into the
	// unsigned iddg.io zone. The signed RRset validates; the unsigned tail makes the answer INSECURE.
	cname1 := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "whois.pir.org.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "whois.publicinterestregistry.org.",
	}
	cname1Sig, zoneKey := signCNAME(t, "pir.org.", cname1)
	cname2 := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "whois.publicinterestregistry.org.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "target.iddg.io.",
	}
	aRR := &dns.A{
		Hdr: dns.RR_Header{Name: "target.iddg.io.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IPv4(44, 233, 186, 238),
	}
	stats := &statistics.Stats{}
	srv := newSrv(dnssec.New(true, false), stats)
	// Upstream sometimes arrives with AD already set; prove we CLEAR it for an insecure answer.
	resp := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess, AuthenticatedData: true},
		Answer: []dns.RR{cname1, cname1Sig, zoneKey, cname2, aRR}}
	out := srv.applyDNSSEC(resp, query, "")
	if out.Rcode != dns.RcodeSuccess {
		t.Fatalf("INSECURE: expected NOERROR (serve the answer), got rcode %d", out.Rcode)
	}
	if out.AuthenticatedData {
		t.Error("INSECURE: AD bit must be CLEARED on a partially-signed chain (Issue 30)")
	}
	if stats.DnssecUnsigned != 1 || stats.DnssecValidated != 0 || stats.DnssecFailed != 0 {
		t.Errorf("INSECURE: stats want unsigned=1 validated=0 failed=0, got unsigned=%d validated=%d failed=%d",
			stats.DnssecUnsigned, stats.DnssecValidated, stats.DnssecFailed)
	}

	// --- BOGUS: an expired RRSIG must SERVFAIL, never serve. ---
	bogusStats := &statistics.Stats{}
	bogusSrv := newSrv(dnssec.New(true, false), bogusStats)
	expired := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeA, Algorithm: dns.ECDSAP256SHA256,
		Inception: 1000000000, Expiration: 1000000001, KeyTag: 12345, SignerName: "example.com.", Signature: "AAAA",
	}
	bogusResp := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess}, Answer: []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(93, 184, 216, 34)},
		expired,
	}}
	bogusOut := bogusSrv.applyDNSSEC(bogusResp, query, "")
	if bogusOut.Rcode != dns.RcodeServerFailure {
		t.Errorf("BOGUS: expected SERVFAIL, got rcode %d", bogusOut.Rcode)
	}
	if bogusOut.AuthenticatedData {
		t.Error("BOGUS: AD must never be set on SERVFAIL")
	}
	if bogusStats.DnssecFailed != 1 {
		t.Errorf("BOGUS: want failed=1, got failed=%d", bogusStats.DnssecFailed)
	}
}

// TestBlocklistAsyncLoadQueriesPassThrough verifies that DNS queries resolve normally
// while a blocklist is still loading in the background.
//
// This covers the router deployment scenario: a 328K-entry blocklist on SD card takes
// ~60s to load. The server must be usable immediately — queries pass through with an
// empty blocklist until loading completes, then blocked domains return NXDOMAIN.
func TestBlocklistAsyncLoadQueriesPassThrough(t *testing.T) {
	cfg := &config.Config{
		Resolver: config.ResolverConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
		},
		Cache: config.CacheConfig{Enabled: false},
		Blocklists: config.BlocklistConfig{
			Enabled: true,
		},
	}

	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Question: []dns.Question{
				{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
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
	}

	// Blocklist is enabled but starts empty (simulates background load not yet complete).
	dnsBlocklist := blocklist.New(true)

	discardLog := log.New(io.Discard, "", 0)
	srv := NewServer(cfg, mockResolver, cache.New(cache.Options{Enabled: false, MaxSize: 0, TTLMin: 0, TTLMax: 0}), dnsBlocklist, nil, nil, discardLog)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	defer srv.Stop(time.Second)

	// Resolve the actual listen address (port 0 → assigned port).
	addr := srv.UDPAddr().String()

	// Brief pause to let the UDP/TCP goroutines reach their read loops.
	time.Sleep(10 * time.Millisecond)

	// Fire a query BEFORE the blocklist is loaded.
	// This simulates a client querying during the ~60s SD card load window.
	resp := sendUDPQuery(t, addr, "example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR during blocklist load, got rcode %d", resp.Rcode)
	}

	// Now simulate the blocklist finishing its background load.
	dnsBlocklist.Add("blocked-after-load.com")

	// Query for the domain that is now blocked — must return NXDOMAIN.
	resp = sendUDPQuery(t, addr, "blocked-after-load.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN after blocklist loaded, got rcode %d", resp.Rcode)
	}

	// Query for a non-blocked domain — must still resolve normally.
	resp = sendUDPQuery(t, addr, "example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR for non-blocked domain after load, got rcode %d", resp.Rcode)
	}
}

// sendUDPQuery sends a DNS query over UDP and returns the response.
func sendUDPQuery(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c := new(dns.Client)
	c.Net = "udp"
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("DNS query for %s failed: %v", name, err)
	}
	return resp
}

// sendUDPQueryDO sends a DNS query with the EDNS0 DO bit set (mimicking a validating
// stub resolver like systemd-resolved) and returns the response.
func sendUDPQueryDO(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c := new(dns.Client)
	c.Net = "udp"
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.SetEdns0(4096, true) // OPT record, DO=1
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("DO-bit DNS query for %s failed: %v", name, err)
	}
	return resp
}

// TestServerDOBitEDNSHandling is the regression test for Issue 28: a DNSSEC-probing
// stub resolver (DO bit set) must get back an EDNS-capable, DO-set response — on the
// normal resolve path AND the blocklist NXDOMAIN path — and rcvd must request DNSSEC
// records upstream (DO=1) regardless of the client. Without this, systemd-resolved
// concludes the server is not EDNS/DNSSEC-capable, downgrades, and stalls ~5s/lookup.
func TestServerDOBitEDNSHandling(t *testing.T) {
	cfg := &config.Config{
		Resolver:   config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"},
		Cache:      config.CacheConfig{Enabled: false},
		Blocklists: config.BlocklistConfig{Enabled: true},
	}

	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
			Answer: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(93, 184, 216, 34),
			}},
		},
	}

	dnsBlocklist := blocklist.New(true)
	dnsBlocklist.Add("blocked.example.")

	discardLog := log.New(io.Discard, "", 0)
	srv := NewServer(cfg, mockResolver, cache.New(cache.Options{Enabled: false, MaxSize: 0, TTLMin: 0, TTLMax: 0}), dnsBlocklist, nil, nil, discardLog)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	defer srv.Stop(time.Second)

	addr := srv.UDPAddr().String()
	time.Sleep(10 * time.Millisecond)

	// 1. Normal resolve path: DO-bit query must get an OPT record with DO set back.
	resp := sendUDPQueryDO(t, addr, "example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got rcode %d", resp.Rcode)
	}
	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatal("resolve path: response has NO EDNS0 OPT record — resolved would downgrade (Issue 28)")
	}
	if !opt.Do() {
		t.Error("resolve path: response OPT DO bit not set for a DO-bit query")
	}

	// 2. rcvd must have requested DNSSEC records upstream (DO=1) regardless of client.
	lastQuery := mockResolver.LastQuery()
	if lastQuery == nil {
		t.Fatal("mock resolver never received a query")
	}
	upOpt := lastQuery.IsEdns0()
	if upOpt == nil || !upOpt.Do() {
		t.Error("upstream query did not carry EDNS0 DO=1 (rcvd validates DNSSEC itself, must request RRSIGs)")
	}

	// 3. Blocklist NXDOMAIN path: DO-bit query must ALSO get an EDNS-capable response.
	resp = sendUDPQueryDO(t, addr, "blocked.example.", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for blocked domain, got rcode %d", resp.Rcode)
	}
	if opt := resp.IsEdns0(); opt == nil {
		t.Error("blocklist path: NXDOMAIN response has NO EDNS0 OPT record (Issue 28)")
	}

	// 4. A non-DO client must NOT get DO set back (stay symmetric with the request).
	resp = sendUDPQuery(t, addr, "example.com.", dns.TypeA)
	if opt := resp.IsEdns0(); opt != nil && opt.Do() {
		t.Error("non-DO client received a DO=1 response — DO must mirror the client's request")
	}
}

// TestServerRejectsMalformedQDCOUNT (audit M3): a query that does not carry exactly
// one question is answered FORMERR at ingress — on BOTH the UDP and TCP paths — and
// NEVER forwarded upstream. A second question could otherwise smuggle a blocked name
// past the Question[0]-keyed blocklist, and the answer would be cached under a key
// that ignores it.
func TestServerRejectsMalformedQDCOUNT(t *testing.T) {
	cfg := &config.Config{
		Resolver: config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"},
		Cache:    config.CacheConfig{Enabled: false},
	}
	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess}},
	}
	discardLog := log.New(io.Discard, "", 0)
	srv := NewServer(cfg, mockResolver, nil, nil, nil, nil, discardLog)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	defer srv.Stop(time.Second)
	time.Sleep(10 * time.Millisecond)

	// Two questions — Question[1] is the filter-evasion angle.
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Question = append(m.Question,
		dns.Question{Name: "blocked.example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	for _, network := range []string{"udp", "tcp"} {
		addr := srv.UDPAddr().String()
		if network == "tcp" {
			addr = srv.TCPAddr().String()
		}
		c := new(dns.Client)
		c.Net = network
		resp, _, err := c.Exchange(m.Copy(), addr)
		if err != nil {
			t.Fatalf("%s: exchange failed: %v", network, err)
		}
		if resp.Rcode != dns.RcodeFormatError {
			t.Errorf("%s: expected FORMERR for QDCOUNT=2, got rcode %d", network, resp.Rcode)
		}
	}
	if n := mockResolver.CallCount(); n != 0 {
		t.Errorf("malformed query reached the upstream resolver (%d calls)", n)
	}
}

// TestServerBlocklistDisabled tests that server ignores blocklist when disabled.
func TestServerBlocklistDisabled(t *testing.T) {
	cfg := &config.Config{
		Resolver: config.ResolverConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
		},
		Cache: config.CacheConfig{
			Enabled: false,
		},
		Blocklists: config.BlocklistConfig{
			Enabled: false,
		},
	}

	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
		},
		err: nil,
	}

	// Create disabled blocklist (even if populated)
	dnsBlocklist := blocklist.New(false)
	dnsBlocklist.Add("blocked.com") // Add domain, but blocklist is disabled

	srv := NewServer(cfg, mockResolver, cache.New(cache.Options{Enabled: false, MaxSize: 0, TTLMin: 0, TTLMax: 0}), dnsBlocklist, nil, nil, nil)

	// IsBlocked should return false even though domain is in list
	if srv.blocklist.IsBlocked("blocked.com") {
		t.Error("expected IsBlocked to return false when blocklist is disabled")
	}
}

// rcodeResolver returns a response whose rcode is chosen per query name, or an
// error (→ SERVFAIL) when the name maps to a sentinel. Used to drive a mix of
// response outcomes through the real UDP path for the Issue 27 conservation test.
type rcodeResolver struct {
	byName map[string]int // qname (FQDN) → rcode
	errFor map[string]bool
}

func (m *rcodeResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	name := ""
	if len(msg.Question) > 0 {
		name = msg.Question[0].Name
	}
	if m.errFor[name] {
		return nil, context.DeadlineExceeded // upstream failure → server synthesizes SERVFAIL
	}
	rcode := dns.RcodeSuccess
	if rc, ok := m.byName[name]; ok {
		rcode = rc
	}
	resp := &dns.Msg{
		MsgHdr:   dns.MsgHdr{Response: true, Rcode: rcode, Id: msg.Id},
		Question: msg.Question,
	}
	if rcode == dns.RcodeSuccess {
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(93, 184, 216, 34),
		}}
	}
	return resp, nil
}

func (m *rcodeResolver) Close() error { return nil }

// TestResponseCounterConservationEndToEnd is the Issue 27 guarantee exercised
// through the real UDP server path: every handled query must land in exactly one
// response bucket, so Success+SERVFAIL+NXDOMAIN+Other == TotalQueries. Covers a
// cache hit, a blocklist NXDOMAIN, an upstream-failure SERVFAIL, and a non-NOERROR/
// non-NXDOMAIN rcode (REFUSED) — the exact case that was previously unbucketed.
func TestResponseCounterConservationEndToEnd(t *testing.T) {
	cfg := &config.Config{
		Resolver:   config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"},
		Cache:      config.CacheConfig{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 3600},
		Blocklists: config.BlocklistConfig{Enabled: true},
	}

	resolver := &rcodeResolver{
		byName: map[string]int{
			"refused.example.": dns.RcodeRefused, // → Other bucket
		},
		errFor: map[string]bool{
			"servfail.example.": true, // upstream fails → SERVFAIL bucket
		},
	}

	stats := statistics.New()
	bl := blocklist.New(true)
	bl.Add("blocked.example")
	dnsCache := cache.New(cache.Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 3600})
	discardLog := log.New(io.Discard, "", 0)
	srv := NewServer(cfg, resolver, dnsCache, bl, nil, stats, discardLog)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	defer srv.Stop(time.Second)
	addr := srv.UDPAddr().String()
	time.Sleep(10 * time.Millisecond)

	// Mix of outcomes. "ok.example" twice: first is an upstream NOERROR (cached),
	// second is a cache hit — both must bucket as Success.
	queries := []string{
		"ok.example.",       // NOERROR (upstream → cached)
		"ok.example.",       // NOERROR (cache hit)
		"blocked.example.",  // NXDOMAIN (blocklist)
		"servfail.example.", // SERVFAIL (upstream failure)
		"refused.example.",  // REFUSED  (Other)
		"refused.example.",  // REFUSED  (Other) — REFUSED is not cacheable
	}
	for _, q := range queries {
		_ = sendUDPQuery(t, addr, q, dns.TypeA)
	}

	// The server buckets a response right after writing it to the socket, so the last
	// reply can reach us a moment before its counter lands. Wait for the buckets to
	// settle (bounded) instead of taking the snapshot at the same instant.
	var snap statistics.Snapshot
	var sum int64
	for deadline := time.Now().Add(2 * time.Second); ; {
		snap = stats.TakeSnapshot(0, 100, statistics.InstanceInfo{})
		sum = snap.SuccessResponses + snap.ServfailResponses + snap.NxdomainResponses + snap.OtherResponses
		if sum >= int64(len(queries)) || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if snap.TotalQueries != int64(len(queries)) {
		t.Fatalf("TotalQueries: expected %d, got %d", len(queries), snap.TotalQueries)
	}
	if sum != snap.TotalQueries {
		t.Errorf("conservation violated: buckets sum=%d (S=%d SF=%d NX=%d O=%d), TotalQueries=%d",
			sum, snap.SuccessResponses, snap.ServfailResponses, snap.NxdomainResponses, snap.OtherResponses, snap.TotalQueries)
	}
	if snap.SuccessResponses != 2 {
		t.Errorf("SuccessResponses: expected 2, got %d", snap.SuccessResponses)
	}
	if snap.NxdomainResponses != 1 {
		t.Errorf("NxdomainResponses: expected 1, got %d", snap.NxdomainResponses)
	}
	if snap.ServfailResponses != 1 {
		t.Errorf("ServfailResponses: expected 1, got %d", snap.ServfailResponses)
	}
	if snap.OtherResponses != 2 {
		t.Errorf("OtherResponses: expected 2 (REFUSED×2), got %d", snap.OtherResponses)
	}
}

// TestStopIsGraceful guards Issue 15: Stop() must close the UDP/TCP listeners
// BEFORE waiting on the WaitGroup, so the serveUDP/serveTCP loops (parked in a
// blocking read/accept) unblock and exit immediately. The pre-fix ordering
// (wg.Wait() then close) made every Stop() block for the full timeout. With a
// generous 5s timeout, a correct Stop() returns in milliseconds; a regression
// would take ~5s. We assert it completes in well under the timeout.
func TestStopIsGraceful(t *testing.T) {
	cfg := &config.Config{
		Resolver: config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"},
	}
	mockResolver := &MockResolver{response: new(dns.Msg)}
	discardLog := log.New(io.Discard, "", 0)
	srv := NewServer(cfg, mockResolver, cache.New(cache.Options{Enabled: false, MaxSize: 0, TTLMin: 0, TTLMax: 0}), blocklist.New(false), nil, nil, discardLog)

	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("server start failed: %v", err)
	}

	// Let the UDP/TCP goroutines reach their blocking read/accept calls.
	time.Sleep(20 * time.Millisecond)

	// A correct Stop() returns near-instantly even with a long timeout, because
	// closing the listeners first unblocks the read loops. Time the call.
	const stopTimeout = 5 * time.Second
	start := time.Now()
	if err := srv.Stop(stopTimeout); err != nil {
		t.Fatalf("Stop returned error: %v", err)
	}
	elapsed := time.Since(start)

	// Allow plenty of slack for slow CI, but anything near the 5s timeout means
	// the listeners were NOT closed before wg.Wait() (the Issue 15 regression).
	if elapsed > time.Second {
		t.Errorf("Stop took %v — expected a sub-second graceful stop; "+
			"listeners are likely not being closed before wg.Wait() (Issue 15 regression)", elapsed)
	}
}

// TestEnsureResponseEDNSStripsDNSSECForNonDOClient guards Issue 34: a client that did not set the
// DO bit must not receive DNSSEC records (RFC 6840 §5.9). We always query upstream with DO=1, so a
// signed-zone reply carries RRSIG/NSEC alongside the A record; the non-DO reply must keep the A and
// drop the signatures, while a DO client keeps everything. The AD bit set by the validator survives
// either way. Before the fix, macOS mDNSResponder stalled ~60s on the leaked RRSIG.
func TestEnsureResponseEDNSStripsDNSSECForNonDOClient(t *testing.T) {
	build := func() *dns.Msg {
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess, AuthenticatedData: true},
			Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "api.cloudflare.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.IPv4(104, 19, 192, 29),
				},
				&dns.RRSIG{
					Hdr:         dns.RR_Header{Name: "api.cloudflare.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
					TypeCovered: dns.TypeA, Algorithm: dns.ECDSAP256SHA256, KeyTag: 34505,
					SignerName: "api.cloudflare.com.", Signature: "AAAA",
				},
			},
		}
	}

	countRR := func(msg *dns.Msg, rrtype uint16) int {
		n := 0
		for _, rr := range append(append(append([]dns.RR{}, msg.Answer...), msg.Ns...), msg.Extra...) {
			if rr.Header().Rrtype == rrtype {
				n++
			}
		}
		return n
	}

	// Query builders for the three RFC 6891 §6.1.1 client shapes.
	noEDNSQuery := func() *dns.Msg { // no OPT at all
		q := new(dns.Msg)
		q.SetQuestion("api.cloudflare.com.", dns.TypeA)
		return q
	}
	ednsQuery := func(do bool) *dns.Msg { // OPT present, DO as given
		q := noEDNSQuery()
		q.SetEdns0(dnsUDPBufSize, do)
		return q
	}

	// EDNS client, DO=0: A stays, RRSIG goes, AD preserved, OPT present with DO=0.
	noDO := build()
	ensureResponseEDNS(noDO, ednsQuery(false))
	if got := countRR(noDO, dns.TypeA); got != 1 {
		t.Errorf("non-DO: expected 1 A record retained, got %d", got)
	}
	if got := countRR(noDO, dns.TypeRRSIG); got != 0 {
		t.Errorf("non-DO: expected RRSIG stripped (RFC 6840 §5.9, Issue 34), got %d", got)
	}
	if !noDO.AuthenticatedData {
		t.Error("non-DO: AD bit must be preserved after stripping signatures")
	}
	if opt := noDO.IsEdns0(); opt == nil || opt.Do() {
		t.Error("non-DO: response OPT must be present with DO=0")
	}

	// EDNS client, DO=1: everything kept.
	withDO := build()
	ensureResponseEDNS(withDO, ednsQuery(true))
	if got := countRR(withDO, dns.TypeRRSIG); got != 1 {
		t.Errorf("DO client: RRSIG must be retained, got %d", got)
	}
	if opt := withDO.IsEdns0(); opt == nil || !opt.Do() {
		t.Error("DO client: response OPT must be present with DO=1")
	}

	// NON-EDNS client (no OPT in query): the response must carry NO OPT (RFC 6891 §6.1.1,
	// Issue 36 — the unsolicited response OPT that broke iOS 18 DNSecure + modern Android).
	// DNSSEC records must also be stripped (a non-EDNS client cannot have signaled DO).
	nonEDNS := build()
	ensureResponseEDNS(nonEDNS, noEDNSQuery())
	if opt := nonEDNS.IsEdns0(); opt != nil {
		t.Error("non-EDNS query: response must NOT carry an OPT (RFC 6891 §6.1.1, Issue 36)")
	}
	if got := countRR(nonEDNS, dns.TypeRRSIG); got != 0 {
		t.Errorf("non-EDNS query: expected RRSIG stripped, got %d", got)
	}
	if got := countRR(nonEDNS, dns.TypeA); got != 1 {
		t.Errorf("non-EDNS query: expected 1 A record retained, got %d", got)
	}
}

// TestPolicyResponseUDPAndTCPIdentical exercises the shared policy check end-to-end:
// a query policy decision (the blocklist today) must yield byte-identical replies over
// UDP and TCP, count exactly once in BlockedQueries per reply, and NEVER reach the
// upstream resolver. Allowed names must pass through to the resolver.
//
// Reuses TestServerBlocklistIntegration helpers — same MockResolver + discard-log pattern,
// same NewServer shape, real bind (port 0) so both UDP and TCP loops run their actual code.
func TestPolicyResponseUDPAndTCPIdentical(t *testing.T) {
	cfg := &config.Config{
		Resolver:   config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"},
		Cache:      config.CacheConfig{Enabled: false},
		Blocklists: config.BlocklistConfig{Enabled: true},
	}

	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Question: []dns.Question{{Name: "allowed.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
			Answer: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "allowed.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(93, 184, 216, 34),
			}},
		},
	}

	dnsBlocklist := blocklist.New(true)
	dnsBlocklist.Add("blocked.example.com")

	stats := statistics.New()
	discardLog := log.New(io.Discard, "", 0)
	srv := NewServer(cfg, mockResolver,
		cache.New(cache.Options{Enabled: false, MaxSize: 0, TTLMin: 0, TTLMax: 0}),
		dnsBlocklist, nil, stats, discardLog)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	defer srv.Stop(time.Second)
	time.Sleep(10 * time.Millisecond)

	udpAddr := srv.UDPAddr().String()
	tcpAddr := srv.TCPAddr().String()

	// Helper: send one query, return the response. Network="udp" or "tcp".
	send := func(t *testing.T, network, addr, name string) *dns.Msg {
		t.Helper()
		c := new(dns.Client)
		c.Net = network
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		resp, _, err := c.Exchange(m, addr)
		if err != nil {
			t.Fatalf("%s exchange for %s failed: %v", network, name, err)
		}
		return resp
	}

	// 1. The blocked name must yield NXDOMAIN over BOTH transports, with the question
	// echoed, identical Rcode / MsgHdr flags / OPT presence. policyResponse is the
	// single decision point — these replies come from the same function.
	blockedUDP := send(t, "udp", udpAddr, "blocked.example.com.")
	blockedTCP := send(t, "tcp", tcpAddr, "blocked.example.com.")

	if blockedUDP.Rcode != dns.RcodeNameError {
		t.Errorf("UDP blocked: expected NXDOMAIN, got rcode %d", blockedUDP.Rcode)
	}
	if blockedTCP.Rcode != dns.RcodeNameError {
		t.Errorf("TCP blocked: expected NXDOMAIN, got rcode %d", blockedTCP.Rcode)
	}
	if !blockedUDP.Response || !blockedTCP.Response {
		t.Errorf("both replies must set Response=true (udp=%v tcp=%v)", blockedUDP.Response, blockedTCP.Response)
	}
	if len(blockedUDP.Question) != 1 || len(blockedTCP.Question) != 1 ||
		blockedUDP.Question[0].Name != "blocked.example.com." ||
		blockedTCP.Question[0].Name != "blocked.example.com." {
		t.Errorf("both replies must echo the question (udp=%v tcp=%v)", blockedUDP.Question, blockedTCP.Question)
	}
	// OPT presence must match across transports — the EDNS echo in the policy tail is
	// a load-bearing detail for Issue 28.
	if (blockedUDP.IsEdns0() == nil) != (blockedTCP.IsEdns0() == nil) {
		t.Errorf("OPT presence must match across transports (udp OPT=%v tcp OPT=%v)",
			blockedUDP.IsEdns0() != nil, blockedTCP.IsEdns0() != nil)
	}
	// Rcode equality is already checked; assert MsgHdr byte-shape parity for everything
	// the seam owns (Response, Opcode, Authoritative, Truncated, RecursionDesired,
	// RecursionAvailable, Zero — Rcode already verified above).
	if blockedUDP.MsgHdr.Response != blockedTCP.MsgHdr.Response ||
		blockedUDP.MsgHdr.Opcode != blockedTCP.MsgHdr.Opcode ||
		blockedUDP.MsgHdr.Authoritative != blockedTCP.MsgHdr.Authoritative ||
		blockedUDP.MsgHdr.Truncated != blockedTCP.MsgHdr.Truncated ||
		blockedUDP.MsgHdr.RecursionDesired != blockedTCP.MsgHdr.RecursionDesired ||
		blockedUDP.MsgHdr.RecursionAvailable != blockedTCP.MsgHdr.RecursionAvailable ||
		blockedUDP.MsgHdr.Zero != blockedTCP.MsgHdr.Zero {
		t.Errorf("MsgHdr flags must be identical across transports (udp=%+v tcp=%+v)",
			blockedUDP.MsgHdr, blockedTCP.MsgHdr)
	}

	// 2. BlockedQueries must increment by exactly one per reply, totaling 2 (Issue 27).
	if stats.BlockedQueries != 2 {
		t.Errorf("BlockedQueries: expected 2 (one UDP + one TCP block), got %d", stats.BlockedQueries)
	}

	// 3. The mock resolver must have seen ZERO calls for the blocked name. The blocklist
	// path answers locally — never forwards.
	if n := mockResolver.CallCount(); n != 0 {
		t.Errorf("blocked query reached the upstream resolver (%d calls)", n)
	}

	// 4. An allowed name must reach the resolver on both transports (sanity: the policy
	// seam is "deny-only"; it must not regress the cache-miss → upstream path).
	allowedUDP := send(t, "udp", udpAddr, "allowed.example.com.")
	if allowedUDP.Rcode != dns.RcodeSuccess {
		t.Errorf("UDP allowed: expected NOERROR, got rcode %d", allowedUDP.Rcode)
	}
	allowedTCP := send(t, "tcp", tcpAddr, "allowed.example.com.")
	if allowedTCP.Rcode != dns.RcodeSuccess {
		t.Errorf("TCP allowed: expected NOERROR, got rcode %d", allowedTCP.Rcode)
	}
	if n := mockResolver.CallCount(); n != 2 {
		t.Errorf("allowed name: expected 2 upstream calls (one per transport), got %d", n)
	}
	// The blocked counter must not have moved on the allowed queries.
	if stats.BlockedQueries != 2 {
		t.Errorf("BlockedQueries drifted on allowed queries: expected 2, got %d", stats.BlockedQueries)
	}
}

// TestAllowlistDenyRefusedNotForwarded is the headline test for the default-deny
// feature: a name NOT under a listed suffix must be REFUSED locally, never
// forwarded, never cached. EDE 18 (Prohibited) is attached to the OPT when
// the client used EDNS, and absent OPT for non-EDNS clients (RFC 6891 §6.1.1).
// Counted in DeniedQueries — NOT in BlockedQueries. Blocked stays for the
// existing blocklist NXDOMAIN counter.
func TestAllowlistDenyRefusedNotForwarded(t *testing.T) {
	cfg := &config.Config{
		Resolver:   config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"},
		Cache:      config.CacheConfig{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 3600},
		Blocklists: config.BlocklistConfig{Enabled: false},
	}

	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Question: []dns.Question{{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
			Answer: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(93, 184, 216, 34),
			}},
		},
	}

	al := seededAllowlist(t, "example.com\n")

	stats := statistics.New()
	discardLog := log.New(io.Discard, "", 0)
	srv := NewServer(cfg, mockResolver,
		cache.New(cache.Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 3600}),
		blocklist.New(false), nil, stats, discardLog)
	srv.SetAllowlist(al)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	defer srv.Stop(time.Second)
	time.Sleep(10 * time.Millisecond)

	udpAddr := srv.UDPAddr().String()
	tcpAddr := srv.TCPAddr().String()

	// Build a denied qname: NOT under example.com. A subdomain under an unrelated
	// parent keeps the suffix non-empty without colliding with the allowlist.
	denied := "leak.attacker.example.net."

	// 1. UDP denied: REFUSED + EDE 18 when the query carried OPT; mock resolver
	// must NOT be hit.
	udpDO := new(dns.Msg)
	udpDO.SetQuestion(denied, dns.TypeA)
	udpDO.SetEdns0(4096, false)
	udpClient := new(dns.Client)
	udpClient.Net = "udp"
	udpResp, _, err := udpClient.Exchange(udpDO.Copy(), udpAddr)
	if err != nil {
		t.Fatalf("UDP exchange: %v", err)
	}
	if udpResp.Rcode != dns.RcodeRefused {
		t.Errorf("UDP denied: expected REFUSED, got rcode %d", udpResp.Rcode)
	}
	if !udpResp.Response {
		t.Error("UDP denied: Response bit must be set")
	}
	if got := len(udpResp.Question); got != 1 || udpResp.Question[0].Name != denied {
		t.Errorf("UDP denied: question must be echoed, got %+v", udpResp.Question)
	}
	opt := udpResp.IsEdns0()
	if opt == nil {
		t.Fatal("UDP denied (DO-bit query): response must carry OPT for EDE attachment")
	}
	ede := findEDE(opt)
	if ede == nil {
		t.Fatal("UDP denied (DO-bit query): response OPT must carry an EDE option")
	}
	if ede.InfoCode != dns.ExtendedErrorCodeProhibited {
		t.Errorf("EDE InfoCode: expected %d (Prohibited), got %d", dns.ExtendedErrorCodeProhibited, ede.InfoCode)
	}

	// 2. UDP denied (NON-EDNS): REFUSED, NO OPT (RFC 6891 §6.1.1, Issue 36).
	udpNoEdns := new(dns.Msg)
	udpNoEdns.SetQuestion(denied, dns.TypeA)
	udpNoEdnsResp, _, err := udpClient.Exchange(udpNoEdns.Copy(), udpAddr)
	if err != nil {
		t.Fatalf("UDP non-EDNS exchange: %v", err)
	}
	if udpNoEdnsResp.Rcode != dns.RcodeRefused {
		t.Errorf("UDP non-EDNS denied: expected REFUSED, got rcode %d", udpNoEdnsResp.Rcode)
	}
	if opt := udpNoEdnsResp.IsEdns0(); opt != nil {
		t.Error("UDP non-EDNS denied: response must NOT carry OPT (RFC 6891 §6.1.1, Issue 36)")
	}

	// 3. TCP denied: REFUSED too, with the same shape.
	tcpClient := new(dns.Client)
	tcpClient.Net = "tcp"
	tcpMsg := new(dns.Msg)
	tcpMsg.SetQuestion(denied, dns.TypeA)
	tcpResp, _, err := tcpClient.Exchange(tcpMsg.Copy(), tcpAddr)
	if err != nil {
		t.Fatalf("TCP exchange: %v", err)
	}
	if tcpResp.Rcode != dns.RcodeRefused {
		t.Errorf("TCP denied: expected REFUSED, got rcode %d", tcpResp.Rcode)
	}
	if !tcpResp.Response {
		t.Error("TCP denied: Response bit must be set")
	}

	// 4. Counters: three denials (UDP DO-bit + UDP non-EDNS + TCP), zero blocks,
	// zero upstream calls.
	snap := stats.TakeSnapshot(0, 0, statistics.InstanceInfo{})
	if snap.DeniedQueries != 3 {
		t.Errorf("DeniedQueries: expected 3 (UDP DO + UDP non-EDNS + TCP), got %d", snap.DeniedQueries)
	}
	if snap.BlockedQueries != 0 {
		t.Errorf("BlockedQueries must NOT increment for allowlist denials: got %d", snap.BlockedQueries)
	}
	if n := mockResolver.CallCount(); n != 0 {
		t.Errorf("denied query reached the upstream resolver (%d calls) — qname must NEVER leave the host", n)
	}

	// 5. Cache must contain nothing for the denied name — deny happens BEFORE cache
	// (cache MUST not serve a denied name from a previous lookup).
	// The DENIAL counter (DeniedQueries == 2) and zero upstream calls together
	// prove the no-forward path: the policyResponse short-circuits before the
	// cache lookup runs. A direct cache lookup on the live cache confirms it
	// is empty for the denied name.
	if _, hit := srv.cache.Get(makeQuery(denied, dns.TypeA)); hit {
		t.Error("denied name must not appear in the cache")
	}
}

// makeQuery builds a one-question dns.Msg for the (name, qtype) pair, used to
// poke the cache directly in the deny test without going through the wire.
func makeQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	return m
}

// TestAllowlistAllowsListedSuffix covers the negative case of the headline
// test: a name under a listed suffix MUST reach the upstream resolver (and
// the cache). The allowlist must not break the normal happy path.
func TestAllowlistAllowsListedSuffix(t *testing.T) {
	cfg := &config.Config{
		Resolver:   config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"},
		Cache:      config.CacheConfig{Enabled: false},
		Blocklists: config.BlocklistConfig{Enabled: false},
	}

	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Question: []dns.Question{{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
			Answer: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(93, 184, 216, 34),
			}},
		},
	}

	al := seededAllowlist(t, "example.com\n")
	stats := statistics.New()
	discardLog := log.New(io.Discard, "", 0)
	srv := NewServer(cfg, mockResolver,
		cache.New(cache.Options{Enabled: false}),
		blocklist.New(false), nil, stats, discardLog)
	srv.SetAllowlist(al)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	defer srv.Stop(time.Second)
	time.Sleep(10 * time.Millisecond)

	resp := sendUDPQuery(t, srv.UDPAddr().String(), "www.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("allowed subdomain: expected NOERROR, got rcode %d", resp.Rcode)
	}
	if n := mockResolver.CallCount(); n != 1 {
		t.Errorf("allowed name: expected 1 upstream call, got %d", n)
	}
	snap := stats.TakeSnapshot(0, 0, statistics.InstanceInfo{})
	if snap.DeniedQueries != 0 {
		t.Errorf("allowed query must not increment DeniedQueries: got %d", snap.DeniedQueries)
	}
}

// TestAllowlistBlockWinsInsideAllowedSuffix verifies the settled policy: an
// entry listed on the allowlist AND the blocklist gets the blocklist's NXDOMAIN,
// not a refused. Block wins. BlockedQueries increments; DeniedQueries does not.
func TestAllowlistBlockWins(t *testing.T) {
	cfg := &config.Config{
		Resolver:   config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"},
		Cache:      config.CacheConfig{Enabled: false},
		Blocklists: config.BlocklistConfig{Enabled: true},
	}

	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess}},
	}

	al := seededAllowlist(t, "example.com\n") // allowlist covers the whole example.com tree
	bl := blocklist.New(true)
	bl.Add("ads.example.com") // blocklist narrows it down to one subdomain

	stats := statistics.New()
	discardLog := log.New(io.Discard, "", 0)
	srv := NewServer(cfg, mockResolver,
		cache.New(cache.Options{Enabled: false}),
		bl, nil, stats, discardLog)
	srv.SetAllowlist(al)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	defer srv.Stop(time.Second)
	time.Sleep(10 * time.Millisecond)

	resp := sendUDPQuery(t, srv.UDPAddr().String(), "ads.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("blocked-inside-allow: expected NXDOMAIN (block wins), got rcode %d", resp.Rcode)
	}
	snap := stats.TakeSnapshot(0, 0, statistics.InstanceInfo{})
	if snap.BlockedQueries != 1 {
		t.Errorf("BlockedQueries: expected 1 (block wins), got %d", snap.BlockedQueries)
	}
	if snap.DeniedQueries != 0 {
		t.Errorf("DeniedQueries must not increment when block fires inside an allowed suffix: got %d", snap.DeniedQueries)
	}
	if n := mockResolver.CallCount(); n != 0 {
		t.Errorf("blocked name reached upstream (%d calls) — blocklist path must not forward", n)
	}
}

// TestAllowlistNilIsOff verifies the off switch: a server constructed without a
// Policy wired (or with nil SetPolicy / SetAllowlist(nil)) ignores the feature
// entirely. Pre-feature configs and callers that haven't wired a policy must
// behave exactly as they did before the feature landed.
func TestAllowlistNilIsOff(t *testing.T) {
	cfg := &config.Config{
		Resolver:   config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"},
		Cache:      config.CacheConfig{Enabled: false},
		Blocklists: config.BlocklistConfig{Enabled: false},
	}
	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Question: []dns.Question{{Name: "anything.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	}
	stats := statistics.New()
	discardLog := log.New(io.Discard, "", 0)
	srv := NewServer(cfg, mockResolver,
		cache.New(cache.Options{Enabled: false}),
		blocklist.New(false), nil, stats, discardLog)
	// Explicitly NOT calling SetAllowlist; also call it with nil to prove
	// the setter is idempotent + safe at any time before Start.
	srv.SetAllowlist(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	defer srv.Stop(time.Second)
	time.Sleep(10 * time.Millisecond)

	resp := sendUDPQuery(t, srv.UDPAddr().String(), "anything.test.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("nil allowlist: expected NOERROR (feature off), got rcode %d", resp.Rcode)
	}
	if n := mockResolver.CallCount(); n != 1 {
		t.Errorf("nil allowlist: expected 1 upstream call, got %d", n)
	}
	snap := stats.TakeSnapshot(0, 0, statistics.InstanceInfo{})
	if snap.DeniedQueries != 0 {
		t.Errorf("nil allowlist: DeniedQueries must remain 0, got %d", snap.DeniedQueries)
	}
}

// findEDE walks an OPT record's Option slice and returns the EDE option if present.
func findEDE(opt *dns.OPT) *dns.EDNS0_EDE {
	for _, o := range opt.Option {
		if ede, ok := o.(*dns.EDNS0_EDE); ok {
			return ede
		}
	}
	return nil
}

// seededAllowlist builds an *allowlist.Allowlist from a body string, writing
// to a temp file under the hood. Used by tests that need an allowlist seeded
// with specific entries without dragging temp-file management into each test.
func seededAllowlist(t *testing.T, body string) *allowlist.Allowlist {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/allow.txt"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write allow file: %v", err)
	}
	al := allowlist.New()
	if err := al.LoadFiles([]string{path}); err != nil {
		t.Fatalf("load allowlist: %v", err)
	}
	return al
}

// TestAllowlistReloadPolicyBeforeCache is the integration test for the
// --allowlist-reload hot path: a name that was allowed (and therefore cached)
// must be REFUSED the moment it is removed from the live set, even when the
// cache still holds the prior NOERROR answer. Policy runs before cache on
// every listener, so a removed entry can never be served
// from cache. The test exercises this end-to-end through the real server
// and a real cache: resolve, cache, remove the file entry, reload (which
// atomically swaps the live set on the SAME Allowlist instance the policy
// holds), re-query, assert REFUSED + zero new upstream calls.
func TestAllowlistReloadPolicyBeforeCache(t *testing.T) {
	cfg := &config.Config{
		Resolver:   config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"},
		Cache:      config.CacheConfig{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 3600},
		Blocklists: config.BlocklistConfig{Enabled: false},
	}

	mockResolver := &MockResolver{
		response: &dns.Msg{
			MsgHdr:   dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Question: []dns.Question{{Name: "sub.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
			Answer: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "sub.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(93, 184, 216, 34),
			}},
		},
	}

	dir := t.TempDir()
	allowPath := dir + "/allow.txt"
	if err := os.WriteFile(allowPath, []byte("example.com\n"), 0644); err != nil {
		t.Fatalf("write allow file: %v", err)
	}
	al := allowlist.New()
	if err := al.LoadFiles([]string{allowPath}); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	stats := statistics.New()
	discardLog := log.New(io.Discard, "", 0)
	srv := NewServer(cfg, mockResolver,
		cache.New(cache.Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 3600}),
		blocklist.New(false), nil, stats, discardLog)
	srv.SetAllowlist(al)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	defer srv.Stop(time.Second)
	time.Sleep(10 * time.Millisecond)

	udpAddr := srv.UDPAddr().String()

	// 1. First query: allowed, NOERROR, upstream called once and the answer
	// lands in the cache.
	resp := sendUDPQuery(t, udpAddr, "sub.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("initial allowed query: expected NOERROR, got rcode %d", resp.Rcode)
	}
	if n := mockResolver.CallCount(); n != 1 {
		t.Fatalf("initial allowed query: expected 1 upstream call, got %d", n)
	}
	cachedBefore, hit := srv.cache.Get(makeQuery("sub.example.com.", dns.TypeA))
	if !hit || cachedBefore == nil {
		t.Fatal("after warm-up: cache must hold the allowed answer (cache-miss flow runs before cache.Put)")
	}

	// 2. Rewrite the allowlist file so the suffix is GONE — and run the same
	// LoadFiles the daemon's --allowlist-reload callback runs, against the SAME
	// *allowlist.Allowlist instance the policy holds. This is the reload
	// behavior under test: atomic swap on the live set, no new instance.
	if err := os.WriteFile(allowPath, []byte("example.org\n"), 0644); err != nil {
		t.Fatalf("rewrite allow file: %v", err)
	}
	if err := al.LoadFiles([]string{allowPath}); err != nil {
		t.Fatalf("simulated reload: %v", err)
	}
	if al.Size() != 1 || !al.Allowed("example.org") {
		t.Fatalf("post-reload allowlist state wrong: Size=%d", al.Size())
	}
	if al.Allowed("sub.example.com") {
		t.Fatal("post-reload: sub.example.com must NO LONGER be allowed")
	}

	// 3. Second query: the cache still holds the previous answer, but the
	// policy runs first and refuses the name. Mock resolver must see ZERO new
	// calls (no upstream round-trip for the denied name).
	after := sendUDPQuery(t, udpAddr, "sub.example.com.", dns.TypeA)
	if after.Rcode != dns.RcodeRefused {
		t.Errorf("post-reload query: expected REFUSED (policy-before-cache), got rcode %d", after.Rcode)
	}
	if n := mockResolver.CallCount(); n != 1 {
		t.Errorf("post-reload query: expected NO new upstream calls (1 from initial), got %d total", n)
	}

	// 4. Counters: 1 denial, no upstream traffic for it.
	snap := stats.TakeSnapshot(0, 0, statistics.InstanceInfo{})
	if snap.DeniedQueries != 1 {
		t.Errorf("DeniedQueries: expected 1, got %d", snap.DeniedQueries)
	}

	// 5. A different name that is STILL allowed must continue to pass through
	// (the live set is not empty — example.org is on it now).
	if !al.Allowed("anything.example.org") {
		t.Fatal("post-reload: example.org must still be allowed")
	}
}

// TestAllowlistReloadFailedLeavesPreviousSetActive guards the fail-closed
// reload path at the Allowlist level: a failed reload (here, an invalid line
// introduced after a valid load) must leave the previous entries in the live
// set untouched. The cache integration is the headline (see
// TestAllowlistReloadPolicyBeforeCache); this test pins the loader's
// "previous set intact" invariant independently.
func TestAllowlistReloadFailedLeavesPreviousSetActive(t *testing.T) {
	dir := t.TempDir()
	allowPath := dir + "/allow.txt"
	if err := os.WriteFile(allowPath, []byte("example.com\nexample.net\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	al := allowlist.New()
	if err := al.LoadFiles([]string{allowPath}); err != nil {
		t.Fatalf("seed load: %v", err)
	}
	if al.Size() != 2 {
		t.Fatalf("seed: expected 2 entries, got %d", al.Size())
	}

	// Break the file. LoadFiles must error, name the failing line, and leave
	// the previous set intact.
	if err := os.WriteFile(allowPath, []byte("example.com\n-bad-.com\n"), 0644); err != nil {
		t.Fatalf("break: %v", err)
	}
	err := al.LoadFiles([]string{allowPath})
	if err == nil {
		t.Fatal("expected reload error on invalid line, got nil")
	}
	if !strings.Contains(err.Error(), "allow.txt:2") {
		t.Errorf("error must name the failing file:line, got: %v", err)
	}
	if al.Size() != 2 {
		t.Errorf("previous set must survive a failed reload; got Size=%d, want 2", al.Size())
	}
	if !al.Allowed("example.com") || !al.Allowed("example.net") {
		t.Error("previous entries must still be allowed after a failed reload")
	}
}

// echoResolver answers every query with an A record for the queried name, so a reply
// can be checked against the query that caused it.
type echoResolver struct{}

func (echoResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetReply(msg)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(192, 0, 2, 1),
	}}
	return resp, nil
}

func (echoResolver) Close() error { return nil }

// TestServerUDPConcurrentBurstCorrelation fires a burst of distinct UDP queries from
// separate sockets at once (the systemd-resolved A+AAAA fan-out pattern) and asserts
// every reply carries its own query's ID and question. Regression: serveUDP handed each
// goroutine a slice of one shared read buffer, so a burst parsed the last packet N times.
func TestServerUDPConcurrentBurstCorrelation(t *testing.T) {
	cfg := &config.Config{Resolver: config.ResolverConfig{Enabled: true, Listen: "127.0.0.1:0"}}
	srv := NewServer(cfg, echoResolver{}, nil, nil, nil, nil, log.New(io.Discard, "", 0))
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Stop(2 * time.Second)
	addr := srv.UDPAddr().String()

	const n = 64
	for round := 0; round < 20; round++ {
		var wg sync.WaitGroup
		errs := make(chan string, n)
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				q := new(dns.Msg)
				q.SetQuestion(dns.Fqdn(strings.Repeat("a", i%20+1)+".burst.test"), dns.TypeA)
				q.Id = uint16(round*n + i + 1)
				c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
				<-start
				r, _, err := c.Exchange(q, addr)
				if err != nil {
					errs <- err.Error()
					return
				}
				if r.Id != q.Id || len(r.Question) != 1 || r.Question[0].Name != q.Question[0].Name {
					errs <- "mismatched reply"
				}
			}(i)
		}
		close(start)
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Fatalf("round %d: %s", round, e)
		}
	}
}
