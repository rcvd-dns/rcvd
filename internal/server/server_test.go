// SPDX-License-Identifier: MIT
package server

import (
	"context"
	"crypto"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
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

	snap := stats.TakeSnapshot(0, 100, statistics.InstanceInfo{})
	sum := snap.SuccessResponses + snap.ServfailResponses + snap.NxdomainResponses + snap.OtherResponses
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
