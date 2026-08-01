// SPDX-License-Identifier: MIT
package cache

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// makeReq creates a minimal *dns.Msg request for testing.
func makeReq(name string, qtype uint16) *dns.Msg {
	return &dns.Msg{
		Question: []dns.Question{{
			Name:   name,
			Qtype:  qtype,
			Qclass: dns.ClassINET,
		}},
	}
}

// makeReqDO creates a *dns.Msg request with the DNSSEC OK (DO) bit set.
func makeReqDO(name string, qtype uint16) *dns.Msg {
	req := makeReq(name, qtype)
	req.SetEdns0(4096, true) // buffer size 4096, DO=true
	return req
}

// TestCacheBasicSetGet tests basic cache put and get operations.
func TestCacheBasicSetGet(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 86400})

	req := makeReq("example.com.", dns.TypeA)

	resp := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:       1234,
			Response: true,
		},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300, // 5 minutes
				},
				A: net.IPv4(93, 184, 216, 34),
			},
		},
	}

	// Cache miss before put
	_, found := c.Get(req)
	if found {
		t.Error("expected cache miss before put")
	}

	// Put response in cache
	c.Put(req, resp)

	// Cache hit after put
	cached, found := c.Get(req)
	if !found {
		t.Error("expected cache hit after put")
	}

	if cached == nil {
		t.Error("expected non-nil cached response")
	}

	if cached.Id != resp.Id {
		t.Errorf("cached response ID mismatch: got %d, want %d", cached.Id, resp.Id)
	}
}

// TestCachePutRejectsMismatchedQuestion (audit H1, defense in depth): a response
// carrying a Question that disagrees with the request key it is stored under must
// NOT be cached — that is the cache-poisoning re-keying class. An absent Question
// (locally synthesized message) is tolerated; case-different QNAMEs are equal (RFC 4343).
func TestCachePutRejectsMismatchedQuestion(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 86400})

	req := makeReq("example.com.", dns.TypeA)
	answer := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.IPv4(93, 184, 216, 34),
		},
	}

	mismatches := map[string]*dns.Msg{
		"foreign QNAME": {
			MsgHdr:   dns.MsgHdr{Response: true},
			Question: []dns.Question{{Name: "evil.example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
			Answer:   answer,
		},
		"foreign QTYPE": {
			MsgHdr:   dns.MsgHdr{Response: true},
			Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}},
			Answer:   answer,
		},
		"QDCOUNT=2": {
			MsgHdr: dns.MsgHdr{Response: true},
			Question: []dns.Question{
				{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				{Name: "evil.example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			Answer: answer,
		},
	}
	for label, resp := range mismatches {
		c.Put(req, resp)
		if _, found := c.Get(req); found {
			t.Errorf("%s: mismatched response was cached under the request key", label)
		}
		c.Clear()
	}

	// A matching Question — even in different case (RFC 4343) — IS cached.
	matching := &dns.Msg{
		MsgHdr:   dns.MsgHdr{Response: true},
		Question: []dns.Question{{Name: "EXAMPLE.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		Answer:   answer,
	}
	c.Put(req, matching)
	if _, found := c.Get(req); !found {
		t.Error("case-different but matching Question must be cached")
	}
}

// TestCacheTTLRespect tests that TTL bounds are respected.
func TestCacheTTLRespect(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 3600}) // 60s min, 1 hour max

	req := makeReq("test.example.com.", dns.TypeA)

	// Test 1: Response with TTL < ttlMin IS cached, with its TTL extended up to the
	// floor (ttl_min is a clamp-up floor, not a reject threshold — see ISSUES 25).
	shortTTLResp := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "test.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    30, // 30s < 60s minimum → should be extended to 60s, not rejected
				},
				A: net.IPv4(1, 2, 3, 4),
			},
		},
	}

	c.Put(req, shortTTLResp)
	_, found := c.Get(req)
	if !found {
		t.Error("expected cache HIT for TTL < ttlMin (extended to floor, not rejected)")
	}

	// Test 2: Response with TTL in valid range should be cached
	goodTTLResp := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "test.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300, // 5 minutes (in range)
				},
				A: net.IPv4(1, 2, 3, 4),
			},
		},
	}

	c.Put(req, goodTTLResp)
	_, found = c.Get(req)
	if !found {
		t.Error("expected cache hit for valid TTL")
	}

	// Test 3: Response with TTL > ttlMax should be clamped
	longTTLResp := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "long.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    86400 * 7, // 7 days (exceeds 1 hour max)
				},
				A: net.IPv4(1, 2, 3, 4),
			},
		},
	}

	req2 := makeReq("long.example.com.", dns.TypeA)
	c.Put(req2, longTTLResp)

	// Entry should exist, but with clamped TTL
	cached, found := c.Get(req2)
	if !found {
		t.Error("expected cache hit for long TTL (should be clamped)")
	}

	// Verify it won't stay cached forever (clamped to 1 hour)
	if cached == nil {
		t.Error("expected non-nil cached response")
	}
}

// TestAggressiveTTLMinExtendsNotRejects is the regression test for ISSUES 25:
// "aggressive" cache mode (ttl_min 300) must CACHE a short-TTL response by extending its
// TTL up to the floor, NOT reject it. The original code rejected any TTL < ttl_min, which
// silently disabled caching in aggressive mode (most real-world TTLs are < 300s), so the
// container test showed Size 0 / 0 hits / every query upstream.
func TestAggressiveTTLMinExtendsNotRejects(t *testing.T) {
	// Aggressive-mode floor.
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 300, TTLMax: 7 * 86400})

	req := makeReq("example.com.", dns.TypeA)
	// A typical real-world short TTL (e.g. example.com ~120s) — well below the 300s floor.
	resp := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    120,
				},
				A: net.IPv4(93, 184, 216, 34),
			},
		},
	}

	c.Put(req, resp)

	// Must be a HIT (the bug was a miss here).
	if _, found := c.Get(req); !found {
		t.Fatal("aggressive mode dropped a 120s-TTL response (ttl_min=300); expected it cached, extended to the floor")
	}

	// And the entry's expiry must reflect the EXTENDED floor (≈300s), not the original 120s.
	c.mu.RLock()
	entry, ok := c.entries[cacheKey(req)]
	c.mu.RUnlock()
	if !ok {
		t.Fatal("expected an entry present after Put")
	}
	remaining := time.Until(entry.ExpiresAt)
	if remaining <= 120*time.Second {
		t.Errorf("expected TTL extended to ~300s floor; remaining=%v (<=120s means it was not extended)", remaining)
	}
	if remaining > 300*time.Second {
		t.Errorf("expected TTL clamped at the 300s floor; remaining=%v (>300s)", remaining)
	}
}

// TestCacheExpiration tests that expired entries are not returned.
func TestCacheExpiration(t *testing.T) {
	// Use low ttlMin to allow testing short expiration times
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 1, TTLMax: 86400})

	req := makeReq("expire.example.com.", dns.TypeA)

	resp := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "expire.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    1, // 1 second (will expire quickly)
				},
				A: net.IPv4(1, 2, 3, 4),
			},
		},
	}

	c.Put(req, resp)

	// Should be in cache immediately
	_, found := c.Get(req)
	if !found {
		t.Error("expected cache hit immediately after put")
	}

	// Wait for expiration
	time.Sleep(1100 * time.Millisecond)

	// Should be expired and removed
	_, found = c.Get(req)
	if found {
		t.Error("expected cache miss after TTL expiration")
	}
}

// TestCacheMaxSize tests that cache respects maximum size limit.
func TestCacheMaxSize(t *testing.T) {
	maxSize := 5
	c := New(Options{Enabled: true, MaxSize: maxSize, TTLMin: 60, TTLMax: 86400})

	// Fill cache to max capacity
	for i := 0; i < maxSize; i++ {
		name := dns.Fqdn("test" + string(rune(i)) + ".example.com")
		req := makeReq(name, dns.TypeA)

		resp := &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true},
			Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.IPv4(1, 2, 3, byte(i)),
				},
			},
		}

		c.Put(req, resp)
	}

	// Cache should be at max size
	if c.Size() != maxSize {
		t.Errorf("cache size mismatch: got %d, want %d", c.Size(), maxSize)
	}

	// Adding one more should trigger eviction of oldest
	req := makeReq("newest.example.com.", dns.TypeA)

	resp := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "newest.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4(255, 255, 255, 255),
			},
		},
	}

	c.Put(req, resp)

	// Cache should still be at max size (one was evicted)
	if c.Size() != maxSize {
		t.Errorf("cache size after eviction: got %d, want %d", c.Size(), maxSize)
	}

	// Newest entry should be in cache
	cached, found := c.Get(req)
	if !found {
		t.Error("expected cache hit for newest entry")
	}
	if cached == nil {
		t.Error("expected non-nil cached response")
	}
}

// TestCacheClear tests clearing the cache.
func TestCacheClear(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 86400})

	req := makeReq("clear.example.com.", dns.TypeA)

	resp := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "clear.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4(1, 2, 3, 4),
			},
		},
	}

	c.Put(req, resp)

	if c.Size() != 1 {
		t.Errorf("expected cache size 1, got %d", c.Size())
	}

	c.Clear()

	if c.Size() != 0 {
		t.Errorf("expected cache size 0 after clear, got %d", c.Size())
	}

	_, found := c.Get(req)
	if found {
		t.Error("expected cache miss after clear")
	}
}

// TestCacheStats tests cache statistics.
func TestCacheStats(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 3600})

	req := makeReq("stats.example.com.", dns.TypeA)

	resp := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "stats.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4(1, 2, 3, 4),
			},
		},
	}

	c.Put(req, resp)

	stats := c.GetStats()

	if stats.Size != 1 {
		t.Errorf("stats Size: got %d, want 1", stats.Size)
	}
	if stats.MaxSize != 100 {
		t.Errorf("stats MaxSize: got %d, want 100", stats.MaxSize)
	}
	if stats.TTLMin != 60 {
		t.Errorf("stats TTLMin: got %d, want 60", stats.TTLMin)
	}
	if stats.TTLMax != 3600 {
		t.Errorf("stats TTLMax: got %d, want 3600", stats.TTLMax)
	}
}

// TestCacheDisabled tests that cache is noop when disabled.
func TestCacheDisabled(t *testing.T) {
	c := New(Options{Enabled: false, MaxSize: 100, TTLMin: 60, TTLMax: 86400}) // Cache disabled

	req := makeReq("disabled.example.com.", dns.TypeA)

	resp := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "disabled.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4(1, 2, 3, 4),
			},
		},
	}

	c.Put(req, resp)

	// Should not be cached (cache disabled)
	_, found := c.Get(req)
	if found {
		t.Error("expected cache miss when cache is disabled")
	}

	if c.Size() != 0 {
		t.Errorf("expected cache size 0 when disabled, got %d", c.Size())
	}
}

// TestCacheMultipleRecords tests caching responses with multiple RRs.
func TestCacheMultipleRecords(t *testing.T) {
	// Use low ttlMin to allow testing with short TTLs
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 1, TTLMax: 86400})

	req := makeReq("multi.example.com.", dns.TypeA)

	resp := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "multi.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    1, // Lowest TTL (will expire quickly)
				},
				A: net.IPv4(1, 1, 1, 1),
			},
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "multi.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4(2, 2, 2, 2),
			},
		},
	}

	c.Put(req, resp)

	cached, found := c.Get(req)
	if !found {
		t.Error("expected cache hit for multi-record response")
	}

	if len(cached.Answer) != 2 {
		t.Errorf("expected 2 answers, got %d", len(cached.Answer))
	}

	// Verify minimum TTL is used (1s, should be cached until expired)
	time.Sleep(1100 * time.Millisecond) // Wait 1.1 seconds

	_, found = c.Get(req)
	if found {
		t.Error("expected cache miss after minimum TTL expiration")
	}
}

// TestCacheDOBitSeparation tests that requests with and without the DNSSEC OK (DO)
// bit are cached separately. Without this, a cached non-DNSSEC response could be
// served to a client that requested DNSSEC records (or vice versa).
func TestCacheDOBitSeparation(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 86400})

	reqNoDO := makeReq("do-test.example.com.", dns.TypeA)
	reqDO := makeReqDO("do-test.example.com.", dns.TypeA)

	respNoDO := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "do-test.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4(1, 2, 3, 4),
			},
		},
	}

	respDO := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "do-test.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4(1, 2, 3, 4),
			},
			// DNSSEC response would also include RRSIG records
			&dns.RRSIG{
				Hdr: dns.RR_Header{
					Name:   "do-test.example.com.",
					Rrtype: dns.TypeRRSIG,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				TypeCovered: dns.TypeA,
				Algorithm:   13, // ECDSAP256SHA256
			},
		},
	}

	// Cache the non-DO response
	c.Put(reqNoDO, respNoDO)

	// DO request should NOT get the non-DO cached response
	_, found := c.Get(reqDO)
	if found {
		t.Error("DO request should not get non-DO cached response")
	}

	// Cache the DO response
	c.Put(reqDO, respDO)

	// Now both should be cached separately
	cachedNoDO, found := c.Get(reqNoDO)
	if !found {
		t.Error("expected cache hit for non-DO request")
	}
	if len(cachedNoDO.Answer) != 1 {
		t.Errorf("non-DO response should have 1 answer, got %d", len(cachedNoDO.Answer))
	}

	cachedDO, found := c.Get(reqDO)
	if !found {
		t.Error("expected cache hit for DO request")
	}
	if len(cachedDO.Answer) != 2 {
		t.Errorf("DO response should have 2 answers (A + RRSIG), got %d", len(cachedDO.Answer))
	}

	// Cache should have 2 entries (one per DO variant)
	if c.Size() != 2 {
		t.Errorf("expected 2 cache entries, got %d", c.Size())
	}
}

// makeNXDOMAIN builds an NXDOMAIN response with an SOA in the Authority section
// carrying the given negative-cache TTL.
func makeNXDOMAIN(name string, soaTTL uint32) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeNameError},
		Ns: []dns.RR{
			&dns.SOA{
				Hdr:     dns.RR_Header{Name: "com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: soaTTL},
				Ns:      "a.gtld-servers.net.",
				Mbox:    "nstld.verisign-grs.com.",
				Serial:  1,
				Refresh: 1800, Retry: 900, Expire: 604800, Minttl: soaTTL,
			},
		},
	}
}

// TestNegativeCachingDisabledByDefault confirms standard/light do NOT cache negatives.
func TestNegativeCachingDisabledByDefault(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 86400}) // NegTTLMax=0
	req := makeReq("nope.example.com.", dns.TypeA)
	c.Put(req, makeNXDOMAIN("nope.example.com.", 300))
	if _, found := c.Get(req); found {
		t.Error("negative response cached even though negative caching is disabled")
	}
}

// TestNegativeCachingEnabled confirms NXDOMAIN is cached + capped when enabled.
func TestNegativeCachingEnabled(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 86400, NegTTLMax: 300})
	req := makeReq("nope.example.com.", dns.TypeA)

	c.Put(req, makeNXDOMAIN("nope.example.com.", 120)) // SOA TTL within cap
	cached, found := c.Get(req)
	if !found {
		t.Fatal("expected NXDOMAIN to be cached when negative caching enabled")
	}
	if cached.Rcode != dns.RcodeNameError {
		t.Errorf("cached rcode = %d, want NXDOMAIN", cached.Rcode)
	}
	if !c.NegativeCachingEnabled() {
		t.Error("NegativeCachingEnabled() should be true")
	}
}

// TestNegativeCachingNoSOA confirms a negative response with no SOA is not cached.
func TestNegativeCachingNoSOA(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 86400, NegTTLMax: 300})
	req := makeReq("nope.example.com.", dns.TypeA)
	resp := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeNameError}} // no Ns/SOA
	c.Put(req, resp)
	if _, found := c.Get(req); found {
		t.Error("NXDOMAIN with no SOA TTL should not be cached")
	}
}

// TestServeStaleDisabled confirms GetStale returns nothing when serve-stale is off.
func TestServeStaleDisabled(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 1, TTLMax: 86400}) // ServeStaleMaxS=0
	req := makeReq("example.com.", dns.TypeA)
	resp := makeRespTTL("example.com.", 1)
	c.Put(req, resp)
	time.Sleep(1100 * time.Millisecond) // let it expire
	if _, found := c.GetStale(req); found {
		t.Error("GetStale should return nothing when serve-stale is disabled")
	}
}

// TestServeStaleWithinWindow confirms an expired entry within the window is served.
func TestServeStaleWithinWindow(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 1, TTLMax: 86400, ServeStaleMaxS: 3600})
	req := makeReq("example.com.", dns.TypeA)
	c.Put(req, makeRespTTL("example.com.", 1))
	time.Sleep(1100 * time.Millisecond) // expired, but well within 1h stale window

	// Normal Get must miss (expired)...
	if _, found := c.Get(req); found {
		t.Error("Get should miss on an expired entry")
	}
	// ...but GetStale should serve it.
	if _, found := c.GetStale(req); !found {
		t.Error("GetStale should serve an expired entry within the window")
	}
	if !c.ServeStaleEnabled() {
		t.Error("ServeStaleEnabled() should be true")
	}
}

// TestServeStaleNotExpired confirms GetStale does NOT return a still-live entry.
func TestServeStaleNotExpired(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 86400, ServeStaleMaxS: 3600})
	req := makeReq("example.com.", dns.TypeA)
	c.Put(req, makeRespTTL("example.com.", 300)) // live
	if _, found := c.GetStale(req); found {
		t.Error("GetStale should not return a still-live (unexpired) entry")
	}
}

// TestCacheGetReturnsPrivateCopy confirms Get hands out a deep copy: every serve path
// mutates the response it got (client ID restore + EDNS0 normalization) before packing,
// and the one cache is shared across Mode-1 and all Mode-2 listeners — so a shared
// pointer let concurrent hits corrupt each other's replies (wrong transaction ID →
// client stub discards the answer → intermittent, self-clearing timeout).
func TestCacheGetReturnsPrivateCopy(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 86400})
	req := makeReq("example.com.", dns.TypeA)
	c.Put(req, makeRespTTL("example.com.", 300))

	first, found := c.Get(req)
	if !found {
		t.Fatal("expected cache hit")
	}
	// Mutate the first hit the way the serve paths do: ID restore + OPT append.
	first.Id = 1111
	first.SetEdns0(1232, false)
	first.Answer = nil // and something destructive, for good measure

	second, found := c.Get(req)
	if !found {
		t.Fatal("expected second cache hit")
	}
	if second.Id == 1111 {
		t.Error("second hit sees first hit's ID mutation — Get returned a shared pointer")
	}
	if second.IsEdns0() != nil {
		t.Error("second hit sees first hit's OPT append — Get returned a shared pointer")
	}
	if len(second.Answer) != 1 {
		t.Errorf("second hit Answer len = %d, want 1 (stored entry was mutated)", len(second.Answer))
	}
}

// TestCachePutStoresPrivateCopy confirms Put stores a deep copy: callers keep mutating
// the response AFTER caching it (ensureResponseEDNS runs post-Put on every serve path),
// which must not contaminate the stored entry.
func TestCachePutStoresPrivateCopy(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 86400})
	req := makeReq("example.com.", dns.TypeA)
	resp := makeRespTTL("example.com.", 300)
	c.Put(req, resp)

	// Mutate the original after Put, the way the serve paths do.
	resp.Id = 2222
	resp.SetEdns0(1232, false)

	cached, found := c.Get(req)
	if !found {
		t.Fatal("expected cache hit")
	}
	if cached.Id == 2222 {
		t.Error("cached entry sees post-Put ID mutation — Put stored the live pointer")
	}
	if cached.IsEdns0() != nil {
		t.Error("cached entry sees post-Put OPT append — Put stored the live pointer")
	}
}

// TestCacheGetStaleReturnsPrivateCopy confirms the serve-stale path has the same
// copy-on-read guarantee as Get.
func TestCacheGetStaleReturnsPrivateCopy(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 1, TTLMax: 86400, ServeStaleMaxS: 3600})
	req := makeReq("example.com.", dns.TypeA)
	c.Put(req, makeRespTTL("example.com.", 1))
	time.Sleep(1100 * time.Millisecond) // expired, within the stale window

	first, found := c.GetStale(req)
	if !found {
		t.Fatal("expected stale hit")
	}
	first.Id = 3333

	second, found := c.GetStale(req)
	if !found {
		t.Fatal("expected second stale hit")
	}
	if second.Id == 3333 {
		t.Error("second stale hit sees first hit's ID mutation — GetStale returned a shared pointer")
	}
}

// TestCacheConcurrentHitMutation drives concurrent Get+mutate+Pack cycles on ONE key —
// the exact shape of simultaneous Mode-1/Mode-2 hits on the shared cache. Each goroutine
// must observe its OWN transaction ID in the packed reply. Run with -race, this is also
// the regression guard for the shared-pointer data race.
func TestCacheConcurrentHitMutation(t *testing.T) {
	c := New(Options{Enabled: true, MaxSize: 100, TTLMin: 60, TTLMax: 86400})
	req := makeReq("example.com.", dns.TypeA)
	c.Put(req, makeRespTTL("example.com.", 300))

	const goroutines = 32
	const iterations = 50
	errs := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id uint16) {
			for i := 0; i < iterations; i++ {
				hit, found := c.Get(req)
				if !found {
					errs <- fmt.Errorf("goroutine %d: unexpected miss", id)
					return
				}
				hit.Id = id
				hit.SetEdns0(1232, false)
				buf, err := hit.Pack()
				if err != nil {
					errs <- fmt.Errorf("goroutine %d: pack: %v", id, err)
					return
				}
				// Wire format: first two bytes are the transaction ID.
				if got := uint16(buf[0])<<8 | uint16(buf[1]); got != id {
					errs <- fmt.Errorf("goroutine %d: packed reply carries ID %d (cross-client ID corruption)", id, got)
					return
				}
			}
			errs <- nil
		}(uint16(g + 1))
	}
	for g := 0; g < goroutines; g++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

// makeRespTTL builds a positive A response with the given TTL.
func makeRespTTL(name string, ttl uint32) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   net.IPv4(93, 184, 216, 34),
			},
		},
	}
}
