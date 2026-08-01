// SPDX-License-Identifier: MIT
package cache

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// CacheEntry represents a cached DNS response with expiration time.
type CacheEntry struct {
	Response  *dns.Msg
	ExpiresAt time.Time
}

// IsExpired returns true if the cache entry has exceeded its TTL.
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// Options configures a Cache. Replaces the older positional New(...) signature now
// that the cache supports negative caching and serve-stale (mode "aggressive").
// Zero values are filled with safe defaults in New.
type Options struct {
	Enabled bool // Cache enabled/disabled flag
	MaxSize int  // Maximum entries (0 → default 4096)
	TTLMin  int  // Minimum TTL in seconds (responses below this are not cached; 0 allowed for "light")
	TTLMax  int  // Maximum TTL in seconds (cap long-lived entries; 0 → default 86400)

	// NegTTLMax caps how long NXDOMAIN / NODATA answers are cached, in seconds.
	// 0 disables negative caching (the "standard"/"light" behavior — only successes cached).
	NegTTLMax int

	// ServeStaleMaxS bounds how far past expiry a stale answer may be served when ALL
	// upstreams fail, in seconds. 0 disables serve-stale. Serve-stale never emits cleartext:
	// the stale answer was already validated and arrived over an encrypted upstream.
	ServeStaleMaxS int
}

// Cache is an in-memory DNS response cache with TTL-aware eviction.
// Thread-safe for concurrent reads and writes.
//
// Design:
// - Keyed by DNS question (QNAME + QTYPE + QCLASS + DO-bit)
// - TTL bounds: ttl_min <= cache TTL <= ttl_max
// - Max size: configurable (default 4096 entries)
// - Eviction: lazy (on access) + evict-soonest-to-expire when full
// - Thread-safe: RWMutex for concurrent access
// - Enabled flag: can be disabled via config (noop cache returns immediately)
// - Negative caching (NXDOMAIN/NODATA): enabled when negTTLMax > 0 (mode "aggressive")
// - Serve-stale: enabled when serveStaleMaxS > 0 (mode "aggressive"); see GetStale
type Cache struct {
	// Configuration
	enabled        bool // Cache enabled/disabled flag
	maxSize        int  // Maximum entries in cache
	ttlMin         int  // Minimum TTL in seconds
	ttlMax         int  // Maximum TTL in seconds
	negTTLMax      int  // Max TTL for negative entries; 0 = negative caching off
	serveStaleMaxS int  // Max seconds past expiry to serve stale; 0 = serve-stale off

	// Storage
	entries map[string]*CacheEntry
	mu      sync.RWMutex
}

// New creates a new DNS cache from Options. Zero/invalid values are defaulted:
// MaxSize→4096, TTLMax→86400. TTLMin is NOT floored (0 is a valid "light" setting
// meaning "cache even very short-TTL responses"). NegTTLMax and ServeStaleMaxS of 0
// mean those features are disabled.
func New(opts Options) *Cache {
	maxSize := opts.MaxSize
	if maxSize <= 0 {
		maxSize = 4096 // Default
	}
	ttlMin := opts.TTLMin
	if ttlMin < 0 {
		ttlMin = 0
	}
	ttlMax := opts.TTLMax
	if ttlMax <= 0 {
		ttlMax = 86400 // Default: 24 hours
	}

	return &Cache{
		enabled:        opts.Enabled,
		maxSize:        maxSize,
		ttlMin:         ttlMin,
		ttlMax:         ttlMax,
		negTTLMax:      opts.NegTTLMax,
		serveStaleMaxS: opts.ServeStaleMaxS,
		entries:        make(map[string]*CacheEntry),
	}
}

// cacheKey generates a unique key for a DNS request.
// Includes the DO (DNSSEC OK) bit so that DNSSEC-aware and DNSSEC-unaware clients
// get separate cache entries. Without this, a cached non-DNSSEC response could be
// served to a client that requested DNSSEC records (or vice versa).
// Format: "name|type|class|do" (e.g., "example.com.|A|IN|1")
func cacheKey(req *dns.Msg) string {
	q := req.Question[0]
	do := "0"
	if opt := req.IsEdns0(); opt != nil && opt.Do() {
		do = "1"
	}
	return q.Name + "|" + dns.TypeToString[q.Qtype] + "|" + dns.ClassToString[q.Qclass] + "|" + do
}

// Get retrieves a cached response for the given DNS request.
// Returns (response, true) if found and not expired.
// Returns (nil, false) if not found, expired, or cache is disabled.
// Expired entries are lazily deleted on access.
// The full request message is needed to include the DO bit in the cache key.
//
// The returned message is a deep COPY of the stored entry. Every hit path mutates the
// response it serves (restores the client's transaction ID, normalizes EDNS0 via
// ensureResponseEDNS) and then Packs it — and this ONE cache is shared across Mode-1
// UDP/TCP and every Mode-2 listener. Handing out the stored pointer let two concurrent
// hits on the same key race on those mutations (one client's reply packed with the
// OTHER client's ID → the stub discards it → an intermittent, self-clearing timeout),
// and was a data race outright. Copy-on-get makes each hit's mutations private.
func (c *Cache) Get(req *dns.Msg) (*dns.Msg, bool) {
	if !c.enabled || req == nil || len(req.Question) == 0 {
		return nil, false
	}

	key := cacheKey(req)

	c.mu.RLock()
	entry, exists := c.entries[key]
	c.mu.RUnlock()

	if !exists {
		return nil, false
	}

	// Check expiration. Normally we lazy-delete an expired entry on access. BUT when
	// serve-stale is enabled we must KEEP the expired entry so the upstream-failure path
	// (GetStale) can still serve it within the stale window. A later successful Put
	// overwrites it; otherwise it is reclaimed by eviction or once it ages out of the
	// stale window (checked in GetStale). Either way Get itself reports a miss so the
	// normal path goes upstream for a fresh answer.
	if entry.IsExpired() {
		if c.serveStaleMaxS <= 0 {
			c.mu.Lock()
			delete(c.entries, key)
			c.mu.Unlock()
		}
		return nil, false
	}

	return entry.Response.Copy(), true
}

// GetStale retrieves an EXPIRED cached response when it is within the serve-stale
// window (serveStaleMaxS seconds past expiry). It is the resilience fallback consulted
// only when all upstreams fail — never on the normal Get path.
//
// Returns (response, true) only if: serve-stale is enabled, an entry exists, the entry
// IS expired, and it expired no more than serveStaleMaxS seconds ago. Unlike Get, this
// does NOT delete the entry (a later upstream success will overwrite it via Put).
// Like Get, the returned message is a deep COPY (see Get for why).
//
// Serve-stale never relaxes the no-cleartext guarantee: the returned answer was already
// DNSSEC-validated and arrived over an encrypted upstream. Only freshness is relaxed.
func (c *Cache) GetStale(req *dns.Msg) (*dns.Msg, bool) {
	if !c.enabled || c.serveStaleMaxS <= 0 || req == nil || len(req.Question) == 0 {
		return nil, false
	}

	key := cacheKey(req)

	c.mu.RLock()
	entry, exists := c.entries[key]
	c.mu.RUnlock()

	if !exists {
		return nil, false
	}

	// Must be expired (a live entry would have been served by Get) AND within the window.
	staleFor := time.Since(entry.ExpiresAt)
	if staleFor <= 0 {
		return nil, false // not actually expired
	}
	if staleFor > time.Duration(c.serveStaleMaxS)*time.Second {
		return nil, false // too stale to serve
	}

	return entry.Response.Copy(), true
}

// isNegative reports whether resp is a negative answer that negative caching covers:
// NXDOMAIN (RcodeNameError), or NODATA (NOERROR with no Answer RRs). Both carry their
// caching TTL in the SOA record of the Authority section (RFC 2308).
func isNegative(resp *dns.Msg) bool {
	if resp.Rcode == dns.RcodeNameError {
		return true
	}
	if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 {
		return true
	}
	return false
}

// negTTL returns the negative-caching TTL for a response: the TTL of the SOA in the
// Authority section (RFC 2308 §5). Falls back to 0 if no SOA is present.
func negTTL(resp *dns.Msg) int {
	for _, rr := range resp.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return int(soa.Header().Ttl)
		}
	}
	return 0
}

// Put stores a DNS response in the cache.
// Positive (NOERROR-with-answers) responses use the minimum RR TTL, clamped to
// [ttlMin, ttlMax]. Negative responses (NXDOMAIN/NODATA) are stored only when negative
// caching is enabled (negTTLMax > 0), using the SOA TTL capped at negTTLMax.
// If cache is full, the soonest-to-expire entry is evicted. Noop if cache is disabled.
// The full request message is needed to include the DO bit in the cache key.
//
// The stored entry is a deep COPY of resp: callers keep mutating the response they
// just cached (ensureResponseEDNS normalizes the OPT record AFTER Put on every serve
// path, and the listeners restore the client ID before packing). Storing the live
// pointer would let those per-client mutations contaminate the shared entry.
func (c *Cache) Put(req *dns.Msg, resp *dns.Msg) {
	if !c.enabled || req == nil || len(req.Question) == 0 || resp == nil {
		return
	}

	// Defense in depth (audit H1): never store a response carrying a Question that
	// disagrees with the request key it is stored under — that is the cache-poisoning
	// re-keying class. The resolver layer already rejects mismatched upstream answers
	// (fallback.go responseMatchesQuery); this enforces the same invariant locally for
	// every current and future Put caller. An ABSENT Question is tolerated (locally
	// synthesized messages may omit the echo; an upstream answer without one never gets
	// past the resolver check). QNAMEs compare case-insensitively (RFC 4343).
	if len(resp.Question) > 1 {
		return
	}
	if len(resp.Question) == 1 {
		q, r := req.Question[0], resp.Question[0]
		if q.Qtype != r.Qtype || q.Qclass != r.Qclass ||
			dns.CanonicalName(q.Name) != dns.CanonicalName(r.Name) {
			return
		}
	}

	var ttl int
	if isNegative(resp) {
		// Negative caching is opt-in (mode "aggressive"). When off, don't cache negatives.
		if c.negTTLMax <= 0 {
			return
		}
		ttl = negTTL(resp)
		if ttl <= 0 {
			return // no SOA TTL to base negative caching on
		}
		if ttl > c.negTTLMax {
			ttl = c.negTTLMax
		}
	} else {
		// Positive response: minimum RR TTL, clamped to [ttlMin, ttlMax].
		// ttl_min is a FLOOR that extends short TTLs UP, not a reject threshold:
		// e.g. "aggressive" (ttl_min 300) caches a 60s record for 300s — the whole
		// point of aggressive caching is to hold short-TTL answers longer and cut
		// upstream queries. (A reject-below-floor here silently disabled caching in
		// aggressive mode, since most real-world TTLs are < 300s — see ISSUES 25.)
		ttl = extractMinTTL(resp)
		if ttl < c.ttlMin {
			ttl = c.ttlMin // Extend short-lived responses up to the floor
		}
		if ttl > c.ttlMax {
			ttl = c.ttlMax // Cap long-lived responses
		}
	}

	key := cacheKey(req)
	expiresAt := time.Now().Add(time.Duration(ttl) * time.Second)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict oldest entry if cache is full
	if len(c.entries) >= c.maxSize && c.entries[key] == nil {
		c.evictOldest()
	}

	c.entries[key] = &CacheEntry{
		Response:  resp.Copy(),
		ExpiresAt: expiresAt,
	}
}

// extractMinTTL returns the minimum TTL from all RRs in the response.
// Returns the smallest TTL found, or ttlMin default if no RRs present.
func extractMinTTL(resp *dns.Msg) int {
	if resp == nil {
		return 60 // Safe default
	}

	minTTL := 86400 // Start with max (24 hours)

	// Check all answer RRs
	for _, rr := range resp.Answer {
		if rr.Header().Ttl < uint32(minTTL) {
			minTTL = int(rr.Header().Ttl)
		}
	}

	// Check all authority RRs (for NXDOMAIN, etc.)
	for _, rr := range resp.Ns {
		if rr.Header().Ttl < uint32(minTTL) {
			minTTL = int(rr.Header().Ttl)
		}
	}

	// Check all additional RRs (skip OPT pseudo-record — its TTL field encodes EDNS0 flags, not a TTL)
	for _, rr := range resp.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		if rr.Header().Ttl < uint32(minTTL) {
			minTTL = int(rr.Header().Ttl)
		}
	}

	// If no RRs, return safe default
	if minTTL == 86400 {
		return 60
	}

	return minTTL
}

// evictOldest removes the entry with the earliest expiration time.
// Assumes lock is already held (called from Put).
// This is a simple eviction strategy; more sophisticated strategies (LRU, LFU)
// can be added later if needed.
func (c *Cache) evictOldest() {
	if len(c.entries) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if oldestKey == "" || entry.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.ExpiresAt
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CacheEntry)
}

// Size returns the current number of entries in the cache.
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Stats returns cache statistics for monitoring.
type Stats struct {
	Size           int // Current number of entries
	MaxSize        int // Maximum allowed entries
	TTLMin         int // Minimum TTL in seconds
	TTLMax         int // Maximum TTL in seconds
	NegTTLMax      int // Max negative-cache TTL in seconds (0 = negative caching off)
	ServeStaleMaxS int // Max serve-stale window in seconds (0 = serve-stale off)
}

// GetStats returns current cache statistics.
func (c *Cache) GetStats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Stats{
		Size:           len(c.entries),
		MaxSize:        c.maxSize,
		TTLMin:         c.ttlMin,
		TTLMax:         c.ttlMax,
		NegTTLMax:      c.negTTLMax,
		ServeStaleMaxS: c.serveStaleMaxS,
	}
}

// NegativeCachingEnabled reports whether NXDOMAIN/NODATA answers are cached.
func (c *Cache) NegativeCachingEnabled() bool { return c.negTTLMax > 0 }

// ServeStaleEnabled reports whether stale answers may be served on upstream failure.
func (c *Cache) ServeStaleEnabled() bool { return c.serveStaleMaxS > 0 }
