// SPDX-License-Identifier: MIT
package statistics

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// Stats holds all runtime counters for a running rcvd instance.
// All fields are int64 and must be accessed via sync/atomic.
// Privacy-safe: no per-client tracking, no query content, no domain names.
type Stats struct {
	// Process
	// startTime uses Go's monotonic clock (immune to NTP corrections after boot).
	// Stored as time.Time, not int64, so time.Since() is always accurate.
	startTime time.Time

	// Queries
	TotalQueries int64 // all queries received (UDP + TCP)

	// Cache
	CacheHits   int64
	CacheMisses int64
	StaleServed int64 // served-stale responses (aggressive mode, upstream failure)

	// Blocklist
	BlockedQueries       int64
	BlocklistFilesLoaded int64 // number of blocklist files successfully loaded (0 = none/loading)

	// Responses — exactly ONE bucket is incremented per response sent to a client,
	// keyed on the response rcode (see RecordResponse). Their sum equals TotalQueries
	// minus the rare responses dropped by a local pack/write error before send. This
	// decoupling from cacheability is the fix for Issue 27.
	ServfailResponses int64 // SERVFAIL sent (fail-closed: upstream/DNSSEC failure)
	NxdomainResponses int64 // NXDOMAIN sent (blocklist or upstream)
	SuccessResponses  int64 // NOERROR sent (cache hit, stale, or fresh upstream)
	OtherResponses    int64 // any other rcode sent (REFUSED/NOTIMP/FORMERR/…)

	// Upstream
	UpstreamQueries   int64 // total sent to upstream resolvers
	UpstreamErrors    int64 // upstream failures
	UpstreamFallbacks int64 // times a backup upstream was used after primary failed

	// Per-protocol (upstream resolver, Mode 1 outbound)
	DoQQueries int64
	DoTQueries int64
	DoHQueries int64

	// DoQ idle-gap recoveries: a reused DoQ connection was found stale (peer closed it
	// at its idle timeout) and the exchange re-dialed on a fresh connection and succeeded.
	// Benign and expected on a bursty/roaming leg — counted so operators can see recovery
	// frequency without the per-event log line (which is debug-only). Never a SERVFAIL.
	DoQIdleRetries int64

	// Per-protocol (upstream service, Mode 2 inbound)
	DoQServed int64
	DoTServed int64
	DoHServed int64

	// DNSSEC
	DnssecValidated int64 // signature verified OK
	DnssecFailed    int64 // signature verification failed
	DnssecUnsigned  int64 // served without AD: no RRSIG present (permissive) OR proven INSECURE (Issue 30)

	// Latency (Mode-1 UPSTREAM FETCH, cache-miss only, rolling). This times
	// s.resolver.Resolve() — the trip out to the public upstream on a miss — NOT a
	// client-facing round trip. Rendered under Mode 1 as "Miss latency".
	LatencyMinUs   int64 // microseconds, use atomic compare-and-swap
	LatencyMaxUs   int64
	LatencyTotalUs int64 // sum for computing average
	LatencyCount   int64 // divisor for average

	// Latency (Mode-2 CLIENT-FACING service time, rolling). Times request-received →
	// response-sent at THIS router's Mode-2 listener — the true "what a pinned LAN client
	// experiences" number. Cache hits are ~0; misses include the router's own upstream
	// fetch. Kept SEPARATE from the Mode-1 upstream-fetch timer above so neither blends
	// into the other. Rendered under Mode 2 as "Avg response".
	Mode2LatencyMinUs   int64
	Mode2LatencyMaxUs   int64
	Mode2LatencyTotalUs int64
	Mode2LatencyCount   int64
}

// InstanceInfo carries static per-instance metadata into the snapshot/render.
// These values are fixed at startup (they don't change while running) and identify
// WHICH rcvd instance + config this stats output belongs to — important when multiple
// instances run on one host. Injected at snapshot time, like cache info.
type InstanceInfo struct {
	ConfigPath   string // absolute path of the loaded config file
	SocketPath   string // this instance's stats socket path
	Mode1Enabled   bool // [resolver] enabled — Mode 1 (forwarding resolver)
	Mode2Enabled   bool // [upstream_service] enabled — Mode 2 (client-facing server)
	DNSSECEnabled  bool // [dnssec] enabled

	// Cache posture (operator-facing): the configured mode name plus the capabilities it
	// actually enabled, read from the live cache (so the descriptor can't drift from
	// behavior). CacheServeStaleS is the serve-stale window in seconds (0 = off).
	CacheType        string // "light" | "standard" | "aggressive" (or "" if cache disabled)
	CacheNegCache    bool   // negative caching (NXDOMAIN/NODATA) enabled
	CacheServeStaleS int    // serve-stale window in seconds (0 = off)
}

// Snapshot is a point-in-time copy of all counters, safe to read without atomics.
type Snapshot struct {
	Instance             InstanceInfo
	Uptime               time.Duration
	TotalQueries         int64
	CacheHits            int64
	CacheMisses          int64
	StaleServed          int64
	BlockedQueries       int64
	BlocklistFilesLoaded int64
	ServfailResponses    int64
	NxdomainResponses    int64
	SuccessResponses     int64
	OtherResponses       int64
	UpstreamQueries      int64
	UpstreamErrors       int64
	UpstreamFallbacks    int64
	DoQQueries           int64
	DoTQueries           int64
	DoHQueries           int64
	DoQIdleRetries       int64
	DoQServed            int64
	DoTServed            int64
	DoHServed            int64
	DnssecValidated      int64
	DnssecFailed         int64
	DnssecUnsigned       int64
	LatencyMinUs         int64 // Mode-1 upstream-fetch (cache-miss) latency
	LatencyMaxUs         int64
	LatencyAvgUs         int64
	LatencyCount         int64
	Mode2LatencyMinUs    int64 // Mode-2 client-facing service time (request-in → response-out)
	Mode2LatencyMaxUs    int64
	Mode2LatencyAvgUs    int64
	Mode2LatencyCount    int64
	CacheSize            int                // current cache entries (injected at snapshot time)
	CacheMaxSize         int                // max cache capacity (injected at snapshot time)
	Connections          []UpstreamConnInfo // per-upstream live health (injected; nil = no fallback chain wired)
}

// UpstreamConnInfo is a render-ready, dependency-free view of one upstream's live
// health for the MODE-1 FORWARDER "Connections" block (Issue 23 Pass-2 stats).
// main.go fills this from FallbackResolver.GetStatus(); the statistics package does
// not import resolver. State is "UP"/"SLOW"/"DOWN". LastError is an upstream/
// transport error string — it MUST never carry a queried name (privacy invariant).
type UpstreamConnInfo struct {
	Name              string
	State             string
	ConsecutiveErrors int
	LastError         string
}

// New creates a Stats instance with startTime set to now (monotonic clock).
func New() *Stats {
	return &Stats{
		startTime: time.Now(),
	}
}

// Uptime returns how long this instance has been running, from the monotonic startTime.
// Used by --audit ("how long has this posture been in force") since AuditInfo is static.
func (s *Stats) Uptime() time.Duration {
	return time.Since(s.startTime)
}

// AddBlocklistFile increments the count of successfully loaded blocklist files by 1.
// Call once per file after it finishes loading (even during async background load).
func (s *Stats) AddBlocklistFile() {
	atomic.AddInt64(&s.BlocklistFilesLoaded, 1)
}

// SetBlocklistFiles sets the loaded-file count to an exact value. Used by the
// hot-reload path (--blocklist-reload), which rebuilds the whole set and so
// replaces the count rather than accumulating onto the startup total.
func (s *Stats) SetBlocklistFiles(n int) {
	atomic.StoreInt64(&s.BlocklistFilesLoaded, int64(n))
}

// DNS rcodes used for response bucketing (RFC 1035 §4.1.1 / RFC 6895).
// Duplicated here as plain ints so the statistics package stays free of the
// miekg/dns dependency; callers pass response.Rcode directly.
const (
	rcodeNOERROR  = 0 // dns.RcodeSuccess
	rcodeSERVFAIL = 2 // dns.RcodeServerFailure
	rcodeNXDOMAIN = 3 // dns.RcodeNameError
)

// RecordResponse increments exactly one response bucket for a reply sent to a
// client, keyed on the DNS rcode. This is the single accounting point for the
// QUERIES "Responses" block — call it once per sent response, regardless of
// whether the answer was cacheable, cached, stale-served, or freshly resolved.
// Decoupling response accounting from cacheability is the Issue 27 fix: it
// guarantees Success+SERVFAIL+NXDOMAIN+Other == TotalQueries (minus the rare
// responses dropped by a local pack/write error before they reach the client).
func (s *Stats) RecordResponse(rcode int) {
	switch rcode {
	case rcodeNOERROR:
		atomic.AddInt64(&s.SuccessResponses, 1)
	case rcodeSERVFAIL:
		atomic.AddInt64(&s.ServfailResponses, 1)
	case rcodeNXDOMAIN:
		atomic.AddInt64(&s.NxdomainResponses, 1)
	default:
		atomic.AddInt64(&s.OtherResponses, 1)
	}
}

// RecordLatency records a Mode-1 upstream-FETCH latency in microseconds (the trip to the
// public upstream on a cache miss — not a client-facing round trip). Updates min, max,
// total, and count atomically.
func (s *Stats) RecordLatency(us int64) {
	recordLatencyInto(&s.LatencyTotalUs, &s.LatencyCount, &s.LatencyMinUs, &s.LatencyMaxUs, us)
}

// RecordMode2Latency records a Mode-2 CLIENT-FACING service time in microseconds
// (request-received → response-sent at this router's listener — cache hits ~0, misses
// include the upstream fetch). Kept separate from the Mode-1 upstream-fetch timer.
func (s *Stats) RecordMode2Latency(us int64) {
	recordLatencyInto(&s.Mode2LatencyTotalUs, &s.Mode2LatencyCount, &s.Mode2LatencyMinUs, &s.Mode2LatencyMaxUs, us)
}

// recordLatencyInto updates a (total, count, min, max) atomic quadruple with one sample.
// Shared by the Mode-1 and Mode-2 latency recorders so both stay identical.
func recordLatencyInto(total, count, minUs, maxUs *int64, us int64) {
	atomic.AddInt64(total, us)
	atomic.AddInt64(count, 1)

	// Update min (CAS loop). min==0 means "unset" (first sample wins).
	for {
		cur := atomic.LoadInt64(minUs)
		if cur != 0 && cur <= us {
			break
		}
		if atomic.CompareAndSwapInt64(minUs, cur, us) {
			break
		}
	}

	// Update max (CAS loop)
	for {
		cur := atomic.LoadInt64(maxUs)
		if cur >= us {
			break
		}
		if atomic.CompareAndSwapInt64(maxUs, cur, us) {
			break
		}
	}
}

// TakeSnapshot reads all atomic counters and returns a Snapshot.
// cacheSize/cacheMaxSize are injected from the cache package; info carries the
// static per-instance metadata (config/socket paths, mode flags).
func (s *Stats) TakeSnapshot(cacheSize, cacheMaxSize int, info InstanceInfo) Snapshot {
	count := atomic.LoadInt64(&s.LatencyCount)
	total := atomic.LoadInt64(&s.LatencyTotalUs)
	var avgUs int64
	if count > 0 {
		avgUs = total / count
	}

	m2count := atomic.LoadInt64(&s.Mode2LatencyCount)
	m2total := atomic.LoadInt64(&s.Mode2LatencyTotalUs)
	var m2avgUs int64
	if m2count > 0 {
		m2avgUs = m2total / m2count
	}

	return Snapshot{
		Instance:             info,
		Uptime:               time.Since(s.startTime),
		TotalQueries:         atomic.LoadInt64(&s.TotalQueries),
		CacheHits:            atomic.LoadInt64(&s.CacheHits),
		CacheMisses:          atomic.LoadInt64(&s.CacheMisses),
		StaleServed:          atomic.LoadInt64(&s.StaleServed),
		BlockedQueries:       atomic.LoadInt64(&s.BlockedQueries),
		BlocklistFilesLoaded: atomic.LoadInt64(&s.BlocklistFilesLoaded),
		ServfailResponses:    atomic.LoadInt64(&s.ServfailResponses),
		NxdomainResponses:    atomic.LoadInt64(&s.NxdomainResponses),
		SuccessResponses:     atomic.LoadInt64(&s.SuccessResponses),
		OtherResponses:       atomic.LoadInt64(&s.OtherResponses),
		UpstreamQueries:      atomic.LoadInt64(&s.UpstreamQueries),
		UpstreamErrors:       atomic.LoadInt64(&s.UpstreamErrors),
		UpstreamFallbacks:    atomic.LoadInt64(&s.UpstreamFallbacks),
		DoQQueries:           atomic.LoadInt64(&s.DoQQueries),
		DoTQueries:           atomic.LoadInt64(&s.DoTQueries),
		DoHQueries:           atomic.LoadInt64(&s.DoHQueries),
		DoQIdleRetries:       atomic.LoadInt64(&s.DoQIdleRetries),
		DoQServed:            atomic.LoadInt64(&s.DoQServed),
		DoTServed:            atomic.LoadInt64(&s.DoTServed),
		DoHServed:            atomic.LoadInt64(&s.DoHServed),
		DnssecValidated:      atomic.LoadInt64(&s.DnssecValidated),
		DnssecFailed:         atomic.LoadInt64(&s.DnssecFailed),
		DnssecUnsigned:       atomic.LoadInt64(&s.DnssecUnsigned),
		LatencyMinUs:         atomic.LoadInt64(&s.LatencyMinUs),
		LatencyMaxUs:         atomic.LoadInt64(&s.LatencyMaxUs),
		LatencyAvgUs:         avgUs,
		LatencyCount:         count,
		Mode2LatencyMinUs:    atomic.LoadInt64(&s.Mode2LatencyMinUs),
		Mode2LatencyMaxUs:    atomic.LoadInt64(&s.Mode2LatencyMaxUs),
		Mode2LatencyAvgUs:    m2avgUs,
		Mode2LatencyCount:    m2count,
		CacheSize:            cacheSize,
		CacheMaxSize:         cacheMaxSize,
	}
}

// Render formats the snapshot as human-readable text, laid out per the design in
// statistics.gotmpl (mode-labeled, operator-focused). Indent convention: top-level
// fields at 4 spaces, nested sub-items at 6 spaces; section headers at column 0.
//
// Pass 1 (current): every section backed by existing counters. The MODE-1 FORWARDER
// per-upstream "Connections" block and a "Last error" breakdown are deferred to Pass 2
// (they need per-upstream + error-classification counters that don't exist yet); for
// now the forwarder section points the operator at --verify-upstream.
func (snap *Snapshot) Render(version string) string {
	var b strings.Builder
	// Label field widths. Both use negative (left-aligned) values.
	// 4-space indent + 22-wide label + 1 space = value at col 27.
	// 6-space indent + 20-wide label + 1 space = value at col 27 (same column).
	const w = -22  // top-level field label width (4-space indent)
	const w2 = -20 // nested sub-item label width (6-space indent)

	// pct returns "n.n%" or "n/a" when the denominator is zero.
	pct := func(num, den int64) string {
		if den <= 0 {
			return "n/a"
		}
		return fmt.Sprintf("%.1f%%", float64(num)/float64(den)*100)
	}

	// ---- header --------------------------------------------------------------
	b.WriteString("RCVD Statistics\n")
	if version != "" {
		fmt.Fprintf(&b, "    %*s %s\n", w, "Version:", version)
	}
	fmt.Fprintf(&b, "    %*s %s\n", w, "Uptime:", formatDuration(snap.Uptime))
	if snap.Instance.ConfigPath != "" {
		fmt.Fprintf(&b, "    %*s %s\n", w, "Config:", snap.Instance.ConfigPath)
	}
	if snap.Instance.SocketPath != "" {
		fmt.Fprintf(&b, "    %*s %s\n", w, "Socket:", snap.Instance.SocketPath)
	}
	b.WriteString("    Active Modes:\n")
	fmt.Fprintf(&b, "      MODE-1 %s\n", onOff(snap.Instance.Mode1Enabled))
	fmt.Fprintf(&b, "      MODE-2 %s\n", onOff(snap.Instance.Mode2Enabled))
	b.WriteByte('\n')

	// ---- SERVICE HEALTH ------------------------------------------------------
	answered := snap.SuccessResponses + snap.ServfailResponses
	b.WriteString("SERVICE HEALTH\n")
	fmt.Fprintf(&b, "    %*s %s\n", w, "Success rate:",
		pct(snap.SuccessResponses, answered))
	// Served-stale is shown only when it has actually fired — it means upstreams failed
	// and rcvd served a bounded-stale (but previously-validated) answer instead of SERVFAIL.
	if snap.StaleServed > 0 {
		fmt.Fprintf(&b, "    %*s %s   upstream failure; bounded-stale, never cleartext\n", w, "Served stale:", fmtInt(snap.StaleServed))
	}
	// No blank line here — QUERIES reads as a continuation of SERVICE HEALTH visually.

	// ---- QUERIES -------------------------------------------------------------
	b.WriteString("QUERIES\n")
	fmt.Fprintf(&b, "    %*s %s\n", w, "Total handled:", fmtInt(snap.TotalQueries))
	b.WriteString("    Responses:\n")
	fmt.Fprintf(&b, "      %*s %s    %s\n", w2, "Success:", fmtInt(snap.SuccessResponses), pct(snap.SuccessResponses, snap.TotalQueries))
	fmt.Fprintf(&b, "      %*s %s    %s\n", w2, "SERVFAIL:", fmtInt(snap.ServfailResponses), pct(snap.ServfailResponses, snap.TotalQueries))
	fmt.Fprintf(&b, "      %*s %s\n", w2, "NXDOMAIN:", fmtInt(snap.NxdomainResponses))
	// Other rcodes (REFUSED/NOTIMP/FORMERR/…) — shown only when nonzero so the
	// common case stays clean. Before Issue 27 these were silently unbucketed.
	if snap.OtherResponses > 0 {
		fmt.Fprintf(&b, "      %*s %s    %s\n", w2, "Other rcode:", fmtInt(snap.OtherResponses), pct(snap.OtherResponses, snap.TotalQueries))
	}
	// Counter-conservation check: the four response buckets should sum to
	// TotalQueries; any positive remainder is a response dropped by a local
	// pack/write error before send (rare). Surfaced so the gap is never silent.
	if gap := snap.TotalQueries - (snap.SuccessResponses + snap.ServfailResponses + snap.NxdomainResponses + snap.OtherResponses); gap > 0 {
		fmt.Fprintf(&b, "      %*s %s    pre-send pack/write drops\n", w2, "Unaccounted:", fmtInt(gap))
	}
	b.WriteByte('\n')
	b.WriteString("    Cache:\n")
	// Type line: shows WHICH cache type is active + what it enables, so an operator can
	// interpret the hit rate (e.g. a low rate under "standard" is expected; under
	// "aggressive" it warrants a look). Descriptor is derived from the live cache's actual
	// capabilities, not just the type name. Omitted when the cache is disabled (type "").
	if snap.Instance.CacheType != "" {
		fmt.Fprintf(&b, "      %*s %s\n", w2, "Type:", cacheTypeDesc(snap.Instance))
	}
	fmt.Fprintf(&b, "      %*s %s / %s\n", w2, "Size:", fmtInt(int64(snap.CacheSize)), fmtInt(int64(snap.CacheMaxSize)))
	cacheTotal := snap.CacheHits + snap.CacheMisses
	fmt.Fprintf(&b, "      %*s %s    %s hits / %s misses\n", w2, "Hit rate:",
		pct(snap.CacheHits, cacheTotal), fmtInt(snap.CacheHits), fmtInt(snap.CacheMisses))
	// Surface serve-stale here too (it's also flagged in SERVICE HEALTH) so it sits next to
	// the cache stats it relates to — only when it has actually fired.
	if snap.StaleServed > 0 {
		fmt.Fprintf(&b, "      %*s %s   (upstream failure; bounded-stale, never cleartext)\n", w2, "Served stale:", fmtInt(snap.StaleServed))
	}
	b.WriteByte('\n')

	// ---- MODE-1 FORWARDER (outbound) — always rendered FIRST ------------------
	// Order is FIXED (Mode 1 before Mode 2) so a Mode-1-only operator's view never
	// shifts when they later enable Mode 2 — the Mode-2 section simply appends below,
	// rather than pushing the familiar forwarder stats down. Shown when Mode 1 is
	// enabled (a Mode-2-only server omits it instead of printing an all-zero block).
	if snap.Instance.Mode1Enabled {
		b.WriteString("MODE-1 - FORWARDER (outbound)\n")
		fmt.Fprintf(&b, "    %*s %s\n", w, "Upstream queries:", fmtInt(snap.UpstreamQueries))
		fmt.Fprintf(&b, "    %*s %s\n", w, "Upstream errors:", fmtInt(snap.UpstreamErrors))
		fmt.Fprintf(&b, "    %*s %s\n", w, "Fallback events:", fmtInt(snap.UpstreamFallbacks))
		fmt.Fprintf(&b, "    %*s DoQ %s    DoT %s    DoH %s\n", w, "By protocol:",
			fmtInt(snap.DoQQueries), fmtInt(snap.DoTQueries), fmtInt(snap.DoHQueries))
		// Upstream-FETCH latency: time to fetch a COLD name from the public upstream on a
		// cache miss. This is a WAN round trip (DoQ/DoT/DoH to AdGuard/Cloudflare/Quad9), NOT
		// a client-facing or LAN number, and it EXCLUDES cache hits — so it reads higher than
		// what a client experiences. It belongs here under Mode 1, where the fetch happens.
		if snap.LatencyCount > 0 {
			fmt.Fprintf(&b, "    %*s %s avg    min: %s    max: %s\n", w, "Miss latency:",
				formatLatency(snap.LatencyAvgUs), formatLatency(snap.LatencyMinUs), formatLatency(snap.LatencyMaxUs))
			b.WriteString("      encrypted upstream round-trip on cache MISS only (excludes hits);\n")
			b.WriteString("      includes the encrypted-transport handshake + DNSSEC chain walk. Cache HITS\n")
			b.WriteString("      skip the network entirely (served from local memory), so they are near-instant.\n")
		}
		// Connections (per-upstream UP/SLOW/DOWN + consecutive errors + last error).
		// Live data comes from the fallback chain (Issue 23). When no chain is wired
		// (e.g. stats queried before the resolver is up), fall back to the placeholder.
		b.WriteString("\n")
		b.WriteString("    Connections:\n")
		if len(snap.Connections) == 0 {
			b.WriteString("      (per-upstream health pending — run --verify-upstream for full rcvd verification)\n")
		} else {
			for _, c := range snap.Connections {
				line := fmt.Sprintf("      %-20s %s", c.Name, c.State)
				if c.ConsecutiveErrors > 0 {
					line += fmt.Sprintf("  (%d consecutive err)", c.ConsecutiveErrors)
				}
				b.WriteString(line + "\n")
				// Last error shown indented under its upstream, only when present.
				// It is a transport/upstream error string — never a queried name.
				if c.LastError != "" {
					fmt.Fprintf(&b, "        last error: %s\n", c.LastError)
				}
			}
		}
		b.WriteByte('\n')
	}

	// ---- MODE-2 SERVER (client-facing) — appended AFTER Mode 1, only if enabled
	if snap.Instance.Mode2Enabled {
		b.WriteString("MODE-2 SERVER (client-facing)\n")
		fmt.Fprintf(&b, "    %*s %s\n", w, "DoH served:", fmtInt(snap.DoHServed))
		fmt.Fprintf(&b, "    %*s %s\n", w, "DoT served:", fmtInt(snap.DoTServed))
		fmt.Fprintf(&b, "    %*s %s\n", w, "DoQ served:", fmtInt(snap.DoQServed))
		// CLIENT-FACING service time: request-received → response-sent at THIS listener —
		// the number a pinned LAN client actually experiences. Cache hits are ~0ms; misses
		// include the router's own upstream fetch (see Mode-1 "Upstream fetch" above), which
		// is why max can be large while the average stays low on a warm cache.
		if snap.Mode2LatencyCount > 0 {
			fmt.Fprintf(&b, "    %*s %s avg    min: %s    max: %s\n", w, "Client service:",
				formatLatency(snap.Mode2LatencyAvgUs), formatLatency(snap.Mode2LatencyMinUs), formatLatency(snap.Mode2LatencyMaxUs))
			b.WriteString("      request-in > response-out at THIS listener (what a pinned client sees).\n")
			b.WriteString("      cache HITS skip the network (local memory) and are near-instant; a MISS\n")
			b.WriteString("      adds this instance's own upstream fetch (see Mode-1 \"Miss latency\") —\n")
			b.WriteString("      which is why max can spike while a warm avg stays low.\n")
		}
		b.WriteByte('\n')
	}

	// ---- DoQ TRANSPORT (mode-independent) ------------------------------------
	// Idle-gap recoveries: a pooled DoQ connection was found stale (peer closed it at
	// its idle timeout) and the exchange re-dialed and succeeded. Benign and expected on
	// a bursty/roaming leg — every one recovered (never a SERVFAIL). Shown only when
	// non-zero so a quiet install prints nothing. The per-event line is debug-only.
	if snap.DoQIdleRetries > 0 {
		b.WriteString("DoQ TRANSPORT\n")
		fmt.Fprintf(&b, "    %*s %s   idle-gap re-dials, all recovered (per-event log at debug)\n",
			w, "Idle retries:", fmtInt(snap.DoQIdleRetries))
		b.WriteByte('\n')
	}

	// ---- DNSSEC --------------------------------------------------------------
	b.WriteString("DNSSEC\n")
	if !snap.Instance.DNSSECEnabled {
		b.WriteString("    disabled\n\n")
	} else {
		// Validation rate = validated / (validated + failed) — i.e. of SIGNED responses,
		// how many passed. Unsigned is reported separately, NOT in the denominator.
		signed := snap.DnssecValidated + snap.DnssecFailed
		fmt.Fprintf(&b, "    %*s %s\n", w, "Validated:", fmtInt(snap.DnssecValidated))
		fmt.Fprintf(&b, "    %*s %s\n", w, "Failed (bogus):", fmtInt(snap.DnssecFailed))
		fmt.Fprintf(&b, "    %*s %s\n", w, "Unsigned:", fmtInt(snap.DnssecUnsigned))
		if signed > 0 {
			fmt.Fprintf(&b, "    %*s %s    %s of %s signed responses\n", w, "Validation rate:",
				pct(snap.DnssecValidated, signed), fmtInt(snap.DnssecValidated), fmtInt(signed))
		} else {
			fmt.Fprintf(&b, "    %*s %s\n", w, "Validation rate:", "n/a (no signed responses yet)")
		}
		b.WriteByte('\n')
	}

	// ---- FILTERING -----------------------------------------------------------
	b.WriteString("FILTERING\n")
	if snap.BlocklistFilesLoaded > 0 {
		fmt.Fprintf(&b, "    %*s %s file(s) loaded\n", w, "Blocklists:", fmtInt(snap.BlocklistFilesLoaded))
	} else {
		fmt.Fprintf(&b, "    %*s %s\n", w, "Blocklists:", "none loaded")
	}
	fmt.Fprintf(&b, "    %*s %s\n", w, "Blocked (NXDOMAIN):", fmtInt(snap.BlockedQueries))

	return b.String()
}

// fmtInt formats an integer with comma separators.
// onOff renders a bool as "on"/"off" for the Active Modes line.
func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// cacheTypeDesc renders the cache mode plus a short, capability-derived descriptor for the
// stats "Cache → Mode:" line, e.g. `aggressive   neg-cache on, serve-stale ≤1h`. The
// descriptor is built from what the live cache ACTUALLY enabled (negative caching, serve-stale
// window) rather than assumed from the mode name, so it can't drift from real behavior. When
// neither capability is on (light/standard), it notes positive-only caching.
func cacheTypeDesc(info InstanceInfo) string {
	var parts []string
	if info.CacheNegCache {
		parts = append(parts, "neg-cache on")
	}
	if info.CacheServeStaleS > 0 {
		parts = append(parts, "serve-stale ≤"+compactDuration(info.CacheServeStaleS))
	}
	if len(parts) == 0 {
		parts = append(parts, "positive-only, no serve-stale")
	}
	return info.CacheType + "   " + strings.Join(parts, ", ")
}

// compactDuration renders a seconds count as a short human window for the cache mode
// descriptor: "1h", "30m", "90s" (largest whole unit; falls through to the next on remainder).
func compactDuration(secs int) string {
	switch {
	case secs%3600 == 0:
		return fmt.Sprintf("%dh", secs/3600)
	case secs%60 == 0:
		return fmt.Sprintf("%dm", secs/60)
	default:
		return fmt.Sprintf("%ds", secs)
	}
}

func fmtInt(n int64) string {
	if n < 0 {
		return "-" + fmtInt(-n)
	}
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}

	var result strings.Builder
	remainder := len(s) % 3
	if remainder > 0 {
		result.WriteString(s[:remainder])
	}
	for i := remainder; i < len(s); i += 3 {
		if result.Len() > 0 {
			result.WriteByte(',')
		}
		result.WriteString(s[i : i+3])
	}
	return result.String()
}

// formatDuration formats a duration as "Xd Yh Zm Ws", dropping leading zero
// units: "Yh Zm Ws" / "Zm Ws" / "Ws".
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	days := int(d / (24 * time.Hour))
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, h, m, s)
	}
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// formatLatency formats microseconds as human-readable latency.
func formatLatency(us int64) string {
	if us >= 1000000 {
		return fmt.Sprintf("%.1fs", float64(us)/1000000)
	}
	if us >= 1000 {
		return fmt.Sprintf("%dms", us/1000)
	}
	return fmt.Sprintf("%dµs", us)
}
