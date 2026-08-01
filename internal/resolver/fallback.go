// SPDX-License-Identifier: MIT
package resolver

import (
	"context"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/rcvd-dns/rcvd/internal/statistics"
)

// ErrAllUpstreamsFailed is returned by Resolve when every upstream in the chain
// failed. It is a real error (not a nil-error SERVFAIL) so callers — notably the
// Mode-1 server — drive their existing fail-closed / serve-stale path off it,
// identically to a single-resolver failure. NEVER cleartext on this path.
var ErrAllUpstreamsFailed = errors.New("all upstreams failed")

// errResponseMismatch is the per-upstream error recorded when a response's Question
// section does not match the query we sent (or the query itself does not carry exactly
// one question). An upstream that answers a DIFFERENT question than it was asked is
// broken or hostile: re-keying its answer onto the client's question would hand the
// client a foreign answer AND poison the shared cache under the asked name (audit
// 2026-07-16 H1). Treated as an upstream failure so the chain falls back — resilience
// first, fail-closed (ErrAllUpstreamsFailed) only if every upstream misbehaves.
var errResponseMismatch = errors.New("upstream response question does not match query")

// responseMatchesQuery reports whether resp answers exactly the question in query:
// one Question section entry on each side, equal QTYPE and QCLASS, and an equal QNAME
// compared case-insensitively (dns.CanonicalName — DNS names are case-insensitive,
// RFC 4343; an upstream may legitimately echo the name in different case).
func responseMatchesQuery(query, resp *dns.Msg) bool {
	if len(query.Question) != 1 || len(resp.Question) != 1 {
		return false
	}
	q, r := query.Question[0], resp.Question[0]
	return q.Qtype == r.Qtype &&
		q.Qclass == r.Qclass &&
		dns.CanonicalName(q.Name) == dns.CanonicalName(r.Name)
}

// State represents the health state of an upstream resolver
type State int

const (
	StateUP   State = iota // Upstream is responding normally
	StateSLOW             // Upstream is slow (above threshold)
	StateDOWN             // Upstream is down (failed health check)
)

// UpstreamState tracks health metrics for a single upstream
type UpstreamState struct {
	Name              string
	Resolver          Resolver // DoQ, DoT, DoH, or fallback chain
	State             State
	LastError         string
	ConsecutiveErrors int
	LastHealthCheck   time.Time
}

// FallbackResolver implements RFC 9250-inspired protocol fallback with a two-phase health model.
// Phase 1 (startup, 5 minutes): Aggressive — 2s timeout marks upstream as DOWN
// Phase 2 (runtime): Gentle — single failure = SLOW, N consecutive = DOWN
//
// Protocol priority: DoQ → DoT → DoH (tries in order, falls back on error)
// Returns SERVFAIL if all upstreams/protocols fail (never cleartext).
type FallbackResolver struct {
	upstreams []*UpstreamState
	logger    *log.Logger
	stats     *statistics.Stats // may be nil; only UpstreamFallbacks is bumped here

	// Phase tracking
	startTime      time.Time
	phase1DurationS int

	// Health check settings
	healthCheckIntervalS int
	phase2FailureThreshold int

	// Synchronization
	mu sync.RWMutex

	// Health check ticker
	healthTicker *time.Ticker
	stopChan    chan struct{}
}

// NewFallbackResolver creates a resolver with fallback across multiple upstreams.
// Each UpstreamState wraps one per-protocol resolver; the chain is tried in order
// (DoQ → DoT → DoH within an upstream, then the next upstream). stats may be nil;
// when set, UpstreamFallbacks is incremented each time a query succeeds only after
// the primary (first chain entry) failed.
func NewFallbackResolver(upstreams []*UpstreamState, logger *log.Logger, stats *statistics.Stats, phase1DurationS, phase2FailureThreshold, healthCheckIntervalS int) *FallbackResolver {
	if len(upstreams) == 0 {
		logger.Println("WARNING: no upstreams provided to fallback resolver")
	}

	return &FallbackResolver{
		upstreams:              upstreams,
		logger:                 logger,
		stats:                  stats,
		startTime:              time.Now(),
		phase1DurationS:        phase1DurationS,
		phase2FailureThreshold: phase2FailureThreshold,
		healthCheckIntervalS:   healthCheckIntervalS,
		stopChan:              make(chan struct{}),
	}
}

// Start begins the health check ticker in background
func (f *FallbackResolver) Start() {
	f.mu.Lock()
	f.healthTicker = time.NewTicker(time.Duration(f.healthCheckIntervalS) * time.Second)
	f.mu.Unlock()

	go f.runHealthChecks()
}

// Resolve tries to resolve a query using available upstreams with fallback.
// Chain order: as built (DoQ → DoT → DoH within an upstream, then next upstream).
// Returns ErrAllUpstreamsFailed if every upstream/protocol fails — the caller
// owns the fail-closed response (SERVFAIL or bounded-stale); this resolver never
// synthesizes a cleartext answer and never returns a nil-error SERVFAIL.
func (f *FallbackResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// A well-formed query carries exactly one question. Reject anything else BEFORE
	// the upstream loop (audit M3): a degenerate message must never be forwarded, and
	// — critically — must never record an error against a healthy upstream (a client
	// spamming QDCOUNT=0 queries could otherwise drive the whole chain DOWN). The
	// ingress listeners answer FORMERR before this is ever reached; this is the backstop.
	if len(msg.Question) != 1 {
		return nil, errResponseMismatch
	}

	f.mu.RLock()
	upstreams := f.upstreams
	phase := f.getCurrentPhase()
	f.mu.RUnlock()

	// triedPrimary becomes true once we have actually ATTEMPTED the first chain
	// entry. A success on any later entry after that is a real failover event.
	triedPrimary := false

	// Try each upstream in order
	for i, upstream := range upstreams {
		// Skip down upstreams (unless this is the only one left to try).
		f.mu.RLock()
		state := upstream.State
		f.mu.RUnlock()

		if state == StateDOWN && len(upstreams) > 1 {
			// Skip this one and try the next
			continue
		}

		// Try to resolve with this upstream
		resp, err := upstream.Resolver.Resolve(ctx, msg)
		if err == nil && resp != nil {
			// H1: never accept an answer for a different question than we asked —
			// callers re-key the response onto the client's query and store it in the
			// shared cache under that key, so a foreign answer would poison the cache
			// for every Mode-1 AND Mode-2 client. A mismatch is an UPSTREAM failure:
			// record it (visible via LastError in --stats/--audit) and try the next one.
			if !responseMatchesQuery(msg, resp) {
				f.recordError(upstream, errResponseMismatch, phase)
				triedPrimary = true
				continue
			}
			// Success — record it. If we only got here after the primary was
			// tried-and-failed (or skipped DOWN), count a fallback event.
			f.recordSuccess(upstream)
			if (triedPrimary || i > 0) && f.stats != nil {
				atomic.AddInt64(&f.stats.UpstreamFallbacks, 1)
			}
			return resp, nil
		}

		// Record the error for this upstream
		f.recordError(upstream, err, phase)
		triedPrimary = true
	}

	// All upstreams failed — return a real error so the caller fails closed.
	// Privacy: log the event only, never the queried name.
	f.logger.Printf("all upstreams failed — returning error to caller (no cleartext)")
	return nil, ErrAllUpstreamsFailed
}

// getCurrentPhase returns current phase based on elapsed time since start
func (f *FallbackResolver) getCurrentPhase() int {
	elapsed := time.Since(f.startTime)
	phase1Duration := time.Duration(f.phase1DurationS) * time.Second
	if elapsed < phase1Duration {
		return 1
	}
	return 2
}

// recordSuccess marks an upstream as UP and resets error counter
func (f *FallbackResolver) recordSuccess(upstream *UpstreamState) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if upstream.State != StateUP {
		f.logger.Printf("upstream %s recovered (UP)", upstream.Name)
	}
	upstream.State = StateUP
	upstream.ConsecutiveErrors = 0
	upstream.LastError = ""
}

// recordError updates upstream state based on error and current phase
func (f *FallbackResolver) recordError(upstream *UpstreamState, err error, phase int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	upstream.ConsecutiveErrors++
	if err != nil {
		upstream.LastError = err.Error()
	}

	if phase == 1 {
		// Phase 1 (startup): aggressive — any error = DOWN
		if upstream.State != StateDOWN {
			f.logger.Printf("upstream %s DOWN (Phase 1 aggressive): %v", upstream.Name, err)
		}
		upstream.State = StateDOWN
	} else {
		// Phase 2 (runtime): gentle — track consecutive failures
		if upstream.ConsecutiveErrors >= f.phase2FailureThreshold {
			if upstream.State != StateDOWN {
				// Include the underlying error (Issue 31): the DoQ client returns distinct
				// strings for an idle-gap read failure vs. a response-question mismatch, and
				// this is the only field-facing place that distinguishes them. Was swallowed
				// on this path — Phase 1 logs %v, Phase 2 did not.
				f.logger.Printf("upstream %s DOWN (Phase 2, %d consecutive errors): %v", upstream.Name, upstream.ConsecutiveErrors, err)
			}
			upstream.State = StateDOWN
		} else if upstream.State != StateSLOW {
			f.logger.Printf("upstream %s SLOW (Phase 2, error %d/%d): %v", upstream.Name, upstream.ConsecutiveErrors, f.phase2FailureThreshold, err)
			upstream.State = StateSLOW
		}
	}
}

// runHealthChecks periodically probes DOWN upstreams to detect recovery
func (f *FallbackResolver) runHealthChecks() {
	for {
		select {
		case <-f.stopChan:
			return
		case <-f.healthTicker.C:
			f.performHealthChecks()
		}
	}
}

// performHealthChecks sends a simple query to DOWN upstreams
func (f *FallbackResolver) performHealthChecks() {
	f.mu.RLock()
	downUpstreams := []*UpstreamState{}
	for _, upstream := range f.upstreams {
		if upstream.State == StateDOWN {
			downUpstreams = append(downUpstreams, upstream)
		}
	}
	f.mu.RUnlock()

	if len(downUpstreams) == 0 {
		return
	}

	// Probe each DOWN upstream with a simple query
	for _, upstream := range downUpstreams {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		testMsg := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id: 0,
				RecursionDesired: true,
			},
		}
		testMsg.Question = []dns.Question{
			{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		}

		resp, err := upstream.Resolver.Resolve(ctx, testMsg)
		cancel()

		if err == nil && resp != nil {
			f.recordSuccess(upstream)
			f.logger.Printf("upstream %s recovered via health check", upstream.Name)
		} else {
			phase := f.getCurrentPhase()
			f.recordError(upstream, err, phase)
		}
	}
}

// UpstreamNames returns upstream names in chain order (DoQ→DoT→DoH per upstream,
// upstreams in config order). GetStatus() returns an unordered map; pair the two to
// render the "Connections" block in priority order.
func (f *FallbackResolver) UpstreamNames() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	names := make([]string, 0, len(f.upstreams))
	for _, u := range f.upstreams {
		names = append(names, u.Name)
	}
	return names
}

// GetStatus returns current status of all upstreams (for monitoring/debugging)
func (f *FallbackResolver) GetStatus() map[string]map[string]interface{} {
	f.mu.RLock()
	defer f.mu.RUnlock()

	status := make(map[string]map[string]interface{})
	for _, upstream := range f.upstreams {
		stateStr := "UP"
		switch upstream.State {
		case StateSLOW:
			stateStr = "SLOW"
		case StateDOWN:
			stateStr = "DOWN"
		}

		status[upstream.Name] = map[string]interface{}{
			"state":              stateStr,
			"consecutive_errors": upstream.ConsecutiveErrors,
			"last_error":         upstream.LastError,
			"last_health_check":  upstream.LastHealthCheck,
		}
	}
	return status
}

// Close stops health checks and closes all resolver connections
func (f *FallbackResolver) Close() error {
	close(f.stopChan)

	f.mu.Lock()
	if f.healthTicker != nil {
		f.healthTicker.Stop()
	}

	for _, upstream := range f.upstreams {
		if upstream.Resolver != nil {
			upstream.Resolver.Close()
		}
	}
	f.mu.Unlock()

	return nil
}
