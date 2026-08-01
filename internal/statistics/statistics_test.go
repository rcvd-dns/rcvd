// SPDX-License-Identifier: MIT
package statistics

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("expected non-nil Stats")
	}
	// startTime should be set and within the last second (monotonic clock)
	if s.startTime.IsZero() {
		t.Error("expected startTime to be set")
	}
	if time.Since(s.startTime) > time.Second {
		t.Errorf("startTime too old: %v ago", time.Since(s.startTime))
	}
}

func TestAtomicCounters(t *testing.T) {
	s := New()

	atomic.AddInt64(&s.TotalQueries, 1)
	atomic.AddInt64(&s.TotalQueries, 1)
	atomic.AddInt64(&s.CacheHits, 5)
	atomic.AddInt64(&s.BlockedQueries, 3)
	atomic.AddInt64(&s.ServfailResponses, 2)

	if got := atomic.LoadInt64(&s.TotalQueries); got != 2 {
		t.Errorf("TotalQueries: expected 2, got %d", got)
	}
	if got := atomic.LoadInt64(&s.CacheHits); got != 5 {
		t.Errorf("CacheHits: expected 5, got %d", got)
	}
	if got := atomic.LoadInt64(&s.BlockedQueries); got != 3 {
		t.Errorf("BlockedQueries: expected 3, got %d", got)
	}
	if got := atomic.LoadInt64(&s.ServfailResponses); got != 2 {
		t.Errorf("ServfailResponses: expected 2, got %d", got)
	}
}

func TestRecordLatency(t *testing.T) {
	s := New()

	s.RecordLatency(100)
	s.RecordLatency(200)
	s.RecordLatency(50)

	if got := atomic.LoadInt64(&s.LatencyMinUs); got != 50 {
		t.Errorf("LatencyMinUs: expected 50, got %d", got)
	}
	if got := atomic.LoadInt64(&s.LatencyMaxUs); got != 200 {
		t.Errorf("LatencyMaxUs: expected 200, got %d", got)
	}
	if got := atomic.LoadInt64(&s.LatencyCount); got != 3 {
		t.Errorf("LatencyCount: expected 3, got %d", got)
	}
	if got := atomic.LoadInt64(&s.LatencyTotalUs); got != 350 {
		t.Errorf("LatencyTotalUs: expected 350, got %d", got)
	}
}

func TestRecordLatencySingleValue(t *testing.T) {
	s := New()
	s.RecordLatency(42)

	if got := atomic.LoadInt64(&s.LatencyMinUs); got != 42 {
		t.Errorf("LatencyMinUs: expected 42, got %d", got)
	}
	if got := atomic.LoadInt64(&s.LatencyMaxUs); got != 42 {
		t.Errorf("LatencyMaxUs: expected 42, got %d", got)
	}
}

func TestRecordMode2Latency(t *testing.T) {
	s := New()

	s.RecordMode2Latency(10)
	s.RecordMode2Latency(90)
	s.RecordMode2Latency(30)

	if got := atomic.LoadInt64(&s.Mode2LatencyMinUs); got != 10 {
		t.Errorf("Mode2LatencyMinUs: expected 10, got %d", got)
	}
	if got := atomic.LoadInt64(&s.Mode2LatencyMaxUs); got != 90 {
		t.Errorf("Mode2LatencyMaxUs: expected 90, got %d", got)
	}
	if got := atomic.LoadInt64(&s.Mode2LatencyCount); got != 3 {
		t.Errorf("Mode2LatencyCount: expected 3, got %d", got)
	}
	if got := atomic.LoadInt64(&s.Mode2LatencyTotalUs); got != 130 {
		t.Errorf("Mode2LatencyTotalUs: expected 130, got %d", got)
	}
}

// The Mode-1 upstream-fetch timer and the Mode-2 client-facing timer must NOT bleed into
// each other — that separation is the whole reason the Mode-2 timer was added (the old
// code showed the Mode-1 upstream-fetch number under the Mode-2 client-facing header).
func TestLatencyTimersAreIndependent(t *testing.T) {
	s := New()

	s.RecordLatency(5000)      // Mode-1 upstream fetch (a slow WAN miss)
	s.RecordMode2Latency(3)    // Mode-2 client-facing (a fast cache hit)

	snap := s.TakeSnapshot(0, 0, InstanceInfo{})
	if snap.LatencyAvgUs != 5000 {
		t.Errorf("Mode-1 LatencyAvgUs: expected 5000, got %d", snap.LatencyAvgUs)
	}
	if snap.Mode2LatencyAvgUs != 3 {
		t.Errorf("Mode-2 Mode2LatencyAvgUs: expected 3, got %d", snap.Mode2LatencyAvgUs)
	}
	if snap.LatencyCount != 1 || snap.Mode2LatencyCount != 1 {
		t.Errorf("counts crossed: mode1=%d mode2=%d (want 1/1)", snap.LatencyCount, snap.Mode2LatencyCount)
	}
}

func TestTakeSnapshot(t *testing.T) {
	s := New()

	atomic.AddInt64(&s.TotalQueries, 100)
	atomic.AddInt64(&s.CacheHits, 60)
	atomic.AddInt64(&s.CacheMisses, 40)
	atomic.AddInt64(&s.DnssecValidated, 30)
	s.RecordLatency(1000)
	s.RecordLatency(2000)

	snap := s.TakeSnapshot(500, 4096, InstanceInfo{})

	if snap.TotalQueries != 100 {
		t.Errorf("TotalQueries: expected 100, got %d", snap.TotalQueries)
	}
	if snap.CacheHits != 60 {
		t.Errorf("CacheHits: expected 60, got %d", snap.CacheHits)
	}
	if snap.LatencyAvgUs != 1500 {
		t.Errorf("LatencyAvgUs: expected 1500, got %d", snap.LatencyAvgUs)
	}
	if snap.LatencyMinUs != 1000 {
		t.Errorf("LatencyMinUs: expected 1000, got %d", snap.LatencyMinUs)
	}
	if snap.LatencyMaxUs != 2000 {
		t.Errorf("LatencyMaxUs: expected 2000, got %d", snap.LatencyMaxUs)
	}
	if snap.CacheSize != 500 {
		t.Errorf("CacheSize: expected 500, got %d", snap.CacheSize)
	}
	if snap.CacheMaxSize != 4096 {
		t.Errorf("CacheMaxSize: expected 4096, got %d", snap.CacheMaxSize)
	}
	if snap.DnssecValidated != 30 {
		t.Errorf("DnssecValidated: expected 30, got %d", snap.DnssecValidated)
	}
}

func TestRender(t *testing.T) {
	s := New()
	atomic.AddInt64(&s.TotalQueries, 14832)
	atomic.AddInt64(&s.CacheHits, 9441)
	atomic.AddInt64(&s.CacheMisses, 5391)
	atomic.AddInt64(&s.BlockedQueries, 584)
	atomic.AddInt64(&s.SuccessResponses, 14201)
	atomic.AddInt64(&s.ServfailResponses, 47)

	// Mode 1 enabled, Mode 2 not — the typical forwarder deployment.
	snap := s.TakeSnapshot(1247, 4096, InstanceInfo{Mode1Enabled: true})
	output := snap.Render("0.1.0-dev")

	// Check key sections exist (template layout — statistics.gotmpl)
	for _, section := range []string{
		"RCVD Statistics",
		"SERVICE HEALTH",
		"QUERIES",
		"Cache:",
		"MODE-1 - FORWARDER",
		"DNSSEC",
		"FILTERING",
	} {
		if !strings.Contains(output, section) {
			t.Errorf("missing section: %q", section)
		}
	}
	// Mode 2 is NOT enabled → its section must NOT appear.
	if strings.Contains(output, "MODE-2 SERVER") {
		t.Error("MODE-2 SERVER section should not render when Mode 2 is disabled")
	}

	// Check formatted numbers
	if !strings.Contains(output, "14,832") {
		t.Error("expected comma-formatted TotalQueries '14,832'")
	}
	if !strings.Contains(output, "9,441") {
		t.Error("expected comma-formatted CacheHits '9,441'")
	}
	if !strings.Contains(output, "1,247 / 4,096") {
		t.Error("expected cache size '1,247 / 4,096'")
	}
	if !strings.Contains(output, "0.1.0-dev") {
		t.Error("expected version in output")
	}
}

func TestRenderHitRate(t *testing.T) {
	s := New()
	atomic.AddInt64(&s.CacheHits, 2)
	atomic.AddInt64(&s.CacheMisses, 1)

	snap := s.TakeSnapshot(0, 0, InstanceInfo{})
	output := snap.Render("")

	if !strings.Contains(output, "66.7%") {
		t.Errorf("expected hit rate 66.7%%, got output:\n%s", output)
	}
}

// TestRenderModeSectionsConditionalAndOrdered verifies a mode's section appears ONLY when
// that mode is enabled, and that when both are on, MODE-1 renders before MODE-2 (fixed order,
// so a Mode-1-only operator's view never shifts when Mode 2 is added later).
func TestRenderModeSectionsConditionalAndOrdered(t *testing.T) {
	render := func(m1, m2 bool) string {
		s := New()
		snap := s.TakeSnapshot(0, 4096, InstanceInfo{Mode1Enabled: m1, Mode2Enabled: m2})
		return snap.Render("test")
	}

	// Mode-1 only: forwarder yes, server no.
	o := render(true, false)
	if !strings.Contains(o, "MODE-1 - FORWARDER") || strings.Contains(o, "MODE-2 SERVER") {
		t.Errorf("mode-1-only: want forwarder, not server:\n%s", o)
	}

	// Mode-2 only: server yes, forwarder no.
	o = render(false, true)
	if strings.Contains(o, "MODE-1 - FORWARDER") || !strings.Contains(o, "MODE-2 SERVER") {
		t.Errorf("mode-2-only: want server, not forwarder:\n%s", o)
	}

	// Both: MODE-1 must appear BEFORE MODE-2.
	o = render(true, true)
	i1 := strings.Index(o, "MODE-1 - FORWARDER")
	i2 := strings.Index(o, "MODE-2 SERVER")
	if i1 < 0 || i2 < 0 {
		t.Fatalf("dual-mode: both sections must render:\n%s", o)
	}
	if i1 > i2 {
		t.Errorf("dual-mode: MODE-1 must render before MODE-2 (got M1@%d, M2@%d)", i1, i2)
	}
}

func TestFmtInt(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1,000"},
		{1234567, "1,234,567"},
		{-1234, "-1,234"},
	}
	for _, tt := range tests {
		got := fmtInt(tt.in)
		if got != tt.want {
			t.Errorf("fmtInt(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestConcurrentIncrements(t *testing.T) {
	s := New()
	var wg sync.WaitGroup
	n := 1000

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			atomic.AddInt64(&s.TotalQueries, 1)
			s.RecordLatency(100)
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&s.TotalQueries); got != int64(n) {
		t.Errorf("TotalQueries: expected %d, got %d", n, got)
	}
	if got := atomic.LoadInt64(&s.LatencyCount); got != int64(n) {
		t.Errorf("LatencyCount: expected %d, got %d", n, got)
	}
}

func TestSocketPath(t *testing.T) {
	// SocketPath derives the socket NAME from the config filename; the DIRECTORY
	// depends on the runtime environment, in precedence order:
	//   1. /run/rcvd/<name>.sock       — if /run/rcvd exists (system daemon)
	//   2. $XDG_RUNTIME_DIR/rcvd/<name>.sock — dev/workstation
	//   3. /tmp/rcvd-<name>.sock       — last resort (neither of the above)
	// The filename is invariant across all three, so assert on that unconditionally.
	// (A minimal CI container has no /run/rcvd and no XDG_RUNTIME_DIR, so it lands
	// on tier 3 — the earlier test wrongly assumed a "/rcvd/" dir segment always exists.)
	// The socket NAME ends the path in every tier — joined as a directory in tiers
	// 1/2 (".../rcvd/rcvd.sock") or prefixed in tier 3 ("/tmp/rcvd-rcvd.sock") — so
	// HasSuffix on the name is the tier-invariant check (Base() is NOT: tier 3's
	// "rcvd-" prefix makes Base() == "rcvd-rcvd.sock").
	for _, tc := range []struct {
		configPath string
		wantName   string
	}{
		{"/etc/rcvd/rcvd.toml", "rcvd.sock"},
		{"/etc/rcvd/rcvd-upstream.toml", "rcvd-upstream.sock"},
	} {
		got := SocketPath(tc.configPath)
		if !strings.HasSuffix(got, tc.wantName) {
			t.Errorf("SocketPath(%q): expected path ending in %q, got %q", tc.configPath, tc.wantName, got)
		}
	}

	// Pin the XDG branch (tier 2) deterministically to prove the directory logic,
	// independent of the ambient environment. Skip only if /run/rcvd exists on this
	// machine, since tier 1 legitimately takes precedence over the XDG override.
	if info, err := os.Stat("/run/rcvd"); err == nil && info.IsDir() {
		t.Skip("skipping XDG-branch assertion: /run/rcvd exists (tier 1 takes precedence)")
	}
	xdg := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	got := SocketPath("/etc/rcvd/rcvd.toml")
	want := filepath.Join(xdg, "rcvd", "rcvd.sock")
	if got != want {
		t.Errorf("SocketPath XDG branch: expected %q, got %q", want, got)
	}
}

// TestRecordResponseBuckets verifies RecordResponse routes each rcode to exactly
// one bucket (Issue 27 — response accounting decoupled from cacheability).
func TestRecordResponseBuckets(t *testing.T) {
	s := New()
	s.RecordResponse(0) // NOERROR  → Success
	s.RecordResponse(0)
	s.RecordResponse(3) // NXDOMAIN → Nxdomain
	s.RecordResponse(2) // SERVFAIL → Servfail
	s.RecordResponse(5) // REFUSED  → Other
	s.RecordResponse(4) // NOTIMP   → Other

	if got := atomic.LoadInt64(&s.SuccessResponses); got != 2 {
		t.Errorf("SuccessResponses: expected 2, got %d", got)
	}
	if got := atomic.LoadInt64(&s.NxdomainResponses); got != 1 {
		t.Errorf("NxdomainResponses: expected 1, got %d", got)
	}
	if got := atomic.LoadInt64(&s.ServfailResponses); got != 1 {
		t.Errorf("ServfailResponses: expected 1, got %d", got)
	}
	if got := atomic.LoadInt64(&s.OtherResponses); got != 2 {
		t.Errorf("OtherResponses: expected 2, got %d", got)
	}
}

// TestResponseCounterConservation is the counter-conservation guarantee from
// Issue 27: when one response bucket is recorded per query handled, the four
// buckets must sum to exactly TotalQueries (no silent unbucketed remainder).
func TestResponseCounterConservation(t *testing.T) {
	s := New()
	// Simulate a realistic mix: every handled query gets TotalQueries++ at ingress
	// and exactly one RecordResponse at its send point.
	rcodes := []int{0, 0, 0, 3, 0, 2, 5, 0, 3, 0} // 6 NOERROR, 2 NXDOMAIN, 1 SERVFAIL, 1 Other
	for _, rc := range rcodes {
		atomic.AddInt64(&s.TotalQueries, 1)
		s.RecordResponse(rc)
	}

	total := atomic.LoadInt64(&s.TotalQueries)
	sum := atomic.LoadInt64(&s.SuccessResponses) +
		atomic.LoadInt64(&s.ServfailResponses) +
		atomic.LoadInt64(&s.NxdomainResponses) +
		atomic.LoadInt64(&s.OtherResponses)
	if sum != total {
		t.Errorf("counter conservation violated: buckets sum=%d, TotalQueries=%d", sum, total)
	}
	if total != int64(len(rcodes)) {
		t.Errorf("TotalQueries: expected %d, got %d", len(rcodes), total)
	}
}

// TestRenderConnectionsLivePerUpstreamHealth verifies the MODE-1 FORWARDER
// "Connections" block renders live per-upstream health when present (Issue 23),
// and shows the placeholder when no fallback chain is wired.
func TestRenderConnectionsLivePerUpstreamHealth(t *testing.T) {
	s := New()

	// No Connections injected → placeholder retained.
	placeholderSnap := s.TakeSnapshot(0, 0, InstanceInfo{Mode1Enabled: true})
	placeholder := placeholderSnap.Render("v")
	if !strings.Contains(placeholder, "per-upstream health pending") {
		t.Error("expected placeholder when no Connections data is present")
	}

	// Connections injected → live render with state + consecutive errors + last error.
	snap := s.TakeSnapshot(0, 0, InstanceInfo{Mode1Enabled: true})
	snap.Connections = []UpstreamConnInfo{
		{Name: "Quad9 (DoQ)", State: "UP"},
		{Name: "Cloudflare (DoT)", State: "DOWN", ConsecutiveErrors: 4, LastError: "DoT dial: i/o timeout"},
	}
	out := snap.Render("v")

	if strings.Contains(out, "per-upstream health pending") {
		t.Error("placeholder should be replaced by live data")
	}
	for _, want := range []string{
		"Quad9 (DoQ)", "UP",
		"Cloudflare (DoT)", "DOWN",
		"4 consecutive err",
		"last error: DoT dial: i/o timeout",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Connections render missing %q\n--- output ---\n%s", want, out)
		}
	}
}
