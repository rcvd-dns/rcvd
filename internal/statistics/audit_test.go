// SPDX-License-Identifier: MIT
package statistics

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderAudit_Mode1Loopback(t *testing.T) {
	a := AuditInfo{
		ConfigPath:    "/etc/rcvd/rcvd.toml",
		SocketPath:    "/run/rcvd/rcvd.sock",
		Mode1Enabled:  true,
		Mode1Listen:   "127.0.0.1:5354",
		Mode1Loopback: true,
		CacheEnabled:  true,
		CacheType:     "standard",
	}
	// Live view: Mode-1 UDP+TCP actually bound.
	live := LiveAudit{Mode1BoundUDP: "127.0.0.1:5354", Mode1BoundTCP: "127.0.0.1:5354", CacheSize: 12, CacheMaxSize: 4096}
	out := a.RenderAudit("0.1.0-dev", 3*time.Minute, live)

	wantContains := []string{
		"RCVD Audit — configured posture + live runtime",
		"127.0.0.1:5354",
		"loopback-only",
		"(bound)", // live bind verdict
		"MODE-2  (disabled)",
		"Port 53 binding:",
		"Cleartext fallback:",
		"loopback only", // inbound plaintext verdict
		"CACHE POSTURE",
		"Type:",
		"standard",
		"Entries:", // live cache occupancy
	}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("audit output missing %q.\n--- output ---\n%s", w, out)
		}
	}
	// No decorative glyphs anywhere in the output.
	if strings.ContainsAny(out, "✓✗") {
		t.Errorf("audit output should contain no ✓/✗ glyphs.\n%s", out)
	}
	// A loopback Mode-1 instance must never render the non-loopback exposure note.
	if strings.Contains(out, "NON-loopback") {
		t.Errorf("loopback Mode-1 should not show a NON-loopback note.\n%s", out)
	}
}

func TestRenderAudit_Mode1NonLoopbackFlagged(t *testing.T) {
	// The warned 0.0.0.0:5300 router case: a non-loopback plaintext listener. config.Validate
	// only rejects this for port 53, so 0.0.0.0:5300 is allowed — but audit must flag it so the
	// operator sees the plaintext exposure rather than a false "loopback-only".
	a := AuditInfo{
		Mode1Enabled:  true,
		Mode1Listen:   "0.0.0.0:5300",
		Mode1Loopback: false,
		CacheEnabled:  true,
		CacheType:     "standard",
	}
	out := a.RenderAudit("v", time.Second, LiveAudit{})

	// A non-loopback listener must be flagged as exposed, in words (no glyphs).
	if !strings.Contains(out, "NON-loopback") {
		t.Errorf("non-loopback Mode-1 should be flagged as NON-loopback.\n%s", out)
	}
	if !strings.Contains(out, "exposed") {
		t.Errorf("non-loopback inbound-plaintext verdict should note it is exposed.\n%s", out)
	}
	if strings.ContainsAny(out, "✓✗") {
		t.Errorf("audit output should contain no ✓/✗ glyphs.\n%s", out)
	}
}

func TestRenderAudit_Mode2EndpointsTLSOnly(t *testing.T) {
	a := AuditInfo{
		Mode2Enabled:   true,
		Mode2ListenDoH: "0.0.0.0:8443",
		Mode2DoH3:      true,
		Mode2ListenDoT: "0.0.0.0:853",
		Mode2ListenDoQ: "0.0.0.0:853",
		CacheEnabled:   true,
		CacheType:      "standard",
	}
	// All three Mode-2 endpoints live-bound.
	live := LiveAudit{Mode2BoundDoH: "0.0.0.0:8443", Mode2BoundDoT: "0.0.0.0:853", Mode2BoundDoQ: "0.0.0.0:853"}
	out := a.RenderAudit("v", time.Second, live)

	wantContains := []string{
		"0.0.0.0:8443",
		"DoH (HTTP/2 + HTTP/3)",
		"0.0.0.0:853",
		"DoT",
		"DoQ",
		"all MODE-2 endpoints TLS-only",
		"MODE-1  (disabled)",
	}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("Mode-2 audit output missing %q.\n--- output ---\n%s", w, out)
		}
	}
	// Each Mode-2 endpoint must be marked TLS-only and live-bound (no glyphs).
	if strings.Count(out, "TLS-only, bound") < 3 {
		t.Errorf("expected each Mode-2 endpoint TLS-only and bound (>=3).\n%s", out)
	}
	if strings.ContainsAny(out, "✓✗") {
		t.Errorf("audit output should contain no ✓/✗ glyphs.\n%s", out)
	}
}

func TestRenderAudit_AggressiveCachePosture(t *testing.T) {
	a := AuditInfo{
		Mode1Enabled:   true,
		Mode1Listen:    "127.0.0.1:5354",
		Mode1Loopback:  true,
		CacheEnabled:   true,
		CacheType:      "aggressive",
		CacheNegCache:  true,
		CacheNegTTLMax: 300,
		CacheStaleS:    3600,
	}
	out := a.RenderAudit("v", time.Second, LiveAudit{})

	wantContains := []string{
		"aggressive",
		"Negative caching:",
		"NXDOMAIN/NODATA ≤ 5m", // compactDuration(300) == "5m" (300s is a whole minute)
		"Serve-stale:",
		"≤ 1h past expiry", // compactDuration(3600) == "1h"
		"never cleartext",
	}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("aggressive cache audit missing %q.\n--- output ---\n%s", w, out)
		}
	}
}

func TestRenderAudit_StandardCacheOptInsOff(t *testing.T) {
	a := AuditInfo{
		Mode1Enabled:  true,
		Mode1Listen:   "127.0.0.1:5354",
		Mode1Loopback: true,
		CacheEnabled:  true,
		CacheType:     "standard",
	}
	out := a.RenderAudit("v", time.Second, LiveAudit{})

	if !strings.Contains(out, "Negative caching:        off") && !strings.Contains(out, "Negative caching:") {
		t.Fatalf("standard cache should show a Negative caching line.\n%s", out)
	}
	// Both opt-ins must read off; serve-stale on/off lines must not advertise a window.
	if strings.Contains(out, "serve-stale ≤") || strings.Contains(out, "past expiry") {
		t.Errorf("standard cache must not show a serve-stale window.\n%s", out)
	}
	// Find the two lines and assert "off".
	for _, label := range []string{"Negative caching:", "Serve-stale:"} {
		line := lineWith(out, label)
		if !strings.Contains(line, "off") {
			t.Errorf("expected %q to be off in standard mode, got: %q", label, line)
		}
	}
}

func TestRenderAudit_CacheDisabled(t *testing.T) {
	a := AuditInfo{
		Mode1Enabled:  true,
		Mode1Listen:   "127.0.0.1:5354",
		Mode1Loopback: true,
		CacheEnabled:  false,
	}
	out := a.RenderAudit("v", time.Second, LiveAudit{})
	line := lineWith(out, "Type:")
	if !strings.Contains(line, "disabled") {
		t.Errorf("cache-disabled audit should report Mode: disabled, got: %q", line)
	}
}

// TestSocketVerbSwitch exercises the real Unix socket: an AUDIT request returns posture,
// while the legacy no-write path (QueryStats sends nothing → EOF) returns statistics. This
// guards the backward-compatibility contract for older --stats clients.
func TestSocketVerbSwitch(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "rcvd-test.sock")
	stats := New()
	info := InstanceInfo{Mode1Enabled: true}
	audit := AuditInfo{
		Mode1Enabled:  true,
		Mode1Listen:   "127.0.0.1:5354",
		Mode1Loopback: true,
		CacheEnabled:  true,
		CacheType:     "standard",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = ListenAndServe(ctx, socketPath, stats, "v", nil, nil, nil, info, audit, nil, nil)
	}()

	// Wait for the socket to come up.
	waitForSocket(t, socketPath)

	auditOut, err := QueryAudit(socketPath)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	if !strings.Contains(auditOut, "RCVD Audit — configured posture + live runtime") {
		t.Errorf("AUDIT request did not return the audit report.\n%s", auditOut)
	}

	statsOut, err := QueryStats(socketPath)
	if err != nil {
		t.Fatalf("QueryStats: %v", err)
	}
	if !strings.Contains(statsOut, "RCVD Statistics") {
		t.Errorf("legacy (no-write/EOF) request did not return statistics.\n%s", statsOut)
	}
	// Ensure the verb actually discriminated — audit output must not be stats and vice versa.
	if strings.Contains(statsOut, "RCVD Audit") {
		t.Errorf("stats path leaked audit content:\n%s", statsOut)
	}
	if strings.Contains(auditOut, "RCVD Statistics") {
		t.Errorf("audit path leaked stats content:\n%s", auditOut)
	}
}

// TestSocketReloadVerb covers the reload verb: with a reload func wired it fires
// the callback and acknowledges with the file count; with a nil func it reports
// the feature unavailable. It also confirms the ack returns without waiting on
// the reload work (fire-and-forget).
func TestSocketReloadVerb(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "rcvd-test.sock")
	stats := New()
	info := InstanceInfo{Mode1Enabled: true}
	audit := AuditInfo{Mode1Enabled: true}

	fired := make(chan struct{}, 1)
	reload := func() int {
		fired <- struct{}{}
		return 2
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = ListenAndServe(ctx, socketPath, stats, "v", nil, nil, nil, info, audit, reload, nil)
	}()
	waitForSocket(t, socketPath)

	out, err := QueryReload(socketPath)
	if err != nil {
		t.Fatalf("QueryReload: %v", err)
	}
	if !strings.Contains(out, "reload started") || !strings.Contains(out, "2 file(s)") {
		t.Errorf("unexpected reload ack: %q", out)
	}
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Error("reload callback was not invoked")
	}
}

func TestSocketReloadUnavailable(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "rcvd-test.sock")
	stats := New()
	info := InstanceInfo{Mode1Enabled: true}
	audit := AuditInfo{Mode1Enabled: true}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// nil reload => feature not wired (blocklists disabled).
		_ = ListenAndServe(ctx, socketPath, stats, "v", nil, nil, nil, info, audit, nil, nil)
	}()
	waitForSocket(t, socketPath)

	out, err := QueryReload(socketPath)
	if err != nil {
		t.Fatalf("QueryReload: %v", err)
	}
	if !strings.Contains(out, "unavailable") {
		t.Errorf("expected unavailable message, got %q", out)
	}
}

// lineWith returns the first line of s containing substr, or "".
func lineWith(s, substr string) string {
	for _, ln := range strings.Split(s, "\n") {
		if strings.Contains(ln, substr) {
			return ln
		}
	}
	return ""
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if _, err := QueryStats(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("socket %s did not come up", path)
}

// TestSocketAllowlistReloadSuccess exercises the synchronous allowlist reload
// path: with a wired callback the server replies with the exact success line
// the CLI prints verbatim, and the callback ran to completion (not fire-and-forget).
func TestSocketAllowlistReloadSuccess(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "rcvd-test.sock")
	stats := New()
	info := InstanceInfo{Mode1Enabled: true}
	audit := AuditInfo{Mode1Enabled: true}

	var fired int
	reload := func() (string, error) {
		fired++
		return "allowlist reloaded: 7 entries from 2 file(s)", nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = ListenAndServe(ctx, socketPath, stats, "v", nil, nil, nil, info, audit, nil, reload)
	}()
	waitForSocket(t, socketPath)

	out, err := QueryAllowlistReload(socketPath)
	if err != nil {
		t.Fatalf("QueryAllowlistReload: %v", err)
	}
	if !strings.HasPrefix(out, "allowlist reloaded:") {
		t.Errorf("expected success line, got %q", out)
	}
	if !strings.Contains(out, "7 entries") || !strings.Contains(out, "2 file(s)") {
		t.Errorf("success line missing counts, got %q", out)
	}
	if fired != 1 {
		t.Errorf("reload callback fired %d times, want 1", fired)
	}
}

// TestSocketAllowlistReloadFailure covers the fail-closed path: a callback that
// returns an error is rendered as the failure line (the CLI parses this prefix
// to choose exit code 1). The error string IS the socket reply, so the operator
// sees the failing file:line in one line.
func TestSocketAllowlistReloadFailure(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "rcvd-test.sock")
	stats := New()
	info := InstanceInfo{Mode1Enabled: true}
	audit := AuditInfo{Mode1Enabled: true}

	reload := func() (string, error) {
		return "", errors.New("allowlist reload FAILED, previous list still active: /etc/rcvd/allow.txt:4: entry \"-bad-.com\" has an invalid label")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = ListenAndServe(ctx, socketPath, stats, "v", nil, nil, nil, info, audit, nil, reload)
	}()
	waitForSocket(t, socketPath)

	out, err := QueryAllowlistReload(socketPath)
	if err != nil {
		t.Fatalf("QueryAllowlistReload: %v", err)
	}
	if !strings.HasPrefix(out, "allowlist reload FAILED") {
		t.Errorf("expected FAILED prefix, got %q", out)
	}
	// The reply must name the failing file:line so the operator can locate the edit.
	if !strings.Contains(out, "/etc/rcvd/allow.txt:4") {
		t.Errorf("failure line must name file:line, got %q", out)
	}
}

// TestSocketAllowlistReloadUnavailable exercises the off switch: a nil
// callback (no allowlist configured) yields the "unavailable" reply so the CLI
// can exit 1 without ever touching the live set.
func TestSocketAllowlistReloadUnavailable(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "rcvd-test.sock")
	stats := New()
	info := InstanceInfo{Mode1Enabled: true}
	audit := AuditInfo{Mode1Enabled: true}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = ListenAndServe(ctx, socketPath, stats, "v", nil, nil, nil, info, audit, nil, nil)
	}()
	waitForSocket(t, socketPath)

	out, err := QueryAllowlistReload(socketPath)
	if err != nil {
		t.Fatalf("QueryAllowlistReload: %v", err)
	}
	if !strings.Contains(out, "unavailable") {
		t.Errorf("expected unavailable message, got %q", out)
	}
	if !strings.Contains(out, "not enabled") {
		t.Errorf("expected unavailable reason (not enabled), got %q", out)
	}
}
