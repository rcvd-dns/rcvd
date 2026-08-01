// SPDX-License-Identifier: MIT
package resolver

import (
	"context"
	"errors"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"github.com/rcvd-dns/rcvd/internal/statistics"
)

// mockResolver is a configurable Resolver for fallback tests. When failing is set
// it returns an error; otherwise it returns a NOERROR response. When answerName is
// set, the response's Question is rewritten to that name — simulating an upstream
// that answers a DIFFERENT question than asked (audit H1). calls counts how many
// times Resolve was invoked.
type mockResolver struct {
	mu         sync.Mutex
	failing    bool
	answerName string
	calls      int64
}

func (m *mockResolver) setFailing(v bool) {
	m.mu.Lock()
	m.failing = v
	m.mu.Unlock()
}

func (m *mockResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	atomic.AddInt64(&m.calls, 1)
	m.mu.Lock()
	failing := m.failing
	answerName := m.answerName
	m.mu.Unlock()
	if failing {
		return nil, errors.New("mock upstream down")
	}
	resp := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess, Id: msg.Id}}
	resp.Question = msg.Question
	if answerName != "" {
		resp.Question = []dns.Question{{Name: answerName, Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	}
	return resp, nil
}

func (m *mockResolver) Close() error { return nil }

func testQuery() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	return m
}

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// TestFallbackPrimarySucceeds: with a healthy primary, the secondary is never
// called and no fallback event is counted.
func TestFallbackPrimarySucceeds(t *testing.T) {
	primary := &mockResolver{}
	secondary := &mockResolver{}
	stats := statistics.New()
	f := NewFallbackResolver([]*UpstreamState{
		{Name: "primary", Resolver: primary},
		{Name: "secondary", Resolver: secondary},
	}, discardLogger(), stats, 300, 3, 30)

	resp, err := f.Resolve(context.Background(), testQuery())
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", resp.Rcode)
	}
	if atomic.LoadInt64(&secondary.calls) != 0 {
		t.Errorf("secondary should not be called when primary succeeds")
	}
	if got := atomic.LoadInt64(&stats.UpstreamFallbacks); got != 0 {
		t.Errorf("UpstreamFallbacks: expected 0, got %d", got)
	}
}

// TestFallbackFailsOverToSecondary: a failing primary must fail over to the
// secondary, return success, and count exactly one fallback event.
func TestFallbackFailsOverToSecondary(t *testing.T) {
	primary := &mockResolver{failing: true}
	secondary := &mockResolver{}
	stats := statistics.New()
	f := NewFallbackResolver([]*UpstreamState{
		{Name: "primary", Resolver: primary},
		{Name: "secondary", Resolver: secondary},
	}, discardLogger(), stats, 300, 3, 30)

	resp, err := f.Resolve(context.Background(), testQuery())
	if err != nil {
		t.Fatalf("expected fail-over success, got %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR from secondary, got rcode %d", resp.Rcode)
	}
	if atomic.LoadInt64(&secondary.calls) != 1 {
		t.Errorf("secondary should have been called once, got %d", atomic.LoadInt64(&secondary.calls))
	}
	if got := atomic.LoadInt64(&stats.UpstreamFallbacks); got != 1 {
		t.Errorf("UpstreamFallbacks: expected 1, got %d", got)
	}
}

// TestFallbackAllFailReturnsError: when every upstream fails, Resolve returns
// ErrAllUpstreamsFailed (a real error, NOT a nil-error SERVFAIL) so the caller
// drives its own fail-closed / serve-stale path. NEVER cleartext.
func TestFallbackAllFailReturnsError(t *testing.T) {
	primary := &mockResolver{failing: true}
	secondary := &mockResolver{failing: true}
	f := NewFallbackResolver([]*UpstreamState{
		{Name: "primary", Resolver: primary},
		{Name: "secondary", Resolver: secondary},
	}, discardLogger(), nil, 300, 3, 30)

	resp, err := f.Resolve(context.Background(), testQuery())
	if !errors.Is(err, ErrAllUpstreamsFailed) {
		t.Errorf("expected ErrAllUpstreamsFailed, got err=%v", err)
	}
	if resp != nil {
		t.Errorf("expected nil response on total failure, got %+v", resp)
	}
}

// TestFallbackStatusUpDownUp exercises the health-state transitions visible via
// GetStatus(): a single-upstream chain goes UP → DOWN (Phase-1 aggressive: one
// error) → UP (on the next success).
func TestFallbackStatusUpDownUp(t *testing.T) {
	up := &mockResolver{}
	f := NewFallbackResolver([]*UpstreamState{
		{Name: "only", Resolver: up},
	}, discardLogger(), nil, 300, 3, 30) // phase1DurationS=300 → we're in Phase 1

	// 1) Initial success → UP.
	if _, err := f.Resolve(context.Background(), testQuery()); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if s := f.GetStatus()["only"]["state"]; s != "UP" {
		t.Errorf("after success: expected UP, got %v", s)
	}

	// 2) Make it fail. Single upstream → it is still tried even when DOWN.
	up.setFailing(true)
	_, err := f.Resolve(context.Background(), testQuery())
	if !errors.Is(err, ErrAllUpstreamsFailed) {
		t.Fatalf("expected failure error, got %v", err)
	}
	if s := f.GetStatus()["only"]["state"]; s != "DOWN" {
		t.Errorf("after failure (Phase 1): expected DOWN, got %v", s)
	}

	// 3) Recover → UP, consecutive errors reset.
	up.setFailing(false)
	if _, err := f.Resolve(context.Background(), testQuery()); err != nil {
		t.Fatalf("recovery resolve: %v", err)
	}
	st := f.GetStatus()["only"]
	if st["state"] != "UP" {
		t.Errorf("after recovery: expected UP, got %v", st["state"])
	}
	if ce, _ := st["consecutive_errors"].(int); ce != 0 {
		t.Errorf("after recovery: expected 0 consecutive errors, got %d", ce)
	}
}

// TestFallbackSkipsDownUpstream: a primary already marked DOWN is skipped, the
// secondary serves, and that still counts as a fallback event (i>0).
func TestFallbackSkipsDownUpstream(t *testing.T) {
	primary := &mockResolver{failing: true}
	secondary := &mockResolver{}
	stats := statistics.New()
	f := NewFallbackResolver([]*UpstreamState{
		{Name: "primary", Resolver: primary},
		{Name: "secondary", Resolver: secondary},
	}, discardLogger(), stats, 300, 3, 30)

	// First call: primary fails (→ DOWN in Phase 1), secondary serves. 1 fallback.
	if _, err := f.Resolve(context.Background(), testQuery()); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	primaryCallsAfterFirst := atomic.LoadInt64(&primary.calls)

	// Second call: primary is DOWN and there is another upstream, so it is skipped
	// entirely (not re-dialed); secondary serves again. Still a fallback event.
	if _, err := f.Resolve(context.Background(), testQuery()); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if atomic.LoadInt64(&primary.calls) != primaryCallsAfterFirst {
		t.Errorf("DOWN primary should be skipped, but was re-dialed")
	}
	if got := atomic.LoadInt64(&stats.UpstreamFallbacks); got != 2 {
		t.Errorf("UpstreamFallbacks: expected 2, got %d", got)
	}
}

// TestFallbackMismatchedResponseFailsOver (audit H1): an upstream that answers a
// DIFFERENT question than asked is treated as failed — its answer must never be
// returned (it would be re-keyed onto the client's question and poison the shared
// cache) — and the chain falls back to the next upstream.
func TestFallbackMismatchedResponseFailsOver(t *testing.T) {
	primary := &mockResolver{answerName: "evil.example.org."}
	secondary := &mockResolver{}
	stats := statistics.New()
	f := NewFallbackResolver([]*UpstreamState{
		{Name: "primary", Resolver: primary},
		{Name: "secondary", Resolver: secondary},
	}, discardLogger(), stats, 300, 3, 30)

	resp, err := f.Resolve(context.Background(), testQuery())
	if err != nil {
		t.Fatalf("expected fail-over success, got %v", err)
	}
	if got := resp.Question[0].Name; got != "example.com." {
		t.Errorf("mismatched answer leaked through: response Question %q", got)
	}
	if atomic.LoadInt64(&secondary.calls) != 1 {
		t.Errorf("secondary should have been called once, got %d", atomic.LoadInt64(&secondary.calls))
	}
	if got := atomic.LoadInt64(&stats.UpstreamFallbacks); got != 1 {
		t.Errorf("UpstreamFallbacks: expected 1, got %d", got)
	}
	// The lying upstream must be recorded as failing (Phase 1 aggressive → DOWN).
	if s := f.GetStatus()["primary"]["state"]; s != "DOWN" {
		t.Errorf("mismatching primary: expected DOWN, got %v", s)
	}
}

// TestFallbackMismatchedResponseAllFail (audit H1): when the ONLY upstream answers a
// foreign question, Resolve fails closed with ErrAllUpstreamsFailed — never the
// mismatched answer, never cleartext.
func TestFallbackMismatchedResponseAllFail(t *testing.T) {
	only := &mockResolver{answerName: "evil.example.org."}
	f := NewFallbackResolver([]*UpstreamState{
		{Name: "only", Resolver: only},
	}, discardLogger(), nil, 300, 3, 30)

	resp, err := f.Resolve(context.Background(), testQuery())
	if !errors.Is(err, ErrAllUpstreamsFailed) {
		t.Errorf("expected ErrAllUpstreamsFailed, got err=%v", err)
	}
	if resp != nil {
		t.Errorf("expected nil response for an all-mismatched chain, got %+v", resp)
	}
}

// TestFallbackAcceptsCaseInsensitiveQNAME: DNS names compare case-insensitively
// (RFC 4343) — an upstream echoing the QNAME in different case is NOT a mismatch.
func TestFallbackAcceptsCaseInsensitiveQNAME(t *testing.T) {
	up := &mockResolver{answerName: "EXAMPLE.com."}
	f := NewFallbackResolver([]*UpstreamState{
		{Name: "only", Resolver: up},
	}, discardLogger(), nil, 300, 3, 30)

	if _, err := f.Resolve(context.Background(), testQuery()); err != nil {
		t.Errorf("case-different QNAME echo must be accepted, got %v", err)
	}
}

// TestFallbackRejectsMalformedQDCOUNT (audit M3 backstop): a query without exactly
// one question errors immediately — no upstream dial, and (critically) no error
// recorded against a healthy upstream, so a client spamming degenerate queries
// cannot drive the chain DOWN.
func TestFallbackRejectsMalformedQDCOUNT(t *testing.T) {
	up := &mockResolver{}
	f := NewFallbackResolver([]*UpstreamState{
		{Name: "only", Resolver: up},
	}, discardLogger(), nil, 300, 3, 30)

	twoQuestions := new(dns.Msg)
	twoQuestions.SetQuestion("example.com.", dns.TypeA)
	twoQuestions.Question = append(twoQuestions.Question,
		dns.Question{Name: "blocked.example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	for _, msg := range []*dns.Msg{new(dns.Msg), twoQuestions} {
		resp, err := f.Resolve(context.Background(), msg)
		if err == nil {
			t.Errorf("QDCOUNT=%d: expected an error, got none", len(msg.Question))
		}
		if resp != nil {
			t.Errorf("QDCOUNT=%d: expected nil response, got %+v", len(msg.Question), resp)
		}
	}
	if got := atomic.LoadInt64(&up.calls); got != 0 {
		t.Errorf("degenerate queries must never reach an upstream; Resolve called %d times", got)
	}
	if s := f.GetStatus()["only"]["state"]; s != "UP" {
		t.Errorf("healthy upstream penalized for a malformed client query: state %v", s)
	}
}
