// SPDX-License-Identifier: MIT
package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
	"github.com/rcvd-dns/rcvd/internal/allowlist"
	"github.com/rcvd-dns/rcvd/internal/blocklist"
	"github.com/rcvd-dns/rcvd/internal/statistics"
)

// makeQuery builds a one-question dns.Msg for the (name, qtype) pair.
func makeQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	return m
}

// seedAllowlist builds an Allowlist seeded with the given body (one domain per line).
// Writes to a temp file under the hood because LoadFiles is the only public seed path.
func seedAllowlist(t *testing.T, body string) *allowlist.Allowlist {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	a := allowlist.New()
	if err := a.LoadFiles([]string{path}); err != nil {
		t.Fatalf("load seed: %v", err)
	}
	return a
}

// TestPolicyNilReceiverReturnsNil guards the off switch: nil *Policy returns nil
// for every query, including an empty one.
func TestPolicyNilReceiverReturnsNil(t *testing.T) {
	var p *Policy // nil
	if got := p.Response(makeQuery("example.com.", dns.TypeA)); got != nil {
		t.Errorf("nil policy: Response returned non-nil: %+v", got)
	}
	if got := p.Response(&dns.Msg{}); got != nil {
		t.Errorf("nil policy on empty query: Response returned non-nil: %+v", got)
	}
}

// TestPolicyNoFiltersReturnsNil: a Policy with neither allowlist nor blocklist is a
// pass-through; it never synthesizes a reply. Same observable behavior as nil.
func TestPolicyNoFiltersReturnsNil(t *testing.T) {
	p := New(nil, nil, nil)
	if got := p.Response(makeQuery("anything.test.", dns.TypeA)); got != nil {
		t.Errorf("empty policy: Response returned non-nil: %+v", got)
	}
}

// TestPolicyAllowlistDeniesBelowSuffix covers the headline shape: a name NOT under a
// listed suffix is REFUSED + EDE 18 (when the query had OPT), counted in DeniedQueries,
// and not forwarded (no further code path runs).
func TestPolicyAllowlistDeniesBelowSuffix(t *testing.T) {
	al := seedAllowlist(t, "example.com\n")
	stats := statistics.New()
	p := New(al, nil, stats)

	denied := "leak.attacker.example.net."
	query := makeQuery(denied, dns.TypeA)
	query.SetEdns0(4096, false) // EDNS, DO=0 → OPT must be present in reply

	resp := p.Response(query)
	if resp == nil {
		t.Fatal("expected REFUSED reply, got nil")
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %d, want REFUSED", resp.Rcode)
	}
	if !resp.Response {
		t.Error("Response bit must be set")
	}
	if got := len(resp.Question); got != 1 || resp.Question[0].Name != denied {
		t.Errorf("question must be echoed: got %+v", resp.Question)
	}
	// EDE 18 attached on the OPT for EDNS clients.
	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatal("EDNS query: response must carry OPT for EDE attachment")
	}
	ede := findEDE(opt)
	if ede == nil {
		t.Fatal("EDNS query: response OPT must carry EDE 18")
	}
	if ede.InfoCode != dns.ExtendedErrorCodeProhibited {
		t.Errorf("EDE InfoCode = %d, want %d (Prohibited)", ede.InfoCode, dns.ExtendedErrorCodeProhibited)
	}

	snap := stats.TakeSnapshot(0, 0, statistics.InstanceInfo{})
	if snap.DeniedQueries != 1 {
		t.Errorf("DeniedQueries = %d, want 1", snap.DeniedQueries)
	}
	if snap.BlockedQueries != 0 {
		t.Errorf("BlockedQueries must not increment on allowlist denial: %d", snap.BlockedQueries)
	}
}

// TestPolicyAllowlistDeniesNonEDNS covers the RFC 6891 §6.1.1 case: a non-EDNS query
// gets a REFUSED reply with NO OPT, regardless of the EDE option the listener would
// have attached.
func TestPolicyAllowlistDeniesNonEDNS(t *testing.T) {
	al := seedAllowlist(t, "example.com\n")
	p := New(al, nil, nil)

	query := makeQuery("leak.attacker.example.net.", dns.TypeA) // no SetEdns0
	resp := p.Response(query)
	if resp == nil {
		t.Fatal("expected REFUSED reply, got nil")
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %d, want REFUSED", resp.Rcode)
	}
	if opt := resp.IsEdns0(); opt != nil {
		t.Errorf("non-EDNS query: response must NOT carry OPT (RFC 6891 §6.1.1), got %+v", opt)
	}
}

// TestPolicyAllowlistAllowsListedSuffix verifies the negative case: a name under a
// listed suffix is passed through (Response returns nil).
func TestPolicyAllowlistAllowsListedSuffix(t *testing.T) {
	al := seedAllowlist(t, "example.com\n")
	p := New(al, nil, nil)
	if got := p.Response(makeQuery("www.example.com.", dns.TypeA)); got != nil {
		t.Errorf("allowed suffix: expected pass-through (nil), got %+v", got)
	}
}

// TestPolicyBlocklistHits: a blocklisted name inside an allowed suffix gets NXDOMAIN.
// Block wins.
func TestPolicyBlocklistHits(t *testing.T) {
	al := seedAllowlist(t, "example.com\n") // allowlist covers the whole example.com tree
	bl := blocklist.New(true)
	bl.Add("ads.example.com") // blocklist narrows it to one subdomain

	stats := statistics.New()
	p := New(al, bl, stats)

	resp := p.Response(makeQuery("ads.example.com.", dns.TypeA))
	if resp == nil {
		t.Fatal("expected NXDOMAIN reply, got nil")
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %d, want NXDOMAIN", resp.Rcode)
	}
	snap := stats.TakeSnapshot(0, 0, statistics.InstanceInfo{})
	if snap.BlockedQueries != 1 {
		t.Errorf("BlockedQueries = %d, want 1", snap.BlockedQueries)
	}
	if snap.DeniedQueries != 0 {
		t.Errorf("DeniedQueries must not increment when block fires inside an allowed suffix: %d", snap.DeniedQueries)
	}
}

// TestPolicySameNameInBothListsBlocks: an operator lists the same name in both the
// allowlist and the blocklist. This is not a startup error; the blocklist wins for the
// name and its subdomains, and other allowed names still pass through.
func TestPolicySameNameInBothListsBlocks(t *testing.T) {
	al := seedAllowlist(t, "example.com\nexample.net\n")
	bl := blocklist.New(true)
	bl.Add("example.com") // same entry as the allowlist

	stats := statistics.New()
	p := New(al, bl, stats)

	for _, name := range []string{"example.com.", "www.example.com."} {
		resp := p.Response(makeQuery(name, dns.TypeA))
		if resp == nil {
			t.Fatalf("%s: expected NXDOMAIN reply, got nil", name)
		}
		if resp.Rcode != dns.RcodeNameError {
			t.Errorf("%s: Rcode = %d, want NXDOMAIN (blocklist wins)", name, resp.Rcode)
		}
	}
	if got := p.Response(makeQuery("www.example.net.", dns.TypeA)); got != nil {
		t.Errorf("www.example.net: expected pass-through (nil), got Rcode %d", got.Rcode)
	}

	snap := stats.TakeSnapshot(0, 0, statistics.InstanceInfo{})
	if snap.BlockedQueries != 2 {
		t.Errorf("BlockedQueries = %d, want 2", snap.BlockedQueries)
	}
	if snap.DeniedQueries != 0 {
		t.Errorf("DeniedQueries = %d, want 0 (names are allowed, then blocked)", snap.DeniedQueries)
	}
}

// TestPolicyAllowlistDeniesBlocklistIgnored verifies the fixed order: when a name is
// NOT on the allowlist, the blocklist is NOT consulted (a deny-then-blocklist-check
// ordering would risk leaking a "blocked" signal for an already-denied name).
func TestPolicyAllowlistDeniesBlocklistIgnored(t *testing.T) {
	al := seedAllowlist(t, "example.com\n")
	bl := blocklist.New(true)
	bl.Add("attacker.example.net") // blocklist has the name; allowlist does NOT cover it

	stats := statistics.New()
	p := New(al, bl, stats)

	resp := p.Response(makeQuery("leak.attacker.example.net.", dns.TypeA))
	if resp == nil {
		t.Fatal("expected REFUSED reply, got nil")
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %d, want REFUSED (allowlist denies first)", resp.Rcode)
	}
	snap := stats.TakeSnapshot(0, 0, statistics.InstanceInfo{})
	if snap.DeniedQueries != 1 {
		t.Errorf("DeniedQueries = %d, want 1", snap.DeniedQueries)
	}
	if snap.BlockedQueries != 0 {
		t.Errorf("BlockedQueries must remain 0 (allowlist denies first): %d", snap.BlockedQueries)
	}
}

// TestPolicyBlocklistAlonePassesForAllowedName: a blocklist-only policy (no allowlist)
// still passes through non-blocked names.
func TestPolicyBlocklistAlonePassesForAllowedName(t *testing.T) {
	bl := blocklist.New(true)
	bl.Add("blocked.example.com")
	p := New(nil, bl, nil)

	if got := p.Response(makeQuery("ok.example.com.", dns.TypeA)); got != nil {
		t.Errorf("non-blocked name: expected pass-through (nil), got %+v", got)
	}
	if got := p.Response(makeQuery("blocked.example.com.", dns.TypeA)); got == nil {
		t.Error("blocked name: expected NXDOMAIN, got nil")
	} else if got.Rcode != dns.RcodeNameError {
		t.Errorf("blocked name Rcode = %d, want NXDOMAIN", got.Rcode)
	}
}

// TestPolicyResponseIsIndependent: each Response call returns a fresh *dns.Msg; the
// caller mutating it (e.g. ensureResponseEDNS, packing) does not bleed into the next
// call. Important because the same Policy is shared across many concurrent queries.
func TestPolicyResponseIsIndependent(t *testing.T) {
	al := seedAllowlist(t, "example.com\n")
	p := New(al, nil, nil)

	r1 := p.Response(makeQuery("leak.attacker.example.net.", dns.TypeA))
	r2 := p.Response(makeQuery("other.attacker.example.org.", dns.TypeA))

	if r1 == nil || r2 == nil {
		t.Fatal("both responses must be non-nil")
	}
	if r1 == r2 {
		t.Fatal("each call must return a fresh *dns.Msg (no aliasing)")
	}
	// Mutate r1; r2 must not see the change.
	r1.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "leak.attacker.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
	}}
	if len(r2.Answer) != 0 {
		t.Errorf("r2 must not be aliased to r1 (saw %d answer RRs)", len(r2.Answer))
	}
}

// TestPolicyEmptyQuestionPassesThrough: an empty Question (which the listeners reject
// at the FORMERR check before reaching policy) returns nil from Response — defense in
// depth, not a crash.
func TestPolicyEmptyQuestionPassesThrough(t *testing.T) {
	al := seedAllowlist(t, "example.com\n")
	p := New(al, nil, nil)
	if got := p.Response(&dns.Msg{}); got != nil {
		t.Errorf("empty question: expected pass-through (nil), got %+v", got)
	}
}

// TestPolicyNilStatsDoesNotPanic: stats is optional; the synthesized reply and rcode
// must still come out correctly.
func TestPolicyNilStatsDoesNotPanic(t *testing.T) {
	al := seedAllowlist(t, "example.com\n")
	p := New(al, nil, nil) // nil stats
	if got := p.Response(makeQuery("leak.attacker.example.net.", dns.TypeA)); got == nil || got.Rcode != dns.RcodeRefused {
		t.Errorf("nil stats: expected REFUSED reply, got %+v", got)
	}
}

// findEDE returns the EDE option attached to opt, or nil if absent.
func findEDE(opt *dns.OPT) *dns.EDNS0_EDE {
	for _, o := range opt.Option {
		if ede, ok := o.(*dns.EDNS0_EDE); ok {
			return ede
		}
	}
	return nil
}

// TestShadowedReportsOnlyFullyCoveredEntries: an allowlist entry is reported only when
// the blocklist covers everything it allows. Partial coverage (one blocked subdomain)
// is normal use and stays quiet.
func TestShadowedReportsOnlyFullyCoveredEntries(t *testing.T) {
	al := seedAllowlist(t, "example.com\nexample.net\n*.example.org\n*.example.edu\nexample.info\n")
	bl := blocklist.New(true)
	bl.Add("example.com")     // same bare entry: fully shadowed
	bl.Add("ads.example.net") // one subdomain only: not shadowed
	bl.Add("*.example.org")   // wildcard covers the allowed wildcard: fully shadowed
	bl.Add("www.example.edu") // one subdomain of an allowed wildcard: not shadowed
	bl.Add("*.example.info")  // subdomains only, apex still resolves: not shadowed

	got := Shadowed(al, bl)
	want := []string{"*.example.org", "example.com"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Shadowed = %v, want %v", got, want)
	}
}

// TestShadowedNilOrDisabled: no warning when either list is off.
func TestShadowedNilOrDisabled(t *testing.T) {
	al := seedAllowlist(t, "example.com\n")
	if got := Shadowed(nil, blocklist.New(true)); got != nil {
		t.Errorf("nil allowlist: got %v", got)
	}
	if got := Shadowed(al, nil); got != nil {
		t.Errorf("nil blocklist: got %v", got)
	}
	off := blocklist.New(false)
	off.Add("example.com")
	if got := Shadowed(al, off); got != nil {
		t.Errorf("disabled blocklist: got %v", got)
	}
}

// TestShadowSummary checks the singular form, the empty case, and the five-name cap.
func TestShadowSummary(t *testing.T) {
	if got := ShadowSummary(nil); got != "" {
		t.Errorf("empty: got %q", got)
	}
	if got, want := ShadowSummary([]string{"example.com"}),
		"1 allowlist entry fully shadowed by the blocklist (always NXDOMAIN): example.com"; got != want {
		t.Errorf("one:\n got %q\nwant %q", got, want)
	}
	seven := []string{"a.example", "b.example", "c.example", "d.example", "e.example", "f.example", "g.example"}
	if got, want := ShadowSummary(seven),
		"7 allowlist entries fully shadowed by the blocklist (always NXDOMAIN): a.example, b.example, c.example, d.example, e.example, and 2 more"; got != want {
		t.Errorf("seven:\n got %q\nwant %q", got, want)
	}
}
