// SPDX-License-Identifier: MIT
package dnssec_test

// live_integration_test.go is an OPT-IN, network-dependent test for the chain-of-trust
// validator. It is SKIPPED unless RCVD_DNSSEC_LIVE=1 so it NEVER runs in the normal
// `go test ./...` suite (which must stay hermetic + fast) and never risks touching the
// network in CI by accident. Run it deliberately — ideally in a container — with:
//
//	RCVD_DNSSEC_LIVE=1 go test ./internal/dnssec/ -run TestLive -v
//
// It builds a REAL DoQ resolver to AdGuard, wires it into a validator with the embedded
// IANA root anchors, and asserts the full fetch-DNSKEY/DS-walk-to-root path works against
// live signed zones — the exact scenario that failed in the field before chain.go.
//
// External test package (dnssec_test) so it can import internal/resolver without any import
// cycle (resolver never imports dnssec).

import (
	"os"
	"testing"

	"github.com/rcvd-dns/rcvd/internal/dnssec"
	"github.com/rcvd-dns/rcvd/internal/resolver"

	"github.com/miekg/dns"
)

// liveSetup builds a validator (embedded root anchors) plus the shared DoQ resolver it both
// fetches keys through AND that the test uses to issue the answer queries.
func liveSetup(t *testing.T) (*dnssec.Validator, resolver.Resolver) {
	t.Helper()
	anchors, err := dnssec.DefaultTrustAnchors()
	if err != nil {
		t.Fatalf("load embedded root anchors: %v", err)
	}
	// A public DoQ resolver (AdGuard). dialHost pinned to the known IP to avoid a
	// cleartext bootstrap lookup for the resolver's own hostname.
	r := resolver.NewDoQResolver("dns.adguard.com", "94.140.14.14", 853, "", nil)
	t.Cleanup(func() { _ = r.Close() })
	v := dnssec.New(true, false)
	v.SetTrustAnchors(anchors)
	v.SetResolver(r)
	return v, r
}

// query builds a DO=1 query and resolves it over the live upstream.
func liveQuery(t *testing.T, r resolver.Resolver, name string, qtype uint16) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.SetEdns0(4096, true)
	resp, err := r.Resolve(t.Context(), q)
	if err != nil {
		t.Fatalf("live query %s/%d: %v", name, qtype, err)
	}
	return resp
}

func TestLiveChainValidatesSignedZones(t *testing.T) {
	if os.Getenv("RCVD_DNSSEC_LIVE") != "1" {
		t.Skip("set RCVD_DNSSEC_LIVE=1 to run the network-dependent DNSSEC chain test")
	}
	v, r := liveSetup(t)

	// Real signed zones (algorithm 13 / ECDSA P-256 — the field-failing case).
	for _, name := range []string{"nlnetlabs.nl", "nextdns.io"} {
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			resp := liveQuery(t, r, name, qt)
			if len(resp.Answer) == 0 {
				t.Logf("%s/%s: no answer (skipping)", name, dns.TypeToString[qt])
				continue
			}
			if err := v.ValidateResponse(resp); err != nil {
				t.Errorf("%s/%s expected VALID, got: %v", name, dns.TypeToString[qt], err)
			}
		}
	}
}

func TestLiveChainRejectsBogus(t *testing.T) {
	if os.Getenv("RCVD_DNSSEC_LIVE") != "1" {
		t.Skip("set RCVD_DNSSEC_LIVE=1 to run the network-dependent DNSSEC chain test")
	}
	v, r := liveSetup(t)

	// dnssec-failed.org is intentionally BOGUS (expired signatures). A validating upstream
	// may itself SERVFAIL it (then there's no signed answer to hand us); if we DO get a
	// signed answer, our chain walk must reject it — never pass.
	resp := liveQuery(t, r, "dnssec-failed.org", dns.TypeA)
	if len(resp.Answer) == 0 {
		t.Skip("upstream returned no answer for dnssec-failed.org (it SERVFAILed it upstream) — nothing to validate")
	}
	if err := v.ValidateResponse(resp); err == nil {
		t.Error("expected dnssec-failed.org to fail validation (bogus), got nil")
	}
}
