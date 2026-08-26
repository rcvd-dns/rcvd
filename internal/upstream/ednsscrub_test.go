// SPDX-License-Identifier: MIT

package upstream

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// TestEnsureResponseEDNSStripsDNSSECForNonDOClient guards the Mode-2 half of Issue 34: a client that
// did not set the DO bit must not receive DNSSEC records (RFC 6840 §5.9). Mode 2 always queries
// upstream with DO=1 (queryWithDO), so a signed-zone reply carries RRSIG alongside the A record; the
// non-DO reply must keep the A and drop the signatures, while a DO client keeps everything. The AD bit
// survives either way. The Mode-1 helper had this fix; the Mode-2 twin was missed — a leaked RRSIG made
// Firefox in DoH-only mode refuse the endpoint (public roaming DoH front door), curl was unaffected.
func TestEnsureResponseEDNSStripsDNSSECForNonDOClient(t *testing.T) {
	build := func() *dns.Msg {
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess, AuthenticatedData: true},
			Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.IPv4(104, 20, 23, 154),
				},
				&dns.RRSIG{
					Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
					TypeCovered: dns.TypeA, Algorithm: dns.ECDSAP256SHA256, KeyTag: 34505,
					SignerName: "example.com.", Signature: "AAAA",
				},
			},
		}
	}

	countRR := func(msg *dns.Msg, rrtype uint16) int {
		n := 0
		for _, rr := range append(append(append([]dns.RR{}, msg.Answer...), msg.Ns...), msg.Extra...) {
			if rr.Header().Rrtype == rrtype {
				n++
			}
		}
		return n
	}

	// Query builders for the three RFC 6891 §6.1.1 client shapes.
	noEDNSQuery := func() *dns.Msg { // no OPT at all
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		return q
	}
	ednsQuery := func(do bool) *dns.Msg { // OPT present, DO as given
		q := noEDNSQuery()
		q.SetEdns0(ednsUDPBufSize, do)
		return q
	}

	// EDNS client, DO=0: A stays, RRSIG goes, AD preserved, OPT present with DO=0.
	noDO := build()
	ensureResponseEDNS(noDO, ednsQuery(false))
	if got := countRR(noDO, dns.TypeA); got != 1 {
		t.Errorf("non-DO: expected 1 A record retained, got %d", got)
	}
	if got := countRR(noDO, dns.TypeRRSIG); got != 0 {
		t.Errorf("non-DO: expected RRSIG stripped (RFC 6840 §5.9, Issue 34), got %d", got)
	}
	if !noDO.AuthenticatedData {
		t.Error("non-DO: AD bit must be preserved after stripping signatures")
	}
	if opt := noDO.IsEdns0(); opt == nil || opt.Do() {
		t.Error("non-DO: response OPT must be present with DO=0")
	}

	// EDNS client, DO=1: everything kept.
	withDO := build()
	ensureResponseEDNS(withDO, ednsQuery(true))
	if got := countRR(withDO, dns.TypeRRSIG); got != 1 {
		t.Errorf("DO client: RRSIG must be retained, got %d", got)
	}
	if opt := withDO.IsEdns0(); opt == nil || !opt.Do() {
		t.Error("DO client: response OPT must be present with DO=1")
	}

	// NON-EDNS client (no OPT in query): the response must carry NO OPT (RFC 6891 §6.1.1,
	// Issue 36 — the unsolicited response OPT that broke iOS 18 DNSecure + modern Android).
	// DNSSEC records must also be stripped (a non-EDNS client cannot have signaled DO).
	nonEDNS := build()
	ensureResponseEDNS(nonEDNS, noEDNSQuery())
	if opt := nonEDNS.IsEdns0(); opt != nil {
		t.Error("non-EDNS query: response must NOT carry an OPT (RFC 6891 §6.1.1, Issue 36)")
	}
	if got := countRR(nonEDNS, dns.TypeOPT); got != 0 {
		t.Errorf("non-EDNS query: expected 0 OPT records in response, got %d", got)
	}
	if got := countRR(nonEDNS, dns.TypeRRSIG); got != 0 {
		t.Errorf("non-EDNS query: expected RRSIG stripped, got %d", got)
	}
	if got := countRR(nonEDNS, dns.TypeA); got != 1 {
		t.Errorf("non-EDNS query: expected 1 A record retained, got %d", got)
	}

	// Belt-and-suspenders for Issue 36: even if the upstream/validator left an OPT in the
	// response, a non-EDNS query must still yield a non-EDNS response.
	withStrayOPT := build()
	withStrayOPT.SetEdns0(ednsUDPBufSize, true) // simulate the DO=1 upstream OPT we always dial with
	ensureResponseEDNS(withStrayOPT, noEDNSQuery())
	if opt := withStrayOPT.IsEdns0(); opt != nil {
		t.Error("non-EDNS query with stray upstream OPT: response OPT must be removed (Issue 36)")
	}
}
