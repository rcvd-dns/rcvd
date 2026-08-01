// SPDX-License-Identifier: MIT
package dnssec

import (
	"context"
	"crypto"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// chain_test.go exercises the chain-of-trust walk (chain.go) fully OFFLINE: it stands up a
// synthetic two-level signed hierarchy (root "." + a child zone), each zone with a KSK+ZSK,
// installs the root KSK as a trust anchor, and drives ValidateResponse through a mock resolver
// that answers DNSKEY/DS fetches from the synthetic zones. Real ECDSA P-256 crypto throughout —
// this is the exact path that failed in the field ("signing DNSKEY not found") before chain.go.

// signedZone holds one zone's keys and the RRs a resolver would return for it.
type signedZone struct {
	name    string
	ksk     *dns.DNSKEY
	kskPriv crypto.Signer
	zsk     *dns.DNSKEY
	zskPriv crypto.Signer
}

// newSignedZone generates a KSK (SEP) and ZSK for a zone using ECDSA P-256 (algorithm 13 —
// the same algorithm that detonated in the field).
func newSignedZone(t *testing.T, name string) *signedZone {
	t.Helper()
	mk := func(flags uint16) (*dns.DNSKEY, crypto.Signer) {
		k := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags:     flags,
			Protocol:  3,
			Algorithm: dns.ECDSAP256SHA256,
		}
		priv, err := k.Generate(256)
		if err != nil {
			t.Fatalf("generate DNSKEY for %s: %v", name, err)
		}
		return k, priv.(crypto.Signer)
	}
	ksk, kskPriv := mk(257) // KSK: SEP + ZONE
	zsk, zskPriv := mk(256) // ZSK: ZONE
	return &signedZone{name: name, ksk: ksk, kskPriv: kskPriv, zsk: zsk, zskPriv: zskPriv}
}

// sign returns an RRSIG over rrs made by the given key/signer.
func sign(t *testing.T, z *signedZone, key *dns.DNSKEY, priv crypto.Signer, rrs []dns.RR) *dns.RRSIG {
	t.Helper()
	h := rrs[0].Header()
	now := time.Now()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: h.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: h.Ttl},
		TypeCovered: h.Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(h.Name)),
		OrigTtl:     h.Ttl,
		Expiration:  uint32(now.Add(24 * time.Hour).Unix()),
		Inception:   uint32(now.Add(-1 * time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  z.name,
	}
	if err := sig.Sign(priv, rrs); err != nil {
		t.Fatalf("sign %s type %d: %v", h.Name, h.Rrtype, err)
	}
	return sig
}

// dnskeyRRset returns the zone's DNSKEY RRset (KSK+ZSK) self-signed by the KSK.
func (z *signedZone) dnskeyRRset(t *testing.T) []dns.RR {
	keys := []dns.RR{z.ksk, z.zsk}
	sig := sign(t, z, z.ksk, z.kskPriv, keys)
	return append(keys, sig)
}

// mockChainResolver answers DNSKEY and DS fetches from a fixed table of RRsets keyed by
// "name/type". Anything else returns SERVFAIL — the walk should never ask for it.
//
// authority holds records placed in the AUTHORITY section for a "name/type" that answers NODATA
// (present in `authority` but absent from `answers`) — this models a signed no-DS denial where the
// NSEC/NSEC3 proof lives in the authority section, exactly as a real TLD returns it.
type mockChainResolver struct {
	answers   map[string][]dns.RR
	authority map[string][]dns.RR
	calls     int
}

func (m *mockChainResolver) Resolve(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
	m.calls++
	resp := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess}}
	resp.Question = q.Question
	if len(q.Question) > 0 {
		key := rrsetKey(q.Question[0].Name, q.Question[0].Qtype)
		if rrs, ok := m.answers[key]; ok {
			resp.Answer = rrs
			return resp, nil
		}
		if ns, ok := m.authority[key]; ok {
			// NODATA: NOERROR, empty answer, proof in the authority section.
			resp.Ns = ns
			return resp, nil
		}
	}
	resp.Rcode = dns.RcodeServerFailure
	return resp, nil
}

// buildTwoLevelChain wires root "." delegating to "example." and returns:
//   - the validator (trust anchor = root KSK, resolver = mock),
//   - the signed A answer for host.example. (as a real upstream would return it: A + RRSIG,
//     signing key NOT in the message),
//   - the mock (to inspect call count).
func buildTwoLevelChain(t *testing.T, tamperDS bool) (*Validator, *dns.Msg, *mockChainResolver) {
	t.Helper()
	root := newSignedZone(t, ".")
	child := newSignedZone(t, "example.")

	// DS for "example." = digest of the child KSK, signed by the ROOT's ZSK (DS lives in parent).
	ds := child.ksk.ToDS(dns.SHA256)
	if tamperDS {
		// Flip the digest so the child KSK no longer matches — should fail bogus.
		b := []byte(ds.Digest)
		if b[0] == '0' {
			b[0] = '1'
		} else {
			b[0] = '0'
		}
		ds.Digest = string(b)
	}
	dsRRset := []dns.RR{ds}
	dsRRset = append(dsRRset, sign(t, root, root.zsk, root.zskPriv, []dns.RR{ds}))

	// The real answer: A record for host.example., signed by the CHILD's ZSK.
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "host.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IPv4(192, 0, 2, 10),
	}
	aSig := sign(t, child, child.zsk, child.zskPriv, []dns.RR{a})

	mock := &mockChainResolver{answers: map[string][]dns.RR{
		rrsetKey(".", dns.TypeDNSKEY):        root.dnskeyRRset(t),
		rrsetKey("example.", dns.TypeDNSKEY): child.dnskeyRRset(t),
		rrsetKey("example.", dns.TypeDS):     dsRRset,
	}}

	// Trust anchor = root KSK.
	rootDS := root.ksk.ToDS(dns.SHA256)
	digest, err := hex.DecodeString(rootDS.Digest)
	if err != nil {
		t.Fatalf("decode root DS digest: %v", err)
	}
	v := New(true, false)
	v.SetTrustAnchors([]TrustAnchor{{
		KeyTag:     root.ksk.KeyTag(),
		Algorithm:  root.ksk.Algorithm,
		DigestType: dns.SHA256,
		Digest:     digest,
	}})
	v.SetResolver(mock)

	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Answer: []dns.RR{a, aSig}}
	return v, msg, mock
}

// dsRRset returns the DS RRset for child (digest of child KSK), signed by parent's ZSK — the DS
// lives in the parent zone.
func dsRRsetFor(t *testing.T, parent, child *signedZone) []dns.RR {
	t.Helper()
	ds := child.ksk.ToDS(dns.SHA256)
	return []dns.RR{ds, sign(t, parent, parent.zsk, parent.zskPriv, []dns.RR{ds})}
}

// nsec3For builds an NSEC3 record (owner = <ownerHash>.<zone>) with the given next-hash, flags,
// and type bitmap, then signs it with the zone's ZSK and returns record + RRSIG. The salt/iters
// mirror common TLD practice (empty salt, 0 iterations) so HashName lines up with Match/Cover.
func nsec3For(t *testing.T, z *signedZone, ownerHash, nextHash string, flags uint8, bitmap []uint16) []dns.RR {
	t.Helper()
	owner := ownerHash + "." + z.name
	if z.name == "." {
		owner = ownerHash + "." // root zone: <hash>. not <hash>..
	}
	n3 := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600,
		},
		Hash:       dns.SHA1,
		Flags:      flags,
		Iterations: 0,
		SaltLength: 0,
		Salt:       "", // empty salt (matches h32 / HashName with salt="")
		HashLength: 20,
		NextDomain: nextHash,
		TypeBitMap: bitmap,
	}
	sig := sign(t, z, z.zsk, z.zskPriv, []dns.RR{n3})
	return []dns.RR{n3, sig}
}

// h32 hashes a name to its RFC 5155 base32 owner-hash label (empty salt, 0 iterations).
func h32(name string) string { return dns.HashName(name, dns.SHA1, 0, "") }

// base32hex is the alphabet NSEC3 owner hashes use (RFC 4648 base32hex, uppercase). It is
// monotonic, so plain string comparison matches hash ordering — which is what NSEC3.Cover relies on.
const base32hex = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

// bracket returns (lo, hi) base32hex hashes with lo < target < hi, so an NSEC3 owned by lo with
// NextDomain hi COVERS target (a non-wrapping interval). It nudges the last character down/up,
// borrowing to the left on an alphabet edge.
func bracket(target string) (lo, hi string) {
	idx := func(c byte) int { return strings.IndexByte(base32hex, c) }
	dec := func(s string) string {
		b := []byte(s)
		for i := len(b) - 1; i >= 0; i-- {
			if p := idx(b[i]); p > 0 {
				b[i] = base32hex[p-1]
				return string(b)
			}
			b[i] = base32hex[len(base32hex)-1] // was '0'; wrap this char, borrow left
		}
		return string(b)
	}
	inc := func(s string) string {
		b := []byte(s)
		for i := len(b) - 1; i >= 0; i-- {
			if p := idx(b[i]); p < len(base32hex)-1 {
				b[i] = base32hex[p+1]
				return string(b)
			}
			b[i] = base32hex[0] // was 'V'; wrap this char, borrow left
		}
		return string(b)
	}
	return dec(target), inc(target)
}

// insecureDelegationFixture stands up a realistic three-level chain:
//
//	.  (root, trust anchor)
//	└── io.            secure delegation (DS from root)
//	    └── example.io. INSECURE delegation (io. publishes NO DS, proven by NSEC3)
//
// example.io. self-signs its own A record (docker.io does exactly this). The io. zone answers the
// example.io./DS query as a signed NODATA whose opt-out NSEC3 (in io.) covers H(example.io.) and a
// matching NSEC3 witnesses the closest encloser (io. apex). Mirrors the real docker.io capture.
//
// stripDenialSigs, when true, drops the RRSIGs off the NSEC3 records — an attacker forging an
// UNSIGNED denial. The validator must then refuse to conclude "insecure" and fail closed.
func insecureDelegationFixture(t *testing.T, stripDenialSigs bool) (*Validator, *dns.Msg) {
	t.Helper()
	root := newSignedZone(t, ".")
	tld := newSignedZone(t, "io.")
	child := newSignedZone(t, "example.io.")

	// example.io. self-signs an A record; its signing DNSKEY is NOT in the answer.
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "host.example.io.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IPv4(192, 0, 2, 10),
	}
	aSig := sign(t, child, child.zsk, child.zskPriv, []dns.RR{a})

	// io.'s NSEC3 denial of example.io./DS: matching NSEC3 for the io. apex (closest encloser) +
	// an opt-out NSEC3 covering H(example.io.). Both signed by io.'s ZSK.
	tldHash := h32("io.")
	exHash := h32("example.io.")
	lo, hi := bracket(exHash)
	apexNSEC3 := nsec3For(t, tld, tldHash, exHash, 0,
		[]uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM})
	optOut := nsec3For(t, tld, lo, hi, 1, // flags bit0 = opt-out
		[]uint16{dns.TypeNS, dns.TypeRRSIG})
	if stripDenialSigs {
		apexNSEC3 = apexNSEC3[:1] // drop RRSIG
		optOut = optOut[:1]       // drop RRSIG
	}
	authorityRRs := append(append([]dns.RR{}, apexNSEC3...), optOut...)

	mock := &mockChainResolver{
		answers: map[string][]dns.RR{
			rrsetKey(".", dns.TypeDNSKEY):           root.dnskeyRRset(t),
			rrsetKey("io.", dns.TypeDNSKEY):         tld.dnskeyRRset(t),
			rrsetKey("io.", dns.TypeDS):             dsRRsetFor(t, root, tld), // io. IS secure
			rrsetKey("example.io.", dns.TypeDNSKEY): child.dnskeyRRset(t),
		},
		authority: map[string][]dns.RR{
			rrsetKey("example.io.", dns.TypeDS): authorityRRs, // NODATA: proof in authority
		},
	}

	rootDS := root.ksk.ToDS(dns.SHA256)
	digest, err := hex.DecodeString(rootDS.Digest)
	if err != nil {
		t.Fatalf("decode root DS digest: %v", err)
	}
	v := New(true, false)
	v.SetTrustAnchors([]TrustAnchor{{
		KeyTag:     root.ksk.KeyTag(),
		Algorithm:  root.ksk.Algorithm,
		DigestType: dns.SHA256,
		Digest:     digest,
	}})
	v.SetResolver(mock)

	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Answer: []dns.RR{a, aSig}}
	return v, msg
}

// TestChainInsecureDelegationOptOut proves the Issue 30 fix: a signed NODATA-DS answer (parent
// authenticatedly proves the child has NO DS, opt-out NSEC3 covering the child) is treated as an
// INSECURE delegation — the child's self-signed answer is served WITHOUT the AD bit (the insecure
// signal), NOT SERVFAIL and NOT AD-authenticated.
func TestChainInsecureDelegationOptOut(t *testing.T) {
	v, msg := insecureDelegationFixture(t, false)
	err := v.ValidateResponse(msg)
	if err == nil {
		t.Fatal("insecure delegation must NOT return nil (that would AD-assert an unauthenticated zone)")
	}
	if !IsInsecure(err) {
		t.Fatalf("insecure delegation must return the insecure signal (no AD, no SERVFAIL), got: %v", err)
	}
}

// TestChainInsecureDelegationUnsignedDenialRejected proves we do NOT accept an UNSIGNED no-DS
// denial: an attacker who strips the RRSIG off the NSEC3 must not be able to force "insecure".
// Without a verifiable denial the walk fails closed (error), not silently insecure.
func TestChainInsecureDelegationUnsignedDenialRejected(t *testing.T) {
	v, msg := insecureDelegationFixture(t, true)
	if err := v.ValidateResponse(msg); err == nil {
		t.Fatal("unsigned no-DS denial must NOT be accepted as insecure — expected error, got nil")
	}
}

// TestChainValidateFullTrust proves an ordinary A answer validates end-to-end via fetched keys.
func TestChainValidateFullTrust(t *testing.T) {
	v, msg, mock := buildTwoLevelChain(t, false)

	if err := v.ValidateResponse(msg); err != nil {
		t.Fatalf("expected chain validation to PASS, got: %v", err)
	}
	if mock.calls == 0 {
		t.Error("expected the validator to FETCH keys (calls>0), but it fetched nothing")
	}

	// Second call must be served from the key cache — no new fetches.
	before := mock.calls
	if err := v.ValidateResponse(msg); err != nil {
		t.Fatalf("second validation failed: %v", err)
	}
	if mock.calls != before {
		t.Errorf("expected cache hit (no new fetches), calls went %d -> %d", before, mock.calls)
	}
}

// TestChainBogusDS proves a broken delegation (DS not matching the child KSK) fails bogus,
// never silently passing.
func TestChainBogusDS(t *testing.T) {
	v, msg, _ := buildTwoLevelChain(t, true)
	if err := v.ValidateResponse(msg); err == nil {
		t.Fatal("expected BOGUS (DS/KSK mismatch) to fail validation, got nil")
	}
}

// TestChainNoResolverFallback proves that without a wired resolver the validator preserves the
// legacy single-message behavior: a missing in-message key is a hard error (no panic, no fetch).
func TestChainNoResolverFallback(t *testing.T) {
	v, msg, _ := buildTwoLevelChain(t, false)
	v.SetResolver(nil) // strip the resolver
	err := v.ValidateResponse(msg)
	if err == nil {
		t.Fatal("expected 'signing DNSKEY not found' without a resolver, got nil")
	}
}

// mixedCNAMEChainFixture reproduces the Issue 30 field case (whois.pir.org). A SIGNED CNAME in a
// SECURE zone points into an INSECURE zone, and the rest of the chain (the target's CNAME/A) is
// UNSIGNED:
//
//	whois.pir.org.                    CNAME whois.publicinterestregistry.org.  ← signed by pir.org (SECURE)
//	whois.publicinterestregistry.org. CNAME target.iddg.io.                    ← UNSIGNED
//	target.iddg.io.                   A     44.233.186.238                     ← UNSIGNED (iddg.io insecure)
//
// The correct DNSSEC result is INSECURE: return the answer with NO AD bit (what Quad9/Cloudflare/
// Google do), never SERVFAIL, and never AD-asserted. rcvd got this wrong: the single signed CNAME
// validated, no other RRSIG existed to check, ValidateResponse returned nil, and the server stamped
// AD=true on a partly-unsigned chain (a false authentication claim).
//
// Zone layout: root -> org. (secure, DS) -> pir.org. (secure, DS); iddg.io. is modeled as a zone the
// answer lands in but for which NO signature is present in the message. We do NOT need to stand up
// io./iddg.io. DS proofs here because the fix must key off the answer having UNSIGNED RRsets, not off
// a DS walk — that is the whole point of the field failure (no RRSIG ever triggers a walk for the A).
func mixedCNAMEChainFixture(t *testing.T) (*Validator, *dns.Msg) {
	t.Helper()
	root := newSignedZone(t, ".")
	org := newSignedZone(t, "org.")
	pir := newSignedZone(t, "pir.org.")

	// The signed head of the chain: whois.pir.org. CNAME ..., signed by pir.org.'s ZSK.
	cname1 := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "whois.pir.org.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "whois.publicinterestregistry.org.",
	}
	cname1Sig := sign(t, pir, pir.zsk, pir.zskPriv, []dns.RR{cname1})

	// The UNSIGNED tail: a second CNAME crossing into iddg.io, then the final A. No RRSIGs — this is
	// exactly what an insecure zone returns.
	cname2 := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "whois.publicinterestregistry.org.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "target.iddg.io.",
	}
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "target.iddg.io.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IPv4(44, 233, 186, 238),
	}

	mock := &mockChainResolver{answers: map[string][]dns.RR{
		rrsetKey(".", dns.TypeDNSKEY):        root.dnskeyRRset(t),
		rrsetKey("org.", dns.TypeDNSKEY):     org.dnskeyRRset(t),
		rrsetKey("org.", dns.TypeDS):         dsRRsetFor(t, root, org),
		rrsetKey("pir.org.", dns.TypeDNSKEY): pir.dnskeyRRset(t),
		rrsetKey("pir.org.", dns.TypeDS):     dsRRsetFor(t, org, pir),
	}}

	rootDS := root.ksk.ToDS(dns.SHA256)
	digest, err := hex.DecodeString(rootDS.Digest)
	if err != nil {
		t.Fatalf("decode root DS digest: %v", err)
	}
	v := New(true, false)
	v.SetTrustAnchors([]TrustAnchor{{
		KeyTag:     root.ksk.KeyTag(),
		Algorithm:  root.ksk.Algorithm,
		DigestType: dns.SHA256,
		Digest:     digest,
	}})
	v.SetResolver(mock)

	// Answer order as a real resolver returns it: signed CNAME (+RRSIG), unsigned CNAME, unsigned A.
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{cname1, cname1Sig, cname2, a},
	}
	return v, msg
}

// TestChainMixedCNAMEIntoInsecureIsInsecure proves the Issue 30 fix: a CNAME chain whose signed head
// validates but whose tail is UNSIGNED (lands in an insecure zone) is treated as INSECURE. It must
// NOT SERVFAIL, and — critically — it must NOT come back AD-authenticated. ValidateResponse returns a
// distinct "insecure" signal (see errInsecureAnswer) so the server can withhold the AD bit.
func TestChainMixedCNAMEIntoInsecureIsInsecure(t *testing.T) {
	v, msg := mixedCNAMEChainFixture(t)
	err := v.ValidateResponse(msg)
	if err == nil {
		t.Fatal("mixed CNAME chain into an insecure zone must NOT return nil (that would AD-assert an unsigned answer)")
	}
	if !IsInsecure(err) {
		t.Fatalf("expected insecure signal (no SERVFAIL, no AD), got: %v", err)
	}
}
