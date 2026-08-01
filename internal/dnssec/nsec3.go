// SPDX-License-Identifier: MIT
package dnssec

import (
	"errors"

	"github.com/miekg/dns"
)

// nsec3.go proves ONE specific thing: that a delegation has NO DS record and is therefore an
// INSECURE (not bogus) delegation. This is the missing case that made the chain walk fail-closed
// to SERVFAIL for a whole class of zones (Issue 30, e.g. docker.io — a signed zone whose .io parent
// publishes no DS for it, so it can't be anchored to the root).
//
// Background: when the chain walk fetches a child's DS RRset (chain.go authenticatedDNSKEYs) and
// the parent answers NOERROR with ZERO DS records, that is not an error — it is an authenticated
// statement that the child is unsigned. The parent proves the absence with NSEC/NSEC3 records in
// the AUTHORITY section. We MUST verify that proof (RFC 4035 §5.4, RFC 5155 §8) before trusting
// "insecure"; a validator that accepts an unsigned or forged denial would let an attacker strip
// DNSSEC off any zone. Once proven, the descendant answer is treated as insecure: return it with
// NO AD bit, never SERVFAIL.
//
// We support opt-out (RFC 5155 §6/§8.9), the common case for TLDs like .io/.com, plus the plain
// matching-NSEC3 case (delegation present, DS absent) and the classic NSEC case (RFC 4035 §5.4).

// errInsecureDelegation is the sentinel the DS branch returns when the parent has AUTHENTICATED
// that the child has no DS. It is caught in ValidateResponse and converted to the INSECURE result
// (errInsecureAnswer), NOT propagated as a validation failure.
var errInsecureDelegation = errors.New("DNSSEC: insecure delegation (no DS, authenticated denial)")

// errInsecureAnswer is the result ValidateResponse returns for an answer that is INSECURE rather
// than secure-or-bogus: the response is legitimate and must be returned to the client, but it is
// NOT authenticated, so the AD bit MUST be withheld (RFC 4035 §4.3 — "Insecure" state). This is
// distinct from nil (fully validated → AD set) and from any other error (bogus → SERVFAIL). Two
// sources feed it: (1) an authenticated no-DS delegation on the chain walk (errInsecureDelegation),
// and (2) an answer RRset that carries NO signature at all — e.g. the unsigned tail of a CNAME
// chain that crosses into an unsigned zone (Issue 30, whois.pir.org).
var errInsecureAnswer = errors.New("DNSSEC: insecure (answer not signed; return without AD)")

// IsInsecure reports whether err is the INSECURE result: the answer should be returned to the
// client WITHOUT the AD bit, and MUST NOT be turned into SERVFAIL. Callers use this to distinguish
// "insecure but serve it" from "bogus, fail closed".
func IsInsecure(err error) bool {
	return errors.Is(err, errInsecureAnswer) || errors.Is(err, errInsecureDelegation)
}

// unprocessableKey reports whether a miekg/dns *.Verify() error means the library COULD NOT PROCESS
// the signing key or algorithm — as opposed to a signature that was processed and found invalid.
//
//	dns.ErrKey    ("bad key")        — publicKeyRSA/ECDSA/ED25519 returned nil: the key blob failed
//	                                    miekg's own parse guards (e.g. an RSA modulus/exponent with a
//	                                    prohibited leading 0x00 byte, or below its 512-bit floor). The
//	                                    signature itself was never checked.
//	dns.ErrAlg    ("bad algorithm")  — the DNSSEC algorithm number is one miekg does not implement.
//	dns.ErrKeyAlg ("bad key algorithm")
//
// vs. dns.ErrSig ("bad signature") — the key parsed and the algorithm ran, but the crypto did NOT
// verify. That is a genuine authentication failure and stays BOGUS.
//
// WHY THIS IS A DIVERGENCE, AND WHY IT IS SPEC-CORRECT:
// miekg/dns is a library, not a validating resolver. Its Verify() conflates "I can't load this key"
// with a hard error, which — if we let it bubble up as a validation failure — turns real, correctly
// signed zones into SERVFAIL. The live example is pir.org: a legacy RSASHA1 (alg 5) DNSKEY whose
// modulus carries a leading zero byte. miekg refuses to load the key (dns.ErrKey), so the signature
// is never even tested; the rest of the internet resolves it fine. Per RFC 4035 §5.2 and RFC 6840
// §5.2, a validator that cannot process the signing algorithm/key MUST treat the data as INSECURE
// (unsigned) — NOT bogus. So when the failure is "unprocessable key/algorithm" we convert it to the
// insecure result (served without AD); only ErrSig-class failures remain bogus. This is rcvd being
// a production tool where the library is merely a component. See repos/CLAUDE.md (miekg policy) and
// ISSUES.md 30.
func unprocessableKey(err error) bool {
	return errors.Is(err, dns.ErrKey) ||
		errors.Is(err, dns.ErrAlg) ||
		errors.Is(err, dns.ErrKeyAlg)
}

// provesNoDS reports whether the authority section of a signed NODATA-DS response authenticates
// that `child` has no DS record — i.e. that `child` is an insecure delegation.
//
// It requires:
//  1. every NSEC/NSEC3 relied upon to be signed by one of parentKeys (already authenticated up to
//     the root anchor by the caller), and
//  2. the RFC 5155 §8.6 / RFC 4035 §5.4 denial to actually hold for `child`'s DS.
//
// parentKeys are the parent zone's authenticated DNSKEYs (the zone that owns the delegation).
func provesNoDS(child string, authority []dns.RR, parentKeys []*dns.DNSKEY) bool {
	child = dns.CanonicalName(child)

	// Partition the authority section into denial records and their covering RRSIGs.
	var (
		nsec3s []*dns.NSEC3
		nsecs  []*dns.NSEC
		sigs   []*dns.RRSIG
	)
	for _, rr := range authority {
		switch t := rr.(type) {
		case *dns.NSEC3:
			nsec3s = append(nsec3s, t)
		case *dns.NSEC:
			nsecs = append(nsecs, t)
		case *dns.RRSIG:
			sigs = append(sigs, t)
		}
	}

	// Helper: an NSEC/NSEC3 record is only usable if it is covered by a valid RRSIG that verifies
	// against one of the parent's authenticated keys. We verify per-record so a forged extra record
	// can't be smuggled in alongside a genuine one.
	verified := func(rr dns.RR) bool {
		return verifyDenialRecord(rr, sigs, parentKeys)
	}

	if len(nsec3s) > 0 {
		return nsec3ProvesNoDS(child, nsec3s, verified)
	}
	if len(nsecs) > 0 {
		return nsecProvesNoDS(child, nsecs, verified)
	}
	return false
}

// nsec3ProvesNoDS implements the RFC 5155 §8.6 authenticated denial of a DS RRset.
//
// Two accepted shapes:
//
//	(a) Matching NSEC3: an NSEC3 whose owner MATCHES the child name, with NS set in its type bitmap
//	    but DS and SOA both CLEAR. That is exactly "a delegation exists here and it has no DS" —
//	    an insecure delegation, no opt-out needed.
//
//	(b) Opt-out: an NSEC3 with the Opt-Out flag set that COVERS the child name, together with a
//	    matching NSEC3 for the closest provable encloser (RFC 5155 §8.9). Under opt-out the parent
//	    is permitted to omit a matching NSEC3 for an insecure delegation, so a covering opt-out
//	    NSEC3 is sufficient proof that no DS exists.
func nsec3ProvesNoDS(child string, nsec3s []*dns.NSEC3, verified func(dns.RR) bool) bool {
	// (a) Matching NSEC3 for the child: NS present, DS and SOA absent.
	for _, n3 := range nsec3s {
		if !verified(n3) {
			continue
		}
		if n3.Match(child) {
			if bitmapHas(n3.TypeBitMap, dns.TypeNS) &&
				!bitmapHas(n3.TypeBitMap, dns.TypeDS) &&
				!bitmapHas(n3.TypeBitMap, dns.TypeSOA) {
				return true
			}
			// A matching NSEC3 that DOES assert DS (or is the apex/SOA) is not a no-DS proof.
			return false
		}
	}

	// (b) Opt-out: a verified opt-out NSEC3 that covers the child, plus a verified NSEC3 that
	// matches the closest provable encloser. For a DS query the child IS the delegation point, so
	// the closest encloser is one of its ancestors; we accept any verified matching NSEC3 for an
	// ancestor of the child as the closest-encloser witness (the parent apex NSEC3 in practice).
	coveredByOptOut := false
	for _, n3 := range nsec3s {
		if !verified(n3) {
			continue
		}
		if n3.Flags&1 == 1 && n3.Cover(child) { // bit 0 = Opt-Out
			coveredByOptOut = true
			break
		}
	}
	if !coveredByOptOut {
		return false
	}
	for _, n3 := range nsec3s {
		if !verified(n3) {
			continue
		}
		if closestEncloserMatch(child, n3) {
			return true
		}
	}
	return false
}

// closestEncloserMatch reports whether n3 matches some ancestor of child (the closest provable
// encloser witness for the opt-out proof). We walk child's ancestor names and test Match on each.
func closestEncloserMatch(child string, n3 *dns.NSEC3) bool {
	name := dns.CanonicalName(child)
	for name != "" {
		if n3.Match(name) {
			return true
		}
		next := parentZone(name)
		if next == name {
			break
		}
		name = next
	}
	return false
}

// nsecProvesNoDS handles the classic (non-hashed) NSEC denial of a DS, RFC 4035 §5.4:
// an NSEC whose owner MATCHES the child, with NS set and DS + SOA clear, is an insecure delegation.
func nsecProvesNoDS(child string, nsecs []*dns.NSEC, verified func(dns.RR) bool) bool {
	for _, n := range nsecs {
		if !verified(n) {
			continue
		}
		if dns.CanonicalName(n.Hdr.Name) == child {
			if bitmapHas(n.TypeBitMap, dns.TypeNS) &&
				!bitmapHas(n.TypeBitMap, dns.TypeDS) &&
				!bitmapHas(n.TypeBitMap, dns.TypeSOA) {
				return true
			}
			return false
		}
	}
	return false
}

// verifyDenialRecord returns true if rr is covered by an in-period RRSIG that verifies against one
// of keys. It reuses the same crypto path as the rest of the validator (verifyRRsetWithKeySet), so
// there is one verification implementation, not two.
func verifyDenialRecord(rr dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY) bool {
	rrtype := rr.Header().Rrtype
	owner := dns.CanonicalName(rr.Header().Name)
	var covering []*dns.RRSIG
	for _, sig := range sigs {
		if sig.TypeCovered == rrtype && dns.CanonicalName(sig.Hdr.Name) == owner {
			covering = append(covering, sig)
		}
	}
	if len(covering) == 0 {
		return false
	}
	return verifyRRsetWithKeySet([]dns.RR{rr}, covering, keys) == nil
}

// bitmapHas reports whether t is present in an NSEC/NSEC3 type bitmap.
func bitmapHas(bitmap []uint16, t uint16) bool {
	for _, b := range bitmap {
		if b == t {
			return true
		}
	}
	return false
}
