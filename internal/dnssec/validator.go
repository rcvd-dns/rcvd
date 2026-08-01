// SPDX-License-Identifier: MIT
package dnssec

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// Validator validates DNSSEC signatures on DNS responses.
// Uses miekg/dns RRSIG.Verify() for full cryptographic verification.
// Optionally checks root KSKs against embedded trust anchors.
type Validator struct {
	enabled      bool
	validateAll  bool
	trustAnchors []TrustAnchor // root KSK trust anchors (from root-anchors.xml)

	// fetcher + keyCache power the chain-of-trust walk (chain.go). When fetcher is nil the
	// validator falls back to inline-key verification only (the legacy single-message mode).
	fetcher  keyFetcher
	keyCache *rrsetCache
}

// New creates a new DNSSEC validator.
// trustAnchors may be nil (disables root anchor verification).
func New(enabled bool, validateAll bool) *Validator {
	return &Validator{
		enabled:     enabled,
		validateAll: validateAll,
		keyCache:    newRRsetCache(),
	}
}

// SetResolver wires the encrypted upstream resolver the validator uses to FETCH DNSKEY/DS
// RRsets during chain-of-trust validation (chain.go). Without it, the validator can only
// verify signatures whose signing DNSKEY is already present in the response message.
// All fetches reuse this encrypted chain — no cleartext, no new egress path.
func (v *Validator) SetResolver(r keyFetcher) {
	v.fetcher = r
}

// SetTrustAnchors loads root trust anchors for KSK verification.
// Call after New() with the result of ParseRootAnchors().
func (v *Validator) SetTrustAnchors(anchors []TrustAnchor) {
	v.trustAnchors = anchors
}

// ValidateResponse performs full cryptographic DNSSEC validation on a DNS response.
//
// Steps:
//  1. Check for RRSIG records. If absent and validateAll=true → SERVFAIL.
//  2. Group answer RRs into RRsets by (owner name, type).
//  3. For each RRSIG in the answer, find the matching DNSKEY (by keytag/algorithm)
//     in the answer or authority section.
//  4. Call rrsig.Verify(dnskey, rrset) — full RSA/ECDSA/Ed25519 verification via miekg/dns.
//  5. If the signing key is a root KSK (flags=257, zone=".") and trust anchors are
//     loaded, verify the DNSKEY digest matches a known root anchor.
//
// Returns nil if valid, error if any check fails.
func (v *Validator) ValidateResponse(msg *dns.Msg) error {
	if !v.enabled || msg == nil {
		return nil
	}

	if len(msg.Answer) == 0 {
		return nil
	}

	// Collect all RRs across answer + authority sections for DNSKEY lookup
	allRRs := make([]dns.RR, 0, len(msg.Answer)+len(msg.Ns))
	allRRs = append(allRRs, msg.Answer...)
	allRRs = append(allRRs, msg.Ns...)

	// Find all RRSIGs in the answer
	var rrsigs []*dns.RRSIG
	for _, rr := range msg.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			rrsigs = append(rrsigs, sig)
		}
	}

	// If no RRSIGs present, the answer is UNSIGNED. Two outcomes, never "secure":
	//   - validateAll: the operator demanded every answer be signed → treat the absence as BOGUS.
	//   - otherwise:   the zone simply isn't signed (e.g. docker.io — signed at the zone but its .io
	//                  parent publishes no DS, so the A answer arrives without RRSIGs). That is the
	//                  INSECURE state (RFC 4035 §4.3), NOT secure. Return the answer but WITHOUT the
	//                  AD bit. Returning nil here was the latent bug behind docker.io coming back
	//                  AD-stamped: nil means "validated" to the caller, which then set AD on an
	//                  unsigned answer. errInsecureAnswer serves it correctly, un-authenticated.
	if len(rrsigs) == 0 {
		if v.validateAll {
			return fmt.Errorf("DNSSEC: no RRSIG records in response (validateAll enabled)")
		}
		return errInsecureAnswer
	}

	// Build RRsets: map of "owner/type" → []dns.RR
	rrsets := buildRRsets(msg.Answer)

	// Track which answer RRsets are covered by (and pass) a signature. Any answer RRset left
	// unsigned means the response is only PARTIALLY authenticated — the classic case is a CNAME
	// chain whose signed head validates but whose tail crosses into an unsigned zone (Issue 30,
	// whois.pir.org → …publicinterestregistry.org → iddg.io). That is INSECURE, not secure: we
	// must NOT let it come back AD-asserted. We collect coverage here and judge it after the loop.
	validated := make(map[string]bool, len(rrsets))

	// Validate each RRSIG
	for _, rrsig := range rrsigs {
		// Check validity period
		if !rrsig.ValidityPeriod(time.Now()) {
			return fmt.Errorf("DNSSEC: RRSIG for %s type %d is outside validity period (inception=%d expiration=%d)",
				rrsig.Hdr.Name, rrsig.TypeCovered, rrsig.Inception, rrsig.Expiration)
		}

		// Find the RRset this RRSIG covers
		key := rrsetKey(rrsig.Hdr.Name, rrsig.TypeCovered)
		rrset, found := rrsets[key]
		if !found || len(rrset) == 0 {
			// No RRset to verify against — skip (may cover auth section records)
			continue
		}

		// Find the signing DNSKEY (match by keytag + algorithm + signer name).
		// Fast path: the key is co-resident in the message (DNSKEY queries, +dnssec traces).
		signingKey := findDNSKEY(allRRs, rrsig.KeyTag, rrsig.Algorithm, rrsig.SignerName)

		// Chain path: for an ordinary answer (A/AAAA/…), the signer's DNSKEY is NOT in the
		// message. If a resolver is wired, FETCH and authenticate the signer's key set up to
		// a root trust anchor, then pick the key that signed this RRSIG. Without a resolver we
		// cannot proceed — preserve the original hard error (single-message mode).
		if signingKey == nil {
			if v.fetcher == nil {
				return fmt.Errorf("DNSSEC: signing DNSKEY not found (keytag=%d, algorithm=%d, signer=%s)",
					rrsig.KeyTag, rrsig.Algorithm, rrsig.SignerName)
			}
			// The chain fetches carry their own per-fetch 5s deadline (fetchRRset), and the
			// whole walk is bounded overall so a slow/looping signer can't wedge a request.
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			keys, err := v.authenticatedDNSKEYs(ctx, rrsig.SignerName, 0)
			cancel()
			if err != nil {
				// An INSECURE delegation somewhere on the chain (a signed "no DS" from the parent,
				// RFC 4035 §5.4 / RFC 5155 §8.6) means the signer's zone is not anchored to the
				// root. The zone may still sign its own data (docker.io does), but we cannot — and
				// per DNSSEC must not — authenticate it. This is INSECURE, not BOGUS: surface the
				// insecure signal so the answer is returned WITHOUT the AD bit (never SERVFAIL,
				// and — the Issue 30 correction — never AD-asserted either).
				if errors.Is(err, errInsecureDelegation) {
					return errInsecureAnswer
				}
				return err
			}
			for _, k := range keys {
				if k.KeyTag() == rrsig.KeyTag && k.Algorithm == rrsig.Algorithm {
					signingKey = k
					break
				}
			}
			if signingKey == nil {
				return fmt.Errorf("DNSSEC: signer %s has no DNSKEY matching keytag=%d algorithm=%d",
					rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm)
			}
		}

		// Full cryptographic verification using miekg/dns
		if err := rrsig.Verify(signingKey, rrset); err != nil {
			// DIVERGENCE FROM miekg/dns: miekg conflates "I can't load this key/algorithm"
			// (dns.ErrKey/ErrAlg) with a verification failure. rcvd separates them. The former
			// (e.g. pir.org's leading-zero RSASHA1 key) is INSECURE per RFC 4035 §5.2 / RFC 6840
			// §5.2 — we cannot authenticate it, but it is not bogus, so serve it without AD rather
			// than SERVFAIL. Only a genuine bad signature (dns.ErrSig) stays bogus below. See
			// unprocessableKey (nsec3.go) for the full rationale.
			if unprocessableKey(err) {
				return errInsecureAnswer
			}
			return fmt.Errorf("DNSSEC: RRSIG verification failed for %s type %d: %w",
				rrsig.Hdr.Name, rrsig.TypeCovered, err)
		}

		// If this is a root KSK (flags=257, zone ".") and we have trust anchors, verify it
		if len(v.trustAnchors) > 0 && isRootKSK(signingKey) {
			if err := VerifyKeyAgainstAnchors(signingKey, v.trustAnchors); err != nil {
				return fmt.Errorf("DNSSEC: root KSK trust anchor mismatch: %w", err)
			}
		}

		// This RRset is now authenticated. Record it so the post-loop coverage check can tell a
		// fully-signed answer from a partially-signed one.
		validated[key] = true
	}

	// Coverage check (Issue 30): every DATA RRset in the answer must have been authenticated. If any
	// answer RRset carries NO signature — the unsigned tail of a CNAME chain that crossed into an
	// unsigned zone — the response is INSECURE, not secure. Return it to the client but WITHOUT the
	// AD bit. This is not bogus (the signed portion verified fine), so it must never become SERVFAIL.
	//
	// DNSKEY/DS RRsets are EXCLUDED from the requirement: they are verification material, not the
	// client's requested payload, and a co-resident DNSKEY (fast-path key, +dnssec traces) is not
	// itself the data whose authenticity we gate here — its trust is established by the chain walk /
	// trust anchors, not by a sibling RRSIG in this same message.
	for key, rrset := range rrsets {
		if len(rrset) == 0 {
			continue
		}
		switch rrset[0].Header().Rrtype {
		case dns.TypeDNSKEY, dns.TypeDS:
			continue // verification material, not gated answer data
		}
		if !validated[key] {
			return errInsecureAnswer
		}
	}

	return nil
}

// buildRRsets groups RRs from an answer section into RRsets keyed by "owner/type".
// RRSIGs are excluded (they are the signatures, not the data).
func buildRRsets(rrs []dns.RR) map[string][]dns.RR {
	sets := make(map[string][]dns.RR)
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		k := rrsetKey(rr.Header().Name, rr.Header().Rrtype)
		sets[k] = append(sets[k], rr)
	}
	return sets
}

// rrsetKey returns a map key for (owner name, rrtype).
func rrsetKey(name string, rrtype uint16) string {
	return fmt.Sprintf("%s/%d", dns.CanonicalName(name), rrtype)
}

// findDNSKEY searches all RRs for a DNSKEY matching the given keytag, algorithm, and owner name.
func findDNSKEY(rrs []dns.RR, keyTag uint16, algorithm uint8, signerName string) *dns.DNSKEY {
	for _, rr := range rrs {
		key, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		if key.KeyTag() == keyTag &&
			key.Algorithm == algorithm &&
			dns.Fqdn(dns.CanonicalName(key.Hdr.Name)) == dns.Fqdn(dns.CanonicalName(signerName)) {
			return key
		}
	}
	return nil
}

// isRootKSK returns true if the DNSKEY is a root zone KSK (SEP flag set, zone=".").
func isRootKSK(key *dns.DNSKEY) bool {
	return key.Hdr.Name == "." &&
		key.Flags&dns.SEP != 0 &&
		key.Flags&dns.ZONE != 0
}

// SupportedAlgorithms returns a list of DNSSEC algorithms supported by miekg/dns.
func SupportedAlgorithms() []uint8 {
	return []uint8{
		dns.RSAMD5,
		dns.RSASHA1,
		dns.RSASHA256,
		dns.RSASHA512,
		dns.ECDSAP256SHA256,
		dns.ECDSAP384SHA384,
		dns.ED25519,
	}
}

// IsSupported returns true if an algorithm is supported.
func IsSupported(algorithm uint8) bool {
	for _, alg := range SupportedAlgorithms() {
		if alg == algorithm {
			return true
		}
	}
	return false
}

// Stats returns DNSSEC validation statistics (placeholder for future implementation).
type Stats struct {
	ValidResponses    int
	InvalidResponses  int
	UnsignedResponses int
}

// GetStats returns current validation statistics.
func (v *Validator) GetStats() Stats {
	return Stats{}
}
