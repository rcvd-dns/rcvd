// SPDX-License-Identifier: MIT
package dnssec

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/rcvd-dns/rcvd/internal/resolver"
)

// chain.go adds the missing subsystem the stateless single-message validator never had:
// the ability to FETCH a signer zone's DNSKEY RRset and a delegation's DS RRset over the
// encrypted upstream, so an ordinary A/AAAA answer (whose RRSIG's signing DNSKEY is NOT
// co-resident in the message) can actually be validated. See validator.go ValidateResponse.
//
// Import direction: dnssec -> resolver is one-way and cycle-free (resolver imports only
// config + statistics, never dnssec — verified). All fetches reuse the SAME encrypted
// resolver chain (DoQ->DoT->DoH), so the zero-cleartext invariant is preserved: no new
// egress path, no plaintext DNS.

// keyFetcher is the minimal slice of resolver.Resolver the chain walk needs. Keeping it a
// local interface (rather than storing *resolver.Resolver directly) keeps tests trivial —
// a mock returning canned DNSKEY/DS answers satisfies it without any transport.
type keyFetcher interface {
	Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
}

// Compile-time assertion that the real resolver satisfies the fetcher.
var _ keyFetcher = (resolver.Resolver)(nil)

// rrsetCacheEntry is a fetched, positively-verified RRset held until its TTL expires.
type rrsetCacheEntry struct {
	rrs       []dns.RR
	expiresAt time.Time
}

// rrsetCache is a tiny TTL-aware cache for DNSKEY/DS RRsets keyed by "zone/type". It exists
// solely to stop a per-query fetch storm: every signed answer would otherwise re-fetch the
// whole chain (zone DNSKEY, parent DS, ... , root) on every lookup. Bounded by TTL only;
// DNSKEY/DS sets are few and small, so no size cap is needed for a forwarder's key set.
type rrsetCache struct {
	mu      sync.Mutex
	entries map[string]rrsetCacheEntry
}

func newRRsetCache() *rrsetCache {
	return &rrsetCache{entries: make(map[string]rrsetCacheEntry)}
}

func (c *rrsetCache) get(zone string, rrtype uint16) ([]dns.RR, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[rrsetKey(zone, rrtype)]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		delete(c.entries, rrsetKey(zone, rrtype))
		return nil, false
	}
	return e.rrs, true
}

func (c *rrsetCache) put(zone string, rrtype uint16, rrs []dns.RR, ttl uint32) {
	if len(rrs) == 0 {
		return
	}
	// Clamp TTL to a sane floor/ceiling: never cache < 60s (avoid thrash on tiny TTLs)
	// nor > 24h (root/TLD keys roll on that order; bound staleness).
	const minTTL, maxTTL = 60, 86400
	if ttl < minTTL {
		ttl = minTTL
	} else if ttl > maxTTL {
		ttl = maxTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[rrsetKey(zone, rrtype)] = rrsetCacheEntry{
		rrs:       rrs,
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

// minTTL returns the smallest TTL across an RRset (RFC 2181 §5.2 — an RRset is served with
// a single TTL; use the minimum so we never over-cache).
func minRRsetTTL(rrs []dns.RR) uint32 {
	var min uint32
	for i, rr := range rrs {
		t := rr.Header().Ttl
		if i == 0 || t < min {
			min = t
		}
	}
	return min
}

// fetchRRset asks the encrypted upstream for (zone, rrtype) with DO=1, returning the RRset
// of exactly that type from the answer (RRSIGs are handled separately by the caller, which
// re-reads them from the same message). Results are cached by TTL. A nil fetcher (validator
// constructed without a resolver) is a hard error — the caller must not attempt a chain walk
// in that state.
func (v *Validator) fetchRRset(ctx context.Context, zone string, rrtype uint16) (rrset []dns.RR, sigs []*dns.RRSIG, err error) {
	if v.fetcher == nil {
		return nil, nil, fmt.Errorf("DNSSEC: no resolver wired for %s/%s fetch", zone, dns.TypeToString[rrtype])
	}
	if cached, ok := v.keyCache.get(zone, rrtype); ok {
		rrset, sigs = splitRRSIGs(cached, rrtype)
		return rrset, sigs, nil
	}

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(zone), rrtype)
	q.SetEdns0(4096, true) // DO=1 — we need the RRSIGs

	fctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := v.fetcher.Resolve(fctx, q)
	if err != nil {
		return nil, nil, fmt.Errorf("DNSSEC: fetch %s/%s: %w", zone, dns.TypeToString[rrtype], err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		rc := -1
		if resp != nil {
			rc = resp.Rcode
		}
		return nil, nil, fmt.Errorf("DNSSEC: fetch %s/%s returned rcode %d", zone, dns.TypeToString[rrtype], rc)
	}

	// Keep the whole answer (typed RRs + their RRSIGs) so the cache preserves the signatures
	// too — a re-fetch from cache must still be verifiable.
	var keep []dns.RR
	for _, rr := range resp.Answer {
		switch rr.Header().Rrtype {
		case rrtype, dns.TypeRRSIG:
			keep = append(keep, rr)
		}
	}
	rrset, sigs = splitRRSIGs(keep, rrtype)
	if len(rrset) == 0 {
		return nil, nil, fmt.Errorf("DNSSEC: fetch %s/%s: no %s records in answer",
			zone, dns.TypeToString[rrtype], dns.TypeToString[rrtype])
	}
	v.keyCache.put(zone, rrtype, keep, minRRsetTTL(rrset))
	return rrset, sigs, nil
}

// fetchDSResponse fetches (zone, DS) with DO=1 and returns the WHOLE response message so the
// caller can inspect BOTH the answer (a present DS RRset = secure delegation) and the authority
// section (NSEC/NSEC3 proving DS absence = insecure delegation). Unlike fetchRRset it does NOT
// treat a NODATA answer as an error — distinguishing "no DS" from "fetch failed" is the whole
// point (Issue 30). A present DS RRset is cached (keyed zone/DS) to preserve anti-storm behavior;
// a NODATA denial is small and rare enough to re-fetch.
func (v *Validator) fetchDSResponse(ctx context.Context, zone string) (*dns.Msg, error) {
	if v.fetcher == nil {
		return nil, fmt.Errorf("DNSSEC: no resolver wired for %s/DS fetch", zone)
	}
	if cached, ok := v.keyCache.get(zone, dns.TypeDS); ok {
		m := new(dns.Msg)
		m.Rcode = dns.RcodeSuccess
		m.Answer = cached
		return m, nil
	}

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(zone), dns.TypeDS)
	q.SetEdns0(4096, true) // DO=1 — we need the RRSIGs (over the DS or over the NSEC/NSEC3)

	fctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := v.fetcher.Resolve(fctx, q)
	if err != nil {
		return nil, fmt.Errorf("DNSSEC: fetch %s/DS: %w", zone, err)
	}
	if resp == nil {
		return nil, fmt.Errorf("DNSSEC: fetch %s/DS: nil response", zone)
	}

	// Cache only a positive DS RRset (+ its RRSIGs). NODATA denials are left uncached.
	if dsRRs, _ := splitRRSIGs(resp.Answer, dns.TypeDS); len(dsRRs) > 0 {
		var keep []dns.RR
		for _, rr := range resp.Answer {
			switch rr.Header().Rrtype {
			case dns.TypeDS, dns.TypeRRSIG:
				keep = append(keep, rr)
			}
		}
		v.keyCache.put(zone, dns.TypeDS, keep, minRRsetTTL(dsRRs))
	}
	return resp, nil
}

// maxChainDepth bounds the delegation walk (. -> tld -> zone -> sub...). A pathological or
// looping response can't spin us forever; real names are far shallower than this.
const maxChainDepth = 24

// authenticatedDNSKEYs returns the DNSKEY RRset for zone, PROVEN authentic all the way up to
// a configured root trust anchor. It:
//  1. fetches zone/DNSKEY (with RRSIGs),
//  2. self-verifies the DNSKEY RRset with a key inside it that is itself trusted — either a
//     root KSK matching an anchor (base case) or a key whose DS is published+verified in the
//     parent (recursive case),
//  3. returns the verified keys so the caller can select the ZSK that signed the real answer.
//
// Results are implicitly cached because fetchRRset caches the DNSKEY/DS RRsets it retrieves.
func (v *Validator) authenticatedDNSKEYs(ctx context.Context, zone string, depth int) ([]*dns.DNSKEY, error) {
	if depth > maxChainDepth {
		return nil, fmt.Errorf("DNSSEC: chain depth exceeded at %s", zone)
	}
	zone = dns.CanonicalName(zone)

	dnskeyRRs, dnskeySigs, err := v.fetchRRset(ctx, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	keys := make([]*dns.DNSKEY, 0, len(dnskeyRRs))
	for _, rr := range dnskeyRRs {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("DNSSEC: %s DNSKEY RRset empty", zone)
	}

	// Establish which keys in this RRset are trusted secure-entry-points (SEPs).
	//   - root zone: a key matching a configured trust anchor.
	//   - non-root: a key whose DS digest is published (and verified) in the parent zone.
	var trustedSEPs []*dns.DNSKEY
	if zone == "." {
		if len(v.trustAnchors) == 0 {
			return nil, fmt.Errorf("DNSSEC: no root trust anchors configured")
		}
		for _, k := range keys {
			if VerifyKeyAgainstAnchors(k, v.trustAnchors) == nil {
				trustedSEPs = append(trustedSEPs, k)
			}
		}
		if len(trustedSEPs) == 0 {
			return nil, fmt.Errorf("DNSSEC: no root DNSKEY matched a trust anchor")
		}
	} else {
		// Fetch the DS response WHOLE (answer + authority) — the authority section carries the
		// NSEC/NSEC3 records that prove an INSECURE delegation when no DS exists.
		dsResp, err := v.fetchDSResponse(ctx, zone)
		if err != nil {
			return nil, fmt.Errorf("DNSSEC: %s DS: %w", zone, err)
		}
		// The parent's keys authenticate EITHER the DS RRset (secure delegation) or the NSEC/NSEC3
		// denial of it (insecure delegation). Get them first, verified up to the root anchor.
		parent := parentZone(zone)
		parentKeys, err := v.authenticatedDNSKEYs(ctx, parent, depth+1)
		if err != nil {
			return nil, err
		}

		dsRRs, dsSigs := splitRRSIGs(dsResp.Answer, dns.TypeDS)
		if len(dsRRs) == 0 {
			// No DS in the answer. This is either an authenticated "no DS → insecure delegation"
			// (RFC 4035 §5.4 / RFC 5155 §8.6) or a genuine failure. Verify the denial against the
			// parent's authenticated keys; if it holds, signal insecure (NOT bogus/SERVFAIL).
			if dsResp.Rcode == dns.RcodeSuccess && provesNoDS(zone, dsResp.Ns, parentKeys) {
				return nil, errInsecureDelegation
			}
			return nil, fmt.Errorf("DNSSEC: %s DS absent and not proven insecure (rcode %d)",
				zone, dsResp.Rcode)
		}
		// Secure delegation: the DS RRset must itself be authentic — it lives in the PARENT zone
		// and is signed by the parent's keys. Verify it before trusting it.
		if err := verifyRRsetWithKeySet(dsRRs, dsSigs, parentKeys); err != nil {
			// Same DIVERGENCE FROM miekg/dns as the DNSKEY self-sig below: if miekg cannot process
			// (dns.ErrKey/ErrAlg) the parent key that signed this DS RRset, we cannot authenticate
			// the secure delegation. rcvd treats that as INSECURE (RFC 6840 §5.2), not bogus, rather
			// than letting the library's inability to load a key fail the whole lookup. A real bad
			// signature (dns.ErrSig) is not unprocessableKey and stays a hard error → BOGUS.
			if unprocessableKey(err) {
				return nil, errInsecureDelegation
			}
			return nil, fmt.Errorf("DNSSEC: %s DS not authentic: %w", zone, err)
		}
		// Now match each DS against a DNSKEY in this zone — those become our trusted SEPs.
		for _, rr := range dsRRs {
			ds, ok := rr.(*dns.DS)
			if !ok {
				continue
			}
			for _, k := range keys {
				if k.KeyTag() == ds.KeyTag && k.Algorithm == ds.Algorithm {
					computed := k.ToDS(ds.DigestType)
					if computed != nil && equalHexDigest(computed.Digest, ds.Digest) {
						trustedSEPs = append(trustedSEPs, k)
					}
				}
			}
		}
		if len(trustedSEPs) == 0 {
			return nil, fmt.Errorf("DNSSEC: no %s DNSKEY matched a parent DS", zone)
		}
	}

	// The whole DNSKEY RRset must be self-signed by one of the trusted SEPs (RFC 4035 §5.2).
	// Once that holds, EVERY key in the RRset (KSK + ZSKs) is authenticated for this zone.
	if err := verifyRRsetWithKeySet(dnskeyRRs, dnskeySigs, trustedSEPs); err != nil {
		// DIVERGENCE FROM miekg/dns: miekg's RRSIG.Verify returns dns.ErrKey ("bad key") when it
		// cannot even LOAD the signing key (e.g. pir.org's legacy RSASHA1 DNSKEY with a leading-zero
		// modulus byte, which miekg's publicKeyRSA guard rejects), so the self-signature is never
		// actually tested. Taking that as a validation failure would SERVFAIL a zone the rest of the
		// internet resolves. rcvd is a production resolver, not the library: per RFC 4035 §5.2 /
		// RFC 6840 §5.2 an algorithm/key the validator cannot process makes the zone INSECURE, not
		// bogus. So we convert the unprocessable-key case to an insecure delegation (answer served
		// without AD). A genuine bad signature (dns.ErrSig) is NOT unprocessableKey and falls through
		// as a hard error → BOGUS. See unprocessableKey (nsec3.go) + repos/CLAUDE.md miekg policy.
		if unprocessableKey(err) {
			return nil, errInsecureDelegation
		}
		return nil, fmt.Errorf("DNSSEC: %s DNSKEY RRset self-signature: %w", zone, err)
	}
	return keys, nil
}

// verifyRRsetWithKeySet performs the cryptographic check: at least one RRSIG over rrset must
// verify under one of keys (matched by keytag+algorithm) and be within its validity period.
//
// On failure it returns the LAST underlying miekg verify error (wrapped) rather than a flat
// "nothing verified" string, so callers can classify it: an unprocessable key/algorithm
// (dns.ErrKey/ErrAlg — see unprocessableKey) must degrade to INSECURE, whereas a genuine bad
// signature (dns.ErrSig) is BOGUS. errors.Is on the returned error sees through the wrap.
func verifyRRsetWithKeySet(rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY) error {
	if len(sigs) == 0 {
		return fmt.Errorf("no RRSIG present")
	}
	var lastErr error
	for _, sig := range sigs {
		if !sig.ValidityPeriod(time.Now()) {
			continue
		}
		for _, k := range keys {
			if k.KeyTag() != sig.KeyTag || k.Algorithm != sig.Algorithm {
				continue
			}
			if err := sig.Verify(k, rrset); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
	}
	if lastErr != nil {
		return fmt.Errorf("no RRSIG verified against %d candidate key(s): %w", len(keys), lastErr)
	}
	return fmt.Errorf("no RRSIG verified against %d candidate key(s)", len(keys))
}

// parentZone returns the immediate parent of a zone name ("a.b.c." -> "b.c."; "c." -> ".").
func parentZone(zone string) string {
	zone = dns.CanonicalName(zone)
	if zone == "." {
		return "."
	}
	labels := dns.SplitDomainName(zone)
	if len(labels) <= 1 {
		return "."
	}
	return dns.Fqdn(dns.CanonicalName(joinLabels(labels[1:])))
}

func joinLabels(labels []string) string {
	out := ""
	for i, l := range labels {
		if i > 0 {
			out += "."
		}
		out += l
	}
	return out
}

// equalHexDigest compares two hex-encoded DS digests case-insensitively.
func equalHexDigest(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// splitRRSIGs partitions a mixed RR slice into the RRset of the requested type and the
// RRSIGs that cover that type.
func splitRRSIGs(rrs []dns.RR, rrtype uint16) (rrset []dns.RR, sigs []*dns.RRSIG) {
	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok {
			if sig.TypeCovered == rrtype {
				sigs = append(sigs, sig)
			}
			continue
		}
		if rr.Header().Rrtype == rrtype {
			rrset = append(rrset, rr)
		}
	}
	return rrset, sigs
}
