// SPDX-License-Identifier: MIT
package dnssec

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

// miekg_divergence_test.go guards the deliberate DIVERGENCE FROM miekg/dns documented on
// unprocessableKey (nsec3.go): miekg's RRSIG.Verify returns dns.ErrKey / dns.ErrAlg when it cannot
// even LOAD the signing key or run the algorithm (as opposed to running it and getting a wrong
// answer, dns.ErrSig). rcvd treats "unprocessable key/algorithm" as INSECURE (RFC 4035 §5.2 /
// RFC 6840 §5.2), NOT bogus. The live trigger is pir.org's legacy RSASHA1 DNSKEY whose modulus has
// a leading zero byte, which miekg's publicKeyRSA guard rejects. These tests keep that mapping — and
// the ErrSig-stays-bogus boundary — from silently regressing.

// TestUnprocessableKeyClassification pins the exact miekg sentinels we treat as "can't process the
// key/algorithm" vs. the one we must NOT (a genuine bad signature).
func TestUnprocessableKeyClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"ErrKey (bad key) -> unprocessable", dns.ErrKey, true},
		{"ErrAlg (bad algorithm) -> unprocessable", dns.ErrAlg, true},
		{"ErrKeyAlg (bad key algorithm) -> unprocessable", dns.ErrKeyAlg, true},
		{"ErrSig (bad signature) -> NOT unprocessable (stays bogus)", dns.ErrSig, false},
		{"nil -> not unprocessable", nil, false},
		{"unrelated error -> not unprocessable", errors.New("some other failure"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := unprocessableKey(tc.err); got != tc.want {
				t.Fatalf("unprocessableKey(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestUnprocessableKeySeesThroughWrap confirms the classifier still works after the error is wrapped
// with %w, exactly as verifyRRsetWithKeySet (chain.go) wraps the last verify error before returning
// it. Without this, the chain.go call sites could not distinguish unprocessable-key from bad-sig.
func TestUnprocessableKeySeesThroughWrap(t *testing.T) {
	wrapped := fmt.Errorf("no RRSIG verified against 2 candidate key(s): %w", dns.ErrKey)
	if !unprocessableKey(wrapped) {
		t.Fatalf("a %%w-wrapped dns.ErrKey must be classified unprocessable, got not")
	}
	wrappedSig := fmt.Errorf("no RRSIG verified against 2 candidate key(s): %w", dns.ErrSig)
	if unprocessableKey(wrappedSig) {
		t.Fatalf("a %%w-wrapped dns.ErrSig must stay bogus, was classified unprocessable")
	}
}

// TestMiekgRejectsShortRSAKey documents WHY the divergence exists at the library level: miekg's
// publicKeyRSA refuses to load an RSA key whose modulus is below its floor, so Verify never tests
// the signature and returns dns.ErrKey. If a future miekg release changes this behavior (e.g. loads
// such keys), this test flags it so we can revisit whether the divergence is still needed.
func TestMiekgRejectsShortRSAKey(t *testing.T) {
	// An RSASHA1 DNSKEY with a deliberately too-short (16-byte) modulus. publicKeyRSA requires the
	// modulus to be >= 64 bytes, so it returns nil and Verify -> dns.ErrKey.
	// Wire format: exponent-length byte (1) + exponent (0x03) + short modulus.
	raw := append([]byte{0x01, 0x03}, make([]byte, 16)...)
	raw[2] = 0x01 // non-zero leading modulus byte (avoid the separate leading-zero rejection path)
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "short.example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA1,
		PublicKey: base64.StdEncoding.EncodeToString(raw),
	}
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: "short.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   []byte{192, 0, 2, 1},
	}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "short.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.RSASHA1,
		Labels:      2,
		OrigTtl:     3600,
		Expiration:  1 << 31, // far future; validity is not what we're testing
		Inception:   0,
		KeyTag:      key.KeyTag(),
		SignerName:  "short.example.",
		Signature:   base64.StdEncoding.EncodeToString([]byte("not-a-real-signature")),
	}

	err := sig.Verify(key, []dns.RR{rr})
	if err == nil {
		t.Fatal("expected miekg Verify to fail on an unloadable short RSA key")
	}
	if !errors.Is(err, dns.ErrKey) {
		t.Fatalf("expected dns.ErrKey (unloadable key), got %v — miekg behavior may have changed", err)
	}
	// The whole point: rcvd classifies this as unprocessable -> INSECURE, not bogus.
	if !unprocessableKey(err) {
		t.Fatalf("short/unloadable RSA key must classify as unprocessable (insecure), got bogus: %v", err)
	}
}
