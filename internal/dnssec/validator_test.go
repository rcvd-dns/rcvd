// SPDX-License-Identifier: MIT
package dnssec

import (
	"crypto"
	"net"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// makeSignedMsg creates a DNS message with a real RRSIG verified by a real DNSKEY.
// The DNSKEY is self-signed for testing using miekg/dns Sign().
func makeSignedMsg(t *testing.T) (*dns.Msg, *dns.DNSKEY) {
	t.Helper()

	// Generate a DNSKEY for example.com. (ZSK)
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     256, // ZSK
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	}
	privKey, err := key.Generate(1024)
	if err != nil {
		t.Fatalf("generate DNSKEY: %v", err)
	}

	aRecord := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.IPv4(93, 184, 216, 34),
	}

	now := time.Now()
	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.RSASHA256,
		Labels:      2,
		OrigTtl:     300,
		Expiration:  uint32(now.Add(24 * time.Hour).Unix()),
		Inception:   uint32(now.Add(-1 * time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  "example.com.",
	}

	if err := rrsig.Sign(privKey.(crypto.Signer), []dns.RR{aRecord}); err != nil {
		t.Fatalf("sign RRSIG: %v", err)
	}

	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{aRecord, rrsig},
	}
	return msg, key
}

// TestValidatorDisabled tests that validation returns nil when disabled.
func TestValidatorDisabled(t *testing.T) {
	v := New(false, false)

	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4(93, 184, 216, 34),
			},
		},
	}

	if err := v.ValidateResponse(msg); err != nil {
		t.Errorf("expected nil when disabled, got %v", err)
	}
}

// TestValidatorEmptyResponse tests validation of empty responses.
func TestValidatorEmptyResponse(t *testing.T) {
	v := New(true, false)

	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{},
	}

	if err := v.ValidateResponse(msg); err != nil {
		t.Errorf("expected nil for empty Answer, got %v", err)
	}
}

// TestValidatorNilResponse tests nil response handling.
func TestValidatorNilResponse(t *testing.T) {
	v := New(true, false)

	if err := v.ValidateResponse(nil); err != nil {
		t.Errorf("expected nil for nil response, got %v", err)
	}
}

// TestValidatorUnsignedPermissive tests unsigned response with validateAll=false.
func TestValidatorUnsignedResponse(t *testing.T) {
	v := New(true, false)

	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4(93, 184, 216, 34),
			},
		},
	}

	// No RRSIG, validateAll=false: the answer is UNSIGNED → INSECURE, not secure. It must be
	// SERVED (not SERVFAIL) but WITHOUT the AD bit (RFC 4035 §4.3). Returning nil here was the
	// latent bug that let docker.io come back AD-stamped; the correct result is errInsecureAnswer,
	// which IsInsecure reports true for and which the caller turns into "serve, clear AD".
	err := v.ValidateResponse(msg)
	if err == nil {
		t.Fatalf("expected insecure (not nil) for unsigned answer in permissive mode")
	}
	if !IsInsecure(err) {
		t.Errorf("expected IsInsecure for unsigned answer, got %v", err)
	}
}

// TestValidatorValidateAllUnsigned tests unsigned response with validateAll=true.
func TestValidatorValidateAllUnsigned(t *testing.T) {
	v := New(true, true)

	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4(93, 184, 216, 34),
			},
		},
	}

	if err := v.ValidateResponse(msg); err == nil {
		t.Error("expected error for unsigned (validateAll=true), got nil")
	}
}

// TestValidatorCryptoVerification tests full cryptographic RRSIG verification.
func TestValidatorCryptoVerification(t *testing.T) {
	v := New(true, false)

	msg, key := makeSignedMsg(t)
	// Add DNSKEY to the answer so the validator can find it
	msg.Answer = append(msg.Answer, key)

	if err := v.ValidateResponse(msg); err != nil {
		t.Errorf("expected valid signed response to pass crypto verification, got %v", err)
	}
}

// TestValidatorMissingDNSKEY tests that a missing DNSKEY causes validation failure.
func TestValidatorMissingDNSKEY(t *testing.T) {
	v := New(true, false)

	msg, _ := makeSignedMsg(t)
	// Do NOT add the DNSKEY — validator can't find it

	if err := v.ValidateResponse(msg); err == nil {
		t.Error("expected error when DNSKEY is missing, got nil")
	}
}

// TestValidatorExpiredRRSIG tests expired signature detection.
func TestValidatorExpiredRRSIG(t *testing.T) {
	v := New(true, false)

	now := time.Now()
	aRecord := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.IPv4(93, 184, 216, 34),
	}

	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
		},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.RSASHA256,
		Labels:      2,
		OrigTtl:     300,
		Expiration:  uint32(now.Add(-1 * time.Hour).Unix()),  // Already expired
		Inception:   uint32(now.Add(-25 * time.Hour).Unix()), // Started 25h ago
		KeyTag:      12345,
		SignerName:  "example.com.",
		Signature:   "fakesignaturebytes",
	}

	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{aRecord, rrsig},
	}

	if err := v.ValidateResponse(msg); err == nil {
		t.Error("expected error for expired RRSIG, got nil")
	}
}

// TestValidatorFutureInception tests future inception time detection.
func TestValidatorFutureInception(t *testing.T) {
	v := New(true, false)

	now := time.Now()
	aRecord := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.IPv4(93, 184, 216, 34),
	}

	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
		},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.RSASHA256,
		Labels:      2,
		OrigTtl:     300,
		Expiration:  uint32(now.Add(48 * time.Hour).Unix()),
		Inception:   uint32(now.Add(1 * time.Hour).Unix()), // Future inception
		KeyTag:      12345,
		SignerName:  "example.com.",
		Signature:   "fakesignaturebytes",
	}

	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{aRecord, rrsig},
	}

	if err := v.ValidateResponse(msg); err == nil {
		t.Error("expected error for future inception RRSIG, got nil")
	}
}

// TestValidatorSupportedAlgorithms tests algorithm support checking.
func TestValidatorSupportedAlgorithms(t *testing.T) {
	supported := SupportedAlgorithms()

	rsaSha256 := false
	ecdsa := false
	ed25519 := false

	for _, alg := range supported {
		switch alg {
		case dns.RSASHA256:
			rsaSha256 = true
		case dns.ECDSAP256SHA256:
			ecdsa = true
		case dns.ED25519:
			ed25519 = true
		}
	}

	if !rsaSha256 {
		t.Error("expected RSASHA256 to be supported")
	}
	if !ecdsa {
		t.Error("expected ECDSAP256SHA256 to be supported")
	}
	if !ed25519 {
		t.Error("expected ED25519 to be supported")
	}

	if !IsSupported(dns.RSASHA256) {
		t.Error("IsSupported(RSASHA256) should return true")
	}
	if IsSupported(255) {
		t.Error("IsSupported(255) should return false")
	}
}

// TestValidatorStats tests stats retrieval.
func TestValidatorStats(t *testing.T) {
	v := New(true, false)
	stats := v.GetStats()

	if stats.ValidResponses != 0 || stats.InvalidResponses != 0 || stats.UnsignedResponses != 0 {
		t.Errorf("expected all zero stats, got %+v", stats)
	}
}

// TestValidatorAlgorithmNames tests that all named algorithms are supported.
func TestValidatorAlgorithmNames(t *testing.T) {
	algorithms := []struct {
		id   uint8
		name string
	}{
		{dns.RSAMD5, "RSAMD5"},
		{dns.RSASHA1, "RSASHA1"},
		{dns.RSASHA256, "RSASHA256"},
		{dns.RSASHA512, "RSASHA512"},
		{dns.ECDSAP256SHA256, "ECDSAP256SHA256"},
		{dns.ECDSAP384SHA384, "ECDSAP384SHA384"},
		{dns.ED25519, "ED25519"},
	}

	for _, alg := range algorithms {
		if !IsSupported(alg.id) {
			t.Errorf("algorithm %s (%d) should be supported", alg.name, alg.id)
		}
	}
}

// TestParseRootAnchors tests parsing of root-anchors.xml.
func TestParseRootAnchors(t *testing.T) {
	anchors, err := DefaultTrustAnchors()
	if err != nil {
		t.Fatalf("DefaultTrustAnchors() failed: %v", err)
	}

	if len(anchors) == 0 {
		t.Fatal("expected at least one valid trust anchor")
	}

	// Verify known current root anchor (keytag 20326, algorithm 8 = RSASHA256)
	found20326 := false
	found38696 := false
	for _, a := range anchors {
		if a.KeyTag == 20326 && a.Algorithm == 8 {
			found20326 = true
		}
		if a.KeyTag == 38696 && a.Algorithm == 8 {
			found38696 = true
		}
		// Verify digest is non-empty
		if len(a.Digest) == 0 {
			t.Errorf("trust anchor keytag=%d has empty digest", a.KeyTag)
		}
	}

	// At least one of the two current root anchors should be present
	if !found20326 && !found38696 {
		t.Errorf("expected root anchor keytag 20326 or 38696, got: %+v", anchors)
	}
}

// TestParseRootAnchorsInvalidXML tests error handling for malformed XML.
func TestParseRootAnchorsInvalidXML(t *testing.T) {
	_, err := ParseRootAnchors([]byte("<invalid>xml"))
	if err == nil {
		t.Error("expected error for invalid XML, got nil")
	}
}

// TestLoadTrustAnchorsFromFileXML: an operator-supplied root-anchors.xml file
// loads the same way as the embedded anchor.
func TestLoadTrustAnchorsFromFileXML(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/root-anchors.xml"
	if err := os.WriteFile(path, rootAnchorsXML, 0644); err != nil {
		t.Fatalf("write xml: %v", err)
	}
	anchors, err := LoadTrustAnchorsFromFile(path)
	if err != nil {
		t.Fatalf("LoadTrustAnchorsFromFile(xml): %v", err)
	}
	if len(anchors) == 0 {
		t.Fatal("expected anchors from xml file")
	}
}

// TestLoadTrustAnchorsFromFileRootKey: a BIND-style root.key (DNSKEY) loads and
// converts to the SHA-256 DS-equivalent anchor (keytag 20326, the current root KSK).
func TestLoadTrustAnchorsFromFileRootKey(t *testing.T) {
	// Public root KSK (keytag 20326), as published in IANA's root.key.
	const rootKey = `.	IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=`
	dir := t.TempDir()
	path := dir + "/root.key"
	if err := os.WriteFile(path, []byte("; comment\n"+rootKey+"\n"), 0644); err != nil {
		t.Fatalf("write root.key: %v", err)
	}
	anchors, err := LoadTrustAnchorsFromFile(path)
	if err != nil {
		t.Fatalf("LoadTrustAnchorsFromFile(root.key): %v", err)
	}
	found := false
	for _, a := range anchors {
		if a.KeyTag == 20326 && a.DigestType == 2 && len(a.Digest) > 0 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected keytag 20326 SHA-256 anchor from root.key, got %+v", anchors)
	}
}

func TestLoadTrustAnchorsFromFileMissing(t *testing.T) {
	if _, err := LoadTrustAnchorsFromFile("/nonexistent/root.key"); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadTrustAnchorsFromFileEmptyRootKey(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/empty.key"
	if err := os.WriteFile(path, []byte("; only a comment, no DNSKEY\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadTrustAnchorsFromFile(path); err == nil {
		t.Error("expected error for root.key with no DNSKEY records")
	}
}

// TestSetTrustAnchors tests loading trust anchors into the validator.
func TestSetTrustAnchors(t *testing.T) {
	v := New(true, false)

	anchors, err := DefaultTrustAnchors()
	if err != nil {
		t.Fatalf("DefaultTrustAnchors() failed: %v", err)
	}

	v.SetTrustAnchors(anchors)

	if len(v.trustAnchors) == 0 {
		t.Error("expected trust anchors to be set")
	}
}

// BenchmarkValidateResponse benchmarks signed response validation with crypto.
func BenchmarkValidateResponse(b *testing.B) {
	v := New(true, false)

	// We need a real signed message for meaningful crypto benchmark
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	}
	privKey, err := key.Generate(1024)
	if err != nil {
		b.Fatalf("generate key: %v", err)
	}

	aRecord := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.IPv4(93, 184, 216, 34),
	}

	now := time.Now()
	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.RSASHA256,
		Labels:      2,
		OrigTtl:     300,
		Expiration:  uint32(now.Add(24 * time.Hour).Unix()),
		Inception:   uint32(now.Add(-1 * time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  "example.com.",
	}
	if err := rrsig.Sign(privKey.(crypto.Signer), []dns.RR{aRecord}); err != nil {
		b.Fatalf("sign: %v", err)
	}

	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{aRecord, rrsig, key},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.ValidateResponse(msg)
	}
}

// TestParseRootKeyFormat verifies that parseRootKey handles a real system root.key
// (BIND-style DNSKEY zone records) and produces anchors matching the known IANA key tags.
func TestParseRootKeyFormat(t *testing.T) {
	data, err := os.ReadFile("testdata/root.key")
	if err != nil {
		t.Fatalf("read testdata/root.key: %v", err)
	}
	anchors, err := parseRootKey(data)
	if err != nil {
		t.Fatalf("parseRootKey: %v", err)
	}
	if len(anchors) == 0 {
		t.Fatal("parseRootKey returned no anchors")
	}

	// Both current IANA KSKs must be present.
	wantTags := map[uint16]bool{20326: false, 38696: false}
	for _, a := range anchors {
		if _, known := wantTags[a.KeyTag]; known {
			wantTags[a.KeyTag] = true
		}
		if len(a.Digest) == 0 {
			t.Errorf("anchor keytag=%d has empty digest", a.KeyTag)
		}
	}
	for tag, found := range wantTags {
		if !found {
			t.Errorf("expected keytag %d not found in parsed anchors", tag)
		}
	}
}

// TestLoadTrustAnchorsFromFileRootKeySystemFile verifies LoadTrustAnchorsFromFile
// against the real system root.key fixture (both current IANA KSKs, 20326 + 38696).
func TestLoadTrustAnchorsFromFileRootKeySystemFile(t *testing.T) {
	anchors, err := LoadTrustAnchorsFromFile("testdata/root.key")
	if err != nil {
		t.Fatalf("LoadTrustAnchorsFromFile: %v", err)
	}
	if len(anchors) < 2 {
		t.Fatalf("expected at least 2 anchors, got %d", len(anchors))
	}
}
