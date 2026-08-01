// SPDX-License-Identifier: MIT
package config

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

// SPKI public-key pin format: "sha256//BASE64".
//
// This is the SINGLE source of truth for the pin format across rcvd. It lives in
// the low-level config package (which imports no other internal package) so both
// the config loader and the resolver's live pin verifier (internal/resolver/pin.go)
// call the SAME parser — they must never drift, since one validates at startup and
// the other gates a real TLS handshake.
//
// The "sha256//" prefix is curl's --pinnedpubkey format
// (https://curl.se/docs/manpage.html#--pinnedpubkey), a de-facto standard
// alongside RFC 7469. The digest is a SHA-256 over the peer leaf certificate's
// DER-encoded SubjectPublicKeyInfo — it binds to the KEY, not the whole cert, so a
// server may re-issue its cert (new dates/SANs) with the same keypair and the pin
// stays stable.

// PinPrefix is the SPKI SHA-256 pin scheme prefix.
const PinPrefix = "sha256//"

// pinSHA256Len is the decoded length of a valid SHA-256 SPKI pin.
const pinSHA256Len = sha256.Size // 32

// ParsePin validates a "sha256//BASE64" pin string and returns the raw 32-byte
// digest. An empty string is NOT valid here — callers must only invoke ParsePin
// when a pin is actually set. This is the one function that defines what a valid
// pin is; validatePinnedPubKey (config load) and the resolver verifier both use it.
func ParsePin(s string) ([]byte, error) {
	if !strings.HasPrefix(s, PinPrefix) {
		return nil, fmt.Errorf("pinned_pubkey must start with %q (SPKI SHA-256 pin, e.g. %ssJ0mL... )", PinPrefix, PinPrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, PinPrefix))
	if err != nil {
		return nil, fmt.Errorf("pinned_pubkey base64 decode: %w", err)
	}
	if len(raw) != pinSHA256Len {
		return nil, fmt.Errorf("pinned_pubkey must decode to %d bytes (SHA-256), got %d", pinSHA256Len, len(raw))
	}
	return raw, nil
}

// SPKIPin returns the "sha256//BASE64" pin for a certificate's public key. It is
// the inverse of ParsePin: given a peer's leaf cert, produce the pin an operator
// would paste into a client's `pinned_pubkey`. Used by --verify-upstream to print
// a ready-to-use pin, and by tests.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return PinPrefix + base64.StdEncoding.EncodeToString(sum[:])
}
