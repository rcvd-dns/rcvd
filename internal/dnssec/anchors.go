// SPDX-License-Identifier: MIT
package dnssec

import (
	_ "embed"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// rootAnchorsXML is the IANA root-anchors.xml embedded at compile time.
//
//go:embed root-anchors.xml
var rootAnchorsXML []byte

// DefaultTrustAnchors parses and returns the embedded root trust anchors.
// Returns an error if the embedded file is missing or malformed.
func DefaultTrustAnchors() ([]TrustAnchor, error) {
	return ParseRootAnchors(rootAnchorsXML)
}

// LoadTrustAnchorsFromFile reads root trust anchors from an operator-supplied
// file, overriding the embedded IANA anchor. It accepts BOTH formats commonly
// found on disk, auto-detected by content:
//
//   - IANA root-anchors.xml (DS records) — the same format rcvd embeds, fetched
//     from https://data.iana.org/root-anchors/root-anchors.xml
//   - BIND-style root.key (DNSKEY records, optionally wrapped in a
//     trust-anchors / managed-keys / trusted-keys block) — the file distros ship
//     and update, e.g. /var/lib/unbound/root.key, /usr/share/dns/root.key.
//
// Letting a packager point at the system anchor file means the distro owns
// anchor updates (incl. KSK rollovers) the normal way, without recompiling rcvd.
func LoadTrustAnchorsFromFile(path string) ([]TrustAnchor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust anchor file %q: %w", path, err)
	}
	if strings.Contains(string(data), "<TrustAnchor") || strings.Contains(string(data), "<KeyDigest") {
		return ParseRootAnchors(data)
	}
	return parseRootKey(data)
}

// parseRootKey parses a BIND-style root.key (DNSKEY zone records). Comments (;),
// blank lines, and trust-anchors/managed-keys/trusted-keys block syntax are
// tolerated by the zone parser. Each DNSKEY is converted to a SHA-256 DS-equivalent
// trust anchor (DigestType 2), which is how VerifyKeyAgainstAnchors compares.
func parseRootKey(data []byte) ([]TrustAnchor, error) {
	var anchors []TrustAnchor
	zp := dns.NewZoneParser(strings.NewReader(string(data)), ".", "")
	zp.SetIncludeAllowed(false)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		key, isKey := rr.(*dns.DNSKEY)
		if !isKey {
			continue
		}
		ds := key.ToDS(dns.SHA256)
		if ds == nil {
			continue
		}
		digestBytes, err := hex.DecodeString(strings.ToLower(ds.Digest))
		if err != nil {
			return nil, fmt.Errorf("decode DS digest for keytag %d: %w", key.KeyTag(), err)
		}
		anchors = append(anchors, TrustAnchor{
			KeyTag:     ds.KeyTag,
			Algorithm:  ds.Algorithm,
			DigestType: ds.DigestType,
			Digest:     digestBytes,
		})
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("parse root.key: %w", err)
	}
	if len(anchors) == 0 {
		return nil, fmt.Errorf("no DNSKEY records found in root.key file")
	}
	return anchors, nil
}

// TrustAnchor represents a DNSSEC root trust anchor from IANA root-anchors.xml.
// Each anchor is a DS record equivalent: KeyTag + Algorithm + DigestType + Digest.
type TrustAnchor struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
	ValidFrom  time.Time
	ValidUntil time.Time // zero means "no expiry"
}

// rootAnchorXML is the parsed structure of IANA root-anchors.xml.
type rootAnchorXML struct {
	Zone      string         `xml:"Zone"`
	KeyDigest []keyDigestXML `xml:"KeyDigest"`
}

type keyDigestXML struct {
	ID         string `xml:"id,attr"`
	ValidFrom  string `xml:"validFrom,attr"`
	ValidUntil string `xml:"validUntil,attr"`
	KeyTag     uint16 `xml:"KeyTag"`
	Algorithm  uint8  `xml:"Algorithm"`
	DigestType uint8  `xml:"DigestType"`
	Digest     string `xml:"Digest"`
}

// ParseRootAnchors parses IANA root-anchors.xml data and returns trust anchors
// that are currently valid (ValidFrom ≤ now, and either no ValidUntil or ValidUntil > now).
func ParseRootAnchors(xmlData []byte) ([]TrustAnchor, error) {
	var raw rootAnchorXML
	if err := xml.Unmarshal(xmlData, &raw); err != nil {
		return nil, fmt.Errorf("parse root anchors XML: %w", err)
	}

	now := time.Now().UTC()
	var anchors []TrustAnchor

	for _, kd := range raw.KeyDigest {
		validFrom, err := time.Parse(time.RFC3339, kd.ValidFrom)
		if err != nil {
			return nil, fmt.Errorf("parse ValidFrom %q: %w", kd.ValidFrom, err)
		}

		var validUntil time.Time
		if kd.ValidUntil != "" {
			validUntil, err = time.Parse(time.RFC3339, kd.ValidUntil)
			if err != nil {
				return nil, fmt.Errorf("parse ValidUntil %q: %w", kd.ValidUntil, err)
			}
		}

		// Skip anchors not yet valid
		if now.Before(validFrom) {
			continue
		}

		// Skip expired anchors
		if !validUntil.IsZero() && now.After(validUntil) {
			continue
		}

		digestHex := strings.ReplaceAll(kd.Digest, " ", "")
		digestBytes, err := hex.DecodeString(digestHex)
		if err != nil {
			return nil, fmt.Errorf("decode digest hex for keytag %d: %w", kd.KeyTag, err)
		}

		anchors = append(anchors, TrustAnchor{
			KeyTag:     kd.KeyTag,
			Algorithm:  kd.Algorithm,
			DigestType: kd.DigestType,
			Digest:     digestBytes,
			ValidFrom:  validFrom,
			ValidUntil: validUntil,
		})
	}

	if len(anchors) == 0 {
		return nil, fmt.Errorf("no valid trust anchors found in root-anchors.xml")
	}

	return anchors, nil
}

// VerifyKeyAgainstAnchors checks whether a DNSKEY matches any of the provided
// trust anchors by computing the DS record and comparing digests.
// Returns nil if matched, error if not matched or on failure.
func VerifyKeyAgainstAnchors(key *dns.DNSKEY, anchors []TrustAnchor) error {
	for _, anchor := range anchors {
		if key.KeyTag() != anchor.KeyTag {
			continue
		}
		if key.Algorithm != anchor.Algorithm {
			continue
		}
		// Compute DS record from the DNSKEY using anchor's digest type
		ds := key.ToDS(anchor.DigestType)
		if ds == nil {
			continue
		}
		// Compare digest (case-insensitive hex)
		computedHex := strings.ToUpper(ds.Digest)
		expectedHex := strings.ToUpper(hex.EncodeToString(anchor.Digest))
		if computedHex == expectedHex {
			return nil
		}
	}
	return fmt.Errorf("DNSKEY keytag=%d does not match any root trust anchor", key.KeyTag())
}
