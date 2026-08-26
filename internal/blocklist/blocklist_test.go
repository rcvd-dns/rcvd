// SPDX-License-Identifier: MIT
package blocklist

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// TestBlocklistExactMatch tests exact domain matching.
func TestBlocklistExactMatch(t *testing.T) {
	b := New(true)

	input := "example.com\nyahoo.com\n"
	if _, err := b.parseFile(strings.NewReader(input)); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !b.IsBlocked("example.com") {
		t.Error("expected example.com to be blocked")
	}

	if !b.IsBlocked("example.com.") {
		t.Error("expected example.com. (FQDN) to be blocked")
	}

	if !b.IsBlocked("yahoo.com") {
		t.Error("expected yahoo.com to be blocked")
	}

	if b.IsBlocked("google.com") {
		t.Error("expected google.com to not be blocked")
	}

	// A bare entry blocks its own subdomains too (dnsmasq address=/domain/ /
	// OISD convention): "example.com" covers "example.com" and everything under it.
	if !b.IsBlocked("sub.example.com") {
		t.Error("expected sub.example.com to be blocked by bare entry example.com")
	}
	if !b.IsBlocked("deep.sub.example.com") {
		t.Error("expected deep.sub.example.com to be blocked by bare entry example.com")
	}

	// But a sibling that merely shares a suffix label is not blocked.
	if b.IsBlocked("notexample.com") {
		t.Error("expected notexample.com to not be blocked")
	}
}

// TestBlocklistUnderscoreLabel verifies underscore-containing hostnames load
// (legal per RFC 2181; a stricter RFC 1123 regex used to silently drop them).
func TestBlocklistUnderscoreLabel(t *testing.T) {
	b := New(true)

	input := "_dmarc.example.com\ntelemetry_v2.tracker.net\n"
	skipped, err := b.parseFile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if skipped != 0 {
		t.Errorf("expected 0 skipped, got %d", skipped)
	}
	if !b.IsBlocked("_dmarc.example.com") {
		t.Error("expected _dmarc.example.com to be blocked")
	}
	if !b.IsBlocked("telemetry_v2.tracker.net") {
		t.Error("expected telemetry_v2.tracker.net to be blocked")
	}
}

// TestBlocklistSkipCount verifies invalid lines are counted, not silently dropped.
func TestBlocklistSkipCount(t *testing.T) {
	b := New(true)

	// Line 2 (leading hyphen) and line 3 (empty label) are invalid hostnames;
	// the blank and comment lines are ignored and must not count as skipped.
	input := "good.com\n-bad.com\nfoo..com\n\n# a comment\nalso-good.net\n"
	skipped, err := b.parseFile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if skipped != 2 {
		t.Errorf("expected 2 skipped invalid lines, got %d", skipped)
	}
	if !b.IsBlocked("good.com") || !b.IsBlocked("also-good.net") {
		t.Error("expected valid entries to load")
	}
}

// TestBlocklistWildcard tests wildcard domain matching (*.example.com).
func TestBlocklistWildcard(t *testing.T) {
	b := New(true)

	input := "*.example.com\n*.evil.net\n"
	if _, err := b.parseFile(strings.NewReader(input)); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Wildcard should match subdomains
	if !b.IsBlocked("sub.example.com") {
		t.Error("expected sub.example.com to be blocked by *.example.com")
	}

	if !b.IsBlocked("deep.sub.example.com") {
		t.Error("expected deep.sub.example.com to be blocked by *.example.com")
	}

	if !b.IsBlocked("anything.evil.net") {
		t.Error("expected anything.evil.net to be blocked")
	}

	// Root domain itself should not match wildcard
	if b.IsBlocked("example.com") {
		t.Error("expected example.com (root) to not match *.example.com")
	}

	// Non-matching domain
	if b.IsBlocked("google.com") {
		t.Error("expected google.com to not be blocked")
	}
}

// TestBlocklistHostsFormat tests parsing hosts file format.
func TestBlocklistHostsFormat(t *testing.T) {
	b := New(true)

	input := `# Hosts file format
127.0.0.1 localhost
127.0.0.1 ad1.example.com ad2.example.com bad.net
0.0.0.0 tracker.com
::1 ipv6-domain.com
`
	if _, err := b.parseFile(strings.NewReader(input)); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Check that domains are loaded
	if !b.IsBlocked("ad1.example.com") {
		t.Error("expected ad1.example.com to be blocked")
	}

	if !b.IsBlocked("ad2.example.com") {
		t.Error("expected ad2.example.com to be blocked")
	}

	if !b.IsBlocked("bad.net") {
		t.Error("expected bad.net to be blocked")
	}

	if !b.IsBlocked("tracker.com") {
		t.Error("expected tracker.com to be blocked")
	}

	if !b.IsBlocked("ipv6-domain.com") {
		t.Error("expected ipv6-domain.com to be blocked")
	}

	// localhost should be loaded
	if !b.IsBlocked("localhost") {
		t.Error("expected localhost to be blocked")
	}
}

// TestBlocklistComments tests comment handling.
func TestBlocklistComments(t *testing.T) {
	b := New(true)

	input := `# This is a comment
example.com
# Another comment
yahoo.com
# More comments
`
	if _, err := b.parseFile(strings.NewReader(input)); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !b.IsBlocked("example.com") {
		t.Error("expected example.com to be blocked")
	}

	if !b.IsBlocked("yahoo.com") {
		t.Error("expected yahoo.com to be blocked")
	}

	// Note: Inline comments on the same line (e.g., "example.com # comment")
	// are not supported. Users should use separate lines for comments.
	// This is intentional for simplicity (no need to strip trailing comments).
}

// TestBlocklistCaseSensitive tests case-insensitive matching.
func TestBlocklistCaseSensitive(t *testing.T) {
	b := New(true)

	input := "Example.COM\nYAHOO.NET\n"
	if _, err := b.parseFile(strings.NewReader(input)); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Should match case-insensitively
	if !b.IsBlocked("example.com") {
		t.Error("expected example.com to match Example.COM (case-insensitive)")
	}

	if !b.IsBlocked("EXAMPLE.COM") {
		t.Error("expected EXAMPLE.COM to match Example.COM")
	}

	if !b.IsBlocked("yahoo.net") {
		t.Error("expected yahoo.net to match YAHOO.NET")
	}
}

// TestBlocklistDisabled tests that blocklist returns false when disabled.
func TestBlocklistDisabled(t *testing.T) {
	b := New(false) // disabled

	input := "example.com\n"
	if _, err := b.parseFile(strings.NewReader(input)); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Even though domain is in blocklist, IsBlocked should return false
	if b.IsBlocked("example.com") {
		t.Error("expected IsBlocked to return false when blocklist disabled")
	}
}

// TestBlocklistSize tests Size and Stats methods.
func TestBlocklistSize(t *testing.T) {
	b := New(true)

	input := `example.com
yahoo.com
*.evil.net
*.ads.com
`
	if _, err := b.parseFile(strings.NewReader(input)); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if b.Size() != 4 {
		t.Errorf("expected size 4, got %d", b.Size())
	}

	stats := b.Stats()
	if stats["total"] != 4 {
		t.Errorf("stats total: expected 4, got %d", stats["total"])
	}

	if stats["domains"] != 2 {
		t.Errorf("stats domains: expected 2, got %d", stats["domains"])
	}

	if stats["wildcard"] != 2 {
		t.Errorf("stats wildcard: expected 2, got %d", stats["wildcard"])
	}
}

// TestBlocklistClear tests Clear method.
func TestBlocklistClear(t *testing.T) {
	b := New(true)

	input := "example.com\nyahoo.com\n"
	if _, err := b.parseFile(strings.NewReader(input)); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if b.Size() != 2 {
		t.Errorf("expected size 2 after load, got %d", b.Size())
	}

	b.Clear()

	if b.Size() != 0 {
		t.Errorf("expected size 0 after clear, got %d", b.Size())
	}

	if b.IsBlocked("example.com") {
		t.Error("expected example.com to not be blocked after clear")
	}
}

// TestBlocklistInvalidDomains tests rejection of invalid domains.
func TestBlocklistInvalidDomains(t *testing.T) {
	b := New(true)

	input := `
valid.com
-invalid.com
invalid-.com
valid-domain.com
_.com
127.0.0.1 should-be-loaded.com
invalid..com
` // Some of these should be rejected, some loaded

	if _, err := b.parseFile(strings.NewReader(input)); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Valid domains should be loaded
	if !b.IsBlocked("valid.com") {
		t.Error("expected valid.com to be loaded")
	}

	if !b.IsBlocked("valid-domain.com") {
		t.Error("expected valid-domain.com to be loaded")
	}

	if !b.IsBlocked("should-be-loaded.com") {
		t.Error("expected should-be-loaded.com (from hosts line) to be loaded")
	}

	// Invalid domains should not be loaded
	if b.IsBlocked("-invalid.com") {
		t.Error("expected -invalid.com (starts with hyphen) to not be loaded")
	}

	if b.IsBlocked("invalid-.com") {
		t.Error("expected invalid-.com (label ends with hyphen) to not be loaded")
	}
}

// TestBlocklistEmptyLines tests empty line handling.
func TestBlocklistEmptyLines(t *testing.T) {
	b := New(true)

	input := `example.com

yahoo.com


google.com
`
	if _, err := b.parseFile(strings.NewReader(input)); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if b.Size() != 3 {
		t.Errorf("expected size 3, got %d", b.Size())
	}

	if !b.IsBlocked("example.com") {
		t.Error("expected example.com to be blocked")
	}

	if !b.IsBlocked("yahoo.com") {
		t.Error("expected yahoo.com to be blocked")
	}

	if !b.IsBlocked("google.com") {
		t.Error("expected google.com to be blocked")
	}
}

// TestBlocklistMultilineAddition tests adding domains from multiple sources.
func TestBlocklistMultilineAddition(t *testing.T) {
	b := New(true)

	// First load
	input1 := "example.com\nyahoo.com\n"
	if _, err := b.parseFile(strings.NewReader(input1)); err != nil {
		t.Fatalf("parse 1: %v", err)
	}

	// Second load (accumulate)
	input2 := "google.com\n"
	if _, err := b.parseFile(strings.NewReader(input2)); err != nil {
		t.Fatalf("parse 2: %v", err)
	}

	if b.Size() != 3 {
		t.Errorf("expected size 3 (accumulated), got %d", b.Size())
	}

	if !b.IsBlocked("example.com") {
		t.Error("expected example.com from first load")
	}

	if !b.IsBlocked("google.com") {
		t.Error("expected google.com from second load")
	}
}

// TestBlocklistDeepWildcard tests multi-level wildcard matching.
func TestBlocklistDeepWildcard(t *testing.T) {
	b := New(true)

	input := "*.level1.example.com\n"
	if _, err := b.parseFile(strings.NewReader(input)); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Should match immediate subdomain
	if !b.IsBlocked("sub.level1.example.com") {
		t.Error("expected sub.level1.example.com to match")
	}

	// Should match deeper subdomain
	if !b.IsBlocked("deep.sub.level1.example.com") {
		t.Error("expected deep.sub.level1.example.com to match")
	}

	// Should not match parent domain
	if b.IsBlocked("level1.example.com") {
		t.Error("expected level1.example.com to not match *.level1.example.com")
	}

	// Should not match sibling
	if b.IsBlocked("other.level2.example.com") {
		t.Error("expected other.level2.example.com to not match")
	}
}

// TestBlocklistMixedFormat tests mixing plain and hosts formats.
func TestBlocklistMixedFormat(t *testing.T) {
	b := New(true)

	input := `# Mixed format
example.com
127.0.0.1 ads.com tracker.net
*.evil.net
0.0.0.0 bad1.com bad2.com
`
	if _, err := b.parseFile(strings.NewReader(input)); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Plain
	if !b.IsBlocked("example.com") {
		t.Error("expected example.com (plain)")
	}

	// From hosts line
	if !b.IsBlocked("ads.com") {
		t.Error("expected ads.com (hosts format)")
	}

	if !b.IsBlocked("tracker.net") {
		t.Error("expected tracker.net (hosts format)")
	}

	if !b.IsBlocked("bad1.com") {
		t.Error("expected bad1.com (hosts format)")
	}

	// Wildcard
	if !b.IsBlocked("sub.evil.net") {
		t.Error("expected sub.evil.net (wildcard)")
	}
}

// TestBlocklistFQDN tests FQDN (trailing dot) handling.
func TestBlocklistFQDN(t *testing.T) {
	b := New(true)

	// Load with FQDN notation
	input := "example.com.\nyahoo.com.\n"
	if _, err := b.parseFile(strings.NewReader(input)); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Should match without trailing dot
	if !b.IsBlocked("example.com") {
		t.Error("expected example.com to match example.com.")
	}

	// Should match with trailing dot
	if !b.IsBlocked("example.com.") {
		t.Error("expected example.com. to match")
	}

	// Wildcards with FQDN
	b2 := New(true)
	input2 := "*.example.com.\n"
	if _, err := b2.parseFile(strings.NewReader(input2)); err != nil {
		t.Fatalf("parse 2: %v", err)
	}

	if !b2.IsBlocked("sub.example.com") {
		t.Error("expected sub.example.com to match *.example.com.")
	}
}

// BenchmarkIsBlocked benchmarks the IsBlocked lookup.
func BenchmarkIsBlocked(b *testing.B) {
	blocklist := New(true)

	// Load a reasonable number of domains
	var buf bytes.Buffer
	for i := 0; i < 10000; i++ {
		buf.WriteString(fmt.Sprintf("domain%d.com\n", i))
	}

	if _, err := blocklist.parseFile(&buf); err != nil {
		b.Fatalf("load: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blocklist.IsBlocked("domain5000.com")
	}
}

// BenchmarkWildcardIsBlocked benchmarks wildcard IsBlocked lookup.
func BenchmarkWildcardIsBlocked(b *testing.B) {
	blocklist := New(true)

	// Load wildcards
	var buf bytes.Buffer
	for i := 0; i < 1000; i++ {
		buf.WriteString(fmt.Sprintf("*.domain%d.com\n", i))
	}

	if _, err := blocklist.parseFile(&buf); err != nil {
		b.Fatalf("load: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blocklist.IsBlocked("sub.domain500.com")
	}
}
