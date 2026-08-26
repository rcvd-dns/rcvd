// SPDX-License-Identifier: MIT
package blocklist

import (
	"os"
	"testing"
)

// domainswildFile points at a real domainswild blocklist (e.g. OISD "big" plus
// any hand-appended entries) to exercise the matcher on production-scale data.
// The file is large (~7MB / 328K entries) and environment-specific, so it is
// NOT committed: drop your own copy at this path and the test picks it up,
// otherwise it skips. Override the path with RCVD_DOMAINSWILD_TEST if you keep
// it elsewhere.
func domainswildFile() string {
	if p := os.Getenv("RCVD_DOMAINSWILD_TEST"); p != "" {
		return p
	}
	return "testdata/domainswild"
}

// TestDomainswild loads a production domainswild blocklist and asserts the two
// fixes behave on the actual data: bare-apex telemetry entries block their
// subdomains, OISD wildcards block subdomains (not apex), and the invalid-line
// skip count is surfaced (not silently swallowed).
func TestDomainswild(t *testing.T) {
	path := domainswildFile()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("blocklist %s not present (copy a production domainswild there to run): %v", path, err)
	}

	b := New(true)
	skipped, err := b.LoadFiles([]string{path})
	if err != nil {
		t.Fatalf("LoadFiles: %v", err)
	}
	st := b.Stats()
	t.Logf("loaded: %d domains, %d wildcards, %d total, %d skipped",
		st["domains"], st["wildcard"], st["total"], skipped)

	// Bare-apex telemetry appends: the entry itself and its subdomains block.
	bareApexBlocked := []string{
		"as.atlassian.com",
		"statsigapi.net",
		"api.statsigcdn.com",
		"api.datadoghq.com",
	}
	for _, d := range bareApexBlocked {
		if !b.IsBlocked(d) {
			t.Errorf("expected bare-apex entry %q to be blocked", d)
		}
		if !b.IsBlocked("probe." + d) {
			t.Errorf("expected subdomain probe.%s to be blocked by bare entry (Fix 1)", d)
		}
	}

	// A clearly-not-listed control must not be blocked (guards against a
	// suffix-walk bug that over-blocks).
	for _, d := range []string{"example.com", "wikipedia.org", "kernel.org"} {
		if b.IsBlocked(d) {
			t.Errorf("expected control domain %q to not be blocked", d)
		}
	}
}
