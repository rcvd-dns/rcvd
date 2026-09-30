// SPDX-License-Identifier: MIT
package allowlist

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestAllowedMatchesTable covers the matching semantics in one place: the
// blocklist's matcher is reused for structure (apex + bare-entry subdomains +
// wildcard + case + trailing dot), so we exercise the same shape here, but in
// the "allow" direction.
func TestAllowedMatchesTable(t *testing.T) {
	a := New()
	load := func(body string) {
		t.Helper()
		if err := scanAllowlistReader(strings.NewReader(body), a.domains, a.wildcard, a.exact, "test"); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// Add a couple entries directly through the helper so test table stays focused
	// on matching, not parsing (parsing has its own tests below).
	load("example.com\n*.allow.example\n")

	cases := []struct {
		name string
		want bool
	}{
		{"example.com", true},            // bare entry covers its apex
		{"example.com.", true},           // trailing-dot FQDN
		{"EXAMPLE.com", true},            // case-insensitive
		{"sub.example.com", true},        // bare entry covers subdomains
		{"deep.sub.example.com", true},   // bare entry covers deep subdomains
		{"sub.allow.example", true},      // wildcard covers subdomains
		{"deep.sub.allow.example", true}, // wildcard covers deep subdomains
		{"allow.example", false},         // wildcard does NOT cover its apex

		// Sibling that merely shares a label — must not be allowed.
		{"badexample.com", false},
		{"notexample.com", false},
		{"myexample.com", false},

		// Anything outside the listed suffixes is denied (default-deny).
		{"example.org", false},
		{"attacker.example.net", false},
		{"unrelated.test", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.Allowed(tc.name); got != tc.want {
				t.Errorf("Allowed(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestAllowedEmptyDeniesAll asserts the fail-closed default: an empty allowlist
// (pre-LoadFiles, or after a failed load leaves the previous set intact but the
// new load was rejected) refuses every name.
func TestAllowedEmptyDeniesAll(t *testing.T) {
	a := New()
	for _, name := range []string{"example.com", "sub.example.com", "anything.test."} {
		if a.Allowed(name) {
			t.Errorf("empty allowlist: Allowed(%q) = true, want false (default-deny)", name)
		}
	}
}

// TestAllowedFQDNInput checks both FQDN and bare-name inputs are accepted.
func TestAllowedFQDNInput(t *testing.T) {
	a := New()
	load(t, a, "example.com\n")

	for _, name := range []string{"example.com", "example.com.", "Example.Com", "EXAMPLE.COM."} {
		if !a.Allowed(name) {
			t.Errorf("Allowed(%q) = false, want true", name)
		}
	}
}

// TestLoadFilesStrictBadHostname makes sure the strict loader rejects a clearly
// invalid hostname on the very first bad line — with a file:line label so the
// operator can find it. Tests use example.com / example.net / example.org.
func TestLoadFilesStrictBadHostname(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	body := "example.com\n-bad.com\nexample.net\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := New()
	err := a.LoadFiles([]string{path})
	if err == nil {
		t.Fatal("expected error for leading-hyphen label, got nil")
	}
	if !strings.Contains(err.Error(), path+":2") {
		t.Errorf("error must name the failing line (file:2), got: %v", err)
	}
}

// TestLoadFilesStrictRejectsHostsFormat guards against a silent "hosts-style"
// line slipping into a domain allowlist — the first IP-token would otherwise
// look like a domain and be allowed.
func TestLoadFilesStrictRejectsHostsFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	body := "example.com\n127.0.0.1 leak.example\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := New()
	err := a.LoadFiles([]string{path})
	if err == nil {
		t.Fatal("expected error for hosts-format line, got nil")
	}
	if !strings.Contains(err.Error(), "hosts-format") {
		t.Errorf("error must mention hosts-format, got: %v", err)
	}
}

// TestLoadFilesStrictRejectsBareTLD asserts "com" / "io" / "." entries are
// rejected as silently too permissive.
func TestLoadFilesStrictRejectsBareTLD(t *testing.T) {
	dir := t.TempDir()
	strictCases := map[string]string{
		"bare tld":   "example.com\ncom\n",
		"dot root":   "example.com\n.\n",
		"bare entry": "com\n",
	}
	for name, body := range strictCases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, "allow-"+name+".txt")
			if err := os.WriteFile(path, []byte(body), 0644); err != nil {
				t.Fatalf("write: %v", err)
			}
			a := New()
			if err := a.LoadFiles([]string{path}); err == nil {
				t.Errorf("expected error for %q, got nil", name)
			}
		})
	}

	// Blank lines are ignored, not rejected.
	path := filepath.Join(dir, "allow-blanks.txt")
	if err := os.WriteFile(path, []byte("example.com\n\n   \n\texample.net\n"), 0644); err != nil {
		t.Fatalf("write blanks: %v", err)
	}
	a := New()
	if err := a.LoadFiles([]string{path}); err != nil {
		t.Errorf("blank/whitespace lines must be ignored, got: %v", err)
	}
	if a.Size() != 2 {
		t.Errorf("expected 2 entries after blanks, got %d", a.Size())
	}
}

// TestLoadFilesStrictRejectsUnderscore asserts underscore labels are rejected.
func TestLoadFilesStrictRejectsUnderscore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	body := "example.com\n_acme.example.org\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := New()
	err := a.LoadFiles([]string{path})
	if err == nil {
		t.Fatal("expected error for underscore label, got nil")
	}
}

// TestLoadFilesCommentsAndBlanks covers the friendly paths: comments (#) and
// blank lines must be silently ignored, and surrounding whitespace must be
// trimmed.
func TestLoadFilesCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	body := `
# this is a comment
example.com
   example.net
	example.org
# trailing comment
`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := New()
	if err := a.LoadFiles([]string{path}); err != nil {
		t.Fatalf("load: %v", err)
	}
	if a.Size() != 3 {
		t.Errorf("expected 3 entries (comments + blanks ignored), got %d", a.Size())
	}
}

// TestLoadFilesMultipleFieldsRejected catches the "two domains on one line"
// mistake — the operator almost certainly meant a newline, not a space.
func TestLoadFilesMultipleFieldsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	body := "example.com example.net\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := New()
	if err := a.LoadFiles([]string{path}); err == nil {
		t.Error("expected error for two domains on one line, got nil")
	}
}

// TestLoadFilesWildcardAccepted confirms a valid *.example.com entry survives
// the loader and matches subdomains but not the apex. Use ONLY the wildcard in
// the file so the apex-vs-bare-entry interaction does not muddy the test.
func TestLoadFilesWildcardAccepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	body := "*.sub.example.com\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := New()
	if err := a.LoadFiles([]string{path}); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !a.Allowed("foo.sub.example.com") {
		t.Error("wildcard subdomain must be allowed")
	}
	if !a.Allowed("deep.foo.sub.example.com") {
		t.Error("deep wildcard subdomain must be allowed")
	}
	if a.Allowed("sub.example.com") {
		t.Error("wildcard must NOT allow its apex")
	}
	if a.Allowed("example.com") {
		t.Error("wildcard must NOT allow the grandparent apex")
	}
}

// TestLoadFilesFailedLeavesPreviousSetIntact guards the "load fails → previous
// set unchanged" invariant. A failed reload must NEVER swap to empty: that
// would silently convert default-deny to "deny all", but worse, a half-loaded
// new set could leak names that the operator explicitly removed.
func TestLoadFilesFailedLeavesPreviousSetIntact(t *testing.T) {
	dir := t.TempDir()
	goodPath := filepath.Join(dir, "good.txt")
	if err := os.WriteFile(goodPath, []byte("example.com\nexample.net\n"), 0644); err != nil {
		t.Fatalf("write good: %v", err)
	}
	badPath := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(badPath, []byte("example.org\n-bad-.com\n"), 0644); err != nil {
		t.Fatalf("write bad: %v", err)
	}

	a := New()
	if err := a.LoadFiles([]string{goodPath}); err != nil {
		t.Fatalf("seed load: %v", err)
	}
	if a.Size() != 2 {
		t.Fatalf("expected 2 entries after seed, got %d", a.Size())
	}

	// A failed load: the whole call must error, and the previous set must
	// survive exactly as it was (Size + Allowed results unchanged).
	if err := a.LoadFiles([]string{badPath}); err == nil {
		t.Fatal("expected load to fail on the second file, got nil")
	}
	if a.Size() != 2 {
		t.Errorf("previous set must survive a failed load; got Size=%d, want 2", a.Size())
	}
	if !a.Allowed("example.com") || !a.Allowed("example.net") {
		t.Error("previous entries must still be allowed after a failed load")
	}
	if a.Allowed("example.org") {
		t.Error("a successfully-parsed entry from the BAD file must NOT have leaked into the live set")
	}
}

// TestLoadFilesMissingFileErrors asserts that a file listed in config but
// absent from disk is a hard error (default-deny cannot start with no list).
func TestLoadFilesMissingFileErrors(t *testing.T) {
	dir := t.TempDir()
	a := New()
	if err := a.LoadFiles([]string{filepath.Join(dir, "does-not-exist.txt")}); err == nil {
		t.Error("missing file must error (a default-deny deploy cannot start with no list)")
	}
	// Empty allowlist (pre-LoadFiles) still denies everything.
	if a.Allowed("example.com") {
		t.Error("failed load must leave the allowlist empty and fail-closed")
	}
}

// TestLoadFilesEmptyFileIsError asserts the fail-closed default for a
// default-deny allowlist that loads zero entries: an empty file (or one that
// contains only comments/whitespace) must error with ErrEmptyAllowlist, NOT
// silently fall through to "deny everything". A default-deny deploy that
// loads nothing would silently cut off all DNS — refusing to start is the
// safer failure mode than starting "deny all".
func TestLoadFilesEmptyFileIsError(t *testing.T) {
	cases := map[string]string{
		"completely empty":  "",
		"only comments":     "# this is a comment\n# so is this\n",
		"only blank lines":  "\n\n   \n\t\n",
		"comments + blanks": "# header\n\n# body\n   \n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "allow.txt")
			if err := os.WriteFile(path, []byte(body), 0644); err != nil {
				t.Fatalf("write: %v", err)
			}
			a := New()
			err := a.LoadFiles([]string{path})
			if err == nil {
				t.Fatalf("expected error for empty allowlist, got nil")
			}
			if !errors.Is(err, ErrEmptyAllowlist) {
				t.Errorf("error must wrap ErrEmptyAllowlist, got: %v", err)
			}
			// The live set must remain empty (no swap to a partial set).
			if a.Size() != 0 {
				t.Errorf("after empty-load failure, Size must remain 0, got %d", a.Size())
			}
		})
	}
}

// TestLoadFilesEmptyAcrossMultipleFilesErrorsOnAggregate covers the multi-file
// case: every individual file might be empty, but the AGGREGATE empty result
// must still error. (And conversely, one valid file among empties must succeed.)
func TestLoadFilesEmptyAcrossMultipleFilesErrorsOnAggregate(t *testing.T) {
	dir := t.TempDir()
	empty1 := filepath.Join(dir, "empty1.txt")
	empty2 := filepath.Join(dir, "empty2.txt")
	if err := os.WriteFile(empty1, []byte("# only a comment\n"), 0644); err != nil {
		t.Fatalf("write empty1: %v", err)
	}
	if err := os.WriteFile(empty2, []byte("\n\n"), 0644); err != nil {
		t.Fatalf("write empty2: %v", err)
	}

	a := New()
	if err := a.LoadFiles([]string{empty1, empty2}); !errors.Is(err, ErrEmptyAllowlist) {
		t.Errorf("aggregate empty load must error with ErrEmptyAllowlist, got: %v", err)
	}
}

// TestLoadFilesUnionNarrowPlusTemporary covers a narrow base list plus a broad
// temporary list: entries from both files are allowed. Emptying the temporary
// file and reloading retires its entries while the base list keeps working.
func TestLoadFilesUnionNarrowPlusTemporary(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.txt")
	temp := filepath.Join(dir, "temporary.txt")
	if err := os.WriteFile(base, []byte("example.com\n"), 0644); err != nil {
		t.Fatalf("write base: %v", err)
	}
	if err := os.WriteFile(temp, []byte("example.net\n*.example.org\n"), 0644); err != nil {
		t.Fatalf("write temporary: %v", err)
	}

	a := New()
	if err := a.LoadFiles([]string{base, temp}); err != nil {
		t.Fatalf("load base+temporary: %v", err)
	}
	if got := a.Size(); got != 3 {
		t.Errorf("Size() = %d, want 3 (entries from both files)", got)
	}
	for _, name := range []string{"www.example.com.", "api.example.net.", "cdn.example.org."} {
		if !a.Allowed(name) {
			t.Errorf("%s must be allowed with both files loaded", name)
		}
	}
	if a.Allowed("www.example.edu.") {
		t.Error("www.example.edu. is in neither file and must be denied")
	}

	// Retire the temporary list: empty it and reload. The union is still
	// non-empty, so the load succeeds and only the base entries remain.
	if err := os.WriteFile(temp, []byte("# retired\n"), 0644); err != nil {
		t.Fatalf("empty temporary: %v", err)
	}
	if err := a.LoadFiles([]string{base, temp}); err != nil {
		t.Fatalf("reload with emptied temporary file: %v", err)
	}
	if !a.Allowed("www.example.com.") {
		t.Error("base entry must survive retiring the temporary list")
	}
	for _, name := range []string{"api.example.net.", "cdn.example.org."} {
		if a.Allowed(name) {
			t.Errorf("%s must be denied after the temporary list is emptied", name)
		}
	}
}

// TestLoadFilesMultipleFiles aggregates across several files and reports
// which file is the source of the error when one of them is bad.
func TestLoadFilesMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.txt")
	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(good, []byte("example.com\n"), 0644); err != nil {
		t.Fatalf("write good: %v", err)
	}
	if err := os.WriteFile(bad, []byte("not-a-tld\n"), 0644); err != nil {
		t.Fatalf("write bad: %v", err)
	}

	a := New()
	err := a.LoadFiles([]string{good, bad})
	if err == nil {
		t.Fatal("expected error from the bad file, got nil")
	}
	// The error wraps the failing file path so the operator can find it.
	if !strings.Contains(err.Error(), "bad.txt") {
		t.Errorf("error must name the failing file (bad.txt), got: %v", err)
	}
	// The previously-loaded good file must NOT have leaked into the live set
	// (we abort on first error, so the good entries stay in the temporary
	// maps and are discarded with them).
	if a.Allowed("example.com") {
		t.Error("aborted load must leave the live set untouched (default-deny default applies)")
	}
}

// load is a tiny test helper that parses body through the internal scanner.
// Bypasses LoadFiles so tests focused on matching can seed without a temp file.
func load(t *testing.T, a *Allowlist, body string) {
	t.Helper()
	if err := scanAllowlistReader(strings.NewReader(body), a.domains, a.wildcard, a.exact, "test"); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// TestLoadAndQueryConcurrentRace exercises the concurrency contract of
// Allowlist: LoadFiles builds a fresh map and swaps it under the write lock,
// while Allowed holds the read lock for its lookup. The hot-reload path must
// not corrupt the live set or deadlock with in-flight queries, and a
// concurrent Allowed must always observe a coherent set (never a torn map).
// Run under `go test -race` to catch any violation.
func TestLoadAndQueryConcurrentRace(t *testing.T) {
	dir := t.TempDir()
	goodPath := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(goodPath, []byte("example.com\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	a := New()
	if err := a.LoadFiles([]string{goodPath}); err != nil {
		t.Fatalf("seed load: %v", err)
	}

	const (
		reloaders           = 4
		queriers            = 8
		reloadsPerGoroutine = 50
		queriesPerGoroutine = 500
	)

	var wg sync.WaitGroup

	// Queriers hammer Allowed() against names under the live set; they must
	// either observe a consistent allow (Allowed returns true) or a consistent
	// deny — never a panic on a torn map.
	for i := 0; i < queriers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < queriesPerGoroutine; j++ {
				_ = a.Allowed("sub.example.com")
				_ = a.Allowed("example.com")
				_ = a.Allowed("other.test.")
			}
		}()
	}

	// Reloaders call LoadFiles on the same shared instance. The strict loader
	// takes the write lock only for the brief final swap, so queriers make
	// progress through the file scan.
	for i := 0; i < reloaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < reloadsPerGoroutine; j++ {
				_ = a.LoadFiles([]string{goodPath})
			}
		}()
	}

	wg.Wait()

	// After all goroutines finish the live set must be the seeded good set.
	if a.Size() != 1 {
		t.Errorf("after concurrent reloads: Size = %d, want 1", a.Size())
	}
	if !a.Allowed("example.com") {
		t.Error("after concurrent reloads: example.com must remain allowed")
	}
}

// TestEntriesSortedCopy: Entries returns bare and wildcard entries, normalized and sorted.
func TestEntriesSortedCopy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(path, []byte("Example.NET.\n*.example.org\nexample.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	a := New()
	if err := a.LoadFiles([]string{path}); err != nil {
		t.Fatal(err)
	}
	got := a.Entries()
	want := []string{"*.example.org", "example.com", "example.net"}
	if len(got) != len(want) {
		t.Fatalf("Entries = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Entries = %v, want %v", got, want)
		}
	}
}

// TestExactEntryMatchesOnlyItsName: "=name" allows that name and nothing under it,
// and an exact entry cannot be a wildcard.
func TestExactEntryMatchesOnlyItsName(t *testing.T) {
	a := New()
	if err := scanAllowlistReader(strings.NewReader("=api.example.com\n"), a.domains, a.wildcard, a.exact, "test"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cases := map[string]bool{
		"api.example.com":   true,
		"API.example.com.":  true,
		"x.api.example.com": false,
		"example.com":       false,
		"other.example.com": false,
	}
	for name, want := range cases {
		if got := a.Allowed(name); got != want {
			t.Errorf("Allowed(%q) = %v, want %v", name, got, want)
		}
	}
	if got := a.Entries(); len(got) != 1 || got[0] != "=api.example.com" {
		t.Errorf("Entries = %v", got)
	}

	for _, bad := range []string{"=*.example.com", "=com", "="} {
		b := New()
		if err := scanAllowlistReader(strings.NewReader(bad+"\n"), b.domains, b.wildcard, b.exact, "test"); err == nil {
			t.Errorf("%q: want load error", bad)
		}
	}
}
