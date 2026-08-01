// SPDX-License-Identifier: MIT
package blocklist

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// writeList writes a blocklist file into a temp dir and returns its path.
func writeList(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// TestReplaceFromFilesAddsAndRemoves is the core of --blocklist-reload: entries
// added to the file appear, and entries removed from the file stop blocking
// (the whole set is rebuilt, not merged).
func TestReplaceFromFilesAddsAndRemoves(t *testing.T) {
	dir := t.TempDir()
	path := writeList(t, dir, "domainswild", "a.com\nb.com\n*.ads.net\n")

	b := New(true)
	res, err := b.ReplaceFromFiles([]string{path})
	if err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	if res.Domains != 2 || res.Wildcards != 1 || res.FilesOK != 1 || res.FilesErr != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !b.IsBlocked("a.com") || !b.IsBlocked("x.ads.net") {
		t.Fatal("expected a.com and *.ads.net to block after first load")
	}

	// Rewrite the file: drop b.com, drop the wildcard, add c.com.
	if err := os.WriteFile(path, []byte("a.com\nc.com\n"), 0644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	res, err = b.ReplaceFromFiles([]string{path})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if res.Domains != 2 || res.Wildcards != 0 {
		t.Fatalf("unexpected result after rewrite: %+v", res)
	}

	// Added entry blocks.
	if !b.IsBlocked("c.com") {
		t.Error("expected c.com to block after reload (add)")
	}
	// Removed entries no longer block — this is what merge-only cannot do.
	if b.IsBlocked("b.com") {
		t.Error("expected b.com to STOP blocking after reload (subtract)")
	}
	if b.IsBlocked("x.ads.net") {
		t.Error("expected *.ads.net to STOP blocking after reload (subtract)")
	}
	// Untouched entry still blocks.
	if !b.IsBlocked("a.com") {
		t.Error("expected a.com to keep blocking across reload")
	}
}

// TestReplaceFromFilesMissingFileSkipped verifies a vanished file is skipped
// (counted in FilesErr) rather than wiping the live set or erroring out.
func TestReplaceFromFilesMissingFileSkipped(t *testing.T) {
	dir := t.TempDir()
	good := writeList(t, dir, "good.txt", "keep.com\n")
	missing := filepath.Join(dir, "does-not-exist.txt")

	b := New(true)
	res, err := b.ReplaceFromFiles([]string{good, missing})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if res.FilesOK != 1 || res.FilesErr != 1 {
		t.Fatalf("expected 1 ok / 1 err, got %+v", res)
	}
	if !b.IsBlocked("keep.com") {
		t.Error("entries from the readable file should still load when another file is missing")
	}
}

// TestReplaceFromFilesMalformedSkipped verifies invalid lines are silently
// skipped, matching the tolerant startup loader.
func TestReplaceFromFilesMalformedSkipped(t *testing.T) {
	dir := t.TempDir()
	path := writeList(t, dir, "list.txt", "good.com\n-bad-.com\n\n# comment\nalso-good.com\n")

	b := New(true)
	res, err := b.ReplaceFromFiles([]string{path})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if res.Domains != 2 {
		t.Fatalf("expected 2 valid domains, got %d (%+v)", res.Domains, res)
	}
	if !b.IsBlocked("good.com") || !b.IsBlocked("also-good.com") {
		t.Error("valid entries around a malformed line should load")
	}
}

// TestReplaceFromFilesConcurrentReads confirms IsBlocked stays safe (no race,
// no panic) while a reload swaps the set underneath it. Run with -race.
func TestReplaceFromFilesConcurrentReads(t *testing.T) {
	dir := t.TempDir()
	path := writeList(t, dir, "list.txt", "stable.com\n")

	b := New(true)
	if _, err := b.ReplaceFromFiles([]string{path}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Readers hammer IsBlocked throughout.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = b.IsBlocked("stable.com")
					_ = b.IsBlocked("churn.com")
				}
			}
		}()
	}

	// Reloader swaps the set repeatedly.
	for i := 0; i < 50; i++ {
		content := "stable.com\n"
		if i%2 == 0 {
			content += "churn.com\n"
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("rewrite: %v", err)
		}
		if _, err := b.ReplaceFromFiles([]string{path}); err != nil {
			t.Fatalf("reload %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()

	// stable.com is present in every version, so it must still block.
	if !b.IsBlocked("stable.com") {
		t.Error("stable.com should block after the reload churn")
	}
}
