// SPDX-License-Identifier: MIT
package blocklist

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Blocklist holds a set of blocked domains with wildcard support.
type Blocklist struct {
	domains map[string]bool // plain domains: example.com
	wildcard map[string]bool // wildcard domains: *.example.com
	mu      sync.RWMutex
	enabled bool
}

// New creates a new blocklist.
func New(enabled bool) *Blocklist {
	return &Blocklist{
		domains:  make(map[string]bool),
		wildcard: make(map[string]bool),
		enabled:  enabled,
	}
}

// IsBlocked checks if a domain is in the blocklist.
// Returns true if the domain matches by any of:
//   - exact match:            entry "example.com" blocks "example.com"
//   - bare-entry subdomains:  entry "example.com" also blocks "sub.example.com"
//     (a listed domain covers itself and everything under it — matching how
//     operators expect a blocklist to behave, e.g. dnsmasq address=/domain/ and
//     the OISD/hosts convention)
//   - wildcard subdomains:    entry "*.example.com" blocks "sub.example.com" but
//     not the apex "example.com" (subdomains-only form)
//
// Domain should be in FQDN format (trailing dot, e.g., "example.com.").
// Matching is case-insensitive.
func (b *Blocklist) IsBlocked(domain string) bool {
	if !b.enabled {
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	// Normalize to lowercase and remove trailing dot for matching
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Check exact match (bare entry blocking its own apex).
	if b.domains[domain] {
		return true
	}

	// Walk parent suffixes once. For "a.b.example.com" this yields
	// "b.example.com", "example.com", "com" — and at each level we check:
	//   - a bare entry for that suffix  → bare entry blocks all subdomains
	//   - "*." + that suffix            → wildcard blocks subdomains (not apex)
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		suffix := strings.Join(parts[i:], ".")
		if b.domains[suffix] || b.wildcard["*."+suffix] {
			return true
		}
	}

	return false
}

// LoadFiles loads blocklists from local files (plain domain list or hosts format).
// Auto-detects format based on file content. Returns the number of lines that
// were skipped as invalid across all files, so the caller can surface silent
// drops (0 = every entry loaded cleanly).
func (b *Blocklist) LoadFiles(paths []string) (skipped int, err error) {
	for _, path := range paths {
		n, err := b.loadFile(path)
		skipped += n
		if err != nil {
			return skipped, fmt.Errorf("load blocklist %s: %w", path, err)
		}
	}
	return skipped, nil
}

// loadFile loads a single blocklist file. Returns the count of skipped
// (invalid) lines.
func (b *Blocklist) loadFile(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	return b.parseFile(file)
}

// parseFile detects format and loads domains from a file, then merges the
// result into the live maps (add-only — used by the startup LoadFiles path).
// Supports:
// - Plain domain list (one domain per line)
// - Hosts format (IP domain domain domain...)
func (b *Blocklist) parseFile(r io.Reader) (int, error) {
	// Scan into temporary local maps — no lock held during the slow I/O scan.
	// This keeps IsBlocked() uncontested for the full duration of file loading.
	tmpDomains := make(map[string]bool)
	tmpWildcard := make(map[string]bool)
	skipped, err := b.scanInto(r, tmpDomains, tmpWildcard)
	if err != nil {
		return skipped, err
	}

	// Merge parsed entries into the live maps under a brief lock.
	b.mu.Lock()
	for k, v := range tmpDomains {
		b.domains[k] = v
	}
	for k, v := range tmpWildcard {
		b.wildcard[k] = v
	}
	b.mu.Unlock()

	return skipped, nil
}

// scanInto parses one blocklist reader into the provided maps (no lock held).
// Split out from parseFile so both the merge path (startup) and the replace
// path (reload) share one scanner/validator. Invalid lines are silently
// skipped, matching the original loader's tolerant behavior.
// Returns the number of non-blank, non-comment lines that were rejected as
// invalid (bad hostname, or a malformed hosts-format line) — so callers can log
// silent drops rather than leaving a filtering gap unreported.
func (b *Blocklist) scanInto(r io.Reader, domains, wildcard map[string]bool) (int, error) {
	addEntry := func(domain string) {
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if strings.HasPrefix(domain, "*.") {
			wildcard[domain] = true
		} else {
			domains[domain] = true
		}
	}

	skipped := 0
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		if net.ParseIP(fields[0]) != nil {
			// Hosts format: IP domain [domain ...]
			for _, domain := range fields[1:] {
				if b.isValidHostname(domain) {
					addEntry(domain)
				} else {
					skipped++
				}
			}
		} else if len(fields) == 1 {
			// Plain domain list
			if b.isValidHostname(fields[0]) {
				addEntry(fields[0])
			} else {
				skipped++
			}
		} else {
			// Non-hosts line with multiple fields — malformed, not loadable.
			skipped++
		}
	}

	if err := scanner.Err(); err != nil {
		return skipped, fmt.Errorf("scan file: %w", err)
	}
	return skipped, nil
}

// ReloadResult reports what a ReplaceFromFiles reload loaded, for logging.
type ReloadResult struct {
	Domains   int // exact-match domains in the new live set
	Wildcards int // wildcard (*.example.com) entries in the new live set
	FilesOK   int // files scanned without error
	FilesErr  int // files that failed to open/scan (skipped)
	Skipped   int // invalid lines dropped across all scanned files
}

// ReplaceFromFiles rebuilds the entire blocklist from the given files and
// atomically swaps it in, so entries removed from the files on disk are also
// removed from the live set (unlike LoadFiles, which only adds). This is the
// hot-reload path (--blocklist-reload).
//
// The full multi-file scan runs with no lock held — IsBlocked() stays
// uncontested for the whole (potentially minute-long) scan, exactly like
// startup. Only the final pointer swap takes the write lock, so DNS is never
// paused for more than that swap. Files that fail to open are skipped (counted
// in FilesErr) rather than aborting the reload; a file that vanished should not
// wipe the whole live set.
func (b *Blocklist) ReplaceFromFiles(paths []string) (ReloadResult, error) {
	newDomains := make(map[string]bool)
	newWildcard := make(map[string]bool)

	res := ReloadResult{}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			res.FilesErr++
			continue
		}
		skipped, err := b.scanInto(f, newDomains, newWildcard)
		f.Close()
		if err != nil {
			res.FilesErr++
			continue
		}
		res.Skipped += skipped
		res.FilesOK++
	}

	// Atomic swap — a pointer assignment under the write lock. Microseconds,
	// regardless of how long the scan above took.
	b.mu.Lock()
	b.domains = newDomains
	b.wildcard = newWildcard
	b.mu.Unlock()

	res.Domains = len(newDomains)
	res.Wildcards = len(newWildcard)
	return res, nil
}

// addDomain adds a domain to the blocklist (thread-safe, acquires lock).
// Handles wildcard domains (*.example.com).
func (b *Blocklist) addDomain(domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.addDomainNoLock(domain)
}

// addDomainNoLock adds a domain without acquiring the lock (caller must hold lock).
func (b *Blocklist) addDomainNoLock(domain string) {
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")

	if strings.HasPrefix(domain, "*.") {
		// Wildcard domain
		b.wildcard[domain] = true
	} else {
		// Plain domain
		b.domains[domain] = true
	}
}

// isValidHostname validates an RFC 1123 hostname (or wildcard variant).
// Allows: *.example.com, example.com, sub.example.com, etc.
func (b *Blocklist) isValidHostname(host string) bool {
	// Remove trailing dot for validation
	host = strings.TrimSuffix(host, ".")

	// Allow wildcard prefix
	if strings.HasPrefix(host, "*.") {
		host = host[2:]
	}

	if host == "" {
		return false
	}

	// Labels can contain alphanumeric, hyphen, and underscore, and cannot
	// start/end with a hyphen. Underscore is permitted because it is legal in
	// DNS names (RFC 2181 places no such restriction) and appears in real
	// blockworthy hosts (service/telemetry labels); rejecting it silently
	// dropped those entries and left a filtering gap.
	parts := strings.Split(host, ".")
	if len(parts) == 0 {
		return false
	}

	for _, part := range parts {
		if !hostLabelRE.MatchString(part) {
			return false
		}
	}

	return true
}

// hostLabelRE matches one DNS label: alphanumeric/underscore body, hyphen
// allowed internally but not at either end. Compiled once, not per-call.
var hostLabelRE = regexp.MustCompile(`^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?$`)

// LoadURLs fetches and loads blocklists from URLs.
// Respects HTTP timeouts and error handling.
func (b *Blocklist) LoadURLs(urls []string, timeout time.Duration) (skipped int, err error) {
	client := &http.Client{
		Timeout: timeout,
	}

	for _, url := range urls {
		n, err := b.loadURL(client, url)
		skipped += n
		if err != nil {
			return skipped, fmt.Errorf("load blocklist from %s: %w", url, err)
		}
	}

	return skipped, nil
}

// loadURL fetches a single URL and loads its content. Returns the count of
// skipped (invalid) lines.
func (b *Blocklist) loadURL(client *http.Client, url string) (int, error) {
	resp, err := client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return b.parseFile(resp.Body)
}

// Clear removes all domains from the blocklist.
func (b *Blocklist) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.domains = make(map[string]bool)
	b.wildcard = make(map[string]bool)
}

// Size returns the number of domains in the blocklist.
func (b *Blocklist) Size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return len(b.domains) + len(b.wildcard)
}

// Stats returns blocklist statistics.
func (b *Blocklist) Stats() map[string]int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return map[string]int{
		"total":    len(b.domains) + len(b.wildcard),
		"domains":  len(b.domains),
		"wildcard": len(b.wildcard),
	}
}

// Add adds a domain to the blocklist (convenience method, thread-safe).
func (b *Blocklist) Add(domain string) {
	b.addDomain(domain)
}
