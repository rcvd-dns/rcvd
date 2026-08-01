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
// Returns true if domain (exact match) or wildcard (*.example.com) matches.
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

	// Check exact match
	if b.domains[domain] {
		return true
	}

	// Check wildcard match: *.example.com matches subdomain.example.com
	// For domain "sub.example.com", check "*.example.com"
	parts := strings.Split(domain, ".")
	if len(parts) > 1 {
		// Check each parent domain
		for i := 1; i < len(parts); i++ {
			wildcard := "*." + strings.Join(parts[i:], ".")
			if b.wildcard[wildcard] {
				return true
			}
		}
	}

	return false
}

// LoadFiles loads blocklists from local files (plain domain list or hosts format).
// Auto-detects format based on file content.
func (b *Blocklist) LoadFiles(paths []string) error {
	for _, path := range paths {
		if err := b.loadFile(path); err != nil {
			return fmt.Errorf("load blocklist %s: %w", path, err)
		}
	}
	return nil
}

// loadFile loads a single blocklist file.
func (b *Blocklist) loadFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	return b.parseFile(file)
}

// parseFile detects format and loads domains from a file, then merges the
// result into the live maps (add-only — used by the startup LoadFiles path).
// Supports:
// - Plain domain list (one domain per line)
// - Hosts format (IP domain domain domain...)
func (b *Blocklist) parseFile(r io.Reader) error {
	// Scan into temporary local maps — no lock held during the slow I/O scan.
	// This keeps IsBlocked() uncontested for the full duration of file loading.
	tmpDomains := make(map[string]bool)
	tmpWildcard := make(map[string]bool)
	if err := b.scanInto(r, tmpDomains, tmpWildcard); err != nil {
		return err
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

	return nil
}

// scanInto parses one blocklist reader into the provided maps (no lock held).
// Split out from parseFile so both the merge path (startup) and the replace
// path (reload) share one scanner/validator. Invalid lines are silently
// skipped, matching the original loader's tolerant behavior.
func (b *Blocklist) scanInto(r io.Reader, domains, wildcard map[string]bool) error {
	addEntry := func(domain string) {
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if strings.HasPrefix(domain, "*.") {
			wildcard[domain] = true
		} else {
			domains[domain] = true
		}
	}

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
				}
			}
		} else if len(fields) == 1 {
			// Plain domain list
			if b.isValidHostname(fields[0]) {
				addEntry(fields[0])
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan file: %w", err)
	}
	return nil
}

// ReloadResult reports what a ReplaceFromFiles reload loaded, for logging.
type ReloadResult struct {
	Domains   int // exact-match domains in the new live set
	Wildcards int // wildcard (*.example.com) entries in the new live set
	FilesOK   int // files scanned without error
	FilesErr  int // files that failed to open/scan (skipped)
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
		err = b.scanInto(f, newDomains, newWildcard)
		f.Close()
		if err != nil {
			res.FilesErr++
			continue
		}
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

	// RFC 1123: labels can contain alphanumeric and hyphen
	// Labels cannot start/end with hyphen
	parts := strings.Split(host, ".")
	if len(parts) == 0 {
		return false
	}

	re := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	for _, part := range parts {
		if !re.MatchString(part) {
			return false
		}
	}

	return true
}

// LoadURLs fetches and loads blocklists from URLs.
// Respects HTTP timeouts and error handling.
func (b *Blocklist) LoadURLs(urls []string, timeout time.Duration) error {
	client := &http.Client{
		Timeout: timeout,
	}

	for _, url := range urls {
		if err := b.loadURL(client, url); err != nil {
			return fmt.Errorf("load blocklist from %s: %w", url, err)
		}
	}

	return nil
}

// loadURL fetches a single URL and loads its content.
func (b *Blocklist) loadURL(client *http.Client, url string) error {
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
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
