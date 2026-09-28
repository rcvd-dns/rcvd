// SPDX-License-Identifier: MIT

// Package allowlist is a default-deny name filter: when enabled, only names under
// listed suffixes resolve, and every other name is answered locally (REFUSED +
// EDE 18) — never forwarded, never cached. Enforced on Mode 1 (the port-5300
// UDP/TCP resolver) and Mode 2 (DoH/DoT/DoQ upstream service) through the shared
// policy package. The loader is strict by design, because a silently dropped allow
// entry would break a sandbox's egress assumption and a typo'd operator config
// would turn into a mysterious resolution failure rather than a startup error.
package allowlist

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Allowlist is a set of allowed name suffixes for default-deny mode.
//
// Matching mirrors blocklist.IsBlocked (apex + bare-entry + wildcard + case-insensitive),
// but in the inverse direction — "is this name under a listed suffix?". The struct
// stays independent of blocklist so the two filters can compose without sharing locks.
type Allowlist struct {
	domains  map[string]bool // plain domains: example.com
	wildcard map[string]bool // wildcard domains: *.example.com
	mu       sync.RWMutex
}

// New creates an empty allowlist. LoadFiles is the only way to populate it.
func New() *Allowlist {
	return &Allowlist{
		domains:  make(map[string]bool),
		wildcard: make(map[string]bool),
	}
}

// LoadFiles parses every file into a fresh set and, on full success, atomically
// swaps it in. The first invalid line aborts with a "file:line: reason" error
// naming the failing position; the previous live set is left unchanged on error.
// An enabled but empty allowlist (zero entries after parsing — e.g. a comments-only
// file) is a hard error too: a default-deny deploy that loads nothing would
// silently deny the entire host's egress, so refusing to start is safer than
// starting "deny all".
func (a *Allowlist) LoadFiles(paths []string) error {
	newDomains := make(map[string]bool)
	newWildcard := make(map[string]bool)

	for _, path := range paths {
		if err := scanAllowlistFile(path, newDomains, newWildcard); err != nil {
			return err
		}
	}

	if len(newDomains) == 0 && len(newWildcard) == 0 {
		return fmt.Errorf("no entries loaded (file(s) empty or contain only comments): %w", ErrEmptyAllowlist)
	}

	a.mu.Lock()
	a.domains = newDomains
	a.wildcard = newWildcard
	a.mu.Unlock()

	return nil
}

// ErrEmptyAllowlist is returned by LoadFiles when every input file parsed cleanly
// but yielded zero entries — a comments-only or whitespace-only file is the
// usual cause. A default-deny allowlist that loads nothing would silently
// refuse every name, so this is a hard startup error rather than a "deny all"
// runtime state.
var ErrEmptyAllowlist = errors.New("allowlist is empty")

// scanAllowlistFile parses one file into the provided maps (no lock held).
// First invalid line aborts the whole load with a "file:line" error.
func scanAllowlistFile(path string, domains, wildcard map[string]bool) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	return scanAllowlistReader(f, domains, wildcard, path)
}

func scanAllowlistReader(r io.Reader, domains, wildcard map[string]bool, label string) error {
	scanner := bufio.NewScanner(r)
	// Allow long lines (e.g. pasted comment blobs).
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())

		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		// Reject hosts-format lines (IP-prefixed) outright: the allowlist is a
		// domain list, not a hosts file.
		if net.ParseIP(firstField(raw)) != nil {
			return fmt.Errorf("%s:%d: hosts-format line is not allowed in an allowlist (got %q)",
				label, lineNo, raw)
		}

		fields := strings.Fields(raw)
		if len(fields) != 1 {
			return fmt.Errorf("%s:%d: expected a single domain per line, got %q",
				label, lineNo, raw)
		}

		entry := fields[0]
		if err := validateAllowlistEntry(entry); err != nil {
			return fmt.Errorf("%s:%d: %w", label, lineNo, err)
		}

		normalized := strings.ToLower(strings.TrimSuffix(entry, "."))
		if strings.HasPrefix(normalized, "*.") {
			wildcard[normalized] = true
		} else {
			domains[normalized] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan file: %w", err)
	}
	return nil
}

// validateAllowlistEntry rejects bare TLDs ("com"), since they would silently
// allow nearly everything. Underscore labels are also rejected.
func validateAllowlistEntry(entry string) error {
	host := strings.TrimSuffix(entry, ".")

	if host == "" {
		return fmt.Errorf("entry is empty")
	}

	// Strip the optional wildcard prefix once.
	if strings.HasPrefix(host, "*.") {
		host = host[2:]
		if host == "" {
			return fmt.Errorf("wildcard with empty suffix")
		}
	}

	// Bare TLDs (no dot after optional strip) — "com", "io", etc. would allow
	// nearly every name.
	if !strings.Contains(host, ".") {
		return fmt.Errorf("entry %q is a bare TLD (must include a dot, e.g. \"example.com\")", entry)
	}

	if !allowlistHostRE.MatchString(host) {
		return fmt.Errorf("entry %q is not a valid hostname", entry)
	}
	for _, label := range strings.Split(host, ".") {
		if !hostLabelRE.MatchString(label) {
			return fmt.Errorf("entry %q has an invalid label", entry)
		}
	}

	return nil
}

// allowlistHostRE is a coarse pre-filter on the joined hostname (after the
// optional "*." strip). The fine-grained check is label-by-label with
// hostLabelRE; this one rejects the obvious junk quickly.
var allowlistHostRE = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)

// hostLabelRE matches one DNS label: alphanumeric body, hyphen allowed internally
// but not at either end, no underscore.
var hostLabelRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// firstField returns the first whitespace-separated token of s. Used to detect
// hosts-format lines without an allocation.
func firstField(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			return s[:i]
		}
	}
	return s
}

// Allowed reports whether name (FQDN, trailing dot optional, any case) is under
// an allowed suffix. Returns false when the allowlist is empty (no entries ⇒
// default-deny ⇒ everything is denied).
func (a *Allowlist) Allowed(name string) bool {
	if name == "" {
		return false
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.domains) == 0 && len(a.wildcard) == 0 {
		return false
	}

	domain := strings.ToLower(strings.TrimSuffix(name, "."))

	// Exact match: an apex entry "example.com" allows the apex itself.
	if a.domains[domain] {
		return true
	}

	// Walk parent suffixes. For "a.b.example.com" this yields "b.example.com",
	// "example.com", "com" — at each level:
	//   - a bare entry for that suffix  → bare entry allows all subdomains
	//   - "*." + that suffix            → wildcard allows subdomains (not apex)
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		suffix := strings.Join(parts[i:], ".")
		if a.domains[suffix] || a.wildcard["*."+suffix] {
			return true
		}
	}

	return false
}

// Entries returns a sorted copy of the current entries, bare and wildcard ("*.")
// forms as written (lowercased, no trailing dot).
func (a *Allowlist) Entries() []string {
	a.mu.RLock()
	out := make([]string, 0, len(a.domains)+len(a.wildcard))
	for d := range a.domains {
		out = append(out, d)
	}
	for w := range a.wildcard {
		out = append(out, w)
	}
	a.mu.RUnlock()
	sort.Strings(out)
	return out
}

// Size returns the number of entries currently in the allowlist (apex + wildcard).
// Zero means default-deny allows nothing — the safe state before LoadFiles succeeds.
func (a *Allowlist) Size() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.domains) + len(a.wildcard)
}
