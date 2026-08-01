// SPDX-License-Identifier: MIT
package tls

import (
	"context"
	"io"
	"log"
	"testing"
)

// discardLogger is a no-op logger for tests (NewManager logs on some paths).
func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// TestNewManagerValidation covers every input-validation branch of NewManager
// that fails BEFORE any storage or network work — pure argument checking.
func TestNewManagerValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *AutomationConfig
		wantErr bool
	}{
		{"nil config", nil, true},
		{
			"on-demand without allowed domains",
			&AutomationConfig{OnDemand: true},
			true,
		},
		{
			"dns01 without provider",
			&AutomationConfig{Challenge: "dns01", StorageDir: t.TempDir()},
			true,
		},
		{
			"dns01 without token",
			&AutomationConfig{Challenge: "dns01", DNSProvider: "cloudflare", StorageDir: t.TempDir()},
			true,
		},
		{
			"invalid challenge type",
			&AutomationConfig{Challenge: "carrier-pigeon", StorageDir: t.TempDir()},
			true,
		},
		{
			"valid minimal (no on-demand, http challenge, temp storage)",
			&AutomationConfig{StorageDir: t.TempDir()},
			false,
		},
		{
			"valid on-demand with allowed domains",
			&AutomationConfig{OnDemand: true, AllowedDomains: []string{"dns.example.com"}, StorageDir: t.TempDir()},
			false,
		},
		{
			"valid dns01 with provider + token",
			&AutomationConfig{Challenge: "dns01", DNSProvider: "cloudflare", DNSAPIToken: "test-token", StorageDir: t.TempDir()},
			false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewManager(tc.cfg, discardLogger())
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got manager %v", m)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if m == nil {
				t.Fatal("expected a manager, got nil")
			}
		})
	}
}

// TestIsAllowed pins the on-demand DecisionFunc: exact-match only, no subdomain
// or wildcard widening. This is the abuse-prevention gate on ACME issuance, so
// its behavior must not loosen silently.
func TestIsAllowed(t *testing.T) {
	m := &Manager{cfg: &AutomationConfig{
		AllowedDomains: []string{"dns.example.com", "resolver.example.org"},
	}}

	allowed := []string{"dns.example.com", "resolver.example.org"}
	for _, name := range allowed {
		if err := m.IsAllowed(context.Background(), name); err != nil {
			t.Errorf("IsAllowed(%q) = %v, want nil (allowed)", name, err)
		}
	}

	// Not allowlisted: unrelated names, AND — importantly — a subdomain of an
	// allowed name. Matching is exact; sub.dns.example.com must NOT pass.
	denied := []string{
		"evil.example.com",
		"sub.dns.example.com",
		"dns.example.com.attacker.net",
		"",
	}
	for _, name := range denied {
		if err := m.IsAllowed(context.Background(), name); err == nil {
			t.Errorf("IsAllowed(%q) = nil, want error (not allowlisted)", name)
		}
	}
}

// TestIsAllowedEmptyList: with no allowed domains, every name is denied.
func TestIsAllowedEmptyList(t *testing.T) {
	m := &Manager{cfg: &AutomationConfig{}}
	if err := m.IsAllowed(context.Background(), "anything.example.com"); err == nil {
		t.Error("IsAllowed with empty allowlist should deny, got nil")
	}
}

// TestNewDNS01Solver checks provider selection: a supported provider yields a
// solver, an unsupported one is a clear error (not a nil-deref later).
func TestNewDNS01Solver(t *testing.T) {
	if _, err := newDNS01Solver(&AutomationConfig{DNSProvider: "cloudflare", DNSAPIToken: "t"}); err != nil {
		t.Errorf("cloudflare provider: unexpected error: %v", err)
	}
	if _, err := newDNS01Solver(&AutomationConfig{DNSProvider: "route53", DNSAPIToken: "t"}); err == nil {
		t.Error("unsupported provider should error, got nil")
	}
}

// TestGetTLSConfigBaseALPN pins the BASE ALPN of the non-on-demand TLS config.
// This config is a base default only — the Mode-2 listeners override NextProtos
// per transport (DoQ→["doq"], DoH TCP→["h2"], DoH3→"h3" via quic-go). The base
// must be exactly ["h2"] and, critically, must NEVER contain "http/1.1": rcvd
// serves DoH strictly over h2/h3 and hard-rejects HTTP/1.1 (Issue 26), so an
// http/1.1 token leaking back into this base would be a silent downgrade surface.
// Regression guard against reintroducing the old ["h2","http/1.1","doq"] slice.
func TestGetTLSConfigBaseALPN(t *testing.T) {
	m, err := NewManager(&AutomationConfig{StorageDir: t.TempDir()}, discardLogger())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	tc := m.GetTLSConfig()
	if tc == nil {
		t.Fatal("GetTLSConfig returned nil")
	}
	if tc.GetCertificate == nil {
		t.Error("base TLS config must set GetCertificate")
	}
	if len(tc.NextProtos) != 1 || tc.NextProtos[0] != "h2" {
		t.Errorf("base NextProtos = %v, want exactly [\"h2\"]", tc.NextProtos)
	}
	for _, p := range tc.NextProtos {
		if p == "http/1.1" {
			t.Errorf("base NextProtos must NOT advertise %q — rcvd rejects HTTP/1.1 (Issue 26)", p)
		}
	}
}
