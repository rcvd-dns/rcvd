// SPDX-License-Identifier: MIT
package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

// generateTestCert creates a self-signed x509 certificate for testing.
func generateTestCert(t *testing.T, cn string, sans []string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: "Test CA", Organization: []string{"Test Org"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     sans,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestFingerprint(t *testing.T) {
	cert := generateTestCert(t, "test.example.com",
		[]string{"test.example.com"},
		time.Now().Add(-time.Hour),
		time.Now().Add(24*time.Hour),
	)

	fp := fingerprint(cert)

	// Must start with SHA256:
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("fingerprint should start with SHA256:, got %s", fp)
	}

	// Must be valid base64 that decodes to 32 bytes (SHA256)
	b64Part := strings.TrimPrefix(fp, "SHA256:")
	decoded, err := base64.RawStdEncoding.DecodeString(b64Part)
	if err != nil {
		t.Fatalf("fingerprint base64 decode failed: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("expected 32 decoded bytes, got %d", len(decoded))
	}

	// Verify it matches manual SHA256
	expected := sha256.Sum256(cert.Raw)
	if string(decoded) != string(expected[:]) {
		t.Error("fingerprint does not match manual SHA256")
	}
}

func TestExtractCerts(t *testing.T) {
	now := time.Now()
	cert := generateTestCert(t, "dns.example.com",
		[]string{"dns.example.com", "dns2.example.com"},
		now.Add(-30*24*time.Hour),
		now.Add(60*24*time.Hour),
	)

	infos := extractCerts([]*x509.Certificate{cert})

	if len(infos) != 1 {
		t.Fatalf("expected 1 cert info, got %d", len(infos))
	}

	info := infos[0]

	// Subject should contain CN
	if !strings.Contains(info.Subject, "dns.example.com") {
		t.Errorf("subject should contain CN, got %s", info.Subject)
	}

	// SANs
	if len(info.SANs) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(info.SANs))
	}
	if info.SANs[0] != "dns.example.com" {
		t.Errorf("expected first SAN dns.example.com, got %s", info.SANs[0])
	}

	// Key algorithm
	if info.KeyAlgorithm != "ECDSA" {
		t.Errorf("expected ECDSA key, got %s", info.KeyAlgorithm)
	}
	if info.KeyDetail != "P-256" {
		t.Errorf("expected P-256 key detail, got %s", info.KeyDetail)
	}

	// Fingerprint present
	if !strings.HasPrefix(info.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint missing, got %s", info.Fingerprint)
	}
}

func TestExtractCertsEmpty(t *testing.T) {
	infos := extractCerts(nil)
	if len(infos) != 0 {
		t.Errorf("expected 0 infos for nil input, got %d", len(infos))
	}
}

func TestFormatResultsSuccess(t *testing.T) {
	results := []UpstreamResult{
		{
			Name:          "TestUpstream",
			Host:          "dns.example.com",
			Port:          853,
			Protocol:      "DoQ",
			Success:       true,
			TLSVersion:    "TLS 1.3",
			ALPN:          "doq",
			CipherSuite:   "TLS_AES_256_GCM_SHA384",
			ChainValid:    true,
			HostnameValid: true,
			DaysRemaining: 45,
			Certs: []CertInfo{
				{
					Subject:      "CN=dns.example.com",
					Issuer:       "CN=Test CA",
					SANs:         []string{"dns.example.com"},
					NotBefore:    time.Now().Add(-30 * 24 * time.Hour),
					NotAfter:     time.Now().Add(45 * 24 * time.Hour),
					KeyAlgorithm: "ECDSA",
					KeyDetail:    "P-256",
					Fingerprint:  "SHA256:qrvM",
				},
			},
		},
	}

	output := formatResults("/etc/rcvd/rcvd.toml", results)

	// Check key sections are present
	checks := []string{
		"RCVD Upstream TLS Verification",
		"Config: /etc/rcvd/rcvd.toml",
		"TestUpstream [DoQ] dns.example.com:853",
		"QUIC + TLS 1.3",
		"ALPN:           doq",
		"TLS_AES_256_GCM_SHA384",
		"[0] Leaf",
		"CN=dns.example.com",
		"CN=Test CA",
		"ECDSA P-256",
		"SHA256:qrvM",
		"Verified against system CA bundle",
		"dns.example.com matches certificate SANs",
		"45 days remaining",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing: %q", check)
		}
	}
}

func TestFormatResultsFailure(t *testing.T) {
	results := []UpstreamResult{
		{
			Name:     "Broken",
			Host:     "bad.example.com",
			Port:     853,
			Protocol: "DoT",
			Success:  false,
			Error:    "connection refused",
		},
	}

	output := formatResults("test.toml", results)

	if !strings.Contains(output, "FAILED") {
		t.Error("output should contain FAILED for failed connection")
	}
	if !strings.Contains(output, "connection refused") {
		t.Error("output should contain error message")
	}
}

func TestFormatResultsExpiryWarning(t *testing.T) {
	results := []UpstreamResult{
		{
			Name:          "Expiring",
			Host:          "dns.example.com",
			Port:          853,
			Protocol:      "DoT",
			Success:       true,
			TLSVersion:    "TLS 1.3",
			CipherSuite:   "TLS_AES_256_GCM_SHA384",
			ChainValid:    true,
			HostnameValid: true,
			DaysRemaining: 7,
			Certs: []CertInfo{
				{
					Subject:      "CN=dns.example.com",
					Issuer:       "CN=Test CA",
					NotBefore:    time.Now().Add(-83 * 24 * time.Hour),
					NotAfter:     time.Now().Add(7 * 24 * time.Hour),
					KeyAlgorithm: "ECDSA",
					KeyDetail:    "P-256",
					Fingerprint:  "SHA256:qrs",
				},
			},
		},
	}

	output := formatResults("test.toml", results)

	if !strings.Contains(output, "WARNING") {
		t.Error("output should contain WARNING for expiring cert")
	}
}
