// SPDX-License-Identifier: MIT
package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"

	"github.com/rcvd-dns/rcvd/internal/config"
)

// TestAutogenSANHosts verifies the listen addresses become SAN hosts, loopback is always
// included, and an unspecified bind (0.0.0.0) is skipped.
func TestAutogenSANHosts(t *testing.T) {
	cfg := &config.UpstreamConfig{
		ListenDoH: "192.0.2.1:8443",
		ListenDoT: "0.0.0.0:853", // unspecified — must be skipped
		ListenDoQ: "",
	}
	hosts := autogenSANHosts(cfg)

	want := map[string]bool{"192.0.2.1": true, "127.0.0.1": true, "localhost": true}
	got := map[string]bool{}
	for _, h := range hosts {
		got[h] = true
	}
	for w := range want {
		if !got[w] {
			t.Errorf("expected SAN host %q in %v", w, hosts)
		}
	}
	if got["0.0.0.0"] {
		t.Errorf("unspecified 0.0.0.0 must NOT be a SAN host: %v", hosts)
	}
}

// TestAutogenSANHostsExtraHosts verifies operator-configured tls_cert_hosts entries (e.g. a
// tunnel hostname) are added to the SAN host list alongside the derived bind address + loopback.
func TestAutogenSANHostsExtraHosts(t *testing.T) {
	cfg := &config.UpstreamConfig{
		ListenDoH:    "0.0.0.0:8443", // unspecified bind — not a meaningful SAN on its own
		TLSCertHosts: []string{"doh-dev.rcvd.net", "192.0.2.10"},
	}
	hosts := autogenSANHosts(cfg)

	got := map[string]bool{}
	for _, h := range hosts {
		got[h] = true
	}
	for _, w := range []string{"doh-dev.rcvd.net", "192.0.2.10", "127.0.0.1", "localhost"} {
		if !got[w] {
			t.Errorf("expected SAN host %q in %v", w, hosts)
		}
	}
	if got["0.0.0.0"] {
		t.Errorf("unspecified 0.0.0.0 must NOT be a SAN host: %v", hosts)
	}
}

// TestGenerateSelfSignedCertSAN verifies the generated cert carries a non-loopback IP SAN
// (the bug fix: a LAN-facing Mode-2 endpoint like 192.0.2.1 must be in the cert, or no
// remote client can validate it). Also confirms the cert verifies against that IP.
func TestGenerateSelfSignedCertSAN(t *testing.T) {
	certPEM, keyPEM, err := generateSelfSignedCert([]string{"192.0.2.1", "127.0.0.1", "localhost"})
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load keypair: %v", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	// The non-loopback IP must be present in the IP SANs.
	found := false
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(net.ParseIP("192.0.2.1")) {
			found = true
		}
	}
	if !found {
		t.Errorf("cert IP SANs %v missing 192.0.2.1", leaf.IPAddresses)
	}

	// VerifyHostname must accept the LAN IP (this is what a browser checks).
	if err := leaf.VerifyHostname("192.0.2.1"); err != nil {
		t.Errorf("cert should be valid for 192.0.2.1: %v", err)
	}
	// And still accept loopback.
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("cert should still be valid for 127.0.0.1: %v", err)
	}
}
