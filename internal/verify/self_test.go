// SPDX-License-Identifier: MIT
package verify

import (
	"strings"
	"testing"

	"github.com/rcvd-dns/rcvd/internal/config"
)

func TestSelfEndpoints_Derivation(t *testing.T) {
	cfg := &config.UpstreamConfig{
		Enabled:   true,
		ListenDoH: "0.0.0.0:8443", // unspecified bind → dial loopback, SNI localhost
		ListenDoT: "127.0.0.1:853",
		ListenDoQ: "", // disabled → not probed
	}
	eps := selfEndpoints(cfg)
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints (DoH+DoT), got %d: %+v", len(eps), eps)
	}

	doh := eps[0]
	if doh.protocol != "DoH" || doh.port != 8443 {
		t.Errorf("DoH endpoint wrong: %+v", doh)
	}
	if doh.dialHost != "127.0.0.1" {
		t.Errorf("unspecified bind should dial loopback, got dialHost=%q", doh.dialHost)
	}
	if doh.sni != "localhost" {
		t.Errorf("unspecified bind SNI should default to localhost, got %q", doh.sni)
	}

	dot := eps[1]
	if dot.protocol != "DoT" || dot.port != 853 || dot.dialHost != "127.0.0.1" {
		t.Errorf("DoT endpoint wrong: %+v", dot)
	}
	// A loopback IP literal isn't a useful SNI; defaults to localhost.
	if dot.sni != "localhost" {
		t.Errorf("IP-literal listener SNI should default to localhost, got %q", dot.sni)
	}
}

func TestSelfEndpoints_HostnameListenerKeepsSNI(t *testing.T) {
	cfg := &config.UpstreamConfig{
		Enabled:   true,
		ListenDoH: "doh.example.com:443",
	}
	eps := selfEndpoints(cfg)
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	if eps[0].dialHost != "doh.example.com" || eps[0].sni != "doh.example.com" {
		t.Errorf("a hostname listener should keep its host for dial + SNI, got %+v", eps[0])
	}
}

func TestSelfEndpoints_NoneWhenUnconfigured(t *testing.T) {
	cfg := &config.UpstreamConfig{Enabled: true}
	if eps := selfEndpoints(cfg); len(eps) != 0 {
		t.Errorf("expected no endpoints when no listener configured, got %+v", eps)
	}
}

func TestClassifySelfCert_SelfSigned(t *testing.T) {
	certs := []CertInfo{{
		Subject: "CN=rcvd-autogen",
		Issuer:  "CN=rcvd-autogen", // leaf is its own issuer, single-cert chain → self-signed
	}}
	got := classifySelfCert(certs)
	if !strings.Contains(got, "SELF-SIGNED") {
		t.Errorf("expected SELF-SIGNED classification, got: %q", got)
	}
}

func TestClassifySelfCert_CAIssued(t *testing.T) {
	certs := []CertInfo{
		{Subject: "CN=doh.example.com", Issuer: "CN=R3,O=Let's Encrypt,C=US"},
		{Subject: "CN=R3,O=Let's Encrypt,C=US", Issuer: "CN=ISRG Root X1,O=Internet Security Research Group"},
	}
	got := classifySelfCert(certs)
	if !strings.Contains(got, "CA-ISSUED") {
		t.Errorf("expected CA-ISSUED classification, got: %q", got)
	}
	if !strings.Contains(got, "R3") {
		t.Errorf("expected issuer CN (R3) surfaced, got: %q", got)
	}
}

func TestClassifySelfCert_Empty(t *testing.T) {
	if got := classifySelfCert(nil); !strings.Contains(got, "no certificate") {
		t.Errorf("empty chain should report no certificate, got: %q", got)
	}
}

func TestIssuerCommonName(t *testing.T) {
	cases := map[string]string{
		"CN=R3,O=Let's Encrypt,C=US": "R3",
		"O=Acme,C=US":                "", // no CN
		"CN=rcvd-autogen":            "rcvd-autogen",
	}
	for in, want := range cases {
		if got := issuerCommonName(in); got != want {
			t.Errorf("issuerCommonName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVerifySelf_Mode2Disabled(t *testing.T) {
	cfg := &config.UpstreamConfig{Enabled: false}
	out, ok := VerifySelf(nil, "/etc/rcvd/rcvd.toml", cfg, "", "")
	if ok {
		t.Error("VerifySelf should report not-ok when Mode 2 is disabled")
	}
	if !strings.Contains(out, "not enabled") {
		t.Errorf("expected a 'not enabled' message, got: %q", out)
	}
}

func TestVerifySelf_NoListeners(t *testing.T) {
	cfg := &config.UpstreamConfig{Enabled: true} // enabled but no listen_* set
	out, ok := VerifySelf(nil, "/etc/rcvd/rcvd.toml", cfg, "", "")
	if ok {
		t.Error("VerifySelf should report not-ok when no listener is configured")
	}
	if !strings.Contains(out, "no listener address") {
		t.Errorf("expected a 'no listener address' message, got: %q", out)
	}
}

func TestFormatSelfResults_ShowsDoHHostname(t *testing.T) {
	// The configured DoH hostname must appear in the header when present, and be
	// absent (no empty "DoH hostname:" line) when not.
	with := formatSelfResults("/etc/rcvd/rcvd-roam.toml", "doh-dev.rcvd.net", nil)
	if !strings.Contains(with, "DoH hostname: doh-dev.rcvd.net") {
		t.Errorf("expected the DoH hostname in the header, got:\n%s", with)
	}
	without := formatSelfResults("/etc/rcvd/rcvd.toml", "", nil)
	if strings.Contains(without, "DoH hostname:") {
		t.Errorf("expected no DoH-hostname line when unset, got:\n%s", without)
	}
}
