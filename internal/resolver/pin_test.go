// SPDX-License-Identifier: MIT
package resolver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rcvd-dns/rcvd/internal/config"
)

// makeSelfSigned builds a self-signed EC leaf cert with the given DNS SAN and an
// optional IP SAN, returning the tls.Certificate (for a server) and the parsed
// x509 leaf (for computing its pin).
func makeSelfSigned(t *testing.T, dnsName string, ip net.IP) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{dnsName},
	}
	if ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

func TestSpkiPinSHA256Deterministic(t *testing.T) {
	_, leaf := makeSelfSigned(t, "router.lan", nil)
	a := config.SPKIPin(leaf)
	b := config.SPKIPin(leaf)
	if a != b {
		t.Fatalf("pin not deterministic: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, config.PinPrefix) {
		t.Fatalf("pin missing %q prefix: %q", config.PinPrefix, a)
	}
	// Two different certs (different keys) must yield different pins.
	_, other := makeSelfSigned(t, "router.lan", nil)
	if config.SPKIPin(other) == a {
		t.Fatal("different keys produced the same pin")
	}
}

func TestParsePin(t *testing.T) {
	_, leaf := makeSelfSigned(t, "router.lan", nil)
	good := config.SPKIPin(leaf)

	raw, err := config.ParsePin(good)
	if err != nil {
		t.Fatalf("valid pin rejected: %v", err)
	}
	if len(raw) != sha256.Size {
		t.Fatalf("parsed pin wrong length: got %d want %d", len(raw), sha256.Size)
	}

	bad := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"no prefix", "AAAA"},
		{"wrong prefix", "sha1//AAAA"},
		{"bad base64", config.PinPrefix + "!!!not-base64!!!"},
		{"too short", config.PinPrefix + "AAAA"},                                       // decodes to 3 bytes
		{"too long", config.PinPrefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, // >32 bytes
	}
	for _, tc := range bad {
		if _, err := config.ParsePin(tc.in); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}

func TestPinnedTLSConfigDefaultPathUnchanged(t *testing.T) {
	// With no pin, the config must be returned untouched: CA validation ON,
	// InsecureSkipVerify must stay false (guards the default path from regressing).
	conf := &tls.Config{ServerName: "router.lan", MinVersion: tls.VersionTLS12}
	out := pinnedTLSConfig(conf, "router.lan", "")
	if out.InsecureSkipVerify {
		t.Fatal("empty pin must NOT set InsecureSkipVerify")
	}
	if out.VerifyConnection != nil {
		t.Fatal("empty pin must NOT install a VerifyConnection closure")
	}
}

// dialPinned stands up a self-signed TLS server on loopback and dials it with the
// given client pin using the pinnedTLSConfig verifier path. Returns the handshake
// error (nil on success). Hermetic: no network beyond loopback.
func dialPinned(t *testing.T, serverCert tls.Certificate, sni, clientPin string) error {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Drive the handshake, then close.
		_ = conn.(*tls.Conn).Handshake()
		conn.Close()
	}()

	clientConf := pinnedTLSConfig(&tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
	}, sni, clientPin)

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", ln.Addr().String(), clientConf)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func TestPinnedHandshakeCorrectPin(t *testing.T) {
	// Self-signed server NOT in any trust store; correct pin must connect anyway
	// (this is the whole point of Option B — no CA trust needed).
	cert, leaf := makeSelfSigned(t, "router.lan", net.ParseIP("127.0.0.1"))
	pin := config.SPKIPin(leaf)
	if err := dialPinned(t, cert, "router.lan", pin); err != nil {
		t.Fatalf("correct pin should connect to self-signed peer, got: %v", err)
	}
}

func TestPinnedHandshakeWrongPin(t *testing.T) {
	cert, _ := makeSelfSigned(t, "router.lan", net.ParseIP("127.0.0.1"))
	// A pin from a DIFFERENT key.
	_, otherLeaf := makeSelfSigned(t, "router.lan", nil)
	wrongPin := config.SPKIPin(otherLeaf)
	if err := dialPinned(t, cert, "router.lan", wrongPin); err == nil {
		t.Fatal("wrong pin must fail the handshake (fail-closed)")
	}
}

func TestPinnedHandshakeWrongHostname(t *testing.T) {
	// Correct pin but SNI/hostname the cert does not cover: must still fail,
	// because the closure enforces VerifyHostname even though CA-chain is off.
	cert, leaf := makeSelfSigned(t, "router.lan", net.ParseIP("127.0.0.1"))
	pin := config.SPKIPin(leaf)
	if err := dialPinned(t, cert, "attacker.example", pin); err == nil {
		t.Fatal("wrong hostname must fail even with a matching pin")
	}
}
