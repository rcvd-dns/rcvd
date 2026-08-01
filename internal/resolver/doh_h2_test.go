// SPDX-License-Identifier: MIT
package resolver

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rcvd-dns/rcvd/internal/config"
	"golang.org/x/net/http2"
)

// h2OnlyDoHServer starts a DoH endpoint that speaks HTTP/2 ONLY — it advertises just
// "h2" in ALPN and never offers http/1.1, exactly like Mullvad's / Quad9's DoH
// endpoints. This is the condition that exposed ISSUES 32: rcvd's DoH client, once a
// custom DialContext was set, silently fell back to HTTP/1.1 and every request against
// such a server failed with `malformed HTTP response "\x00\x00\x06\x04…"` (the server's
// h2 SETTINGS frame parsed as an HTTP/1 status line). Returns the listen host:port and
// the server cert (for pinning). The server answers /dns-query with a fixed A record.
func h2OnlyDoHServer(t *testing.T) (hostport string, cert tls.Certificate) {
	t.Helper()
	serverCert, _ := makeSelfSigned(t, "doh.test", net.ParseIP("127.0.0.1"))

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		// Guard: this test is meaningless unless the request actually arrived over h2.
		if r.ProtoMajor != 2 {
			t.Errorf("server received %s, expected HTTP/2", r.Proto)
			http.Error(w, "expected h2", http.StatusHTTPVersionNotSupported)
			return
		}
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		resp := new(dns.Msg)
		resp.SetReply(q)
		rr, _ := dns.NewRR("example.com. 60 IN A 192.0.2.1")
		resp.Answer = append(resp.Answer, rr)
		buf, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(buf)
	})

	srv := &http.Server{Handler: mux}
	// h2-only ALPN — no "http/1.1". A client offering only http/1.1 fails the handshake.
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		NextProtos:   []string{"h2"},
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		t.Fatalf("configure h2 server: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConf)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), serverCert
}

// TestDoHClientH2OnlyUpstream is the regression guard for ISSUES 32: the classic-DoH
// (non-DoH3) client MUST negotiate HTTP/2 against an h2-only upstream. Before the fix the
// client spoke HTTP/1.1 (custom DialContext disables stdlib auto-h2) and this failed with
// a "malformed HTTP response" from the server's h2 SETTINGS frame.
func TestDoHClientH2OnlyUpstream(t *testing.T) {
	hostport, serverCert := h2OnlyDoHServer(t)
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("split hostport: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	// Pin the server's SPKI (self-signed) — same trust model as the live pinned legs,
	// and it means the client dials by IP with SNI "doh.test".
	pin := config.SPKIPin(serverCert.Leaf)

	r, err := NewHTTPResolver("doh.test", host, port, "/dns-query", false /* useH3 */, pin, nil)
	if err != nil {
		t.Fatalf("NewHTTPResolver: %v", err)
	}
	defer r.Close()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := r.Resolve(ctx, q)
	if err != nil {
		t.Fatalf("ISSUES 32: DoH resolve against h2-only upstream failed (client not speaking h2?): %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
}
