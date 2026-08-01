// SPDX-License-Identifier: MIT
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/rcvd-dns/rcvd/internal/config"
	"github.com/rcvd-dns/rcvd/internal/resolver"
)

// TestDoQClientRetriesStaleConnection reproduces the dominant Issue 31 field failure and
// asserts the exchange-level retry silences it: a query issued on a pooled connection whose
// server side has gone away (the router's 30s idle close, or a restart) must transparently
// re-dial and succeed on the second attempt — NOT return a "DoQ read length" error that
// bubbles up as SERVFAIL. Without the retry, the second query below fails.
func TestDoQClientRetriesStaleConnection(t *testing.T) {
	certPEM, keyPEM, err := generateSelfSignedCert([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	pin := config.SPKIPin(leaf)

	const addr = "127.0.0.1:18855"
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	startServer := func() (*DOQListener, context.CancelFunc) {
		l, err := NewDOQListener(addr, tlsConfig, echoQuestionResolver{}, nil, nil, nil, testLoggerDoQ())
		if err != nil {
			t.Fatalf("create DoQ listener: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go l.Serve(ctx)
		time.Sleep(300 * time.Millisecond) // let the UDP/QUIC listener bind
		return l, cancel
	}

	l1, cancel1 := startServer()

	// A logger we can inspect to confirm the retry PATH classification (Issue 31 3a).
	var logBuf bytes.Buffer
	client := resolver.NewDoQResolver("localhost", "127.0.0.1", 18855, pin, nil)
	client.SetLogger(log.New(&logBuf, "", 0))
	defer client.Close()

	ask := func(name string) (*dns.Msg, error) {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		q.Id = 0
		qCtx, qCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer qCancel()
		return client.Resolve(qCtx, q)
	}

	// First query establishes and pools a connection to l1.
	if _, err := ask("first.example.com."); err != nil {
		t.Fatalf("first query (fresh conn) failed: %v", err)
	}

	// Kill the server out from under the pooled connection, then bring an identical one
	// back on the same address. The client still holds the now-dead conn — exactly the
	// live "router closed the idle connection" condition.
	cancel1()
	l1.Close()
	time.Sleep(200 * time.Millisecond)
	l2, cancel2 := startServer()
	defer func() { cancel2(); l2.Close() }()

	// Second query: the pooled conn is stale. With the retry it re-dials and succeeds.
	resp, err := ask("second.example.com.")
	if err != nil {
		t.Fatalf("Issue 31: query on a stale pooled conn was NOT retried — got error: %v", err)
	}
	if len(resp.Question) != 1 || dns.CanonicalName(resp.Question[0].Name) != dns.CanonicalName("second.example.com.") {
		t.Fatalf("wrong response question after retry: %+v", resp.Question)
	}

	// The retry path should have logged the stale-conn classification, NOT a mismatch.
	logs := logBuf.String()
	if !strings.Contains(logs, "DoQ retry") {
		t.Errorf("expected a retry log line, got: %q", logs)
	}
	if strings.Contains(logs, "mismatch") {
		t.Errorf("stale-conn retry should not be classified as a question mismatch; logs: %q", logs)
	}
}
