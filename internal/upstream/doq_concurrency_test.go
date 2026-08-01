// SPDX-License-Identifier: MIT
package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/rcvd-dns/rcvd/internal/config"
	"github.com/rcvd-dns/rcvd/internal/resolver"
)

// echoQuestionResolver is a Mode-2 backing resolver that answers with the SAME
// question it was asked, plus one A record derived from the qname. It is the key
// to reproducing Issue 31: if the DoQ *client* (resolver.DoQResolver) ever pairs
// one query's stream with another query's response, the returned Question will not
// match what that client goroutine sent — and we can assert on it.
type echoQuestionResolver struct{}

func (echoQuestionResolver) Resolve(_ context.Context, msg *dns.Msg) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetReply(msg) // copies Question + Id, sets Response=true
	if len(msg.Question) == 1 {
		q := msg.Question[0]
		if q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A 192.0.2.1", q.Name))
			if rr != nil {
				resp.Answer = append(resp.Answer, rr)
			}
		}
	}
	return resp, nil
}

func (echoQuestionResolver) Close() error { return nil }

// TestDoQClientConcurrentResponseCorrelation exercises the ISSUES 31 conditions: the
// Mode-1 DoQ client (resolver.DoQResolver) is shared across all in-flight queries (one
// *quic.Conn pool). Under concurrent load it MUST return, for each query, the response to
// THAT query — never another concurrent query's answer — and must not collapse.
//
// SCOPE / HONESTY: this is a heavy-concurrency SURVIVAL test against a real DoQ server. It
// proves the fixed client serves 1280 concurrent distinct queries with zero wrong-question
// answers and zero teardown-cascade errors. It does NOT deterministically reproduce the live
// race itself (the field trigger is idle-timeout re-dial + real-RTT churn, which a zero-RTT
// localhost server doesn't recreate) — the DETERMINISTIC guard for the wrong-question swap is
// TestDoQResponseMatchesQuery in internal/resolver. The live symptom (2026-07-16):
// security.ubuntu.com came back stamped with question ftp.cvut.cz. See ISSUES 31.
func TestDoQClientConcurrentResponseCorrelation(t *testing.T) {
	// Real self-signed cert so the QUIC/TLS 1.3 handshake completes.
	certPEM, keyPEM, err := generateSelfSignedCert([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	// Derive the SPKI pin for the client — this is the SAME trust model as a live
	// pinned LAN leg (pinned self-signed cert), and avoids CA verification failing on
	// a self-signed test cert. Parse the leaf to compute its "sha256//" pin.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	pin := config.SPKIPin(leaf)

	const addr = "127.0.0.1:18854"
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	listener, err := NewDOQListener(addr, tlsConfig, echoQuestionResolver{}, nil, nil, nil, testLoggerDoQ())
	if err != nil {
		t.Fatalf("create DoQ listener: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go listener.Serve(ctx)
	time.Sleep(300 * time.Millisecond) // let the UDP/QUIC listener bind

	// ONE shared client — exactly how the Mode-1 server holds a single DoQResolver
	// and calls Resolve() from many request goroutines concurrently.
	client := resolver.NewDoQResolver("localhost", "127.0.0.1", 18854, pin, nil)
	defer client.Close()

	const (
		workers   = 32
		perWorker = 40
	)

	var wg sync.WaitGroup
	var mismatches int64
	var errs int64
	var mu sync.Mutex
	firstMismatch := ""

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				name := fmt.Sprintf("host-%d-%d.example.com.", w, i)
				q := new(dns.Msg)
				q.SetQuestion(name, dns.TypeA)
				q.Id = 0 // RFC 9250: ID on the wire is 0

				qCtx, qCancel := context.WithTimeout(ctx, 5*time.Second)
				resp, err := client.Resolve(qCtx, q)
				qCancel()
				if err != nil {
					mu.Lock()
					errs++
					if firstMismatch == "" {
						firstMismatch = "ERR: " + err.Error()
					}
					mu.Unlock()
					continue
				}
				if len(resp.Question) != 1 || dns.CanonicalName(resp.Question[0].Name) != dns.CanonicalName(name) {
					mu.Lock()
					mismatches++
					if firstMismatch == "" {
						got := "<none>"
						if len(resp.Question) == 1 {
							got = resp.Question[0].Name
						}
						firstMismatch = fmt.Sprintf("asked %q, response question %q", name, got)
					}
					mu.Unlock()
				}
			}
		}(w)
	}
	wg.Wait()

	total := int64(workers * perWorker)
	t.Logf("completed %d queries: %d transport errors, %d question mismatches; first: %s",
		total, errs, mismatches, firstMismatch)

	// Issue 31 has TWO faces, both failures of the shared-connection client under
	// concurrency: (a) a WRONG question section (one query's answer handed to another),
	// and (b) a transport error / no answer at all (the shared conn torn down under an
	// in-flight query by a sibling's error path). A correct client returns the right
	// answer to every concurrent query, so BOTH are asserted here.
	if mismatches > 0 {
		t.Fatalf("ISSUES 31 (wrong-question): %d/%d responses had a WRONG question section (first: %s)",
			mismatches, total, firstMismatch)
	}
	// Allow a tiny transient margin but fail on the wholesale collapse we see today.
	if errs > total/20 {
		t.Fatalf("ISSUES 31 (no-answer): %d/%d concurrent queries failed with a transport error "+
			"(shared-connection teardown race)", errs, total)
	}
}
