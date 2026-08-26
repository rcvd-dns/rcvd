// SPDX-License-Identifier: MIT
package resolver

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rcvd-dns/rcvd/internal/config"
)

// staleFirstConnDoTServer is a minimal RFC 7858 DoT server that CLOSES the
// connection immediately after answering the very first exchange, then answers
// normally on every subsequent connection. This reproduces the Issue 37 field
// condition: Mullvad drops the idle pooled DoT conn server-side, so the first
// query after an idle gap rides a dead connection. It returns the listen
// host:port and the server cert (for pinning).
func staleFirstConnDoTServer(t *testing.T, name string) (hostport string, cert tls.Certificate, exchanges *int64) {
	t.Helper()
	serverCert, _ := makeSelfSigned(t, name, net.ParseIP("127.0.0.1"))

	tlsConf := &tls.Config{Certificates: []tls.Certificate{serverCert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConf)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var count int64 // total exchanges served (across all conns)
	var firstConn int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			first := atomic.AddInt64(&firstConn, 1) == 1
			go serveDoTOneExchange(conn, &count, first)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), serverCert, &count
}

// serveDoTOneExchange reads one length-prefixed query, writes a length-prefixed
// answer echoing the query ID, then (if closeAfter) drops the connection — the
// stale-conn condition the client must survive by retrying on a fresh dial.
func serveDoTOneExchange(conn net.Conn, count *int64, closeAfter bool) {
	defer conn.Close()
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return
	}
	qlen := int(lenBuf[0])<<8 | int(lenBuf[1])
	qbuf := make([]byte, qlen)
	if _, err := io.ReadFull(conn, qbuf); err != nil {
		return
	}
	q := new(dns.Msg)
	if err := q.Unpack(qbuf); err != nil {
		return
	}
	resp := new(dns.Msg)
	resp.SetReply(q)
	rr, _ := dns.NewRR("example.com. 60 IN A 192.0.2.1")
	resp.Answer = append(resp.Answer, rr)
	rbuf, err := resp.Pack()
	if err != nil {
		return
	}
	out := append([]byte{byte(len(rbuf) >> 8), byte(len(rbuf))}, rbuf...)
	if _, err := conn.Write(out); err != nil {
		return
	}
	atomic.AddInt64(count, 1)
	if closeAfter {
		return // drop the conn — the client's pooled conn is now dead
	}
	// keep the conn open a beat so the client may pool it, then let cleanup close it
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadFull(conn, make([]byte, 1))
}

// TestDoTStaleConnRetry is the deterministic guard for Issue 37: a query whose
// pooled DoT connection has gone stale server-side must succeed via the one-shot
// retry on a fresh connection, NOT surface an error (which, with a single
// upstream, becomes "all upstreams failed" → SERVFAIL). Before the fix the retry
// was dead code (isPooled() was always false post-teardown) and this failed.
func TestDoTStaleConnRetry(t *testing.T) {
	hostport, serverCert, _ := staleFirstConnDoTServer(t, "dot.test")
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("split hostport: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	pin := config.SPKIPin(serverCert.Leaf)
	r := NewTLSResolver("dot.test", host, port, pin, nil)
	defer r.Close()

	q := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		return m
	}

	// First query: dials fresh, gets an answer; server closes the conn afterward,
	// so the pooled conn is now dead server-side.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.Resolve(ctx, q()); err != nil {
		t.Fatalf("first DoT resolve failed: %v", err)
	}

	// Second query: the pooled conn is stale. The retry must dial fresh and
	// succeed. This is the exact Issue 37 apex-vs-www ordering the fix addresses.
	resp, err := r.Resolve(ctx, q())
	if err != nil {
		t.Fatalf("Issue 37: DoT resolve over a stale pooled conn should retry and succeed, got: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer after retry, got %d", len(resp.Answer))
	}
}
