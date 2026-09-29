// SPDX-License-Identifier: MIT
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/rcvd-dns/rcvd/internal/allowlist"
	"github.com/rcvd-dns/rcvd/internal/blocklist"
	"github.com/rcvd-dns/rcvd/internal/cache"
	"github.com/rcvd-dns/rcvd/internal/policy"
	"github.com/rcvd-dns/rcvd/internal/statistics"
)

// policyMockResolver is a Mode-2 backing resolver used by the policy end-to-end
// tests. It returns NOERROR with a fixed A record; callCount tracks how many times
// upstream is invoked so a test can assert the deny path never reaches it.
type policyMockResolver struct {
	response  *dns.Msg
	callCount atomic.Int64
}

func (p *policyMockResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	p.callCount.Add(1)
	if p.response == nil {
		return new(dns.Msg).SetReply(msg), nil
	}
	resp := p.response.Copy()
	resp.Id = msg.Id
	return resp, nil
}

func (p *policyMockResolver) Close() error { return nil }

// policyOKAnswer is the NOERROR reply the policy tests' mock resolver returns.
var policyOKAnswer = &dns.Msg{
	MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
	Answer: []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(93, 184, 216, 34),
		},
	},
}

func policyDiscardLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// seedAllowlistFile writes a temp allowlist file containing the given body
// and returns its path. The tests then load it through LoadFiles so they
// exercise the same public path the daemon uses.
func seedAllowlistFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write allow file: %v", err)
	}
	return path
}

// loadAllowlistFromFile reads an allowlist file from path and returns the
// configured Allowlist. Mirrors the daemon's startup loader path.
func loadAllowlistFromFile(t *testing.T, path string) *allowlist.Allowlist {
	t.Helper()
	a := allowlist.New()
	if err := a.LoadFiles([]string{path}); err != nil {
		t.Fatalf("load allowlist: %v", err)
	}
	return a
}

// genTestCert returns a self-signed cert + keypair usable on loopback.
func genTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	certPEM, keyPEM, err := generateSelfSignedCert([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load keypair: %v", err)
	}
	return cert
}

// spinDoH starts a real DoH listener with the given policy, ready for an
// HTTP/2 DoH round-trip. Returns (addr, mockResolver, stopFn).
func spinDoH(t *testing.T, addr string, p *policy.Policy, withDDR bool) (string, *policyMockResolver, func()) {
	t.Helper()
	mock := &policyMockResolver{response: policyOKAnswer}
	cert := genTestCert(t)
	listener, err := NewDOHListener(addr, &tls.Config{Certificates: []tls.Certificate{cert}},
		mock, cache.New(cache.Options{Enabled: false}), nil, statistics.New(), policyDiscardLogger(), false)
	if err != nil {
		t.Fatalf("create DoH listener: %v", err)
	}
	if withDDR {
		listener.ddr = newDDRZone("doh3.example.net", "0.0.0.0:443", "", "", false, nil)
	}
	listener.SetPolicy(p)
	ctx, cancel := context.WithCancel(context.Background())
	go listener.Serve(ctx)
	time.Sleep(200 * time.Millisecond)
	return addr, mock, func() {
		cancel()
		listener.Close()
	}
}

// spinDoT starts a real DoT listener with the given policy. Returns
// (addr, mockResolver, stopFn).
func spinDoT(t *testing.T, addr string, p *policy.Policy) (string, *policyMockResolver, func()) {
	t.Helper()
	mock := &policyMockResolver{response: policyOKAnswer}
	cert := genTestCert(t)
	listener, err := NewDOTListener(addr, &tls.Config{Certificates: []tls.Certificate{cert}},
		mock, cache.New(cache.Options{Enabled: false}), nil, statistics.New(), policyDiscardLogger())
	if err != nil {
		t.Fatalf("create DoT listener: %v", err)
	}
	listener.SetPolicy(p)
	ctx, cancel := context.WithCancel(context.Background())
	go listener.Serve(ctx)
	time.Sleep(100 * time.Millisecond)
	return addr, mock, func() {
		cancel()
		listener.Close()
	}
}

// spinDoQ starts a real DoQ listener with the given policy. Returns
// (addr, mockResolver, stopFn).
func spinDoQ(t *testing.T, addr string, p *policy.Policy) (string, *policyMockResolver, func()) {
	t.Helper()
	mock := &policyMockResolver{response: policyOKAnswer}
	cert := genTestCert(t)
	listener, err := NewDOQListener(addr, &tls.Config{Certificates: []tls.Certificate{cert}},
		mock, cache.New(cache.Options{Enabled: false}), nil, statistics.New(), policyDiscardLogger())
	if err != nil {
		t.Fatalf("create DoQ listener: %v", err)
	}
	listener.SetPolicy(p)
	ctx, cancel := context.WithCancel(context.Background())
	go listener.Serve(ctx)
	time.Sleep(200 * time.Millisecond)
	return addr, mock, func() {
		cancel()
		listener.Close()
	}
}

// findPolicyEDE walks an OPT record's Option slice and returns the EDE option.
func findPolicyEDE(opt *dns.OPT) *dns.EDNS0_EDE {
	for _, o := range opt.Option {
		if ede, ok := o.(*dns.EDNS0_EDE); ok {
			return ede
		}
	}
	return nil
}

// exchangeDoH performs one DoH POST round-trip via the live listener and returns
// the unpacked DNS reply. Mirrors TestDOHListener_DDR_EndToEnd's client shape.
func exchangeDoH(t *testing.T, addr string, query *dns.Msg) *dns.Msg {
	t.Helper()
	body, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}},
			ForceAttemptHTTP2: true,
		},
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+addr+"/dns-query", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("DoH round-trip: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	got := &dns.Msg{}
	if err := got.Unpack(respBody); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	return got
}

// exchangeDoT performs one DoT round-trip: TLS handshake, 2-byte length prefix,
// DNS message.
func exchangeDoT(t *testing.T, addr string, query *dns.Msg) *dns.Msg {
	t.Helper()
	conn, err := tls.DialWithDialer(new(net.Dialer), "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}})
	if err != nil {
		t.Fatalf("DoT dial: %v", err)
	}
	defer conn.Close()
	body, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	prefix := []byte{byte(len(body) >> 8), byte(len(body))}
	if _, err := conn.Write(append(prefix, body...)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		t.Fatalf("read response length: %v", err)
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		t.Fatalf("read response body: %v", err)
	}
	got := &dns.Msg{}
	if err := got.Unpack(respBuf); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	return got
}

// exchangeDoQ performs one DoQ round-trip: QUIC handshake, 2-byte length prefix,
// DNS message on a fresh stream.
func exchangeDoQ(t *testing.T, addr string, query *dns.Msg) *dns.Msg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"doq"}}, &quic.Config{})
	if err != nil {
		t.Fatalf("DoQ dial: %v", err)
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	body, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	prefix := []byte{byte(len(body) >> 8), byte(len(body))}
	if _, err := stream.Write(append(prefix, body...)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	stream.Close()
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		t.Fatalf("read response length: %v", err)
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(stream, respBuf); err != nil {
		t.Fatalf("read response body: %v", err)
	}
	got := &dns.Msg{}
	if err := got.Unpack(respBuf); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	return got
}

// TestPolicyEnforced_DoH is the headline DoH policy test: an allowlist of
// example.com denies x.attacker.example.net with REFUSED + EDE 18 (query had OPT),
// while www.example.com resolves. The mock resolver sees ZERO calls for the denied
// name and exactly ONE call for the allowed name.
func TestPolicyEnforced_DoH(t *testing.T) {
	path := seedAllowlistFile(t, "example.com\n")
	al := loadAllowlistFromFile(t, path)
	stats := statistics.New()
	p := policy.New(al, nil, stats)

	addr, mock, stop := spinDoH(t, "127.0.0.1:18553", p, false)
	defer stop()

	// 1. Denied query (DO-bit client → OPT present + EDE 18).
	denied := new(dns.Msg)
	denied.SetQuestion("x.attacker.example.net.", dns.TypeA)
	denied.SetEdns0(4096, true)

	resp := exchangeDoH(t, addr, denied)
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("DoH denied: expected REFUSED, got rcode %d", resp.Rcode)
	}
	if opt := resp.IsEdns0(); opt == nil {
		t.Error("DoH denied (DO-bit): response must carry OPT for EDE")
	} else if ede := findPolicyEDE(opt); ede == nil {
		t.Error("DoH denied (DO-bit): response OPT must carry EDE")
	} else if ede.InfoCode != dns.ExtendedErrorCodeProhibited {
		t.Errorf("EDE InfoCode = %d, want %d (Prohibited)", ede.InfoCode, dns.ExtendedErrorCodeProhibited)
	}
	if n := mock.callCount.Load(); n != 0 {
		t.Errorf("DoH denied: mock resolver called %d time(s); want 0 (deny is local)", n)
	}

	// 2. Non-EDNS denied query → REFUSED, no OPT.
	deniedNoEdns := new(dns.Msg)
	deniedNoEdns.SetQuestion("x.attacker.example.net.", dns.TypeA)
	resp2 := exchangeDoH(t, addr, deniedNoEdns)
	if resp2.Rcode != dns.RcodeRefused {
		t.Errorf("DoH denied (non-EDNS): expected REFUSED, got rcode %d", resp2.Rcode)
	}
	if opt := resp2.IsEdns0(); opt != nil {
		t.Error("DoH denied (non-EDNS): response must NOT carry OPT (RFC 6891 §6.1.1)")
	}

	// 3. Allowed query → NOERROR and mock resolver called once.
	allowed := new(dns.Msg)
	allowed.SetQuestion("www.example.com.", dns.TypeA)
	resp3 := exchangeDoH(t, addr, allowed)
	if resp3.Rcode != dns.RcodeSuccess {
		t.Errorf("DoH allowed: expected NOERROR, got rcode %d", resp3.Rcode)
	}
	if n := mock.callCount.Load(); n != 1 {
		t.Errorf("DoH allowed: mock resolver called %d time(s); want 1", n)
	}

	// 4. Stats: 2 denies (the DO-bit + non-EDNS denied queries), 0 blocks.
	snap := stats.TakeSnapshot(0, 0, statistics.InstanceInfo{})
	if snap.DeniedQueries != 2 {
		t.Errorf("DeniedQueries = %d, want 2", snap.DeniedQueries)
	}
	if snap.BlockedQueries != 0 {
		t.Errorf("BlockedQueries must remain 0 (no blocklist in this test): %d", snap.BlockedQueries)
	}
}

// TestPolicyEnforced_DoT is the DoT counterpart: same shape as DoH. Real TLS
// handshake + DNS round-trip over the encrypted transport.
func TestPolicyEnforced_DoT(t *testing.T) {
	path := seedAllowlistFile(t, "example.com\n")
	al := loadAllowlistFromFile(t, path)
	stats := statistics.New()
	p := policy.New(al, nil, stats)

	addr, mock, stop := spinDoT(t, "127.0.0.1:18554", p)
	defer stop()

	denied := new(dns.Msg)
	denied.SetQuestion("x.attacker.example.net.", dns.TypeA)
	denied.SetEdns0(4096, true)

	resp := exchangeDoT(t, addr, denied)
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("DoT denied: expected REFUSED, got rcode %d", resp.Rcode)
	}
	if opt := resp.IsEdns0(); opt == nil {
		t.Error("DoT denied (DO-bit): response must carry OPT")
	} else if ede := findPolicyEDE(opt); ede == nil || ede.InfoCode != dns.ExtendedErrorCodeProhibited {
		t.Errorf("DoT denied (DO-bit): EDE missing or wrong: %+v", ede)
	}
	if n := mock.callCount.Load(); n != 0 {
		t.Errorf("DoT denied: mock resolver called %d time(s); want 0", n)
	}

	allowed := new(dns.Msg)
	allowed.SetQuestion("www.example.com.", dns.TypeA)
	resp2 := exchangeDoT(t, addr, allowed)
	if resp2.Rcode != dns.RcodeSuccess {
		t.Errorf("DoT allowed: expected NOERROR, got rcode %d", resp2.Rcode)
	}
	if n := mock.callCount.Load(); n != 1 {
		t.Errorf("DoT allowed: mock resolver called %d time(s); want 1", n)
	}
}

// TestPolicyEnforced_DoQ is the DoQ counterpart: same shape as DoH/DoT. Real
// QUIC handshake + DNS round-trip over UDP.
func TestPolicyEnforced_DoQ(t *testing.T) {
	path := seedAllowlistFile(t, "example.com\n")
	al := loadAllowlistFromFile(t, path)
	stats := statistics.New()
	p := policy.New(al, nil, stats)

	addr, mock, stop := spinDoQ(t, "127.0.0.1:18555", p)
	defer stop()

	denied := new(dns.Msg)
	denied.SetQuestion("x.attacker.example.net.", dns.TypeA)
	denied.SetEdns0(4096, true)

	resp := exchangeDoQ(t, addr, denied)
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("DoQ denied: expected REFUSED, got rcode %d", resp.Rcode)
	}
	if opt := resp.IsEdns0(); opt == nil {
		t.Error("DoQ denied (DO-bit): response must carry OPT")
	} else if ede := findPolicyEDE(opt); ede == nil || ede.InfoCode != dns.ExtendedErrorCodeProhibited {
		t.Errorf("DoQ denied (DO-bit): EDE missing or wrong: %+v", ede)
	}
	if n := mock.callCount.Load(); n != 0 {
		t.Errorf("DoQ denied: mock resolver called %d time(s); want 0", n)
	}

	allowed := new(dns.Msg)
	allowed.SetQuestion("www.example.com.", dns.TypeA)
	resp2 := exchangeDoQ(t, addr, allowed)
	if resp2.Rcode != dns.RcodeSuccess {
		t.Errorf("DoQ allowed: expected NOERROR, got rcode %d", resp2.Rcode)
	}
	if n := mock.callCount.Load(); n != 1 {
		t.Errorf("DoQ allowed: mock resolver called %d time(s); want 1", n)
	}
}

// TestPolicyEnforced_BlockWinsInsideAllowedSuffix_DoH covers the "block wins"
// rule over DoH: an allowlist covers example.com and the blocklist narrows it to
// ads.example.com — the latter gets NXDOMAIN locally, never reaching the
// upstream resolver.
func TestPolicyEnforced_BlockWinsInsideAllowedSuffix_DoH(t *testing.T) {
	path := seedAllowlistFile(t, "example.com\n")
	al := loadAllowlistFromFile(t, path)
	bl := blocklist.New(true)
	bl.Add("ads.example.com")
	stats := statistics.New()
	p := policy.New(al, bl, stats)

	addr, mock, stop := spinDoH(t, "127.0.0.1:18557", p, false)
	defer stop()

	q := new(dns.Msg)
	q.SetQuestion("ads.example.com.", dns.TypeA)
	resp := exchangeDoH(t, addr, q)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("DoH block-wins: expected NXDOMAIN, got rcode %d", resp.Rcode)
	}
	if n := mock.callCount.Load(); n != 0 {
		t.Errorf("DoH block-wins: mock resolver called %d time(s); want 0", n)
	}
	snap := stats.TakeSnapshot(0, 0, statistics.InstanceInfo{})
	if snap.BlockedQueries != 1 {
		t.Errorf("BlockedQueries = %d, want 1", snap.BlockedQueries)
	}
	if snap.DeniedQueries != 0 {
		t.Errorf("DeniedQueries must remain 0 (block wins): %d", snap.DeniedQueries)
	}
}

// TestPolicyEnforced_DDR_BeatsPolicy_DoH covers the order: a resolver.arpa SVCB
// probe with the allowlist enabled and resolver.arpa NOT listed must be answered
// by DDR (RFC 9462 §6.4) and never reach the policy or the upstream resolver.
func TestPolicyEnforced_DDR_BeatsPolicy_DoH(t *testing.T) {
	path := seedAllowlistFile(t, "example.com\n")
	al := loadAllowlistFromFile(t, path)
	stats := statistics.New()
	p := policy.New(al, nil, stats)

	addr, mock, stop := spinDoH(t, "127.0.0.1:18558", p, true)
	defer stop()

	q := new(dns.Msg)
	q.SetQuestion("_dns.resolver.arpa.", dns.TypeSVCB)
	q.Id = 7777
	got := exchangeDoH(t, addr, q)
	if len(got.Answer) != 1 {
		t.Fatalf("DDR probe: expected 1 SVCB answer, got %d", len(got.Answer))
	}
	if _, ok := got.Answer[0].(*dns.SVCB); !ok {
		t.Fatalf("DDR probe: answer is %T, want *dns.SVCB", got.Answer[0])
	}
	// DeniedQueries must NOT increment — DDR is a local answer about this
	// instance, not subject to policy.
	snap := stats.TakeSnapshot(0, 0, statistics.InstanceInfo{})
	if snap.DeniedQueries != 0 {
		t.Errorf("DDR probe: DeniedQueries = %d, want 0 (DDR bypasses policy)", snap.DeniedQueries)
	}
	// Mock resolver never called.
	if n := mock.callCount.Load(); n != 0 {
		t.Errorf("DDR probe: mock resolver called %d time(s); want 0 (RFC 9462 §6.4)", n)
	}
}
