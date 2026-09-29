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
	"github.com/rcvd-dns/rcvd/internal/cache"
	"github.com/rcvd-dns/rcvd/internal/config"
	"github.com/rcvd-dns/rcvd/internal/policy"
	"github.com/rcvd-dns/rcvd/internal/statistics"
)

// servicePolicyMockResolver is the upstream.Service backing resolver used by the
// Service-level policy tests. The Service is constructed with this object as
// `resolv`, and the count tracks how many upstream calls leak through — for a
// properly-enforced deny it must stay at zero.
type servicePolicyMockResolver struct {
	response  *dns.Msg
	callCount atomic.Int64
}

func (r *servicePolicyMockResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	r.callCount.Add(1)
	if r.response == nil {
		return new(dns.Msg).SetReply(msg), nil
	}
	resp := r.response.Copy()
	resp.Id = msg.Id
	return resp, nil
}

func (r *servicePolicyMockResolver) Close() error { return nil }

// servicePolicyOKAnswer is the NOERROR reply the Service-level tests' resolver
// returns on a permitted query, so the test can tell "policy let it through"
// apart from "cache/transport failed".
var servicePolicyOKAnswer = &dns.Msg{
	MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
	Answer: []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(93, 184, 216, 34),
		},
	},
}

// servicePolicyLogger is a discard logger for the Service in tests.
func servicePolicyLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// servicePolicyConfig builds the upstream.* + fullConfig pair used by the
// Service-level tests. Self-signed cert (no certmagic, no DNS-01 token), fixed
// loopback port so the client side can dial, no upstream_service.advertise_ips
// (DDR is off by default in the Service).
//
// Three transports enabled by default (DoH, DoT, DoQ) — the call sites pick
// which to spin up. Listen addresses are wired to fixed ports to avoid racing
// on port 0 in the same test binary.
func servicePolicyConfig(t *testing.T, dohAddr, dotAddr, doqAddr string) (*config.UpstreamConfig, *config.Config) {
	t.Helper()
	upstreamCfg := &config.UpstreamConfig{
		Enabled:        true,
		ListenDoH:      dohAddr,
		ListenDoT:      dotAddr,
		ListenDoQ:      doqAddr,
		TLSCertAutoGen: true,
	}
	full := &config.Config{
		UpstreamService: *upstreamCfg,
		// No upstream entries: the Service never actually reaches resolv.Resolve
		// on a denied query, so no fallback chain is needed for the deny path.
		// For the allowed-path sanity check the test resolver returns directly.
	}
	return upstreamCfg, full
}

// servicePolicySeedAllowlist writes a temp allowlist file containing the given
// body and returns its path.
func servicePolicySeedAllowlist(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write allow file: %v", err)
	}
	return path
}

// servicePolicyLoadAllowlist builds an *allowlist.Allowlist from a path.
func servicePolicyLoadAllowlist(t *testing.T, path string) *allowlist.Allowlist {
	t.Helper()
	a := allowlist.New()
	if err := a.LoadFiles([]string{path}); err != nil {
		t.Fatalf("load allowlist: %v", err)
	}
	return a
}

// servicePolicyDoHRoundTrip performs one DoH POST round-trip via the live
// Service listener and returns the parsed reply.
func servicePolicyDoHRoundTrip(t *testing.T, addr string, query *dns.Msg) *http.Response {
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
	return resp
}

// servicePolicyDoTRoundTrip performs one DoT round-trip via the live Service
// listener and returns the parsed reply.
func servicePolicyDoTRoundTrip(t *testing.T, addr string, query *dns.Msg) *dns.Msg {
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

// servicePolicyDoQRoundTrip performs one DoQ round-trip via the live Service
// listener and returns the parsed reply.
func servicePolicyDoQRoundTrip(t *testing.T, addr string, query *dns.Msg) *dns.Msg {
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

// TestService_PolicyEnforced_DoH exercises the full Mode-2 plumbing path:
// upstream.New → upstream.Service.SetPolicy(p) → upstream.Service.Start →
// DoH listener. A real DoH round-trip over the Service's bound listener must
// REFUSE a denied query (with EDE 18 on the DO-bit path) and never call the
// backing resolver.
//
// Cross-mode coverage (one Policy covers Mode 1 server.Server AND Mode 2
// upstream.Service identically) is asserted in dual_mode_policy_test.go as
// `package upstream_test`, which is an external test package that can import
// both server and upstream.
func TestService_PolicyEnforced_DoH(t *testing.T) {
	// Fixed loopback ports to avoid test-binary race conditions with port 0.
	const dohAddr = "127.0.0.1:18561"
	const dotAddr = "127.0.0.1:18562"
	const doqAddr = "127.0.0.1:18563"

	// 1. Build one shared Policy instance.
	allowPath := servicePolicySeedAllowlist(t, "example.com\n")
	al := servicePolicyLoadAllowlist(t, allowPath)
	stats := statistics.New()
	p := policy.New(al, nil, stats)

	// 2. Spin up the Mode-2 Service (DoH) with the shared Policy.
	upstreamCfg, full := servicePolicyConfig(t, dohAddr, dotAddr, doqAddr)
	resolv := &servicePolicyMockResolver{response: servicePolicyOKAnswer}
	svc, err := New(upstreamCfg, full, resolv,
		cache.New(cache.Options{Enabled: false}), nil, stats, servicePolicyLogger())
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	svc.SetPolicy(p)
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("upstream.Service.Start: %v", err)
	}
	defer func() { _ = svc.Stop(2 * time.Second) }()
	// Let the HTTP/2 + TLS handshake settle.
	time.Sleep(150 * time.Millisecond)

	// 3. Denied query (DO-bit client → OPT present + EDE 18).
	denied := new(dns.Msg)
	denied.SetQuestion("x.attacker.example.net.", dns.TypeA)
	denied.SetEdns0(4096, true)
	httpResp := servicePolicyDoHRoundTrip(t, dohAddr, denied)
	defer httpResp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, dns.MaxMsgSize))
	if err != nil {
		t.Fatalf("read DoH body: %v", err)
	}
	dohReply := &dns.Msg{}
	if err := dohReply.Unpack(respBody); err != nil {
		t.Fatalf("unpack DoH reply: %v", err)
	}
	if dohReply.Rcode != dns.RcodeRefused {
		t.Errorf("DoH denied: expected REFUSED, got rcode %d", dohReply.Rcode)
	}
	if opt := dohReply.IsEdns0(); opt == nil {
		t.Error("DoH denied (DO-bit): response must carry OPT for EDE attachment")
	} else if ede := findPolicyEDE(opt); ede == nil || ede.InfoCode != dns.ExtendedErrorCodeProhibited {
		t.Errorf("DoH denied (DO-bit): EDE missing or wrong: %+v", ede)
	}
	if n := resolv.callCount.Load(); n != 0 {
		t.Errorf("DoH denied reached backing resolver %d time(s); want 0", n)
	}

	// 4. Allowed query → NOERROR, exactly one resolver call.
	allowed := new(dns.Msg)
	allowed.SetQuestion("www.example.com.", dns.TypeA)
	httpResp2 := servicePolicyDoHRoundTrip(t, dohAddr, allowed)
	defer httpResp2.Body.Close()
	allowedBody, err := io.ReadAll(io.LimitReader(httpResp2.Body, dns.MaxMsgSize))
	if err != nil {
		t.Fatalf("read allowed DoH body: %v", err)
	}
	allowedReply := &dns.Msg{}
	if err := allowedReply.Unpack(allowedBody); err != nil {
		t.Fatalf("unpack allowed DoH reply: %v", err)
	}
	if allowedReply.Rcode != dns.RcodeSuccess {
		t.Errorf("DoH allowed: expected NOERROR, got rcode %d", allowedReply.Rcode)
	}
	if n := resolv.callCount.Load(); n != 1 {
		t.Errorf("DoH allowed: backing resolver called %d time(s); want 1", n)
	}
}

// TestService_PolicyEnforced_DoT is the DoT counterpart to TestService_PolicyEnforced_DoH.
// Same shared-Policy pattern; proves DoT listener enforces the deny.
func TestService_PolicyEnforced_DoT(t *testing.T) {
	const dohAddr = "127.0.0.1:18571"
	const dotAddr = "127.0.0.1:18572"
	const doqAddr = "127.0.0.1:18573"

	allowPath := servicePolicySeedAllowlist(t, "example.com\n")
	al := servicePolicyLoadAllowlist(t, allowPath)
	stats := statistics.New()
	p := policy.New(al, nil, stats)

	upstreamCfg, full := servicePolicyConfig(t, dohAddr, dotAddr, doqAddr)
	resolv := &servicePolicyMockResolver{response: servicePolicyOKAnswer}
	svc, err := New(upstreamCfg, full, resolv,
		cache.New(cache.Options{Enabled: false}), nil, stats, servicePolicyLogger())
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	svc.SetPolicy(p)
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("upstream.Service.Start: %v", err)
	}
	defer func() { _ = svc.Stop(2 * time.Second) }()
	time.Sleep(150 * time.Millisecond)

	denied := new(dns.Msg)
	denied.SetQuestion("x.attacker.example.net.", dns.TypeA)
	denied.SetEdns0(4096, true)
	reply := servicePolicyDoTRoundTrip(t, dotAddr, denied)
	if reply.Rcode != dns.RcodeRefused {
		t.Errorf("DoT denied: expected REFUSED, got rcode %d", reply.Rcode)
	}
	if opt := reply.IsEdns0(); opt == nil {
		t.Error("DoT denied (DO-bit): response must carry OPT for EDE attachment")
	} else if ede := findPolicyEDE(opt); ede == nil || ede.InfoCode != dns.ExtendedErrorCodeProhibited {
		t.Errorf("DoT denied (DO-bit): EDE missing or wrong: %+v", ede)
	}
	if n := resolv.callCount.Load(); n != 0 {
		t.Errorf("DoT denied reached backing resolver %d time(s); want 0", n)
	}

	allowed := new(dns.Msg)
	allowed.SetQuestion("www.example.com.", dns.TypeA)
	reply2 := servicePolicyDoTRoundTrip(t, dotAddr, allowed)
	if reply2.Rcode != dns.RcodeSuccess {
		t.Errorf("DoT allowed: expected NOERROR, got rcode %d", reply2.Rcode)
	}
	if n := resolv.callCount.Load(); n != 1 {
		t.Errorf("DoT allowed: backing resolver called %d time(s); want 1", n)
	}
}

// TestService_PolicyEnforced_DoQ is the DoQ counterpart to TestService_PolicyEnforced_DoH.
// Same shared-Policy pattern; proves DoQ listener enforces the deny.
func TestService_PolicyEnforced_DoQ(t *testing.T) {
	const dohAddr = "127.0.0.1:18581"
	const dotAddr = "127.0.0.1:18582"
	const doqAddr = "127.0.0.1:18583"

	allowPath := servicePolicySeedAllowlist(t, "example.com\n")
	al := servicePolicyLoadAllowlist(t, allowPath)
	stats := statistics.New()
	p := policy.New(al, nil, stats)

	upstreamCfg, full := servicePolicyConfig(t, dohAddr, dotAddr, doqAddr)
	resolv := &servicePolicyMockResolver{response: servicePolicyOKAnswer}
	svc, err := New(upstreamCfg, full, resolv,
		cache.New(cache.Options{Enabled: false}), nil, stats, servicePolicyLogger())
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	svc.SetPolicy(p)
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("upstream.Service.Start: %v", err)
	}
	defer func() { _ = svc.Stop(2 * time.Second) }()
	time.Sleep(200 * time.Millisecond)

	denied := new(dns.Msg)
	denied.SetQuestion("x.attacker.example.net.", dns.TypeA)
	denied.SetEdns0(4096, true)
	reply := servicePolicyDoQRoundTrip(t, doqAddr, denied)
	if reply.Rcode != dns.RcodeRefused {
		t.Errorf("DoQ denied: expected REFUSED, got rcode %d", reply.Rcode)
	}
	if opt := reply.IsEdns0(); opt == nil {
		t.Error("DoQ denied (DO-bit): response must carry OPT for EDE attachment")
	} else if ede := findPolicyEDE(opt); ede == nil || ede.InfoCode != dns.ExtendedErrorCodeProhibited {
		t.Errorf("DoQ denied (DO-bit): EDE missing or wrong: %+v", ede)
	}
	if n := resolv.callCount.Load(); n != 0 {
		t.Errorf("DoQ denied reached backing resolver %d time(s); want 0", n)
	}

	allowed := new(dns.Msg)
	allowed.SetQuestion("www.example.com.", dns.TypeA)
	reply2 := servicePolicyDoQRoundTrip(t, doqAddr, allowed)
	if reply2.Rcode != dns.RcodeSuccess {
		t.Errorf("DoQ allowed: expected NOERROR, got rcode %d", reply2.Rcode)
	}
	if n := resolv.callCount.Load(); n != 1 {
		t.Errorf("DoQ allowed: backing resolver called %d time(s); want 1", n)
	}
}
