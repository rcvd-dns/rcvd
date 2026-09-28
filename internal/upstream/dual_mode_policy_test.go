// SPDX-License-Identifier: MIT
package upstream_test

// dual_mode_policy_test.go is an EXTERNAL test package (upstream_test) so it can
// import internal/server alongside internal/upstream. The test spins up one
// Mode-1 server.Server and one Mode-2 upstream.Service, both wired with the
// SAME *policy.Policy instance, and asserts that a denied query is REFUSED on
// both surfaces with zero backing-resolver calls. The single Policy object is
// the contract that closes the cross-transport bypass.

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/rcvd-dns/rcvd/internal/allowlist"
	"github.com/rcvd-dns/rcvd/internal/blocklist"
	"github.com/rcvd-dns/rcvd/internal/cache"
	"github.com/rcvd-dns/rcvd/internal/config"
	"github.com/rcvd-dns/rcvd/internal/policy"
	"github.com/rcvd-dns/rcvd/internal/server"
	"github.com/rcvd-dns/rcvd/internal/statistics"
	"github.com/rcvd-dns/rcvd/internal/upstream"
)

// dualModeMockResolver counts Resolve calls. Each surface (Mode 1 / Mode 2)
// has its own backing object, mirroring the real deployment where Mode 1 and
// Mode 2 each own their upstream chain.
type dualModeMockResolver struct {
	callCount atomic.Int64
}

func (r *dualModeMockResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	r.callCount.Add(1)
	resp := new(dns.Msg)
	resp.SetReply(msg)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{93, 184, 216, 34},
	}}
	return resp, nil
}

func (r *dualModeMockResolver) Close() error { return nil }

func dualModeLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// TestDualMode_SharedPolicy_DenyOnBothSurfaces is the cross-mode coverage test:
// one *policy.Policy instance wired into BOTH a Mode-1 server.Server (UDP/TCP
// forwarder) and a Mode-2 upstream.Service (DoH listener) denies the same
// qname on both surfaces, with zero backing-resolver calls on each.
//
// The Mode-1 server exercises SetPolicy(p) (in cmd/rcvd/main.go the same
// instance is passed to NewServer + Service.SetPolicy). The Mode-2 service
// exercises the full upstream.New → SetPolicy → Start → listener plumbing that
// the per-listener SetPolicy calls are normally hidden behind. A deny on the
// real DoH listener proves Service.SetPolicy was honored; a deny on the real
// Mode-1 server proves the same Policy object makes the same decision there.
func TestDualMode_SharedPolicy_DenyOnBothSurfaces(t *testing.T) {
	// Fixed loopback ports to keep the test binary race-free (port 0 would
	// race when several subtests in the same package bind it).
	const mode1Addr = "127.0.0.1:18591"
	const dohAddr = "127.0.0.1:18592"
	const dotAddr = "127.0.0.1:18593"
	const doqAddr = "127.0.0.1:18594"

	// 1. ONE shared *policy.Policy.
	dir := t.TempDir()
	allowPath := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(allowPath, []byte("example.com\n"), 0644); err != nil {
		t.Fatalf("write allow file: %v", err)
	}
	al := allowlist.New()
	if err := al.LoadFiles([]string{allowPath}); err != nil {
		t.Fatalf("load allowlist: %v", err)
	}
	stats := statistics.New()
	p := policy.New(al, nil, stats)

	// 2. Mode 2 — upstream.Service wired with the same p.
	upstreamCfg := &config.UpstreamConfig{
		Enabled:        true,
		ListenDoH:      dohAddr,
		ListenDoT:      dotAddr,
		ListenDoQ:      doqAddr,
		TLSCertAutoGen: true,
	}
	full := &config.Config{UpstreamService: *upstreamCfg}
	mode2Resolv := &dualModeMockResolver{}
	svc, err := upstream.New(upstreamCfg, full, mode2Resolv,
		cache.New(cache.Options{Enabled: false}), nil, stats, dualModeLogger())
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	svc.SetPolicy(p)
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("upstream.Service.Start: %v", err)
	}
	defer func() { _ = svc.Stop(2 * time.Second) }()
	time.Sleep(150 * time.Millisecond) // let TLS handshakes settle

	// 3. Mode 1 — server.Server wired with the same p.
	mode1Cfg := &config.Config{
		Resolver: config.ResolverConfig{Enabled: true, Listen: mode1Addr},
	}
	mode1Resolv := &dualModeMockResolver{}
	mode1 := server.NewServer(mode1Cfg, mode1Resolv,
		cache.New(cache.Options{Enabled: false}),
		blocklist.New(false), nil, stats, dualModeLogger())
	mode1.SetPolicy(p)
	if err := mode1.Start(context.Background()); err != nil {
		t.Fatalf("server.Server.Start: %v", err)
	}
	defer func() { _ = mode1.Stop(time.Second) }()
	time.Sleep(50 * time.Millisecond)

	// 4. Build the denied query (DO-bit client so EDE 18 attaches).
	denied := new(dns.Msg)
	denied.SetQuestion("leak.attacker.example.net.", dns.TypeA)
	denied.SetEdns0(4096, true)

	// 5. Mode-2 path: a real DoH round-trip over the Service listener must
	//    return REFUSED + EDE 18 and never call mode2Resolv.
	body, err := denied.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}},
			ForceAttemptHTTP2: true,
		},
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+dohAddr+"/dns-query",
		bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("DoH round-trip: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize))
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
	} else {
		var found bool
		for _, o := range opt.Option {
			if ede, ok := o.(*dns.EDNS0_EDE); ok && ede.InfoCode == dns.ExtendedErrorCodeProhibited {
				found = true
			}
		}
		if !found {
			t.Error("DoH denied (DO-bit): EDE 18 missing on response OPT")
		}
	}
	if n := mode2Resolv.callCount.Load(); n != 0 {
		t.Errorf("DoH denied: Mode-2 backing resolver called %d time(s); want 0", n)
	}

	// 6. Mode-1 path: the same denied query over UDP must return REFUSED on
	//    the Mode-1 server and never call mode1Resolv.
	udpClient := new(dns.Client)
	udpClient.Net = "udp"
	udpResp, _, err := udpClient.Exchange(denied.Copy(), mode1Addr)
	if err != nil {
		t.Fatalf("Mode 1 UDP exchange: %v", err)
	}
	if udpResp.Rcode != dns.RcodeRefused {
		t.Errorf("Mode 1 denied: expected REFUSED, got rcode %d", udpResp.Rcode)
	}
	if n := mode1Resolv.callCount.Load(); n != 0 {
		t.Errorf("Mode 1 denied: Mode-1 backing resolver called %d time(s); want 0", n)
	}

	// 7. Both surfaces share one *statistics.Stats, so the deny counter on
	//    the SAME *statistics.Stats records denies from BOTH surfaces.
	snap := stats.TakeSnapshot(0, 0, statistics.InstanceInfo{})
	if snap.DeniedQueries != 2 {
		t.Errorf("DeniedQueries: expected 2 (one Mode-1 + one Mode-2 deny on shared stats), got %d", snap.DeniedQueries)
	}
}
