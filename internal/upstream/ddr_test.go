// SPDX-License-Identifier: MIT
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ddrQuery builds a client SVCB query for _dns.resolver.arpa (the DDR discovery probe).
func ddrQuery() *dns.Msg {
	q := &dns.Msg{}
	q.SetQuestion(ddrQueryName, dns.TypeSVCB)
	return q
}

// svcbParam returns the SVCBKeyValue of key k from an SVCB RR, or nil if absent.
func svcbParam(svcb *dns.SVCB, k dns.SVCBKey) dns.SVCBKeyValue {
	for _, kv := range svcb.Value {
		if kv.Key() == k {
			return kv
		}
	}
	return nil
}

// dohOnlyZone is the common QA shape: a Mode-2 box serving only DoH.
func dohOnlyZone() ddrZone {
	return newDDRZone("doh3.qa.rcvd.net", "0.0.0.0:443", "", "", true, nil)
}

func TestDDRZone_DoHDesignation(t *testing.T) {
	z := newDDRZone("doh3.qa.rcvd.net", "0.0.0.0:443", "", "", true, nil)
	resp := z.answer(ddrQuery())
	if resp == nil {
		t.Fatal("answer returned nil for a valid DDR query")
	}
	if !resp.Response || resp.Rcode != dns.RcodeSuccess || !resp.Authoritative {
		t.Fatalf("header wrong: Response=%v Rcode=%d AA=%v", resp.Response, resp.Rcode, resp.Authoritative)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	svcb, ok := resp.Answer[0].(*dns.SVCB)
	if !ok {
		t.Fatalf("answer is %T, want *dns.SVCB", resp.Answer[0])
	}
	if svcb.Hdr.Name != ddrQueryName {
		t.Errorf("SVCB name = %q, want %q", svcb.Hdr.Name, ddrQueryName)
	}
	if svcb.Priority != ddrPriorityDoH {
		t.Errorf("priority = %d, want %d", svcb.Priority, ddrPriorityDoH)
	}
	if svcb.Target != "doh3.qa.rcvd.net." {
		t.Errorf("target = %q, want fully-qualified cert hostname", svcb.Target)
	}
	// RFC 9462 §4: the TargetName MUST NOT be "." or "resolver.arpa".
	if svcb.Target == "." || svcb.Target == ddrZoneName {
		t.Errorf("target %q violates RFC 9462 §4", svcb.Target)
	}
	alpn, _ := svcbParam(svcb, dns.SVCB_ALPN).(*dns.SVCBAlpn)
	if alpn == nil || len(alpn.Alpn) != 2 || alpn.Alpn[0] != alpnHTTP3 {
		t.Errorf("alpn = %v, want h3 first on a DoH3 box", alpn)
	}
	dp, _ := svcbParam(svcb, dns.SVCB_DOHPATH).(*dns.SVCBDoHPath)
	if dp == nil || dp.Template != "/dns-query{?dns}" {
		t.Errorf("dohpath = %v, want the exact Android-accepted template", dp)
	}
}

// TestDDRZone_AllTransports covers RFC 9462 §3: a resolver serving several encrypted
// transports advertises one SVCB record each, ordered by the priority field.
func TestDDRZone_AllTransports(t *testing.T) {
	z := newDDRZone("qa.rcvd.net", "0.0.0.0:443", "0.0.0.0:853", "0.0.0.0:853", false, nil)
	resp := z.answer(ddrQuery())
	if resp == nil {
		t.Fatal("answer returned nil")
	}
	if len(resp.Answer) != 3 {
		t.Fatalf("expected 3 designations (DoH+DoT+DoQ), got %d", len(resp.Answer))
	}

	// Every transport here runs on its default port, so per RFC 9461 §4.2 (port is
	// automatically mandatory) none of the records must carry a port SvcParam.
	want := []struct {
		priority uint16
		alpn     string
		dohpath  bool
	}{
		{ddrPriorityDoH, alpnHTTP2, true},
		{ddrPriorityDoT, alpnDoT, false},
		{ddrPriorityDoQ, alpnDoQ, false},
	}
	for i, w := range want {
		svcb, ok := resp.Answer[i].(*dns.SVCB)
		if !ok {
			t.Fatalf("answer[%d] is %T, want *dns.SVCB", i, resp.Answer[i])
		}
		if svcb.Priority != w.priority {
			t.Errorf("answer[%d] priority = %d, want %d", i, svcb.Priority, w.priority)
		}
		alpn, _ := svcbParam(svcb, dns.SVCB_ALPN).(*dns.SVCBAlpn)
		if alpn == nil || alpn.Alpn[0] != w.alpn {
			t.Errorf("answer[%d] alpn = %v, want %q", i, alpn, w.alpn)
		}
		if p := svcbParam(svcb, dns.SVCB_PORT); p != nil {
			t.Errorf("answer[%d] carries a port SvcParam (%v) on a default-port transport; "+
				"RFC 9461 §4.2 makes port automatically mandatory, so it must be omitted", i, p)
		}
		// dohpath is meaningful only for a DoH designation; RFC 9461 §5 scopes it to DoH.
		dp := svcbParam(svcb, dns.SVCB_DOHPATH)
		if w.dohpath && dp == nil {
			t.Errorf("answer[%d] missing dohpath on the DoH designation", i)
		}
		if !w.dohpath && dp != nil {
			t.Errorf("answer[%d] has dohpath on a non-DoH designation: %v", i, dp)
		}
	}
}

// TestDDRZone_PortSvcParamOnlyWhenNonDefault is the regression guard for the RFC 9461 §4.2
// "port is automatically mandatory" rule: a default port must NOT be advertised (a strict
// client would discard the whole record), and a non-default port MUST be, so the client can
// reach the endpoint at all.
func TestDDRZone_PortSvcParamOnlyWhenNonDefault(t *testing.T) {
	t.Run("default ports omit the port SvcParam", func(t *testing.T) {
		z := newDDRZone("qa.rcvd.net", "0.0.0.0:443", "0.0.0.0:853", "0.0.0.0:853", false, nil)
		resp := z.answer(ddrQuery())
		if resp == nil || len(resp.Answer) != 3 {
			t.Fatalf("expected 3 designations, got %v", resp)
		}
		for i, rr := range resp.Answer {
			if p := svcbParam(rr.(*dns.SVCB), dns.SVCB_PORT); p != nil {
				t.Errorf("answer[%d] emitted port %v on a default-port transport; want omitted", i, p)
			}
		}
	})

	t.Run("non-default ports emit the port SvcParam", func(t *testing.T) {
		// DoH off 443, DoT off 853, DoQ off 853 — each must carry its port.
		z := newDDRZone("qa.rcvd.net", "0.0.0.0:8443", "0.0.0.0:8853", "0.0.0.0:9853", false, nil)
		resp := z.answer(ddrQuery())
		if resp == nil || len(resp.Answer) != 3 {
			t.Fatalf("expected 3 designations, got %v", resp)
		}
		wantPorts := []uint16{8443, 8853, 9853}
		for i, rr := range resp.Answer {
			port, _ := svcbParam(rr.(*dns.SVCB), dns.SVCB_PORT).(*dns.SVCBPort)
			if port == nil {
				t.Errorf("answer[%d] missing port SvcParam on a non-default port", i)
				continue
			}
			if port.Port != wantPorts[i] {
				t.Errorf("answer[%d] port = %d, want %d", i, port.Port, wantPorts[i])
			}
		}
	})

	t.Run("mixed: default DoH omits, non-default DoT emits", func(t *testing.T) {
		z := newDDRZone("qa.rcvd.net", "0.0.0.0:443", "0.0.0.0:8530", "", false, nil)
		resp := z.answer(ddrQuery())
		if resp == nil || len(resp.Answer) != 2 {
			t.Fatalf("expected 2 designations, got %v", resp)
		}
		if p := svcbParam(resp.Answer[0].(*dns.SVCB), dns.SVCB_PORT); p != nil {
			t.Errorf("DoH on default 443 must omit port, got %v", p)
		}
		port, _ := svcbParam(resp.Answer[1].(*dns.SVCB), dns.SVCB_PORT).(*dns.SVCBPort)
		if port == nil || port.Port != 8530 {
			t.Errorf("DoT on non-default 8530 must emit port=8530, got %v", port)
		}
	})
}

// TestDDRZone_OnlyRunningTransports asserts rcvd advertises what it actually serves —
// a DoT-only box designates DoT alone, never a DoH endpoint it does not run.
func TestDDRZone_OnlyRunningTransports(t *testing.T) {
	z := newDDRZone("dot.qa.rcvd.net", "", "0.0.0.0:853", "", false, nil)
	resp := z.answer(ddrQuery())
	if resp == nil {
		t.Fatal("answer returned nil")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 designation on a DoT-only box, got %d", len(resp.Answer))
	}
	svcb := resp.Answer[0].(*dns.SVCB)
	alpn, _ := svcbParam(svcb, dns.SVCB_ALPN).(*dns.SVCBAlpn)
	if alpn == nil || alpn.Alpn[0] != alpnDoT {
		t.Errorf("alpn = %v, want %q", alpn, alpnDoT)
	}
	if svcbParam(svcb, dns.SVCB_DOHPATH) != nil {
		t.Error("DoT designation must not carry dohpath")
	}
}

// TestDDRZone_NoDesignationsNODATA covers RFC 9462 §4: a resolver with no Designated
// Resolver returns NODATA — an accurate signal, distinguishable from a dropped query —
// rather than forwarding the probe upstream.
func TestDDRZone_NoDesignationsNODATA(t *testing.T) {
	z := newDDRZone("", "0.0.0.0:443", "", "", true, nil) // no cert hostname
	if z.advertises() {
		t.Fatal("zone with no cert hostname must not advertise")
	}
	resp := z.answer(ddrQuery())
	if resp == nil {
		t.Fatal("zone must still answer resolver.arpa, not fall through to upstream")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want NOERROR (NODATA, not NXDOMAIN)", resp.Rcode)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("expected no answer records, got %d", len(resp.Answer))
	}
	if len(resp.Ns) != 1 {
		t.Fatalf("expected a SOA in authority for negative caching, got %d records", len(resp.Ns))
	}
	if _, ok := resp.Ns[0].(*dns.SOA); !ok {
		t.Errorf("authority record is %T, want *dns.SOA", resp.Ns[0])
	}
}

// TestDDRZone_LocallyServedZone covers RFC 9462 §6.4: every name and type under
// resolver.arpa is answered locally with NODATA (except the SVCB probe itself), so a
// client probe never leaks to a third-party upstream.
func TestDDRZone_LocallyServedZone(t *testing.T) {
	z := dohOnlyZone()

	tests := []struct {
		name        string
		qname       string
		qtype       uint16
		wantAnswers int // 0 => NODATA
	}{
		{"the DDR probe itself", "_dns.resolver.arpa.", dns.TypeSVCB, 1},
		{"probe name, wrong type A", "_dns.resolver.arpa.", dns.TypeA, 0},
		{"probe name, wrong type AAAA", "_dns.resolver.arpa.", dns.TypeAAAA, 0},
		{"zone apex A", "resolver.arpa.", dns.TypeA, 0},
		{"zone apex SVCB", "resolver.arpa.", dns.TypeSVCB, 0},
		{"other subdomain SVCB", "foo.resolver.arpa.", dns.TypeSVCB, 0},
		{"deep subdomain any", "a.b.resolver.arpa.", dns.TypeTXT, 0},
		{"case-insensitive probe", "_DNS.RESOLVER.ARPA.", dns.TypeSVCB, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := &dns.Msg{}
			q.SetQuestion(tc.qname, tc.qtype)
			resp := z.answer(q)
			if resp == nil {
				t.Fatalf("%s %s fell through to upstream; RFC 9462 §6.4 requires a local answer",
					tc.qname, dns.TypeToString[tc.qtype])
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Errorf("Rcode = %d, want NOERROR", resp.Rcode)
			}
			if len(resp.Answer) != tc.wantAnswers {
				t.Errorf("got %d answers, want %d", len(resp.Answer), tc.wantAnswers)
			}
			if tc.wantAnswers == 0 && len(resp.Ns) == 0 {
				t.Error("NODATA response missing SOA for negative caching")
			}
		})
	}
}

// TestDDRZone_IgnoresOtherNames asserts the zone declines everything outside
// resolver.arpa so normal resolution is untouched.
func TestDDRZone_IgnoresOtherNames(t *testing.T) {
	z := dohOnlyZone()
	for _, name := range []string{
		"example.com.",
		"resolver.arpa.example.com.", // resolver.arpa as a prefix, not the parent
		"arpa.",
		"notresolver.arpa.",
	} {
		q := &dns.Msg{}
		q.SetQuestion(name, dns.TypeA)
		if resp := z.answer(q); resp != nil {
			t.Errorf("%s was intercepted; want fall-through to normal resolution", name)
		}
	}
	// A multi-question message is malformed for DNS and must not be intercepted.
	multi := &dns.Msg{}
	multi.Question = []dns.Question{
		{Name: ddrQueryName, Qtype: dns.TypeSVCB, Qclass: dns.ClassINET},
		{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	if resp := z.answer(multi); resp != nil {
		t.Error("multi-question message was intercepted; want nil")
	}
}

// checkIPs compares a hint slice against expected literals.
func checkIPs(t *testing.T, label string, got []net.IP, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %v (%d), want %v (%d)", label, got, len(got), want, len(want))
		return
	}
	for i := range want {
		if !got[i].Equal(net.ParseIP(want[i])) {
			t.Errorf("%s[%d] = %v, want %s", label, i, got[i], want[i])
		}
	}
}

// TestDDRHints covers both hint sources: the bind address (single-homed case) and the
// advertise_ips override (wildcard/NAT case, which is every real Mode-2 deployment).
func TestDDRHints(t *testing.T) {
	tests := []struct {
		name         string
		listenAddr   string
		advertiseIPs []string
		wantV4       []string
		wantV6       []string
	}{
		{
			name:       "concrete IPv4 bind derives a v4 hint",
			listenAddr: "10.20.0.31:443",
			wantV4:     []string{"10.20.0.31"},
		},
		{
			name:       "concrete IPv6 bind derives a v6 hint",
			listenAddr: "[2a05:d014:16d8:ae00::11]:443",
			wantV6:     []string{"2a05:d014:16d8:ae00::11"},
		},
		{
			name:       "wildcard v4 bind yields no hints",
			listenAddr: "0.0.0.0:443",
		},
		{
			name:       "wildcard v6 bind yields no hints",
			listenAddr: "[::]:443",
		},
		{
			name:       "unparseable bind yields no hints",
			listenAddr: "nonsense",
		},
		{
			name:         "advertise_ips wins over a wildcard bind",
			listenAddr:   "0.0.0.0:443",
			advertiseIPs: []string{"35.159.188.251", "2a05:d014:16d8:ae00::11"},
			wantV4:       []string{"35.159.188.251"},
			wantV6:       []string{"2a05:d014:16d8:ae00::11"},
		},
		{
			name:         "advertise_ips overrides a concrete bind",
			listenAddr:   "10.0.0.5:443",
			advertiseIPs: []string{"203.0.113.7"},
			wantV4:       []string{"203.0.113.7"},
		},
		{
			name:         "multiple addresses per family are all published",
			listenAddr:   "0.0.0.0:443",
			advertiseIPs: []string{"198.51.100.1", "203.0.113.7", "2001:db8::1", "2001:db8::2"},
			wantV4:       []string{"198.51.100.1", "203.0.113.7"},
			wantV6:       []string{"2001:db8::1", "2001:db8::2"},
		},
		{
			name:         "invalid and unspecified entries are skipped defensively",
			listenAddr:   "0.0.0.0:443",
			advertiseIPs: []string{"not-an-ip", "0.0.0.0", "::", "203.0.113.7"},
			wantV4:       []string{"203.0.113.7"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v4, v6 := ddrHints(tc.listenAddr, tc.advertiseIPs)
			checkIPs(t, "v4", v4, tc.wantV4)
			checkIPs(t, "v6", v6, tc.wantV6)
		})
	}
}

// TestDDRZone_HintsOnEveryDesignation asserts the address hints ride every advertised
// record, not just the first — a client selecting DoT must get hints too.
func TestDDRZone_HintsOnEveryDesignation(t *testing.T) {
	z := newDDRZone("qa.rcvd.net", "0.0.0.0:443", "0.0.0.0:853", "", false,
		[]string{"35.159.188.251", "2a05:d014:16d8:ae00::11"})
	resp := z.answer(ddrQuery())
	if resp == nil || len(resp.Answer) != 2 {
		t.Fatalf("expected 2 designations, got %v", resp)
	}
	for i, rr := range resp.Answer {
		svcb := rr.(*dns.SVCB)
		if svcbParam(svcb, dns.SVCB_IPV4HINT) == nil {
			t.Errorf("answer[%d] missing ipv4hint", i)
		}
		if svcbParam(svcb, dns.SVCB_IPV6HINT) == nil {
			t.Errorf("answer[%d] missing ipv6hint", i)
		}
	}
}

func TestDDROwnsName(t *testing.T) {
	in := []string{"resolver.arpa.", "_dns.resolver.arpa.", "foo.resolver.arpa.", "_DNS.Resolver.Arpa."}
	out := []string{"example.com.", "arpa.", "notresolver.arpa.", "resolver.arpa.evil.com."}
	for _, n := range in {
		if !ddrOwnsName(n) {
			t.Errorf("ddrOwnsName(%q) = false, want true", n)
		}
	}
	for _, n := range out {
		if ddrOwnsName(n) {
			t.Errorf("ddrOwnsName(%q) = true, want false", n)
		}
	}
}

func TestAdvertPort(t *testing.T) {
	tests := []struct {
		addr string
		def  int
		want int
	}{
		{"0.0.0.0:443", 443, 443},
		{"10.20.0.31:8443", 443, 8443},
		{"[::]:443", 443, 443},
		{"0.0.0.0:853", 853, 853},
		{"nonsense", 443, 443},      // fallback to the caller's default
		{"host:notaport", 853, 853}, // non-numeric port falls back
	}
	for _, tc := range tests {
		if got := advertPort(tc.addr, tc.def); got != tc.want {
			t.Errorf("advertPort(%q, %d) = %d, want %d", tc.addr, tc.def, got, tc.want)
		}
	}
}

// TestDOHListener_DDR_EndToEnd drives a real DoH listener with DDR enabled and confirms an
// HTTP/2 SVCB probe for _dns.resolver.arpa is answered locally (correct dohpath) without ever
// touching the upstream resolver.
func TestDOHListener_DDR_EndToEnd(t *testing.T) {
	mockResolver := &MockResolver{
		response: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess}},
	}

	certPEM, keyPEM, err := generateSelfSignedCert([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}

	const addr = "127.0.0.1:18455"
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := NewDOHListener(addr, tlsConfig, mockResolver, nil, nil, nil, testLoggerDoH(), false)
	if err != nil {
		t.Fatalf("create DoH listener: %v", err)
	}
	// Enable DDR the way Service.Start() does.
	listener.ddr = newDDRZone("doh3.qa.rcvd.net", "0.0.0.0:443", "", "", false, nil)
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go listener.Serve(ctx)
	time.Sleep(300 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}},
			ForceAttemptHTTP2: true,
		},
		Timeout: 5 * time.Second,
	}

	// dohRoundTrip posts a DNS query over the live listener and returns the parsed reply.
	dohRoundTrip := func(t *testing.T, query *dns.Msg) *dns.Msg {
		t.Helper()
		body, err := query.Pack()
		if err != nil {
			t.Fatalf("pack query: %v", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+"/dns-query", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/dns-message")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("DoH round-trip failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
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

	t.Run("SVCB probe answered locally", func(t *testing.T) {
		query := &dns.Msg{}
		query.SetQuestion(ddrQueryName, dns.TypeSVCB)
		query.Id = 9999

		got := dohRoundTrip(t, query)
		if len(got.Answer) != 1 {
			t.Fatalf("expected 1 SVCB answer, got %d", len(got.Answer))
		}
		svcb, ok := got.Answer[0].(*dns.SVCB)
		if !ok {
			t.Fatalf("answer is %T, want *dns.SVCB", got.Answer[0])
		}
		if dp, _ := svcbParam(svcb, dns.SVCB_DOHPATH).(*dns.SVCBDoHPath); dp == nil || dp.Template != "/dns-query{?dns}" {
			t.Errorf("dohpath wrong or missing: %v", dp)
		}
	})

	t.Run("other resolver.arpa names get NODATA, not forwarded", func(t *testing.T) {
		query := &dns.Msg{}
		query.SetQuestion("foo.resolver.arpa.", dns.TypeA)
		query.Id = 10000

		got := dohRoundTrip(t, query)
		if got.Rcode != dns.RcodeSuccess {
			t.Errorf("Rcode = %d, want NOERROR (NODATA)", got.Rcode)
		}
		if len(got.Answer) != 0 {
			t.Errorf("expected NODATA, got %d answers", len(got.Answer))
		}
	})

	// RFC 9462 §6.4: nothing in the zone may reach the upstream resolver.
	if n := mockResolver.callCount.Load(); n != 0 {
		t.Errorf("resolver.arpa queries reached upstream %d time(s); want 0", n)
	}
}
