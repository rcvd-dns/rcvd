// SPDX-License-Identifier: MIT

// Package policy decides whether a query is answered locally instead of forwarded.
//
// One Policy is wired into every entry point — UDP, TCP, DoH, DoT, DoQ — so the
// allowlist and blocklist cannot drift across transports. The two filters compose in
// a fixed order:
//
//  1. Allowlist (default-deny). If set and the qname is not under a listed suffix, the
//     reply is REFUSED + EDE 18 (Prohibited). The qname never leaves the host.
//  2. Blocklist. Inside an allowed suffix, block wins — NXDOMAIN.
//
// A nil *Policy is a no-op: every Response call returns nil (feature off). The caller is
// responsible for EDNS normalization (ensureResponseEDNS), packing, writing, and the
// per-listener response accounting.
package policy

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/rcvd-dns/rcvd/internal/allowlist"
	"github.com/rcvd-dns/rcvd/internal/blocklist"
	"github.com/rcvd-dns/rcvd/internal/statistics"
)

// ednsUDPBufSize mirrors internal/server.dnsUDPBufSize. The synthesized REFUSED reply
// carries an OPT with this bufsize when the query had one, so the EDE option rides
// alongside the EDNS0 record.
const ednsUDPBufSize = 1232

// Policy is the single source of truth for "answer locally or forward". Wire one
// instance into every listener (Mode 1 + Mode 2) so the allowlist cannot be bypassed
// by switching transports.
type Policy struct {
	allow *allowlist.Allowlist
	block *blocklist.Blocklist
	stats *statistics.Stats
}

// New builds a Policy from an optional allowlist, optional blocklist, and optional stats.
// A nil allowlist means default-deny is off; a nil blocklist means no blocklist; a nil
// stats pointer means counters are not updated (handy for tests that don't construct
// statistics).
func New(allow *allowlist.Allowlist, block *blocklist.Blocklist, stats *statistics.Stats) *Policy {
	return &Policy{allow: allow, block: block, stats: stats}
}

// Response returns a synthesized reply when the query must not be forwarded, or nil to
// let the caller continue to cache/upstream. nil receiver returns nil (feature off).
//
// Updates DeniedQueries / BlockedQueries when stats is non-nil. The caller still runs
// ensureResponseEDNS on the returned reply (the deny reply carries OPT only when the
// query had OPT; the EDE option rides alongside when present).
func (p *Policy) Response(query *dns.Msg) *dns.Msg {
	if p == nil {
		return nil
	}
	if len(query.Question) == 0 {
		return nil
	}

	if p.allow != nil && !p.allow.Allowed(query.Question[0].Name) {
		if p.stats != nil {
			atomic.AddInt64(&p.stats.DeniedQueries, 1)
		}
		resp := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:                 query.Id,
				Response:           true,
				Rcode:              dns.RcodeRefused,
				RecursionAvailable: true,
			},
			Question: query.Question,
		}
		// EDE 18 only when the client sent OPT — non-EDNS clients get no OPT
		// (RFC 6891 §6.1.1; ensureResponseEDNS strips any we add here).
		if query.IsEdns0() != nil {
			resp.SetEdns0(ednsUDPBufSize, false)
			if opt := resp.IsEdns0(); opt != nil {
				opt.Option = append(opt.Option, &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeProhibited,
					ExtraText: "default-deny allowlist",
				})
			}
		}
		return resp
	}

	if p.block != nil && p.block.IsBlocked(query.Question[0].Name) {
		if p.stats != nil {
			atomic.AddInt64(&p.stats.BlockedQueries, 1)
		}
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:       query.Id,
				Response: true,
				Rcode:    dns.RcodeNameError,
			},
			Question: query.Question,
		}
	}

	return nil
}

// shadowProbeLabel is a label no blocklist entry can contain (blocklist labels are
// [a-z0-9_-]), so probing "<label>.<suffix>" only matches entries that cover every
// subdomain of suffix, never one specific name.
const shadowProbeLabel = "#"

// Shadowed returns the allowlist entries that the blocklist fully covers, sorted. Such
// an entry can never resolve: every name it allows gets NXDOMAIN. A blocklist entry that
// covers only part of an allowed suffix (ads.example.com under example.com) is normal
// use and is not reported. Returns nil when either list is nil or disabled.
func Shadowed(allow *allowlist.Allowlist, block *blocklist.Blocklist) []string {
	if allow == nil || block == nil {
		return nil
	}
	var out []string
	for _, e := range allow.Entries() {
		// A bare entry covers the apex and all subdomains. Any blocklist match on the
		// apex (exact bare entry or a parent) also matches every subdomain.
		probe := e
		// A wildcard entry covers subdomains only, so probe an arbitrary subdomain.
		if strings.HasPrefix(e, "*.") {
			probe = shadowProbeLabel + e[1:]
		}
		if block.IsBlocked(probe) {
			out = append(out, e)
		}
	}
	return out
}

// ShadowSummary formats a one-line operator warning for Shadowed's result, or "" when
// nothing is shadowed. At most five names are listed.
func ShadowSummary(shadowed []string) string {
	if len(shadowed) == 0 {
		return ""
	}
	noun := "entries"
	if len(shadowed) == 1 {
		noun = "entry"
	}
	names := shadowed
	more := ""
	if len(names) > 5 {
		more = fmt.Sprintf(", and %d more", len(names)-5)
		names = names[:5]
	}
	return fmt.Sprintf("%d allowlist %s fully shadowed by the blocklist (always NXDOMAIN): %s%s",
		len(shadowed), noun, strings.Join(names, ", "), more)
}
