// SPDX-License-Identifier: MIT

// Package policy decides whether a query is answered locally instead of forwarded.
//
// One Policy is wired into every entry point — UDP, TCP, DoH, DoT, DoQ — so the
// allowlist and blocklist cannot drift across transports. The two filters compose in
// a fixed order:
//
//  1. Allowlist (default-deny). If set and the qname is not under a listed suffix, or
//     the qtype is not in the optional qtype set, the reply is REFUSED + EDE 18
//     (Prohibited). The query never leaves the host.
//  2. Blocklist. Inside an allowed suffix, block wins — NXDOMAIN.
//
// With the allowlist on, Answer also checks what comes back. The qname check alone
// cannot stop an allowed name from CNAME-ing to a name outside the list: the upstream
// follows the chain and rcvd would hand the result to the client, which is a reply
// channel the allowlist was meant to close.
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
	allow  *allowlist.Allowlist
	block  *blocklist.Blocklist
	stats  *statistics.Stats
	qtypes map[uint16]bool // allowed query/answer types; nil = any. Only enforced with an allowlist.
}

// New builds a Policy from an optional allowlist, optional blocklist, and optional stats.
// A nil allowlist means default-deny is off; a nil blocklist means no blocklist; a nil
// stats pointer means counters are not updated (handy for tests that don't construct
// statistics).
func New(allow *allowlist.Allowlist, block *blocklist.Blocklist, stats *statistics.Stats) *Policy {
	return &Policy{allow: allow, block: block, stats: stats}
}

// SetQTypes restricts the query types, and the record types an answer may carry, to
// types (e.g. A + AAAA). Empty means any type. Only enforced alongside an allowlist,
// since it exists to narrow a default-deny sandbox. Call before serving.
func (p *Policy) SetQTypes(types []uint16) {
	if len(types) == 0 {
		p.qtypes = nil
		return
	}
	p.qtypes = make(map[uint16]bool, len(types))
	for _, t := range types {
		p.qtypes[t] = true
	}
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

	if p.allow != nil {
		q := query.Question[0]
		if !p.allow.Allowed(q.Name) {
			return p.deny(query, "default-deny allowlist")
		}
		if p.qtypes != nil && !p.qtypes[q.Qtype] {
			return p.deny(query, "qtype not allowed")
		}
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

// Answer checks a reply about to be sent (upstream or cache) against the allowlist.
// It returns resp unchanged when it passes, or a REFUSED + EDE 18 reply in its place
// when any Answer record is owned by, or points at (CNAME/DNAME target), a name
// outside the allowlist, or has a type outside the qtype set. The whole reply is
// refused rather than trimmed: a partial chain is a broken answer, and the EDE text
// tells the operator why. RRSIGs are skipped; they follow the
// records they sign. A nil receiver, or no allowlist, returns resp.
//
// Call it at every send point for forwarded or cached replies. Locally synthesized
// replies (policy denials, DDR's resolver.arpa zone) must not go through it.
func (p *Policy) Answer(query, resp *dns.Msg) *dns.Msg {
	if p == nil || p.allow == nil || resp == nil {
		return resp
	}
	for _, rr := range resp.Answer {
		h := rr.Header()
		if h.Rrtype == dns.TypeRRSIG {
			continue
		}
		if p.qtypes != nil && !p.qtypes[h.Rrtype] {
			return p.deny(query, "answer type not allowed")
		}
		if !p.allow.Allowed(h.Name) {
			return p.deny(query, "answer outside allowlist")
		}
		switch r := rr.(type) {
		case *dns.CNAME:
			if !p.allow.Allowed(r.Target) {
				return p.deny(query, "answer outside allowlist")
			}
		case *dns.DNAME:
			if !p.allow.Allowed(r.Target) {
				return p.deny(query, "answer outside allowlist")
			}
		}
	}
	return resp
}

// deny builds the REFUSED + EDE 18 reply and counts it as a denied query.
func (p *Policy) deny(query *dns.Msg, reason string) *dns.Msg {
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
				ExtraText: reason,
			})
		}
	}
	return resp
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
		// An exact-only entry covers just its own name.
		probe = strings.TrimPrefix(probe, "=")
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
