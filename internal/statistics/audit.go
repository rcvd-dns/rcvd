// SPDX-License-Identifier: MIT
package statistics

import (
	"fmt"
	"strings"
	"time"
)

// AuditInfo carries the static, point-in-time POSTURE facts that `--audit` reports.
//
// Where --stats answers "what has happened since startup" (counters), --audit answers
// "what is this running instance's posture right now" — the verifiable security stance an
// operator can confirm without reaching for tcpdump, nmap, or ss. Every field here is a
// function of the loaded Config plus rcvd's two design invariants (port-53 loopback
// enforcement, no-cleartext fallback); none of it requires runtime tracking, so the whole
// struct is captured ONCE in main.go at startup and frozen, exactly like InstanceInfo.
//
// Privacy constraint (same as --stats): no per-client IPs, no domain names, no query
// content. Audit reports what rcvd is configured to do and what posture it holds — never
// who is querying it.
//
// Pass 1 scope: LISTENERS + NO-CLEARTEXT POSTURE + CACHE POSTURE. Deferred to later passes:
// per-upstream live health, the Mode-2 cert summary (that is --verify-self), and a
// recent-activity tail.
type AuditInfo struct {
	// Identity / header (mirrors the InstanceInfo header fields).
	ConfigPath string
	SocketPath string

	// LISTENERS — Mode 1 (plaintext-side forwarder).
	Mode1Enabled  bool
	Mode1Listen   string // cfg.Resolver.Listen
	Mode1Loopback bool   // listen host is a loopback address

	// LISTENERS — Mode 2 (encrypted client-facing endpoints). Empty string = endpoint disabled.
	Mode2Enabled   bool
	Mode2ListenDoH string // cfg.UpstreamService.ListenDoH
	Mode2DoH3      bool   // also serving DoH3 (HTTP/3 over QUIC) on the DoH addr
	Mode2ListenDoT string // cfg.UpstreamService.ListenDoT
	Mode2ListenDoQ string // cfg.UpstreamService.ListenDoQ

	// CACHE POSTURE.
	CacheEnabled   bool
	CacheType      string // "light" | "standard" | "aggressive"
	CacheNegCache  bool   // negative caching (NXDOMAIN/NODATA) in force
	CacheNegTTLMax int    // negative-cache TTL cap, seconds (0 = off)
	CacheStaleS    int    // serve-stale window, seconds (0 = off)
}

// LiveAudit carries the RUNTIME facts the daemon reads at audit-request time (as opposed to
// the config-derived AuditInfo captured once at startup). Unlike AuditInfo, this is refreshed
// on every --audit request so it reflects the process's actual current state: which listener
// addresses are really bound (a nil/empty address means the listener is NOT up), the live cache
// occupancy, and live per-upstream health. It contains NO self-dialing — every field is read
// from handles the daemon already holds (net.Listener.Addr, cache.Size, fallback health). Live
// TLS/port-53 verification is intentionally left to --verify-self / --verify-upstream.
type LiveAudit struct {
	// Actually-bound listener addresses (LocalAddr of the live net.Listener/PacketConn).
	// Empty string = that listener is not currently bound.
	Mode1BoundUDP string
	Mode1BoundTCP string
	Mode2BoundDoH string
	Mode2BoundDoT string
	Mode2BoundDoQ string

	// Live cache occupancy (0/0 when caching is disabled or the handle is unavailable).
	CacheSize    int
	CacheMaxSize int

	// Live per-upstream health (nil when no fallback chain is wired yet).
	Connections []UpstreamConnInfo
}

// RenderAudit formats the audit posture as human-readable text, in the same indent
// convention as Render (top-level fields at 4 spaces, section headers at column 0).
//
// This reports CONFIGURED posture (the loaded config + rcvd's design invariants) MERGED with
// the LIVE runtime facts in `live` (actually-bound listeners, live cache occupancy, upstream
// health). It performs NO self-dialing — for live TLS/port-53 verification use --verify-self
// and --verify-upstream. version and uptime are passed in because AuditInfo itself is static;
// uptime (monotonic) answers "how long has this posture been in force".
func (a *AuditInfo) RenderAudit(version string, uptime time.Duration, live LiveAudit) string {
	var b strings.Builder
	const w = -24 // field label width (4-space indent), matching Render

	// boundVerdict describes a listener's live bind state for the LISTENERS block. `want` is
	// the configured address; `bound` is what the live listener reports (empty = not bound).
	boundVerdict := func(bound string) string {
		if bound != "" {
			return "bound"
		}
		return "NOT BOUND"
	}

	// ---- header --------------------------------------------------------------
	// Configured posture + live runtime facts, captured/refreshed at request time. This is
	// NOT a live TLS/port-53 probe — those live checks are --verify-self / --verify-upstream.
	b.WriteString("RCVD Audit — configured posture + live runtime\n")
	b.WriteString("    (live TLS/reachability checks: --verify-self, --verify-upstream)\n")
	if version != "" {
		fmt.Fprintf(&b, "    %*s %s\n", w, "Version:", version)
	}
	fmt.Fprintf(&b, "    %*s %s\n", w, "Uptime:", formatDuration(uptime))
	if a.ConfigPath != "" {
		fmt.Fprintf(&b, "    %*s %s\n", w, "Config:", a.ConfigPath)
	}
	if a.SocketPath != "" {
		fmt.Fprintf(&b, "    %*s %s\n", w, "Socket:", a.SocketPath)
	}
	b.WriteByte('\n')

	// ---- LISTENERS -----------------------------------------------------------
	// Configured address + the LIVE bind state: "bound" means the daemon actually holds an
	// open listener on that address right now; "NOT BOUND" means it is enabled in config but
	// no live listener was found (still starting, or failed to bind). The loopback note is a
	// config fact (the address family), kept in words — no glyphs.
	b.WriteString("LISTENERS (inbound)\n")
	if a.Mode1Enabled {
		loop := "loopback-only"
		if !a.Mode1Loopback {
			loop = "NON-loopback"
		}
		// Mode 1 binds UDP and TCP on the same address; report a single verdict, but note
		// if only one of the two is live (an unexpected split).
		live1 := boundVerdict(firstNonEmpty(live.Mode1BoundUDP, live.Mode1BoundTCP))
		if (live.Mode1BoundUDP == "") != (live.Mode1BoundTCP == "") {
			live1 = fmt.Sprintf("UDP %s / TCP %s", boundVerdict(live.Mode1BoundUDP), boundVerdict(live.Mode1BoundTCP))
		}
		fmt.Fprintf(&b, "    MODE-1  %-18s UDP+TCP   plaintext, %s   (%s)\n", a.Mode1Listen, loop, live1)
	} else {
		b.WriteString("    MODE-1  (disabled)\n")
	}
	if a.Mode2Enabled {
		any := false
		if a.Mode2ListenDoH != "" {
			proto := "DoH (HTTP/2)"
			if a.Mode2DoH3 {
				proto = "DoH (HTTP/2 + HTTP/3)"
			}
			fmt.Fprintf(&b, "    MODE-2  %-18s %-24s TLS-only, %s\n", a.Mode2ListenDoH, proto, boundVerdict(live.Mode2BoundDoH))
			any = true
		}
		if a.Mode2ListenDoT != "" {
			fmt.Fprintf(&b, "    MODE-2  %-18s %-24s TLS-only, %s\n", a.Mode2ListenDoT, "DoT", boundVerdict(live.Mode2BoundDoT))
			any = true
		}
		if a.Mode2ListenDoQ != "" {
			fmt.Fprintf(&b, "    MODE-2  %-18s %-24s TLS-only, %s\n", a.Mode2ListenDoQ, "DoQ", boundVerdict(live.Mode2BoundDoQ))
			any = true
		}
		if !any {
			b.WriteString("    MODE-2  (enabled, but no endpoint address configured)\n")
		}
	} else {
		b.WriteString("    MODE-2  (disabled)\n")
	}
	b.WriteByte('\n')

	// ---- NO-CLEARTEXT POSTURE ------------------------------------------------
	// These are design GUARANTEES, not tunables and not live probes: port-53 binds are
	// rejected on non-loopback interfaces at config validation, and no cleartext path exists
	// in the resolver (all upstreams fail → SERVFAIL). Stated as guarantees — no glyphs, no
	// fake pass marks. The one live-derived line is "Inbound plaintext", which reflects the
	// Mode-1 listener's configured address family.
	b.WriteString("NO-CLEARTEXT POSTURE (design guarantees)\n")
	fmt.Fprintf(&b, "    %*s loopback-only enforced   (rejects non-loopback :53 at startup)\n",
		w, "Port 53 binding:")
	fmt.Fprintf(&b, "    %*s disabled                 (all upstreams fail → SERVFAIL, never plaintext)\n",
		w, "Cleartext fallback:")
	if a.Mode1Enabled {
		fmt.Fprintf(&b, "    %*s %s            (Mode-1 plaintext listener on %s)\n",
			w, "Inbound plaintext:", inboundPlaintextVerdict(a.Mode1Loopback), a.Mode1Listen)
	}
	if a.Mode2Enabled {
		fmt.Fprintf(&b, "    %*s all MODE-2 endpoints TLS-only   (no cleartext-HTTP DoH mode exists)\n",
			w, "Inbound encryption:")
	}
	b.WriteByte('\n')

	// ---- CACHE POSTURE -------------------------------------------------------
	// Serve-stale relaxes freshness (never provenance — a stale answer was already
	// DNSSEC-validated and arrived encrypted), so an operator should see at a glance
	// whether it is on. Surfacing it here keeps serve-stale observable, never silent.
	b.WriteString("CACHE POSTURE\n")
	if !a.CacheEnabled {
		fmt.Fprintf(&b, "    %*s disabled\n", w, "Type:")
		return b.String()
	}
	mode := a.CacheType
	if mode == "" {
		mode = "standard"
	}
	fmt.Fprintf(&b, "    %*s %s\n", w, "Type:", mode)
	// Live occupancy (read from the cache handle at request time), shown when a max size is known.
	if live.CacheMaxSize > 0 {
		fmt.Fprintf(&b, "    %*s %s / %s   (live)\n", w, "Entries:",
			fmtInt(int64(live.CacheSize)), fmtInt(int64(live.CacheMaxSize)))
	}
	if a.CacheNegCache {
		fmt.Fprintf(&b, "    %*s on  (NXDOMAIN/NODATA ≤ %s)\n", w, "Negative caching:", compactDuration(a.CacheNegTTLMax))
	} else {
		fmt.Fprintf(&b, "    %*s off\n", w, "Negative caching:")
	}
	if a.CacheStaleS > 0 {
		fmt.Fprintf(&b, "    %*s on  (≤ %s past expiry; validated answers only, never cleartext)\n",
			w, "Serve-stale:", compactDuration(a.CacheStaleS))
	} else {
		fmt.Fprintf(&b, "    %*s off\n", w, "Serve-stale:")
	}

	// ---- UPSTREAMS (live health) ---------------------------------------------
	// Live per-upstream state read from the fallback chain at request time (same source as
	// --stats Connections). Shown only for a Mode-1 forwarder with a wired chain; the state
	// string is transport-level (UP/DOWN/…), never a queried name.
	if a.Mode1Enabled && len(live.Connections) > 0 {
		b.WriteByte('\n')
		b.WriteString("UPSTREAMS (live health)\n")
		for _, c := range live.Connections {
			line := fmt.Sprintf("    %-20s %s", c.Name, c.State)
			if c.ConsecutiveErrors > 0 {
				line += fmt.Sprintf("   (%d consecutive err)", c.ConsecutiveErrors)
			}
			b.WriteString(line + "\n")
		}
	}

	return b.String()
}

// firstNonEmpty returns the first non-empty string among its arguments, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// inboundPlaintextVerdict describes the Mode-1 plaintext listener's exposure for the
// NO-CLEARTEXT POSTURE block.
func inboundPlaintextVerdict(loopback bool) string {
	if loopback {
		return "loopback only"
	}
	return "NON-loopback (exposed)"
}
