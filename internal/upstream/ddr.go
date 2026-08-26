// Package upstream — DDR (Discovery of Designated Resolvers, RFC 9462).
//
// This file owns everything about the "resolver.arpa" special-use domain: deciding which
// queries belong to it, building the SVCB answer that advertises rcvd's own encrypted
// listeners, and containing every other name in the zone. It is deliberately the single
// place that knows the zone exists — the DoH/DoT/DoQ listeners hand a query to
// ddrZone.answer and either get a reply to write or nil meaning "not mine, resolve it".
//
// What DDR is for: a client that reaches a resolver over one transport asks it "what
// encrypted endpoints do you designate?" and gets back SVCB records describing them. The
// client can then upgrade. rcvd answers this about itself — the records are synthesized
// here, never fetched, never published in an authoritative zone. That is not an
// optimization; "_dns.resolver.arpa" is an RFC 8375 special-use name and cannot be
// delegated in the global DNS, so self-answering is the only conformant implementation.
//
// Two rules from the RFC shape the whole file:
//
//   - §3: a resolver advertises one record per designated protocol, ordering preference
//     with the SVCB priority field. rcvd therefore enumerates every encrypted listener it
//     actually runs rather than naming a single favored one.
//   - §6.4: a resolver answering DDR MUST treat resolver.arpa as a locally served zone
//     (RFC 6303) — every other name and type under it gets NODATA, not a trip upstream.
//
// One RFC 9461 SHOULD is deliberately not implemented: §5 recommends publishing an equivalent
// HTTPS RR alongside the DoH SVCB record "if clients might learn about this DoH service through
// a different channel." Here the SVCB record lives only at _dns.resolver.arpa, an RFC 8375
// special-use name that is self-answered and never delegated, so there is no other channel to be
// consistent with — the recommendation does not apply to this synthesized zone.
package upstream

import (
	"net"
	"strconv"

	"github.com/miekg/dns"
)

// ddrQueryName is the special-use name a client queries (SVCB) to discover a resolver's
// designated encrypted endpoints, per RFC 9462 §4.
const ddrQueryName = "_dns.resolver.arpa."

// ddrZoneName is the apex of the locally served zone (RFC 9462 §6.4, RFC 6303). Every name
// at or below it is answered here and never forwarded upstream.
const ddrZoneName = "resolver.arpa."

// ddrTTL is the TTL on both the SVCB advert and the negative (NODATA) answers.
//
// Deliberately short. RFC 9462 §4.2 has clients suppress re-discovery for the length of
// this TTL when validation fails, so a long TTL turns one transient failure — a cert still
// being issued at first boot, a listener not yet up — into a long window where a client
// refuses to retry. Five minutes keeps rcvd's designation responsive to config changes
// without making the query hot.
const ddrTTL = 300

// ddrDoHPath is the URI Template advertised for the DoH endpoint (RFC 9461 §3, over the
// RFC 8484 §4.1 path).
//
// It must be exactly this string for Android's native Private DNS to accept the record:
// PrivateDnsConfiguration.cpp compares dohpath == "/dns-query{?dns}" byte-for-byte before
// upgrading to DoH. Any other template is silently ignored and the OS falls back to DoT on
// :853 — which a DoH-only deployment cannot answer, so the failure looks like a broken
// endpoint rather than a rejected record.
const ddrDoHPath = "/dns-query{?dns}"

// ALPN identifiers for the encrypted DNS transports rcvd can designate.
//
// "dot" and "doq" are the RFC 9461 §4 registrations (RFC 7858 and RFC 9250 respectively);
// "h2" and "h3" are the standard HTTP ALPNs a DoH endpoint is reached over.
const (
	alpnDoT   = "dot"
	alpnDoQ   = "doq"
	alpnHTTP2 = "h2"
	alpnHTTP3 = "h3"
)

// SVCB priority values expressing rcvd's designation preference (RFC 9462 §3: "the resolver
// deployment can indicate a preference using the priority fields"). Lower is preferred.
//
// DoH leads because it is the transport real discovering clients act on — Android's native
// resolver upgrades to DoH and nothing else, and DoH's port 443 survives networks that drop
// :853. That ordering is about client reachability, and is the reverse of rcvd's own
// upstream preference (DoQ → DoT → DoH), which optimizes a different thing: rcvd choosing
// how to egress, where DoQ's lower handshake cost wins and no middlebox is in the way.
const (
	ddrPriorityDoH = 1
	ddrPriorityDoT = 2
	ddrPriorityDoQ = 3
)

// designation is one encrypted endpoint rcvd advertises as a Designated Resolver: one SVCB
// record in the DDR answer.
type designation struct {
	priority    uint16   // SVCB priority; lower is preferred
	alpn        []string // ALPN set for this transport
	port        int      // port clients connect to
	defaultPort int      // this transport's default port (443 DoH, 853 DoT/DoQ)
	dohPath     bool     // emit the dohpath SvcParam (DoH designations only)
}

// ddrZone answers queries for the resolver.arpa locally served zone.
//
// It is built once at startup from the listener configuration and then read-only, so the
// listeners share one value with no synchronization. A zone with no designations still
// answers — RFC 9462 §4 wants an explicit NODATA from a resolver that designates nothing,
// so clients can tell "no designation" apart from a dropped query. Only the host is
// optional in the sense that it gates advertising, not answering.
type ddrZone struct {
	// host is the SVCB TargetName: the name clients reach these endpoints by, and the name
	// their certificate must cover. Empty means rcvd cannot name itself (no cert hostname
	// configured), so it advertises nothing and serves NODATA throughout the zone.
	//
	// RFC 9462 §4 forbids "." and "resolver.arpa" as the TargetName precisely so a client
	// can distinguish designations and tie them to a certificate; an unnameable endpoint has
	// no conformant record to emit, which is why this failing closed is correct rather than
	// a limitation.
	host string

	// designations is the advertised set, in priority order. Empty when rcvd runs no
	// encrypted listener it can name.
	designations []designation

	// v4/v6 are the address hints attached to every designation (RFC 9460 §7.3 ipv4hint/
	// ipv6hint). They save the client a round trip resolving the TargetName, and Android's
	// resolver requires them outright — it dials the first hint directly and never resolves
	// the target name at all. May be empty; see ddrHints.
	v4, v6 []net.IP
}

// newDDRZone builds the zone from the Mode-2 listener configuration.
//
// host is the certificate hostname clients reach rcvd by; empty disables advertising. Each
// listen address is "" when that transport is not configured. doh3 adds HTTP/3 to the DoH
// designation's ALPN set. advertiseIPs overrides the address hints; see ddrHints.
//
// A transport is designated only if it is actually listening: rcvd advertises what it runs,
// never a nominal endpoint. Callers get a usable zone in every case — with no designations
// it still contains resolver.arpa per §6.4.
func newDDRZone(host, listenDoH, listenDoT, listenDoQ string, doh3 bool, advertiseIPs []string) ddrZone {
	z := ddrZone{host: host}
	if host == "" {
		return z
	}

	if listenDoH != "" {
		// h3 first when DoH3 is on: Android's DDR validation probe is HTTP/3, and ALPN
		// order is the preference signal to any client negotiating the connection.
		alpn := []string{alpnHTTP2}
		if doh3 {
			alpn = []string{alpnHTTP3, alpnHTTP2}
		}
		z.designations = append(z.designations, designation{
			priority:    ddrPriorityDoH,
			alpn:        alpn,
			port:        advertPort(listenDoH, 443),
			defaultPort: 443,
			dohPath:     true,
		})
	}
	if listenDoT != "" {
		z.designations = append(z.designations, designation{
			priority:    ddrPriorityDoT,
			alpn:        []string{alpnDoT},
			port:        advertPort(listenDoT, 853),
			defaultPort: 853,
		})
	}
	if listenDoQ != "" {
		z.designations = append(z.designations, designation{
			priority:    ddrPriorityDoQ,
			alpn:        []string{alpnDoQ},
			port:        advertPort(listenDoQ, 853),
			defaultPort: 853,
		})
	}

	// Hints describe the host, which is one machine serving every listener above, so they
	// are derived once and attached to all designations. Prefer an explicit DoH bind as the
	// derivation source only because it is the most commonly concrete one; advertiseIPs
	// wins over all of them when set.
	bind := listenDoH
	if bind == "" {
		bind = listenDoT
	}
	if bind == "" {
		bind = listenDoQ
	}
	z.v4, z.v6 = ddrHints(bind, advertiseIPs)

	return z
}

// advertises reports whether the zone has at least one designation to publish.
func (z ddrZone) advertises() bool { return len(z.designations) > 0 }

// owns reports whether name falls inside the resolver.arpa locally served zone.
//
// Matching the whole subtree, not just the DDR query name, is what RFC 9462 §6.4 requires:
// the zone is served locally in its entirety, so a probe for any name under it is answered
// here rather than leaking upstream to a third party that would return NXDOMAIN from the
// real (empty) resolver.arpa.
func ddrOwnsName(name string) bool {
	return dns.IsSubDomain(ddrZoneName, dns.Fqdn(name))
}

// answer returns rcvd's reply for query, or nil if the query is not for this zone and the
// caller should resolve it normally.
//
// The behavior is the RFC 9462 §6.4 locally-served-zone rule:
//
//   - SVCB for _dns.resolver.arpa → the designations, or NODATA when there are none
//     (§4: an explicit "no Designated Resolver" signal beats silence)
//   - any other type for that name → NODATA
//   - any name under resolver.arpa → NODATA
//
// Answers are authoritative and are never cached or forwarded: they describe this instance,
// so caching them across a config change or serving them on another resolver's behalf would
// both be wrong.
func (z ddrZone) answer(query *dns.Msg) *dns.Msg {
	if len(query.Question) != 1 {
		return nil
	}
	q := query.Question[0]
	if !ddrOwnsName(q.Name) {
		return nil
	}

	if q.Qtype == dns.TypeSVCB && dns.CanonicalName(q.Name) == ddrQueryName && z.advertises() {
		return z.svcbResponse(query)
	}
	return z.nodataResponse(query)
}

// svcbResponse builds the positive DDR answer: one SVCB record per designation.
func (z ddrZone) svcbResponse(query *dns.Msg) *dns.Msg {
	target := dns.Fqdn(z.host)
	answer := make([]dns.RR, 0, len(z.designations))

	for _, d := range z.designations {
		params := []dns.SVCBKeyValue{
			&dns.SVCBAlpn{Alpn: d.alpn},
		}

		// Emit the port SvcParam only for a non-default port. RFC 9461 §4.2 makes "port"
		// automatically mandatory (Appendix A) — a client that does not implement the key MUST
		// ignore any record that carries it. So publishing port=443 on the DoH designation (443
		// is the DoH default, §4.2) adds no information yet can make a strict client discard
		// rcvd's most important record, the one iOS and Android act on. The RFC's own DoH-only
		// example omits port for exactly this reason. When the port is genuinely non-default it
		// is emitted, and the automatically-mandatory rule then applies without an explicit
		// "mandatory" SvcParam (§4.2), so none is added.
		if d.port != d.defaultPort {
			params = append(params, &dns.SVCBPort{Port: uint16(d.port)})
		}

		if d.dohPath {
			// dohpath is a relative URI Template (RFC 9461 §5) resolved against the "https"
			// origin — the authentication name plus the port SvcParam if present. ddrDoHPath is
			// a fixed template that carries no port, so it stays coherent only while the DoH
			// endpoint is on its default 443 or the non-default port is expressed via the port
			// SvcParam above. rcvd never binds DoH off 443 for mobile, so this holds today; a
			// future non-default DoH port would need this pairing checked.
			params = append(params, &dns.SVCBDoHPath{Template: ddrDoHPath})
		}
		// Hints go last: RFC 9460 §2.2 requires SvcParams in ascending key order on the
		// wire, and ipv4hint (4) / ipv6hint (6) outrank alpn (1), port (3) and dohpath (7)
		// only partially — miekg/dns sorts on pack, so ordering here is for readability.
		if len(z.v4) > 0 {
			params = append(params, &dns.SVCBIPv4Hint{Hint: z.v4})
		}
		if len(z.v6) > 0 {
			params = append(params, &dns.SVCBIPv6Hint{Hint: z.v6})
		}

		answer = append(answer, &dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   ddrQueryName,
				Rrtype: dns.TypeSVCB,
				Class:  dns.ClassINET,
				Ttl:    ddrTTL,
			},
			Priority: d.priority,
			Target:   target,
			Value:    params,
		})
	}

	response := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:            query.Id,
			Response:      true,
			Authoritative: true,
			Rcode:         dns.RcodeSuccess,
		},
		Question: query.Question,
		Answer:   answer,
	}
	ensureResponseEDNS(response, query)
	return response
}

// nodataResponse builds the negative answer for the zone: NOERROR with no records, plus a
// SOA in the authority section so a client can cache the negative result (RFC 2308 §3).
//
// NODATA rather than NXDOMAIN is deliberate and is what RFC 9462 §4 and §6.4 both specify:
// the zone exists and is served locally, there is simply no data of the requested type.
// NXDOMAIN would assert the name does not exist, which is a different and false claim.
func (z ddrZone) nodataResponse(query *dns.Msg) *dns.Msg {
	response := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:            query.Id,
			Response:      true,
			Authoritative: true,
			Rcode:         dns.RcodeSuccess,
		},
		Question: query.Question,
		Ns:       []dns.RR{ddrSOA()},
	}
	ensureResponseEDNS(response, query)
	return response
}

// ddrSOA is the synthetic SOA for the locally served resolver.arpa zone, used to bound
// negative caching. The zone is synthesized per instance and never transferred, so the
// mname/rname are placeholders under the zone itself rather than real hostnames, and the
// serial is fixed — there is nothing for a secondary to track.
func ddrSOA() *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   ddrZoneName,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    ddrTTL,
		},
		Ns:      ddrZoneName,
		Mbox:    ddrZoneName,
		Serial:  1,
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minttl:  ddrTTL,
	}
}

// advertPort returns the port to advertise for a listener, parsed from its "host:port"
// listen address, falling back to def when the address cannot be parsed.
func advertPort(listenAddr string, def int) int {
	if _, port, err := net.SplitHostPort(listenAddr); err == nil {
		if p, err := strconv.Atoi(port); err == nil && p > 0 {
			return p
		}
	}
	return def
}

// ddrHints returns the IPv4/IPv6 address hints to publish in the DDR SVCB records.
//
// advertiseIPs (config `advertise_ips`) wins when set: it is the only source that can be
// right for a wildcard-bound or NAT'd endpoint, where the address a client dials is not the
// address rcvd binds. On EC2 the instance holds a private address and the Elastic IP is
// NAT'd in front of it, so the socket simply does not know the public address.
//
// Otherwise the hints are derived from listenAddr when it is a concrete IP literal — the
// single-homed case, where bind address and dialed address coincide.
//
// Both may be empty (wildcard bind, no advertise_ips). That is spec-legal: RFC 9460 §7.3
// makes hints optional and a conformant client resolves the TargetName itself. It is not
// sufficient for Android's native resolver, which requires the hints and ignores the target
// name entirely — see the advertise_ips doc comment in internal/config. Callers warn when
// they detect that shape.
func ddrHints(listenAddr string, advertiseIPs []string) (v4, v6 []net.IP) {
	if len(advertiseIPs) > 0 {
		for _, addr := range advertiseIPs {
			ip := net.ParseIP(addr)
			if ip == nil || ip.IsUnspecified() {
				continue // config validation rejects these; skip defensively
			}
			if ip4 := ip.To4(); ip4 != nil {
				v4 = append(v4, ip4)
			} else {
				v6 = append(v6, ip)
			}
		}
		return v4, v6
	}

	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil, nil
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return nil, nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return []net.IP{ip4}, nil
	}
	return nil, []net.IP{ip}
}
