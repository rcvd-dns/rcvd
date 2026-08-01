// SPDX-License-Identifier: MIT
package resolver

import (
	"context"

	"github.com/miekg/dns"
)

// Resolver interface abstracts over different DNS encryption protocols.
// Each resolver handles a single protocol (DoQ, DoT, DoH).
type Resolver interface {
	// Resolve sends a DNS query and returns the response.
	// Returns error if the query fails; never returns SERVFAIL for cleartext fallback.
	Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)

	// Close closes the resolver and any open connections.
	Close() error
}
