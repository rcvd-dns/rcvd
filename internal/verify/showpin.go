// SPDX-License-Identifier: MIT
package verify

import (
	"context"
	"fmt"
	"time"

	"github.com/rcvd-dns/rcvd/internal/config"
)

// ShowPin probes ONE upstream (0-based index into [[upstreams]]) and returns just
// its leaf SPKI pin ("sha256//…"), ready to paste into that upstream's
// pinned_pubkey. This is the BOOTSTRAP verb of the three-verb pin lifecycle
// (bootstrap: --show-pin → config: pinned_pubkey → audit: --verify-pin).
//
// Unlike --verify-upstream (which CA-validates) and --verify-pin (which compares an
// already-configured pin), --show-pin needs NO pin configured — that's the point:
// you're generating one. It probes the leaf with CA validation OFF (we only want to
// read the key, not judge the chain), so it works for a self-signed leg too.
//
// The pin is written to STDOUT with nothing else, so `pin=$(rcvd --show-pin 0 …)`
// captures exactly the value; all diagnostics/banners go to STDERR (handled by the
// caller in main.go). Returns the pin string and an error; on error the caller
// prints to stderr and exits non-zero.
func ShowPin(ctx context.Context, upstreams []config.UpstreamServer, index int) (string, error) {
	if len(upstreams) == 0 {
		return "", fmt.Errorf("no upstreams configured")
	}
	if index < 0 || index >= len(upstreams) {
		return "", fmt.Errorf("upstream index %d out of range (have %d: valid 0..%d)",
			index, len(upstreams), len(upstreams)-1)
	}

	up := upstreams[index]

	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Reuse the pin-path leaf probe (InsecureSkipVerify + no hostname judgment) so
	// --show-pin reads the SAME leaf the pinned resolver path would, and works on a
	// self-signed leg. We compute the pin from that leaf — the single source of
	// truth in config.SPKIPin, shared with --verify-pin and the config loader.
	leaf, err := probePinLeaf(probeCtx, &up)
	if err != nil {
		return "", fmt.Errorf("probe upstream %d (%s %s:%d): %w", index, up.Name, up.Host, up.Port, err)
	}

	return config.SPKIPin(leaf), nil
}
