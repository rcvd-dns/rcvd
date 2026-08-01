// SPDX-License-Identifier: MIT
package verify

import (
	"context"
	"strings"
	"testing"

	"github.com/rcvd-dns/rcvd/internal/config"
)

// TestShowPinIndexBounds covers the pure index-validation logic of --show-pin
// without any network I/O: an out-of-range or negative index must error clearly,
// and an empty upstream list must error rather than panic. A valid index falls
// through to the probe (which we do not exercise here — that needs a live server).
func TestShowPinIndexBounds(t *testing.T) {
	two := []config.UpstreamServer{
		{Name: "a", Host: "a.example", Port: 853, DoQ: true, PinnedPubKey: "sha256//x"},
		{Name: "b", Host: "b.example", Port: 853, DoT: true},
	}

	cases := []struct {
		name      string
		upstreams []config.UpstreamServer
		index     int
		wantErr   string // substring; "" means "must reach the probe" (checked separately)
	}{
		{"empty list", nil, 0, "no upstreams configured"},
		{"negative index", two, -1, "out of range"},
		{"index past end", two, 2, "out of range"},
		{"index way past end", two, 99, "out of range"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ShowPin(context.Background(), tc.upstreams, tc.index)
			if err == nil {
				t.Fatalf("ShowPin(index=%d) = nil error, want %q", tc.index, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("ShowPin(index=%d) error = %q, want substring %q", tc.index, err.Error(), tc.wantErr)
			}
		})
	}
}

// TestVerifyPinsSkipsUnpinned confirms an upstream with NO pinned_pubkey is reported
// as (none configured), NOT probed or failed — so --verify-pin and --verify-upstream
// never overlap in meaning. With only unpinned upstreams there is nothing to verify,
// so it reports that and stays allOK=true (no false failure from an un-dialable host).
func TestVerifyPinsSkipsUnpinned(t *testing.T) {
	upstreams := []config.UpstreamServer{
		{Name: "public", Host: "9.9.9.9", Port: 443, DoH: true}, // no pin
	}
	out, allOK := VerifyPins(context.Background(), "test.toml", upstreams)
	if !allOK {
		t.Errorf("VerifyPins with only unpinned upstreams: allOK = false, want true")
	}
	if !strings.Contains(out, "none configured") {
		t.Errorf("expected an unpinned upstream to be reported as (none configured); got:\n%s", out)
	}
	if !strings.Contains(out, "nothing to verify") {
		t.Errorf("expected the 'nothing to verify' summary; got:\n%s", out)
	}
}
