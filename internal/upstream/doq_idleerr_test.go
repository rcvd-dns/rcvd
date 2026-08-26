// SPDX-License-Identifier: MIT
package upstream

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
)

// TestIsBenignIdleConnErr locks the classification the server-side DoQ log gating relies on:
// a client's clean/idle connection close (NO_ERROR 0x0, idle timeout, closed conn) is benign
// (routes to debug), while a genuine error is not (stays on the unconditional logger).
func TestIsBenignIdleConnErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"net.ErrClosed", net.ErrClosed, true},
		{"idle timeout", &quic.IdleTimeoutError{}, true},
		{"app NO_ERROR (remote)", &quic.ApplicationError{Remote: true, ErrorCode: 0}, true},
		{"app NO_ERROR (local)", &quic.ApplicationError{Remote: false, ErrorCode: 0}, true},
		{"wrapped app NO_ERROR", fmt.Errorf("DoQ write length: %w", &quic.ApplicationError{ErrorCode: 0}), true},
		{"app non-zero code", &quic.ApplicationError{ErrorCode: 2}, false},
		{"generic error", errors.New("something real broke"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isBenignIdleConnErr(tc.err); got != tc.want {
				t.Errorf("isBenignIdleConnErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
