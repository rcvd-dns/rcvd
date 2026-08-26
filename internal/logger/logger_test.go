// SPDX-License-Identifier: MIT
package logger

import (
	"bytes"
	"strings"
	"testing"
)

// TestLevelGating verifies the leveled methods honor the configured threshold — the fix
// for the previously-dead [logging] level knob. Debug must be suppressed at info and emitted
// at debug; error must always emit.
func TestLevelGating(t *testing.T) {
	tests := []struct {
		level     string
		wantDebug bool // is a Debugf line emitted at this level?
		wantInfo  bool
	}{
		{"debug", true, true},
		{"info", false, true},
		{"", false, true}, // empty defaults to info
		{"warn", false, false},
		{"error", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.level, func(t *testing.T) {
			var buf bytes.Buffer
			l := New(tc.level, &buf)

			buf.Reset()
			l.Debugf("dbg %d", 1)
			if got := strings.Contains(buf.String(), "dbg"); got != tc.wantDebug {
				t.Errorf("Debugf at level %q: emitted=%v, want %v", tc.level, got, tc.wantDebug)
			}

			buf.Reset()
			l.Infof("inf %d", 2)
			if got := strings.Contains(buf.String(), "inf"); got != tc.wantInfo {
				t.Errorf("Infof at level %q: emitted=%v, want %v", tc.level, got, tc.wantInfo)
			}

			// Error must always emit regardless of threshold.
			buf.Reset()
			l.Errorf("err %d", 3)
			if !strings.Contains(buf.String(), "err") {
				t.Errorf("Errorf at level %q: expected to always emit", tc.level)
			}
		})
	}
}

// TestEmbeddedLoggerUnconditional confirms the embedded *log.Logger path (used by the ~125
// not-yet-reclassified call sites) still logs unconditionally, so the level fix is additive
// and does not silence existing lines before the global reclassification pass.
func TestEmbeddedLoggerUnconditional(t *testing.T) {
	var buf bytes.Buffer
	l := New("error", &buf) // highest threshold
	l.Printf("legacy line")
	if !strings.Contains(buf.String(), "legacy line") {
		t.Errorf("embedded *log.Logger.Printf must still emit regardless of level; got %q", buf.String())
	}
}
