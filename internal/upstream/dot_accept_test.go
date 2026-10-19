// SPDX-License-Identifier: MIT
package upstream

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"
)

// flakyListener fails Accept a few times with a non-closed error, then blocks until Close.
type flakyListener struct {
	mu       sync.Mutex
	failures int
	calls    int
	closed   chan struct{}
	once     sync.Once
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.calls++
	fail := l.calls <= l.failures
	l.mu.Unlock()
	if fail {
		return nil, errors.New("accept: too many open files")
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *flakyListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *flakyListener) Addr() net.Addr { return &net.TCPAddr{} }

func (l *flakyListener) callCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// TestDoTServeSurvivesTransientAcceptError checks that a non-closed accept error is retried
// instead of ending Serve, and that Serve still exits cleanly on context cancellation.
func TestDoTServeSurvivesTransientAcceptError(t *testing.T) {
	ln := &flakyListener{failures: 3, closed: make(chan struct{})}
	d := &DOTListener{listener: ln, logger: log.New(io.Discard, "", 0)}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- d.Serve(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for ln.callCount() <= ln.failures {
		if time.Now().After(deadline) {
			t.Fatalf("accept was not retried past the transient errors (calls=%d)", ln.callCount())
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case err := <-served:
		t.Fatalf("Serve returned early on a transient accept error: %v", err)
	default:
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v on shutdown, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}
