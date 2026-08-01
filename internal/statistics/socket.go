// SPDX-License-Identifier: MIT
package statistics

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SocketPath derives the Unix socket path from a config file path.
// Resolves symlinks so the socket name reflects the real config file, not the symlink.
// /etc/rcvd/rcvd.toml (symlink → rcvd-adguard-doq-test.toml) → /run/rcvd/rcvd-adguard-doq-test.sock
// Falls back to $XDG_RUNTIME_DIR/rcvd/<name>.sock for non-system (dev/workstation) use.
func SocketPath(configPath string) string {
	// Resolve symlinks so socket name matches the real config file, not the symlink
	if resolved, err := filepath.EvalSymlinks(configPath); err == nil {
		configPath = resolved
	}

	base := filepath.Base(configPath)
	name := strings.TrimSuffix(base, filepath.Ext(base)) + ".sock"

	// Primary: /run/rcvd/ — the standard FHS runtime directory for the rcvd daemon.
	// Created by the OpenRC init script (start_pre) with correct ownership before daemon start.
	runDir := "/run/rcvd"
	if info, err := os.Stat(runDir); err == nil && info.IsDir() {
		return filepath.Join(runDir, name)
	}

	// Fallback: $XDG_RUNTIME_DIR/rcvd/ — for dev/workstation use running as a regular user.
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		fallbackDir := filepath.Join(xdg, "rcvd")
		if err := os.MkdirAll(fallbackDir, 0755); err == nil {
			return filepath.Join(fallbackDir, name)
		}
	}

	// Last resort: /tmp/rcvd-<name>.sock
	return filepath.Join(os.TempDir(), "rcvd-"+name)
}

// CacheInfoFunc is called by the socket server to get current cache state.
// Returns (currentSize, maxSize).
type CacheInfoFunc func() (int, int)

// StatusFunc is called by the socket server to get live per-upstream health for
// the MODE-1 FORWARDER "Connections" block. Returns nil when no fallback chain is
// wired (older single-resolver path) — the render then omits the block. Defined
// here (not in internal/resolver) so the statistics package stays dependency-free
// of resolver; main.go adapts FallbackResolver.GetStatus() into this shape.
type StatusFunc func() []UpstreamConnInfo

// ListenerFunc returns the daemon's actually-bound listener addresses at call time, for the
// live portion of --audit. An empty string for a field means that listener is not bound. It
// reads net.Listener/PacketConn LocalAddr values the daemon already holds — no self-dialing.
type ListenerFunc func() ListenerLive

// ListenerLive carries the live-bound listener addresses reported by a ListenerFunc.
type ListenerLive struct {
	Mode1UDP string
	Mode1TCP string
	Mode2DoH string
	Mode2DoT string
	Mode2DoQ string
}

// ReloadFunc triggers a hot-reload of the blocklist files in the running daemon
// (the --blocklist-reload verb). It is fire-and-forget: the implementation kicks
// off the reload asynchronously and returns immediately, mirroring the async
// startup load so DNS is never blocked. It returns the number of files that will
// be (re)scanned, for the acknowledgment line. A nil ReloadFunc means no
// blocklist is wired, in which case the server reports that reload is unavailable.
type ReloadFunc func() (files int)

// ListenAndServe starts a Unix socket server that responds to stats and audit queries.
// Blocks until ctx is cancelled. Removes the socket file on return.
// info carries static per-instance metadata (config/socket paths, mode flags) into each snapshot.
// audit carries the static posture facts rendered for an "AUDIT" request (see QueryAudit).
//
// Request protocol (backward compatible): the server reads one line first. "AUDIT" → posture
// snapshot; "RELOAD-BLOCKLIST" → trigger an async blocklist reload and acknowledge; "STATS",
// EOF, or anything else → statistics. An older --stats client writes nothing, so the server
// sees EOF and renders stats, unchanged.
//
// reload is fire-and-forget (may be nil if no blocklist is configured); see ReloadFunc.
func ListenAndServe(ctx context.Context, socketPath string, stats *Stats, version string, cacheInfo CacheInfoFunc, statusInfo StatusFunc, listenerInfo ListenerFunc, info InstanceInfo, audit AuditInfo, reload ReloadFunc) error {
	// Remove stale socket
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen unix %s: %w", socketPath, err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	// Set socket permissions: owner + group read/write.
	// The rcvd daemon runs as user rcvd; admins in the rcvd group can query stats.
	if err := os.Chmod(socketPath, 0660); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	// Close listener when context is done
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}

		// Handle connection: read the request verb, render the matching report, write, close.
		go func() {
			defer conn.Close()

			// Read one request line. A short deadline keeps a slow/silent client from
			// blocking this goroutine; on timeout or EOF we default to stats (the legacy
			// behavior, where --stats clients send nothing). The verb is bounded by the
			// same 1 MiB cap used on the client read.
			verb := ""
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			line, err := bufio.NewReader(io.LimitReader(conn, 1<<20)).ReadString('\n')
			if err == nil || line != "" {
				verb = strings.TrimSpace(line)
			}
			_ = conn.SetReadDeadline(time.Time{}) // clear deadline before writing

			if verb == "RELOAD-BLOCKLIST" {
				// Fire-and-forget: kick off the reload and acknowledge immediately.
				// The actual (possibly minute-long) rescan runs in the daemon's own
				// goroutine; the client does not wait for it. Final counts land in
				// the daemon log when the swap completes.
				if reload == nil {
					conn.Write([]byte("blocklist reload unavailable: no blocklist configured\n"))
					return
				}
				files := reload()
				conn.Write([]byte(fmt.Sprintf("blocklist reload started (%d file(s), background)\n", files)))
				return
			}

			if verb == "AUDIT" {
				// Assemble the live audit facts at request time from the daemon's own handles
				// (bound listeners, cache occupancy, upstream health) — no self-dialing.
				live := LiveAudit{}
				if listenerInfo != nil {
					l := listenerInfo()
					live.Mode1BoundUDP = l.Mode1UDP
					live.Mode1BoundTCP = l.Mode1TCP
					live.Mode2BoundDoH = l.Mode2DoH
					live.Mode2BoundDoT = l.Mode2DoT
					live.Mode2BoundDoQ = l.Mode2DoQ
				}
				if cacheInfo != nil {
					live.CacheSize, live.CacheMaxSize = cacheInfo()
				}
				if statusInfo != nil {
					live.Connections = statusInfo()
				}
				conn.Write([]byte(audit.RenderAudit(version, stats.Uptime(), live)))
				return
			}

			cacheSize, cacheMax := 0, 0
			if cacheInfo != nil {
				cacheSize, cacheMax = cacheInfo()
			}
			snap := stats.TakeSnapshot(cacheSize, cacheMax, info)
			if statusInfo != nil {
				snap.Connections = statusInfo()
			}
			conn.Write([]byte(snap.Render(version)))
		}()
	}
}

// QueryStats connects to a running rcvd instance's stats socket and returns
// the rendered statistics string.
func QueryStats(socketPath string) (string, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return "", fmt.Errorf("connect to %s: %w (is rcvd running with stats_enabled?)", socketPath, err)
	}
	defer conn.Close()

	// Half-close the write side so the server's request-line read returns EOF
	// immediately and defaults to stats — without this it would block on the
	// per-connection read deadline (2s) before falling through. Stats clients
	// send no request verb; the EOF IS the "give me stats" signal.
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}

	// Bound the read even though this is a local trusted socket — the stats
	// snapshot is a few KB; cap well above that (1 MiB) to avoid an unbounded
	// read if the peer ever misbehaves.
	data, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read stats: %w", err)
	}

	return string(data), nil
}

// QueryAudit connects to a running rcvd instance's socket and returns the rendered
// posture audit. It sends the "AUDIT\n" request verb (QueryStats sends nothing); the
// server branches on that verb, so the two share one socket without a protocol bump.
func QueryAudit(socketPath string) (string, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return "", fmt.Errorf("connect to %s: %w (is rcvd running with stats_enabled?)", socketPath, err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("AUDIT\n")); err != nil {
		return "", fmt.Errorf("write audit request: %w", err)
	}

	data, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read audit: %w", err)
	}

	return string(data), nil
}

// QueryReload connects to a running rcvd instance's socket and triggers an async
// blocklist reload, returning the daemon's acknowledgment line. It sends the
// "RELOAD-BLOCKLIST\n" verb; the server kicks off the rescan in the background and
// replies immediately, so this returns without waiting for the (possibly
// minute-long) scan to finish.
func QueryReload(socketPath string) (string, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return "", fmt.Errorf("connect to %s: %w (is rcvd running with stats_enabled?)", socketPath, err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("RELOAD-BLOCKLIST\n")); err != nil {
		return "", fmt.Errorf("write reload request: %w", err)
	}

	data, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read reload response: %w", err)
	}

	return string(data), nil
}
