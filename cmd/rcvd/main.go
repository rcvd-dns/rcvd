// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/rcvd-dns/rcvd/internal/blocklist"
	"github.com/rcvd-dns/rcvd/internal/cache"
	"github.com/rcvd-dns/rcvd/internal/config"
	"github.com/rcvd-dns/rcvd/internal/dnssec"
	"github.com/rcvd-dns/rcvd/internal/logger"
	"github.com/rcvd-dns/rcvd/internal/resolver"
	"github.com/rcvd-dns/rcvd/internal/server"
	"github.com/rcvd-dns/rcvd/internal/statistics"
	"github.com/rcvd-dns/rcvd/internal/upstream"
	"github.com/rcvd-dns/rcvd/internal/verify"
)

// version, buildDate, and buildSource are stamped at compile time via
// -ldflags "-X main.<name>=...". Their defaults describe a plain, untagged
// local build so that even a bare `go build ./cmd/rcvd` self-reports honestly.
//
//	version     — release version, normally the git tag (e.g. "0.1.0").
//	              Default "0.1.0-dev" marks an untagged development build.
//	buildDate   — UTC build timestamp (RFC 3339), e.g. "2026-07-07T10:00:00Z".
//	buildSource — what produced the binary: "local" (a developer machine),
//	              "github-runner", "gitlab-runner", etc. Lets anyone inspect an
//	              artifact and know its provenance.
var (
	version     = "0.1.0-dev"
	buildDate   = "unknown"
	buildSource = "local"
)

// vcsRevision returns the git commit the binary was built from, read from the
// build metadata Go embeds automatically (runtime/debug.ReadBuildInfo). No
// -ldflags stamping is required: any `go build` inside a git checkout records
// vcs.revision + vcs.modified. Returns "unknown" when built outside a VCS tree
// (e.g. from a source tarball). A "-dirty" suffix marks an uncommitted tree.
func vcsRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	var rev, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if rev == "" {
		return "unknown"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if modified == "true" {
		rev += "-dirty"
	}
	return rev
}

func main() {
	configPath := flag.String("config", "rcvd.toml", "path to config file")
	showVersion := flag.Bool("version", false, "show version and exit")
	showHelp := flag.Bool("help", false, "show help and exit")
	showStats := flag.Bool("stats", false, "query running instance for statistics and exit")
	showAudit := flag.Bool("audit", false, "query running instance for live posture audit and exit")
	blocklistReload := flag.Bool("blocklist-reload", false, "trigger an async blocklist file reload in the running instance and exit")
	verifyUpstream := flag.Bool("verify-upstream", false, "verify upstream TLS certificates (CA-validating) and exit")
	verifyPin := flag.Bool("verify-pin", false, "validate each upstream's configured pinned_pubkey against the live server and exit")
	showPin := flag.Int("show-pin", -1, "probe upstream at the given 0-based index, print its SPKI pin (sha256//…) to stdout, and exit")
	verifySelf := flag.Bool("verify-self", false, "verify the TLS certificate THIS instance presents on its Mode-2 listeners and exit")
	serverName := flag.String("server-name", "", "TLS SNI to use for --verify-self (default: derived from the listener host)")

	flag.Parse()

	// Reject leftover positional arguments. rcvd's action flags (--stats, --audit,
	// --verify-upstream, --verify-pin, --verify-self) are BOOLEAN and take no value, and Go's flag package
	// stops parsing at the first non-flag token — so `rcvd --verify-self /etc/rcvd/rcvd.toml`
	// silently DROPS the path and falls back to the default config "rcvd.toml", failing with a
	// confusing "open rcvd.toml: no such file" that never mentions the path the user typed.
	// Fail loudly instead, and point at the correct -config form. (TODO.md 2026-06-09.)
	if flag.NArg() > 0 {
		extra := flag.Arg(0)
		fmt.Fprintf(os.Stderr,
			"error: unexpected argument %q — rcvd action flags take no path argument.\n"+
				"       The config path goes with -config, e.g.:  rcvd -config %s <flag>\n",
			extra, configHintPath(extra, *configPath))
		os.Exit(2)
	}

	if *showVersion {
		// Omit the commit when it's unknown (e.g. built from a release tarball,
		// which carries no .git) — a bare "commit unknown" is just noise. Git
		// builds (dev / CI) still show the revision.
		if rev := vcsRevision(); rev != "unknown" {
			fmt.Printf("RCVD v%s (built %s, source %s, commit %s)\n", version, buildDate, buildSource, rev)
		} else {
			fmt.Printf("RCVD v%s (built %s, source %s)\n", version, buildDate, buildSource)
		}
		os.Exit(0)
	}

	if *showHelp {
		printHelp()
		os.Exit(0)
	}

	if *showStats {
		socketPath := statistics.SocketPath(*configPath)
		output, err := statistics.QueryStats(socketPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(output)
		os.Exit(0)
	}

	if *showAudit {
		socketPath := statistics.SocketPath(*configPath)
		output, err := statistics.QueryAudit(socketPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(output)
		os.Exit(0)
	}

	if *blocklistReload {
		socketPath := statistics.SocketPath(*configPath)
		output, err := statistics.QueryReload(socketPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(output)
		os.Exit(0)
	}

	if *verifyUpstream {
		cfg, err := config.LoadForDiagnostics(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "config error: %v\n", err)
			os.Exit(1)
		}
		output, allOK := verify.VerifyUpstreams(context.Background(), *configPath, cfg.Upstreams)
		fmt.Print(output)
		if !allOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *showPin >= 0 {
		cfg, err := config.LoadForDiagnostics(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "config error: %v\n", err)
			os.Exit(1)
		}
		// Banner + diagnostics to STDERR so stdout carries ONLY the pin — makes
		// `pin=$(rcvd --show-pin 0 -config …)` capture exactly the value.
		fmt.Fprintf(os.Stderr, "RCVD show-pin: probing upstream %d for its leaf SPKI pin\n", *showPin)
		pin, err := verify.ShowPin(context.Background(), cfg.Upstreams, *showPin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(pin)
		os.Exit(0)
	}

	if *verifyPin {
		cfg, err := config.LoadForDiagnostics(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "config error: %v\n", err)
			os.Exit(1)
		}
		output, allOK := verify.VerifyPins(context.Background(), *configPath, cfg.Upstreams)
		fmt.Print(output)
		if !allOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *verifySelf {
		cfg, err := config.LoadForDiagnostics(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "config error: %v\n", err)
			os.Exit(1)
		}
		// The DoH hostname is the cert's subject — the first tls_automation allowed_domains
		// entry (both modes populate it). Passed so --verify-self can report it and default
		// the DoH SNI to it (instead of the IP-derived "localhost" autogen).
		var dohHostname string
		if len(cfg.TLSAutomation.AllowedDomains) > 0 {
			dohHostname = cfg.TLSAutomation.AllowedDomains[0]
		}
		output, allOK := verify.VerifySelf(context.Background(), *configPath, &cfg.UpstreamService, *serverName, dohHostname)
		fmt.Print(output)
		if !allOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	var logFile *os.File
	var appLogger *logger.Logger

	switch cfg.Logging.File {
	case "stdout":
		// Container-friendly: log to stdout so `podman logs` / `docker logs` and
		// log aggregators capture output. No file handle to manage.
		appLogger = logger.New(cfg.Logging.Level, os.Stdout)
	case "stderr", "":
		appLogger = logger.New(cfg.Logging.Level, os.Stderr)
	default:
		logFile, err = os.OpenFile(cfg.Logging.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot open log file %s: %v\n", cfg.Logging.File, err)
			os.Exit(1)
		}
		appLogger = logger.New(cfg.Logging.Level, logFile)
	}

	appLogger.Printf("starting RCVD v%s — Resilient, Cryptographic, Verifiable DNS\n", version)

	// Announce this instance's identity unambiguously. Multiple rcvd instances can
	// run on one host, each with a different config file (and thus a different stats
	// socket). Log the ABSOLUTE config path so an admin can tell co-running instances
	// apart at a glance (cf. stubby printing its config path).
	absConfig, absErr := filepath.Abs(*configPath)
	if absErr != nil {
		absConfig = *configPath // fall back to the path as given
	}
	appLogger.Printf("RCVD instance — config: %s", absConfig)
	// Only advertise a socket path when statistics are enabled; with stats off no
	// Unix socket is ever created, so logging a path here would misrepresent reality.
	if cfg.StatsEnabled {
		appLogger.Printf("RCVD instance — socket: %s", statistics.SocketPath(*configPath))
	}

	for _, w := range cfg.Warnings() {
		appLogger.Printf("WARNING: %s", w)
	}

	// Initialize resolver (Phase 1-2: DoQ, DoT, or DoH)
	if len(cfg.Upstreams) == 0 {
		fmt.Fprintf(os.Stderr, "error: no upstreams configured\n")
		os.Exit(1)
	}

	// Require at least one upstream with an encrypted protocol (DoQ/DoT/DoH). The
	// full chain (every upstream × its enabled protocols) is built after stats init
	// below so the per-protocol resolvers get the stats pointer (Issue 23).
	hasEncrypted := false
	for _, up := range cfg.Upstreams {
		if up.DoQ || up.DoT || up.DoH {
			hasEncrypted = true
			break
		}
	}
	if !hasEncrypted {
		fmt.Fprintf(os.Stderr, "error: no encrypted upstream configured (need DoQ, DoT, or DoH)\n")
		os.Exit(1)
	}

	// Resolver is constructed after stats init (below) so the stats pointer is available.
	var resolv resolver.Resolver
	// fallbackResolver is the concrete chain (for GetStatus()/Close()); resolv is the
	// same object behind the Resolver interface. Kept separately so we can wire its
	// live per-upstream health into the stats "Connections" block.
	var fallbackResolver *resolver.FallbackResolver
	// Mode-1 server and Mode-2 service handles, declared here (before the stats goroutine)
	// so the --audit listenerInfo callback can capture them by reference and report their
	// live-bound addresses. Both are constructed further below; the callback null-checks.
	var srv *server.Server
	var upstreamSvc *upstream.Service

	// Initialize cache (mode preset already resolved in config.Validate)
	dnsCache := cache.New(cache.Options{
		Enabled:        cfg.Cache.Enabled,
		MaxSize:        cfg.Cache.MaxSize,
		TTLMin:         cfg.Cache.TTLMin,
		TTLMax:         cfg.Cache.TTLMax,
		NegTTLMax:      cfg.Cache.NegTTLMax,
		ServeStaleMaxS: cfg.Cache.ServeStaleMaxS,
	})

	// Initialize blocklist
	dnsBlocklist := blocklist.New(cfg.Blocklists.Enabled)
	if cfg.Blocklists.Enabled {
		fileCount := len(cfg.Blocklists.Files) + len(cfg.Blocklists.UpdateURLs)
		if fileCount > 0 {
			appLogger.Printf("blocklist: loading %d source(s) in background — queries resolve normally during load", fileCount)
		}
	}

	// Initialize DNSSEC validator
	dnsValidator := dnssec.New(cfg.DNSSEC.Enabled, cfg.DNSSEC.ValidateAll)
	if cfg.DNSSEC.Enabled {
		// Root KSK trust anchors: operator-supplied root_key_file if set (lets a
		// distro point rcvd at the system anchor it already updates), otherwise the
		// embedded IANA root-anchors.xml.
		var anchors []dnssec.TrustAnchor
		if cfg.DNSSEC.RootKeyFile != "" {
			anchors, err = dnssec.LoadTrustAnchorsFromFile(cfg.DNSSEC.RootKeyFile)
			if err != nil {
				appLogger.Printf("warning: could not load root trust anchors from %s: %v", cfg.DNSSEC.RootKeyFile, err)
			} else {
				appLogger.Printf("DNSSEC: loaded %d root trust anchor(s) from %s", len(anchors), cfg.DNSSEC.RootKeyFile)
			}
		} else {
			anchors, err = dnssec.DefaultTrustAnchors()
			if err != nil {
				appLogger.Printf("warning: could not load embedded root trust anchors: %v", err)
			} else {
				appLogger.Printf("DNSSEC: loaded %d embedded root trust anchor(s)", len(anchors))
			}
		}
		if len(anchors) > 0 {
			dnsValidator.SetTrustAnchors(anchors)
		}
		appLogger.Printf("DNSSEC validation enabled (validate_all=%v)", cfg.DNSSEC.ValidateAll)
	}

	// Initialize statistics (if enabled)
	var stats *statistics.Stats
	var statsCancel context.CancelFunc
	if cfg.StatsEnabled {
		stats = statistics.New()
		appLogger.Println("statistics enabled")

		// Start stats socket listener
		statsCtx, cancel := context.WithCancel(context.Background())
		statsCancel = cancel
		socketPath := statistics.SocketPath(*configPath)
		// Static per-instance metadata for the stats header (config/socket/modes).
		instInfo := statistics.InstanceInfo{
			ConfigPath:    absConfig,
			SocketPath:    socketPath,
			Mode1Enabled:  cfg.Resolver.Enabled,
			Mode2Enabled:  cfg.UpstreamService.Enabled,
			DNSSECEnabled: cfg.DNSSEC.Enabled,
		}
		// Cache posture for the stats "Cache → Mode:" line. Mode name from config; the
		// capability flags from the live cache so the descriptor matches actual behavior.
		// An empty mode (no [cache] mode set, but caching on) reports as "standard" since
		// config applies the standard baseline in that case.
		if cfg.Cache.Enabled {
			mode := cfg.Cache.Type
			if mode == "" {
				mode = "standard"
			}
			instInfo.CacheType = mode
			instInfo.CacheNegCache = dnsCache.NegativeCachingEnabled()
			if dnsCache.ServeStaleEnabled() {
				instInfo.CacheServeStaleS = cfg.Cache.ServeStaleMaxS
			}
		}
		// Static (configured) posture facts for --audit; see audit-command-design.md.
		// Derived once from cfg + the design invariants — no runtime tracking — and frozen,
		// exactly like instInfo. The LIVE facts (bound listeners, cache occupancy, upstream
		// health) are gathered per-request in the AUDIT socket handler, not here. The loopback
		// verdict on the Mode-1 listener is computed here (config address family).
		auditInfo := statistics.AuditInfo{
			ConfigPath:     absConfig,
			SocketPath:     socketPath,
			Mode1Enabled:   cfg.Resolver.Enabled,
			Mode1Listen:    cfg.Resolver.Listen,
			Mode2Enabled:   cfg.UpstreamService.Enabled,
			Mode2ListenDoH: cfg.UpstreamService.ListenDoH,
			Mode2DoH3:      cfg.UpstreamService.DoH3,
			Mode2ListenDoT: cfg.UpstreamService.ListenDoT,
			Mode2ListenDoQ: cfg.UpstreamService.ListenDoQ,
			CacheEnabled:   cfg.Cache.Enabled,
			CacheType:      cfg.Cache.Type,
			CacheNegCache:  dnsCache.NegativeCachingEnabled(),
			CacheNegTTLMax: cfg.Cache.NegTTLMax,
		}
		if dnsCache.ServeStaleEnabled() {
			auditInfo.CacheStaleS = cfg.Cache.ServeStaleMaxS
		}
		if host, _, err := net.SplitHostPort(cfg.Resolver.Listen); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				auditInfo.Mode1Loopback = ip.IsLoopback()
			}
		}
		go func() {
			cacheInfo := func() (int, int) {
				return dnsCache.Size(), cfg.Cache.MaxSize
			}
			// statusInfo adapts the fallback chain's live health into the dependency-free
			// shape the stats render expects. Captures fallbackResolver by reference — it
			// is constructed just below, well before any stats request can arrive. Returns
			// nil until then (render shows the placeholder), and nil for a non-chain path.
			statusInfo := func() []statistics.UpstreamConnInfo {
				if fallbackResolver == nil {
					return nil
				}
				return upstreamConnInfo(fallbackResolver)
			}
			// listenerInfo reports the daemon's actually-bound listener addresses for the
			// live portion of --audit. Captures srv/upstreamSvc by reference (both built
			// below); returns empty fields until they exist. No self-dialing.
			listenerInfo := func() statistics.ListenerLive {
				var l statistics.ListenerLive
				if srv != nil {
					if a := srv.UDPAddr(); a != nil {
						l.Mode1UDP = a.String()
					}
					if a := srv.TCPAddr(); a != nil {
						l.Mode1TCP = a.String()
					}
				}
				if upstreamSvc != nil {
					l.Mode2DoH, l.Mode2DoT, l.Mode2DoQ = upstreamSvc.BoundAddrs()
				}
				return l
			}
			// reloadInfo backs --blocklist-reload: it rebuilds the blocklist from
			// cfg.Blocklists.Files (add and remove) and atomically swaps it in. It is
			// fire-and-forget — the (possibly minute-long) rescan runs in its own
			// goroutine so the DNS path is never blocked, mirroring the async startup
			// load. nil when blocklists are disabled, so the socket reports it as
			// unavailable rather than silently succeeding.
			var reloadInfo statistics.ReloadFunc
			if cfg.Blocklists.Enabled {
				files := cfg.Blocklists.Files
				reloadInfo = func() int {
					go func() {
						res, _ := dnsBlocklist.ReplaceFromFiles(files)
						stats.SetBlocklistFiles(res.FilesOK)
						appLogger.Printf("blocklist: reloaded — %d domains, %d wildcards, %d/%d file(s) OK, %d line(s) skipped",
							res.Domains, res.Wildcards, res.FilesOK, res.FilesOK+res.FilesErr, res.Skipped)
					}()
					return len(files)
				}
			}
			if err := statistics.ListenAndServe(statsCtx, socketPath, stats, version, cacheInfo, statusInfo, listenerInfo, instInfo, auditInfo, reloadInfo); err != nil {
				appLogger.Printf("stats socket error: %v", err)
			}
		}()
		appLogger.Printf("stats socket: %s", socketPath)
	}

	// Build the FULL fallback chain (after stats init so per-protocol counters are
	// wired in). One UpstreamState per (upstream × enabled protocol), DoQ→DoT→DoH
	// within an upstream, upstreams in config order. A single-upstream/single-protocol
	// config yields a one-entry chain — functionally identical to the old single
	// resolver, but now running through the health state machine so multi-upstream
	// failover actually works and per-upstream health is observable (Issue 23).
	chain, err := buildUpstreamChain(cfg.Upstreams, stats, appLogger)
	if err != nil {
		appLogger.Printf("error: building upstream chain: %v", err)
		os.Exit(1)
	}
	fallbackResolver = resolver.NewFallbackResolver(
		chain, appLogger.Logger, stats,
		cfg.Fallback.Phase1DurationS,
		cfg.Fallback.Phase2FailureThreshold,
		cfg.Fallback.HealthCheckIntervalS,
	)
	fallbackResolver.Start()
	resolv = fallbackResolver
	appLogger.Printf("upstream chain: %d resolver(s) across %d upstream(s) — fallback + health checks active",
		len(chain), len(cfg.Upstreams))

	// Wire the encrypted resolver into the DNSSEC validator so it can FETCH DNSKEY/DS RRsets
	// to build the chain of trust for ordinary answers (whose signing key is not in-message).
	// Reuses this same DoQ->DoT->DoH chain — no cleartext, no new egress path. Only relevant
	// when DNSSEC is enabled; harmless otherwise.
	if cfg.DNSSEC.Enabled {
		dnsValidator.SetResolver(resolv)
	}

	// Require at least one mode to be enabled, else there is nothing to run.
	if !cfg.Resolver.Enabled && !cfg.UpstreamService.Enabled {
		appLogger.Println("error: no mode enabled — set resolver.enabled and/or upstream_service.enabled")
		os.Exit(1)
	}

	// Initialize and start Mode 1 (Resolver) ONLY if enabled. A Mode-2-only
	// deployment (e.g. DoH/DoT/DoQ upstream service behind a tunnel) legitimately
	// disables the resolver — in that case skip straight to the upstream service.
	if cfg.Resolver.Enabled {
		srv = server.NewServer(cfg, resolv, dnsCache, dnsBlocklist, dnsValidator, stats, appLogger.Logger)
		if err := srv.Start(context.Background()); err != nil {
			appLogger.Printf("error: failed to start resolver: %v", err)
			os.Exit(1)
		}
	}

	// Initialize upstream service (Mode 2: Encrypted endpoints)
	if cfg.UpstreamService.Enabled {
		var err error
		upstreamSvc, err = upstream.New(&cfg.UpstreamService, cfg, resolv, dnsCache, dnsValidator, stats, appLogger.Logger)
		if err != nil {
			appLogger.Printf("error: upstream service: %v", err)
			os.Exit(1)
		}
		// Route the DoQ listener's benign-idle server-side lines (client-closed write, idle
		// accept close) through the leveled logger so they log at debug, not unconditionally.
		upstreamSvc.SetDebugLogger(appLogger)

		// Start upstream service
		if err := upstreamSvc.Start(context.Background()); err != nil {
			appLogger.Printf("error: failed to start upstream service: %v", err)
			os.Exit(1)
		}
		appLogger.Println("upstream service started")
	}

	appLogger.Println("RCVD running")

	// Load blocklists in background — server is already accepting queries.
	// During load, IsBlocked() returns false (empty list), which is safe.
	// Each file is counted in stats as it finishes loading.
	if cfg.Blocklists.Enabled {
		go func() {
			for _, path := range cfg.Blocklists.Files {
				skipped, err := dnsBlocklist.LoadFiles([]string{path})
				if err != nil {
					appLogger.Printf("blocklist: error loading %s: %v", path, err)
					continue
				}
				if skipped > 0 {
					appLogger.Printf("blocklist: loaded %s (%d invalid line(s) skipped)", path, skipped)
				} else {
					appLogger.Printf("blocklist: loaded %s", path)
				}
				if stats != nil {
					stats.AddBlocklistFile()
				}
			}
			if len(cfg.Blocklists.UpdateURLs) > 0 {
				if skipped, err := dnsBlocklist.LoadURLs(cfg.Blocklists.UpdateURLs, 30*time.Second); err != nil {
					appLogger.Printf("blocklist: error loading URLs: %v", err)
				} else {
					appLogger.Printf("blocklist: loaded %d URL source(s) (%d invalid line(s) skipped)", len(cfg.Blocklists.UpdateURLs), skipped)
					if stats != nil {
						for range cfg.Blocklists.UpdateURLs {
							stats.AddBlocklistFile()
						}
					}
				}
			}
		}()
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	appLogger.Println("stopping RCVD")

	// Stop stats socket
	if statsCancel != nil {
		statsCancel()
	}

	// Graceful shutdown (5s timeout for in-flight queries)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Stop upstream service first (Mode 2)
	if upstreamSvc != nil {
		if err := upstreamSvc.Stop(5 * time.Second); err != nil {
			appLogger.Printf("error: upstream service shutdown: %v", err)
		}
	}

	// Stop resolver server (Mode 1) if it was started.
	if srv != nil {
		done := make(chan error)
		go func() {
			done <- srv.Stop(5 * time.Second)
		}()

		select {
		case err := <-done:
			if err != nil {
				appLogger.Printf("error: shutdown: %v", err)
			}
		case <-ctx.Done():
			appLogger.Println("error: shutdown timeout")
		}
	}

	// Stop the upstream fallback chain: halts health checks and closes all
	// per-upstream connections (DoQ/DoT/DoH).
	if fallbackResolver != nil {
		if err := fallbackResolver.Close(); err != nil {
			appLogger.Printf("error: upstream chain shutdown: %v", err)
		}
	}

	appLogger.Println("RCVD stopped")

	// Close log file if open
	if logFile != nil {
		logFile.Close()
	}
}

// buildUpstreamChain constructs the fallback chain: one UpstreamState per
// (upstream × enabled protocol), ordered DoQ → DoT → DoH within an upstream and
// upstreams in config order. Each state wraps the matching per-protocol resolver
// (with stats wired in). This is what makes multi-upstream + multi-protocol
// fallback actually run (Issue 23). Returns an error only if a resolver fails to
// construct (DoH transport setup); upstreams with no protocol flag are skipped
// (already validated that at least one encrypted upstream exists).
func buildUpstreamChain(upstreams []config.UpstreamServer, stats *statistics.Stats, appLogger *logger.Logger) ([]*resolver.UpstreamState, error) {
	var chain []*resolver.UpstreamState
	for i := range upstreams {
		up := &upstreams[i]
		dialHost := up.DialHost()
		// Display name: configured name, else host. Protocol suffix added per entry
		// so a multi-protocol upstream shows as e.g. "Quad9 (DoQ)" / "Quad9 (DoT)".
		baseName := up.Name
		if baseName == "" {
			baseName = up.Host
		}

		if up.DoQ {
			doqResolver := resolver.NewDoQResolver(up.Host, dialHost, up.Port, up.PinnedPubKey, stats)
			// Wire the retry-path logger (Issue 31): distinguishes benign idle-gap retries
			// from rare response-question mismatches in the daemon log.
			if appLogger != nil {
				doqResolver.SetLogger(appLogger)
			}
			chain = append(chain, &resolver.UpstreamState{
				Name:     baseName + " (DoQ)",
				Resolver: doqResolver,
			})
		}
		if up.DoT {
			chain = append(chain, &resolver.UpstreamState{
				Name:     baseName + " (DoT)",
				Resolver: resolver.NewTLSResolver(up.Host, dialHost, up.Port, up.PinnedPubKey, stats),
			})
		}
		if up.DoH {
			dohPath := up.DoHPath
			if dohPath == "" {
				dohPath = "/dns-query"
			}
			// up.DoH3 selects HTTP/3 over QUIC (DoH3); default is HTTP/2 over TCP.
			r, err := resolver.NewHTTPResolver(up.Host, dialHost, up.Port, dohPath, up.DoH3, up.PinnedPubKey, stats)
			if err != nil {
				return nil, fmt.Errorf("DoH resolver for %s: %w", baseName, err)
			}
			label := " (DoH)"
			if up.DoH3 {
				label = " (DoH3)"
			}
			chain = append(chain, &resolver.UpstreamState{
				Name:     baseName + label,
				Resolver: r,
			})
		}
	}
	if len(chain) == 0 {
		// Should not happen — caller validated an encrypted upstream exists — but
		// fail loud rather than start a no-upstream resolver.
		return nil, fmt.Errorf("no encrypted upstream resolvers could be built")
	}
	return chain, nil
}

// upstreamConnInfo adapts the fallback chain's GetStatus() map into the
// dependency-free []statistics.UpstreamConnInfo the stats render consumes. Order
// follows the chain (DoQ→DoT→DoH per upstream, upstreams in config order) so the
// "Connections" block reads top-to-bottom in priority order. PRIVACY: last_error
// is a transport/upstream error string and never carries a queried name.
func upstreamConnInfo(f *resolver.FallbackResolver) []statistics.UpstreamConnInfo {
	status := f.GetStatus()
	out := make([]statistics.UpstreamConnInfo, 0, len(status))
	for _, name := range f.UpstreamNames() {
		s, ok := status[name]
		if !ok {
			continue
		}
		info := statistics.UpstreamConnInfo{Name: name}
		if v, ok := s["state"].(string); ok {
			info.State = v
		}
		if v, ok := s["consecutive_errors"].(int); ok {
			info.ConsecutiveErrors = v
		}
		if v, ok := s["last_error"].(string); ok {
			info.LastError = v
		}
		out = append(out, info)
	}
	return out
}

// configHintPath picks the most helpful path to show in the unexpected-argument hint. When the
// stray positional looks like a config file (ends in .toml), the user almost certainly meant it
// AS the config, so echo it back; otherwise fall back to the active -config value.
func configHintPath(extra, configPath string) string {
	if strings.HasSuffix(extra, ".toml") {
		return extra
	}
	return configPath
}

func printHelp() {
	fmt.Print(`RCVD — Resilient, Cryptographic, Verifiable DNS

A privacy-first DNS resolver that encrypts all upstream queries.
Encrypted transports only. Port 53 is never a plaintext egress - loopback-only if used.

Usage:
  rcvd [flags]

Flags:
  -config string
    	path to config file (default "rcvd.toml")
  -stats
    	query running instance for statistics and exit
  -audit
    	query running instance for live posture audit and exit
  -blocklist-reload
    	trigger an async blocklist file reload in the running instance and exit
  -verify-upstream
    	verify upstream TLS certificates (CA-validating) and exit
  -verify-pin
    	validate each upstream's configured pinned_pubkey against the live server and exit
  -show-pin int
    	probe upstream at the given 0-based index, print its SPKI pin (sha256//…) to stdout, and exit
  -verify-self
    	verify the TLS certificate THIS instance presents on its Mode-2 listeners and exit
  -server-name string
    	TLS SNI to use for -verify-self (default: derived from the listener host)
  -version
    	show version and exit
  -help
    	show this help message

Configuration:
  RCVD is configured via TOML files. See docs/CONFIG.md for details.

Examples:
  rcvd -config rcvd-resolver.toml
  rcvd -config rcvd-upstream.toml

License:
  MIT License — see LICENSE file for details

`)
}
