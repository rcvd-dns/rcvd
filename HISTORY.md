# RCVD - Pre-Release Development History (May–July 2026)

The development record of `rcvd` through its private development phase, up to the
initial public source release.

Newest first.
Issue numbers here refer to the internal issue tracker used during private development and are kept here as historical markers.

By design, during this phase there was no per-commit git history.   
The focus was on shipping field useable, as close to production-ready as possible, statically-linked binaries 
that run live on real routing hardware carrying daily DNS traffic.

Most code changes and/or bug fixes were also tested in specific `podman` container 
test cases to pre-validate functionality before deploying live.

**Validated live in the field**, not just in a `go test`, a `go build`.  

This history log captures much, but not all of that private development effort, the design decisions, 
the bugs found in production, and how each was root-caused, fixed, tested, and re-verified live.

For changes **after** the public release, see [`CHANGELOG.md`](CHANGELOG.md),
the git history, and the tagged releases.

---

## 2026-07-31

- **PACKAGING:** Homebrew formulae added, split per-OS
  (`packaging/homebrew/macos/rcvd.rb` + `packaging/homebrew/linux/rcvd.rb`). Each
  builds `rcvd` from source (static, `-trimpath`, `-s -w`), installs the man page +
  example configs, and defines a `service {}` block (brew generates launchd on macOS
  / systemd on Linux). Per-OS DoQ sysctl caveats are documented (macOS
  `net.inet.udp.*` vs Linux `net.core.*`). Both proven green (build + audit) on a
  real Intel Mac (Mach-O x86_64) and Linuxbrew (ELF x86-64); the `url`/`sha256` are
  release-time placeholders.
- **PACKAGING:** the launchd Intel plist
  (`packaging/launchd/com.rcvd.dns.intel64.plist`) reworked to the un-privileged
  service-user / FHS model (`/etc/rcvd`, `/var/{log,run}/rcvd`); dropped the
  site-specific config-profile noise.
- **BUILD:** added `.gitattributes` — `export-ignore` for maintainer-only paths so
  they stay tracked locally but are omitted from `git archive` release tarballs.

## 2026-07-29

- **FIX (Issue 31):** DoQ client resilience — absorb the intermittent
  stale-connection blips on the encrypted LAN leg that produced same-second bursts of
  SERVFAIL and a ~26s max-latency outlier. An 8-day field-log analysis showed ~85% of
  leg-drops happened plugged-in (not suspend/wake), each a fast, self-recovering
  SLOW→DOWN→UP that the client was turning into hard failures. Changes, all in
  `internal/resolver/doq.go` unless noted:
  - **Exchange-level retry-once:** refactored `Resolve` into `exchangeOnce()`; any
    stream-scoped failure (read length/msg, unpack, or response-question mismatch) now
    recycles the exact conn and re-asks once on a fresh connection. Bounded to one
    retry so a genuinely down leg still fails fast.
  - **Stream deadline on every exchange** (`streamExchangeTimeout=2s`): QUIC stream
    reads now honor the stream deadline, not the context — without it, a read on a
    silently-dead pooled conn blocked to the 30s idle timeout (the outlier). Now it
    trips in ~2s with budget left for the retry; the caller ctx deadline wins when
    sooner.
  - `openStream()` caps `OpenStreamSync` at 2s, and the dial gains
    `HandshakeIdleTimeout=5s`, so a silently-vanished or truly-down peer is detected
    fast instead of hanging to the idle timeout. The idle-reuse margin widened to 10s
    clear of the 30s peer timeout to avoid reusing a half-closed conn.
  - Opt-in retry-path logging distinguishes a benign idle-gap read failure from a rare
    response-question mismatch (the latter would flag residual cross-wiring); kept off
    `--stats`. `internal/resolver/fallback.go`: the Phase-2 SLOW/DOWN log lines now
    include the underlying error, which was previously swallowed on exactly the path
    the router leg travels.
  - **Tests:** `internal/upstream/doq_retry_test.go` proves a query on a stale pooled
    conn is transparently retried (2.9s, was a 30s hang) and logs the stale-conn
    classification, not a mismatch. The existing 1280-query concurrency correlation
    test still passes under `-race`.
- **FEATURE:** blocklist hot-reload via `rcvd -blocklist-reload`. Edit the
  `[blocklists] files` on disk, then run the command to reload them into the running
  process with no restart — so statistics, cache, connections, and uptime are all
  preserved (a restart resets them by design). Motivation: temporary blocks (block a
  domain for a few hours, then remove it) on a long-lived resolver without discarding
  accumulated cache and field stats.
  - `internal/blocklist/blocklist.go`: split the file scanner out of `parseFile` into
    `scanInto()` so the add-only startup merge and the new replace path share one
    scanner/validator. Added `ReplaceFromFiles(paths)` — rebuilds the entire set into
    fresh maps with no lock held for the whole (possibly minute-long) scan, then takes
    the write lock only for an atomic pointer swap. This gives
    subtract-as-well-as-add semantics (the disk files become the exact live set),
    which the merge-only startup path cannot express. Missing files are skipped
    (counted, not fatal) so a vanished file never wipes the live set.
  - `internal/statistics/socket.go`: a new `RELOAD-BLOCKLIST` verb on the existing
    stats Unix socket (same auth as `-stats`/`-audit`; no protocol bump, backward
    compatible). Fire-and-forget: the verb kicks off the async reload and acknowledges
    immediately with the file count, so the CLI never blocks on the scan and DNS is
    never paused.
  - `cmd/rcvd/main.go`: the `-blocklist-reload` flag (client path, like `-stats`); the
    server-side reload closure runs `ReplaceFromFiles` in its own goroutine, updates
    stats, and logs the final counts. Scope: local files only; `update_urls` are not
    re-fetched (instant, cannot hang on the network).
  - **TESTS:** `internal/blocklist/reload_test.go` (add+subtract, missing-file-skipped,
    malformed-skipped, concurrent-reads-under-swap with `-race`); the statistics reload
    verb + unavailable cases; and the `cmd/rcvd` help/manpage drift guards extended to
    `-blocklist-reload`. Docs: `man/rcvd.1(.md)`, `CONFIG.md`. `go test ./...` green;
    `-race` green on blocklist + statistics.

## 2026-07-22

- **HARDENING (Issue 26):** narrowed the base ALPN of the non-on-demand certmagic
  TLS config (`getStaticTLSConfig` in `internal/rcvd_tls/automation.go`) from
  `["h2", "http/1.1", "doq"]` to exactly `["h2"]`. That config is only a BASE
  default — every Mode-2 listener overrides `NextProtos` for its own transport (DoQ
  clones + pins `["doq"]` per RFC 9250 §4.1; DoH TCP pins `["h2"]` and hard-rejects
  non-h2; DoH3/QUIC gets `"h3"` from quic-go) — so the `http/1.1` and `doq` tokens in
  the base were dead weight AND a latent downgrade surface: any future path that
  served this config unmodified could silently expose HTTP/1.1 (rcvd serves DoH
  strictly over h2/h3, Issue 26) or advertise a bogus transport. Now the base cannot
  leak either. The doc comment was expanded to record why the per-listener override
  contract holds.
  - **TEST** (`internal/rcvd_tls/automation_test.go`): renamed
    `TestGetTLSConfigPreloadedALPN` → `TestGetTLSConfigBaseALPN` and flipped it from
    asserting the old three-token set to asserting the base is exactly `["h2"]`, with
    an explicit regression guard that `http/1.1` is NEVER present.
  - `go test ./...` green. No functional change to the live listeners (they already
    override `NextProtos`); this closes the base-config downgrade surface.

## 2026-07-20

- **FIX (`--verify-self`):** the server-side `--verify-self` now prints the leaf SPKI
  pin (`sha256//BASE64`) right after the Fingerprint line, mirroring
  `--verify-upstream`. Motivation: `--verify-self` (Mode-2 server side) printed only
  the colon-hex fingerprint, while `--verify-pin`/`--show-pin` (Mode-1 client side)
  displayed the base64 SPKI pin — an operator managing BOTH ends of a Mode-1 ↔ Mode-2
  pinned leg had two different strings for the same key and no way to eyeball-match
  them. Now the server emits the exact `sha256//…` value a client pastes into
  `[[upstreams]] pinned_pubkey` and confirms with `--verify-pin` — same form both
  sides, no conversion, no confusion. `CertInfo.SPKIPin` was already populated (`config.SPKIPin`,
  single source of truth); this just prints it. `internal/verify/self.go` (leaf
  branch of `formatSelfResults`); manpage `-verify-self` entry updated + roff
  regenerated. `go test ./...` green. Round-trip verified in the field: the server's
  `--verify-self` SPKI pin equals the client's `--verify-pin` configured pin, both OK.

## 2026-07-19

- **BUGFIX (Issue 33):** shared-cache response messages were mutated in place by
  every serve path. `cache.Get`/`GetStale` returned the STORED `*dns.Msg` pointer and
  all five hit paths (Mode-1 UDP+TCP in `internal/server/server.go`, Mode-2
  DoQ/DoT/DoH listeners in `internal/upstream/`) then mutated it (client
  transaction-ID restore + `ensureResponseEDNS` OPT rewrite) before `Pack`. `Put`
  additionally stored the caller's live pointer, which the caller keeps mutating
  AFTER caching. With ONE cache shared across Mode-1 and Mode-2, two concurrent hits
  on the same key raced on those mutations — one client's reply could be packed with
  the OTHER client's transaction ID (the stub silently discards it → intermittent,
  self-clearing timeout), and it was a data race outright (the race detector fires on
  the pre-fix code under the new concurrency test). Same symptom FAMILY as Issue 31
  (wrong-correlation under concurrent load) but a DISTINCT bug.
  - **FIX** (`internal/cache/cache.go`): copy-on-read (`Get` + `GetStale` return
    `entry.Response.Copy()`) + copy-on-write (`Put` stores `resp.Copy()`) — one
    place, covers every current and future caller. `server.go`
    `upstreamFailureResponse` dropped its now-redundant `stale.Copy()`.
  - **TESTS** (`internal/cache/cache_test.go`): private-copy guards on
    Get/Put/GetStale plus a concurrent-hit-mutation test (32 goroutines × 50 iters on
    one key, asserts per-goroutine transaction ID in the packed wire bytes; a `-race`
    regression guard). All four verified to FAIL on the pre-fix code and PASS on the fix.
- **BUGFIX:** `Close()`/`Serve()` data race in all three Mode-2 listeners
  (`DOQListener`, `DOTListener`, `DOHListener`, `internal/upstream/`). `Close` used a
  nil-out "mark as closed" pattern (`d.listener = nil` / `d.h2server = nil` /
  `d.h3server = nil`) on fields the Serve accept/server goroutines read concurrently —
  a data race, and on the DoQ accept loop a latent nil-deref if it iterated mid-Close.
  Replaced with a `sync.Once` per listener; fields are closed but never nil'd (closing
  is what unblocks Accept/Serve; the Once provides the double-close safety the
  nil-marker was for). Surfaced by running the suite under `-race` for the cache fix above.
- **TEST-HARNESS race fixes** (found by the same `-race` sweep; not production code):
  `MockResolver` capture fields were read by test goroutines while listener/server
  goroutines wrote them. `dot_test.go` callCount → `atomic.Int64`; `server_test.go`
  callCount/lastQuery → mutex + accessors. `go test -race ./...` now passes CLEAN
  across the whole module (first time the full suite is race-clean).

## 2026-07-18

- **CLEANUP (pre-public-ship):** resolved all dead/inert TOML-tagged config fields
  ("advertised config that does nothing" — a credibility footgun for a public launch).
  - **REMOVED** `quic_0rtt`. It was a dead privacy knob — referenced nowhere in the
    dial path, controlled nothing. Decision: rcvd will not enable 0-RTT early data
    (RFC 9250 §7.1 replay risk) — refused by design, not configurable. Behavior was
    already safe by construction (`internal/resolver/doq.go` dials `quic.DialAddr` + a
    1-RTT `ClientSessionCache`, never `DialEarly`), so this is a docs/config-surface
    fix, no behavior change. A stale `quic_0rtt` in a user TOML now fails loud via the
    existing unknown-key check in `config.Load`.
  - Marked **RESERVED** (honest no-op, matching the existing `Prefetch` precedent),
    each paired with its deferred parent feature: `update_interval` (SIGHUP/periodic
    blocklist reload), `phase2_slow_threshold_ms` + `phase1_timeout_ms` (fallback
    StateSLOW / phase-1 timeout not wired in), `metrics` (Prometheus endpoint deferred).
  - **GUARD TEST** (`internal/config/deadfields_test.go`): parses `config.go`'s AST,
    enumerates every `toml:`-tagged field, and FAILS if a field is referenced only at
    its declaration site (dead), OR if an allowlisted RESERVED field lost its
    `// RESERVED — …` marker comment. Both failure modes verified to have teeth.
    Composes with the 2026-07-17 flag↔help↔manpage drift tests. `go build ./...` +
    `go test ./...` green.

## 2026-07-17

- **FEATURE (SPKI-pin lifecycle verbs):** completed the three-verb split — added
  `--verify-pin` and `--show-pin` alongside the existing `--verify-upstream`.
  Motivation: `--verify-upstream` dials CA-validating
  (`InsecureSkipVerify=false`), so a pin-only self-signed leg (the encrypted LAN leg:
  client Mode-1 → pinned DoQ → router Mode-2, self-signed cert) FALSE-FAILs the
  handshake with `x509: certificate signed by unknown authority` even though live
  traffic works fine — the resolver path (`internal/resolver/pin.go`) dials
  `InsecureSkipVerify=true` + manual SPKI compare, a DIFFERENT question than the CA
  verb. Rather than make one verb branch on posture, split by posture so each dials
  the way its leg actually runs:
  - `--verify-upstream` (unchanged verdict) — CA-only, "valid Web-PKI/private-CA cert
    for this name?" Now prints a hint on the FAILED line when the failing upstream has
    `pinned_pubkey` set (points to `--verify-pin`) so a pin-only leg's expected CA
    failure isn't read as a broken live path.
  - `--verify-pin` (NEW) — AUDIT verb. For every upstream with `pinned_pubkey`, dials
    like `resolver/pin.go` (`InsecureSkipVerify=true`, no `VerifyHostname` — the pin is
    the trust root), computes the leaf SPKI pin, constant-time compares to the
    configured pin → OK / MISMATCH. Unpinned upstreams skipped. Exit 0 iff every
    pinned upstream matches — cron/monitoring-friendly, catches a silent far-end key
    rotation. `internal/verify/pin.go`.
  - `--show-pin <index>` (NEW) — BOOTSTRAP verb. Probes ONE upstream (0-based index)
    with CA validation off, prints JUST its leaf SPKI pin (`sha256//…`) to STDOUT
    (banner/diagnostics to STDERR) so `pin=$(rcvd -show-pin 0 -config …)` captures
    exactly the value to paste into `pinned_pubkey`. `internal/verify/showpin.go`.
  Lifecycle: `--show-pin` (generate) → `pinned_pubkey` (configure) → `--verify-pin`
  (audit). Tests: `internal/verify/showpin_test.go` + `cmd/rcvd/main_test.go`
  (guard flag↔help↔manpage drift). Manpage updated + roff regenerated.
- **FIX (Issue 32):** the DoH CLIENT now speaks HTTP/2 to h2-only upstreams (was
  silently HTTP/1.1). Go's `http.Transport` only auto-negotiates h2 when it dials the
  TLS connection itself; rcvd's classic-DoH client sets a custom `DialContext` (to
  reach the pinned upstream IP while keeping SNI = hostname), which DISABLES the
  stdlib's implicit h2 wiring — so the transport spoke HTTP/1.1. Against an h2-only
  DoH endpoint (Mullvad, Quad9 — no `http/1.1` in ALPN) every request failed 100%:
  the server's HTTP/2 SETTINGS frame parsed as a malformed HTTP/1 status line,
  surfacing as `DoH server error: HTTP 505`. FIX in `internal/resolver/doh.go`
  (non-DoH3 branch): `NextProtos=["h2"]` (advertise ONLY h2 — a mismatch fails the
  handshake instead of silently downgrading), `ForceAttemptHTTP2:true`, and
  `http2.ConfigureTransport(transport)` to install Go's h2 handler despite the custom
  dial. Regression guard: `internal/resolver/doh_h2_test.go`. This was the true cause
  of the long-running "Quad9 blocks my public IP" misattribution — the HTTP 505 was
  rcvd's own client, not the upstream.
- **FIX (Issue 31):** DoQ CLIENT response correlation under concurrent load. The
  Mode-1 DoQ resolver shares one `*quic.Conn` pool across all in-flight queries; any
  query's error path called an unconditional `closeConnection()`, tearing down the
  connection out from under sibling queries (wrong-question replies / no-answers under
  concurrency). FIX in `internal/resolver/doq.go`: `recycleConn(bad)` only clears the
  pool when the bad conn is still the current one (connection-identity-scoped
  teardown), plus a per-query guard `doqResponseMatchesQuery` (QTYPE/QCLASS +
  case-insensitive QNAME per RFC 4343) that rejects+recycles a mismatched response
  instead of handing a foreign answer to the caller. Guards:
  `internal/resolver/doq_test.go` + `internal/upstream/doq_concurrency_test.go`
  (a 1280-query survival test against a real DoQ server).
- **DEPLOYED** both fixes to production (router + client). Post-deploy: Mullvad DoH UP,
  Upstream errors 0, Fallback events 0; `--verify-upstream` completes a full
  TLS 1.3 h2 DoH handshake.

## 2026-07-16

- **SECURITY (remote-attack-surface audit):** findings H1, M3, M1, M5 fixed together.
  1. **H1** — an upstream response is now MATCHED to the query before it is served or
     cached (was: never checked). An upstream (buggy/hostile/compromised) that answered
     a DIFFERENT question than asked had its answer re-keyed onto the client's question
     AND stored in the SHARED cache under the asked name — poisoning it for every
     Mode-1 + Mode-2 client. FIX in `internal/resolver/fallback.go` (the single choke
     point all five ingress paths AND the DNSSEC `chain.go` key fetches funnel
     through): new `responseMatchesQuery()` — exactly one Question on each side, equal
     QTYPE/QCLASS, QNAME equal case-insensitively (RFC 4343). A mismatch is treated as
     an UPSTREAM FAILURE so the chain FALLS OVER to the next upstream; all-mismatched →
     existing fail-closed SERVFAIL/serve-stale path. Defense-in-depth: `cache.go`
     `Put()` independently refuses to store a response whose Question disagrees with
     the storage key.
  2. **M3** — queries without exactly ONE question are REJECTED with FORMERR at
     ingress, never forwarded. Blocklist + cache key only consult `Question[0]`, so a
     blocked name in `Question[1]` bypassed the filter, and a 0-question message was
     forwarded upstream as-is. FIX: `QDCOUNT != 1` → FORMERR on all five listeners.
     The fallback resolver carries the same guard as a BACKSTOP, placed BEFORE the
     upstream loop so a client spamming degenerate queries cannot mark a healthy
     upstream DOWN (the guard would otherwise be a DoS lever).
  3. **M1** — the Mode-1 TCP path now uses `io.ReadFull` for the 2-byte length prefix
     AND the message body (was: bare `conn.Read`, which can short-read and mis-size the
     body → misparse; mild slowloris angle). Matches the Mode-2 DoT/DoQ readers.
  4. **M5** — the DoT and DoH UPSTREAM CLIENT legs raised to MinVersion TLS 1.3 (was
     1.2), matching the DoQ leg. Uniform 1.3 downgrade-resistance and preserves the
     Go-default X25519MLKEM768 hybrid post-quantum key exchange (a 1.3-only mechanism;
     rcvd's harvest-now-decrypt-later defense) which a forced-1.2 MITM could otherwise
     strip. This is the egress side only — the browser-facing Mode-2 TLS configs are
     UNCHANGED.
- **TEST:** `fallback_test.go` — mismatched answer fails over + lying primary marked
  DOWN; case-different QNAME echo accepted; `QDCOUNT != 1` never dials upstream and
  never damages upstream health state. `cache_test.go` — mismatched-Question store
  rejected. `server_test.go` — end-to-end FORMERR over UDP + TCP. Full suite + `go vet`
  green; new tests pass under `-race`.
- **UX (`--verify-upstream`):** the `SPKI pin:` line is now printed ONLY for an
  upstream that actually has a `pinned_pubkey` configured (was: computed from the
  presented leaf and printed for every upstream, misleadingly implying key-pinning was
  in force when it was not). Each upstream header now also leads with its 0-based
  INDEX (`Upstream 0: AdGuard DoQ [DoQ] …`), matching `[[upstreams]]` order.

## 2026-07-15

- **CODE (DNSSEC, Issue 30 — three related correctness fixes):** the chain-of-trust
  validator was asserting AUTHENTICATION (the AD bit) on answers it had NOT actually
  authenticated, and was failing CLOSED (SERVFAIL) on zones a correct validator must
  treat as insecure. Three distinct root causes, all in `internal/dnssec/`:
  1. **Partially-signed / mixed CNAME chains** (the original Issue 30). A signed CNAME
     head in a secure zone whose tail crosses into an UNSIGNED zone validated the head,
     but the unsigned tail RRsets carry NO RRSIG, so nothing flagged them — validation
     returned nil and the caller stamped AD on a partly-unauthenticated answer. FIX
     (`validator.go`): track per-RRset coverage during the verify loop, then a
     post-loop COVERAGE CHECK — every DATA RRset in the answer must have been
     authenticated; any answer RRset with no verifying signature makes the whole
     response INSECURE (served WITHOUT AD, never SERVFAIL). DNSKEY/DS RRsets are
     excluded (verification material, not gated answer data).
  2. **Unsigned answers were AD-stamped** (surfaced by a signed zone under a parent
     that publishes no DS, so the answer arrives with ZERO RRSIGs). The no-RRSIG branch
     returned nil in permissive mode, and nil means "validated" to the caller (RFC 4035
     §4.3: unsigned = Insecure = no AD). FIX (`validator.go`): no-RRSIG +
     `validate_all=false` now returns the insecure signal (served, AD cleared) instead
     of nil; `validate_all=true` still treats missing signatures as bogus.
  3. **DIVERGENCE FROM `miekg/dns` for unprocessable keys/algorithms.** `miekg`'s
     `RRSIG.Verify` returns `dns.ErrKey` / `dns.ErrAlg` when it cannot even LOAD the
     signing key or run the algorithm (as opposed to running the crypto and getting a
     wrong answer). The live trigger is a legacy RSASHA1 (alg 5) DNSKEY whose modulus
     carries a leading zero byte, which `miekg`'s guard rejects, so the signature is
     never tested and the zone SERVFAILed — while the rest of the internet resolves it.
     Per RFC 4035 §5.2 / RFC 6840 §5.2 a validator that cannot process the algorithm/key
     MUST treat the data as INSECURE, not bogus. FIX: new `unprocessableKey()`
     classifier (`nsec3.go`) maps those errors → INSECURE at all four verify sites;
     `dns.ErrSig` stays BOGUS. Each site carries an explicit "DIVERGENCE FROM miekg/dns"
     code comment (rcvd is a production resolver, not the library).
  Net field behavior (confirmed on the router): `example.com` → validated + AD;
  unsigned answers → served, Unsigned counter, no AD; `dnssec-failed.org` → still
  SERVFAIL (bogus).
- **TEST (Issue 30):** `internal/dnssec/miekg_divergence_test.go` (new) pins the
  `unprocessableKey` sentinel classification and includes a probe proving `miekg`
  really returns `dns.ErrKey` on an unloadable short RSA key (flags a future `miekg`
  behavior change). `chain_test.go` gains a mixed CNAME → insecure fixture;
  `validator_test.go` + `server_test.go` updated to assert unsigned answers are
  INSECURE, not nil. The container gate `insecure-delegation-test` extended with AD-bit
  assertions (insecure⇒ad=0, mixed⇒ad=0, secure⇒ad=1) — all PASS. Full suite + `go vet`
  green; all five pre-router-ship container gates PASS.
- **DEPLOY:** router only (the DNSSEC validating leg); the client leg runs `[dnssec]`
  off by choice, so it was intentionally not shipped this round.

## 2026-07-13

- **CODE:** Issue 29 — stop the Mode-2 DoQ accept loop from spinning a whole CPU
  core when a WARM persistent QUIC connection is lost ungracefully (the peer
  suspends or vanishes — a laptop sleeping, a network sever). ROOT CAUSE
  (`internal/upstream/doq.go`, `handleConnection`): when the peer disappears,
  quic-go's own 30s idle timer eventually fires and `AcceptStream` then returns a
  terminal `*quic.IdleTimeoutError` on EVERY iteration, immediately, forever. That
  error reports `Timeout()==true` and Unwraps to `net.ErrClosed`, so
  `isNonCriticalNetErr`'s `net.Error` timeout check MISCLASSIFIED it as "just idle"
  → the loop `continue`d with no I/O and pegged a core.
  - FIX (1): in `handleConnection`, BEFORE the `isNonCriticalNetErr` branch, check
    `conn.Context().Err()` — quic-go cancels the connection context when the
    connection closes, so a non-nil error there means the connection is DEAD →
    return, don't continue.
  - FIX (2): harden `isNonCriticalNetErr` to explicitly exclude
    `*quic.IdleTimeoutError` and `net.ErrClosed` (terminal → return false) while
    still keeping our OWN `acceptStream` `WithTimeout` deadline
    (`context.DeadlineExceeded`) as a keep-looping signal.
  - Net effect: a dead connection makes `handleConnection` RETURN and the goroutine
    is reaped; a genuinely idle-but-live connection still loops and waits.
- **TEST:** Issue 29 — reproduced the burn in a CPU-capped container soak (a debug
  build with `net/http/pprof` behind a build tag + env gate, never shipped). The
  trigger is a WARM connection then ungraceful loss (`podman network disconnect`) —
  a graceful client exit does NOT reproduce it. The two binaries told a clear
  before/after story under an identical CPU cap:
  - Buggy binary: CPU climbs `0.1% → 3.3% → 7.9% → … → 23%+` and keeps rising;
    `handleConnection` spins forever, and a pprof goroutine dump NAMES it parked at
    the `acceptStream` call.
  - Fixed binary: CPU flat/decaying (~0.08%); `handleConnection` RETURNS at ~t+40s
    (just past the 30s idle timeout), and the goroutine count drops back as the
    connection's goroutine is reaped.

  `go vet` + full suite green.

## 2026-07-11

- **CODE (DNSSEC):** implement the chain-of-trust validator — fixes a SERVFAIL
  storm where every signed zone failed `DNSSEC: signing DNSKEY not found
  (algorithm=13, signer=…)`. ROOT CAUSE: the validator
  (`internal/dnssec/validator.go`) was a STATELESS single-message verifier — it
  only looked for the signing DNSKEY *inside the response being validated*. That
  holds for a DNSKEY query or a `+dnssec` trace, but an ordinary A/AAAA answer
  carries the RRSIG WITHOUT the signer's DNSKEY, so `findDNSKEY` returned nil and it
  hard-failed → behind a validating chain, ~every signed answer became SERVFAIL. It
  had no way to FETCH keys, no DS/DNSKEY cache, no delegation walk. FIX (new
  `internal/dnssec/chain.go`): the Validator now takes an optional
  `resolver.Resolver` (`SetResolver`) and, when a signing key is not co-resident,
  FETCHES the signer's DNSKEY RRset, verifies it against the parent's DS, walks
  `.` → tld → zone, and anchors at the configured root KSK (reusing
  `VerifyKeyAgainstAnchors`). A tiny TTL-aware DNSKEY/DS cache (`rrsetCache`, 60s–24h
  clamp) stops a per-query fetch storm; the walk is depth-bounded (24) and each
  fetch carries a 5s deadline (whole walk ≤15s). All key/DS fetches reuse the SAME
  encrypted DoQ→DoT→DoH chain — no cleartext, no new egress path (zero-cleartext
  invariant preserved). The import edge `dnssec`→`resolver` is one-way/cycle-free.
  Wired in `cmd/rcvd/main.go` (`SetResolver` after the fallback chain is built, only
  when `[dnssec]` enabled). Legacy fast path unchanged: a nil resolver keeps the old
  single-message behavior (co-resident key still works; missing key still a hard
  error). TESTS (`internal/dnssec/chain_test.go`, OFFLINE, real ECDSA P-256/algo-13):
  a synthetic 2-level signed hierarchy (root→example) proves (a) an ordinary A answer
  validates end-to-end via fetched keys with a second-call cache hit, (b) a tampered
  DS fails BOGUS (no silent pass), (c) no-resolver preserves the legacy hard error.
  Plus an OPT-IN live test (`RCVD_DNSSEC_LIVE=1`): real DoQ to AdGuard, asserts
  `nlnetlabs.nl`/`nextdns.io` VALID and `dnssec-failed.org` BOGUS — SKIPPED in the
  normal suite so `go test ./...` stays hermetic. Full suite (10 pkgs) + `go vet`
  green.
- **CODE (Mode-2 DoQ):** fix missing `doq` ALPN on the DoQ server listener — the
  encrypted-LAN-leg DoQ endpoint was un-connectable. RFC 9250 §4.1 requires the
  `doq` ALPN token; `NewDOQListener` (`internal/upstream/doq.go`) passed the SHARED
  `tls.Config` straight to `quic.Listen`, but that config is shared with the DoT/DoH
  listeners and sets NO `NextProtos`, so the QUIC server advertised no ALPN and
  EVERY client handshake aborted with `tls: server did not select an ALPN protocol`
  (CRYPTO_ERROR 0x178). Fix: clone the config inside `NewDOQListener` and pin
  `NextProtos=["doq"]` locally (does not mutate the shared config DoT/DoH use). WHY
  IT SHIPPED: the DoQ tests only covered packing/serialization — no test ever
  completed a real handshake against the listener. Added `TestDOQListenerRoundTripALPN`
  (`internal/upstream/doq_test.go`): a real QUIC dial + length-prefixed query
  round-trip; PROVEN to fail with the exact production error without the fix and pass
  with it. Full suite (10 pkgs) + `go vet` green.
- **TEST (container):** FIELD-PROVEN the chain validator AND the DoQ-ALPN fix
  together in a two-container LAN harness (`tests/containers/pinned-pubkey-lan-test`).
  Converted that suite's encrypted LAN leg DoT→DoQ and turned `[dnssec]` ON on the
  router. All assertions PASS: (1) DoQ + correct pin → NOERROR (self-signed peer,
  zero CA trust — proves the DoQ listener now advertises the `doq` ALPN), (2) wrong
  pin → SERVFAIL (fail-closed), (3) DO-bit query → NOERROR + EDNS0 DO (Issue 28), (4)
  `nlnetlabs.nl +dnssec` → NOERROR + AD (the chain-of-trust walk fetched DNSKEY/DS
  and validated to the root anchor), and (5) `dnssec-failed.org +dnssec` → SERVFAIL
  (BOGUS zone fails closed). Ran in a CONTAINER, not on the dev host. Suite
  self-cleans.
- **TEST (container):** added a DoT sibling of the above — a full DoT variant of the
  pinned-pubkey LAN harness (`tests/containers/pinned-pubkey-lan-dot-test`), mirroring
  the DoQ suite's 5 assertions but over DoT (RFC 7858, TLS 1.3-over-TCP). Two flavors
  were exercised, both GREEN: (a) MIXED — client→router DoT-pinned, router→AdGuard
  DoQ; and (b) DoT END-TO-END — the router's Mode-1 outbound leg also flipped to DoT,
  so no QUIC anywhere in the path. Both ran 3× back-to-back = 3/3 pass, 15/15
  assertions, ZERO flakiness. Notably, the wrong-pin case is rejected AT the DoT TLS
  handshake (`pin: peer public key does not match pinned_pubkey`), not a dial timeout
  — so the zero-cleartext invariant holds on the DoT path. Transport genuineness
  re-verified from configs + the router's `DoT endpoint listening` log line (no DoQ
  listener present) so the pass can't be a hidden-QUIC false green. Self-cleans; the
  original DoQ suite still passes unchanged (regression-guarded).

## 2026-07-10

- **CODE (pin):** unify the SPKI pin format into ONE source of truth + surface it in
  `--verify-upstream`. Previously the `sha256//BASE64` parse/validate logic was
  hand-copied in TWO places — config's `validatePinnedPubKey` (startup check) and
  resolver's `parsePin` (live handshake gate) — nearly identical and free to drift.
  Fix: new `internal/config/pin.go` owns `ParsePin` + `SPKIPin` (moved from
  resolver's `spkiPinSHA256`). config lives below everything (imports no internal pkg
  → no cycle) and verify already imports it. `validatePinnedPubKey` now delegates to
  `ParsePin`; `resolver/pin.go` calls `config.ParsePin`. Also: `--verify-upstream`
  now prints a ready-to-paste `SPKI pin: sha256//…` for each LEAF cert (next to the
  existing Fingerprint), closing the provisioning loop — you can now READ a pin off
  an upstream and paste it straight into a client's `pinned_pubkey`. Verified against
  Cloudflare DoT (leaf pin renders; intermediates correctly get none). Full suite +
  `go vet` green.
- **CODE (stats):** the Mode-2 "Avg response" line was mislabeled AND mis-scoped — it
  displayed the Mode-1 UPSTREAM-FETCH latency (`RecordLatency`, timing the WAN leg)
  under a "client-facing" header. That read a blended cache-miss WAN round trip,
  which is NOT what a pinned LAN client experiences (sub-ms LAN + cache hits). Fix:
  add a SEPARATE Mode-2 client-facing timer (`RecordMode2Latency`) that measures
  request-parsed → response-sent at the listener itself, instrumented in all three
  Mode-2 handlers (`dot.go`, `doq.go`, `doh.go`). The Mode-1 line is RELABELED
  "Upstream fetch:" (cache-miss fetch to upstream; excludes hits); the Mode-2 line
  reads the new timer (request-in → response-out; hits ~0, misses include upstream).
  The two timers are independent. Tests: `TestRecordMode2Latency` +
  `TestLatencyTimersAreIndependent` (asserts the Mode-1 and Mode-2 numbers never
  cross). Full suite + `go vet` green.
- **CODE:** Issue 28 — fix EDNS0/DO handling so a validating stub resolver
  (systemd-resolved) no longer downgrades + stalls ~5s/lookup on the encrypted-LAN
  leg. Two distinct bugs, both fixed, identical behavior in Mode 1 and Mode 2:
  - (1) `rcvd` DROPPED EDNS/DO from replies — answers and synthesized
    NXDOMAIN/SERVFAIL went back with no OPT and DO=0 (plus a nonstandard udp:0
    bufsize). A DO=1 prober read that as "not DNSSEC-capable" and downgraded. Fix:
    `ensureResponseEDNS()` puts a single OPT with DO mirroring the client's request +
    udp:1232 (DNS-flag-day, RFC 6891) on EVERY send point (resolve reply, blocklist
    NXDOMAIN, cache hit).
  - (2) Forcing DO upstream produced a MALFORMED double-OPT query → upstream FORMERR.
    `dns.SetEdns0` APPENDS an OPT (does not replace); a `+dnssec`/resolved query
    already carries one, so two OPTs shipped (RFC 6891 §6.1.1 violation). Fix:
    `stripOPT()` before `SetEdns0` in `queryWithDO()`.
  - `rcvd` validates DNSSEC itself, so it now always requests records upstream (DO=1)
    regardless of the client, giving the validator real RRSIGs. Cache Get/Put still
    key off the ORIGINAL query (DO-sensitive key preserved). Tests:
    `TestServerDOBitEDNSHandling` (real UDP socket) + the pinned-pubkey LAN container
    assertion over a real DoT chain — the gate that caught the double-OPT FORMERR;
    mock-resolver unit tests could not. Full suite + `go vet` green.

## 2026-07-08

- **CODE:** `pinned_pubkey` is now LIVE — SPKI public-key pinning for upstream TLS
  (was a dead config stub, declared but referenced nowhere — the worst failure mode
  for a security tool). Format is `sha256//BASE64` (RFC 7469 / curl `--pinnedpubkey`
  style): SHA-256 over the peer LEAF cert's DER SubjectPublicKeyInfo, so the pin binds
  to the KEY — a server may re-issue its cert (new dates/SANs) reusing the same
  keypair and the pin stays stable. New `internal/resolver/pin.go` holds
  `spkiPinSHA256` / `parsePin` / `pinnedTLSConfig`. Wired into all three client
  resolvers (`dot.go`, `doq.go`, `doh.go` — DoH covers both h2 and h3 via the shared
  tlsConf) plus the three construction sites in `cmd/rcvd/main.go`. Enables the
  LAN-tier encryption use case: an `rcvd` Mode-1 client can trust a self-signed `rcvd`
  Mode-2 peer by exact key, one config line, no OS trust-store install. RING-FENCED:
  when a pin is set, verification REPLACES CA-chain trust for THAT upstream only
  (`InsecureSkipVerify=true` — the ONLY such site in the codebase, in a single gated
  helper, heavily commented) but is defense-in-depth and fail-closed: (1) the pin is
  format-validated at CONFIG LOAD (`validatePinnedPubKey` → hard startup error on a
  malformed pin, never a silent no-op), so the skip path is unreachable without a good
  pin; (2) `VerifyConnection` still enforces `leaf.VerifyHostname` BEFORE the pin
  compare; (3) constant-time SPKI compare, error unless every check passes; (4) belt
  checks (non-empty peer chain, pin decodes to exactly 32 bytes). Empty pin = prior
  behavior byte-for-byte (normal CA validation, `InsecureSkipVerify` stays false —
  guarded by test). NOTE: pin the STABLE file-based cert (`tls_cert`/`tls_key`), NOT
  `tls_cert_autogen` (regenerates its key per boot → the pin would break). Tests:
  `internal/resolver/pin_test.go` (determinism, `parsePin` good/bad, default-path
  stays false, hermetic loopback handshakes: correct pin connects to a self-signed
  peer with NO CA trust, wrong pin fails, right-pin+wrong-hostname fails) +
  `config_test.go`. `go build`/`vet` + `go test ./...` all clean. Client-side (Mode-1
  upstream) only; independent of and does not touch `tls_automation` / DNS-01
  (server-side); the two coexist per-upstream.

## 2026-07-07

- **CODE:** `--stats` / `--audit` Uptime now breaks out DAYS as its highest unit.
  `formatDuration` (`statistics/statistics.go`) capped at hours, so a multi-day
  run rendered as e.g. `Uptime: 138h 18m 17s` instead of `5d 18h 18m 17s`. Added
  a days unit (`int(d / 24h)`, no modulo so it accumulates without a ceiling);
  hours now wrap `% 24`. Leading zero-units are still dropped (`Yh Zm Ws` / `Zm
  Ws` / `Ws`). One helper, shared by `--stats` and `--audit`, so both are fixed at
  once. This is NOT the earlier monotonic-clock / NTP-immunity uptime fix (that was
  a correctness change) — this is display-only. Days stays the highest unit
  DELIBERATELY (no years) — correct + unambiguous, matches daemon convention;
  verified safe well past a year (`400d 3h 2m 1s`, no rollover — `time.Duration`
  is int64 ns, ceiling ~292 years). `go test ./internal/statistics/` passes.

## 2026-07-01

- **BUILD:** certmagic bumped v0.25.3 → v0.25.4. Picks up: a jobManager
  goroutine-tracking leak fix (the tracked item — `rcvd`'s
  `ManageDomains`→`ManageAsync` path exercises it, so a long-lived Mode-2 +
  `tls_automation` server could have slowly leaked); a handshake fix that
  propagates the leader's load/obtain outcome to waiters in a `defer` so
  concurrent waiters don't recursively re-enter the cert-load wait queue
  (Mode-2 concurrent-handshake robustness); and preservation of DNS-provider
  record data for cleanup on the DNS-01 path. Validated: `go build`/`vet`/`test
  ./...` clean + all 4 podman gates pass (verify-self Mode-2 self-signed,
  audit-posture, cache-regression real-DoQ 0 SERVFAIL, port53-reject). Rebuilt
  amd64 + arm64. CAVEAT: picked up, NOT live-ACME-validated — the router is
  Mode-1 only (certmagic dormant in prod) and the gates exercise self-signed
  Mode-2, a different path than certmagic's ACME/on-demand management; real-ACME
  validation still gated on the DNS-01 live-flow item.
- **BUILD:** Issue 8 — quic-go bumped off a master pseudo-version to the tagged
  release **v0.60.0**. Delta = 5 commits, only 2 functional, both in paths `rcvd`
  uses: a fix for max-datagram-size estimation after MTU discovery (DoQ/DoH3
  transport) + an `http3` nil-ptr-deref fix when `Server.Logger` is unset
  (guards `rcvd`'s Mode-2 DoH3 `http3.Server`); the other 3 are OSS-Fuzz/CI. The
  `OpenStreamSync` context-cancel fix that motivated the pseudo-version is
  included. Now shipping a real tagged dependency, not a moving commit.
  Validated: `go build`/`vet`/`test ./...` clean, the DoH3 round-trip test
  (`ProtoMajor==3`) passes, and ALL FOUR podman gates pass (cache-regression
  real-DoQ 0 SERVFAIL, port53-reject, audit-posture, verify-self) — confirms
  QUIC handshake + session-resumption work against a live AdGuard DoQ upstream
  on v0.60.0.

## 2026-06-30

- **CODE:** Issue 15 — graceful shutdown always timed out (~5s). `Server.Stop()`
  called `s.wg.Wait()` BEFORE closing the listeners; the `serveUDP`/`serveTCP`
  loops park in `ReadFromUDP` (5s deadline) / `Accept` (no deadline) and can't
  see ctx cancellation while blocked — only a socket `Close()` unblocks them. So
  every restart waited out the full timeout (UDP woke on its 5s deadline → the
  consistent ~5s; TCP would block indefinitely). On a router that's a ~5s DNS
  gap per restart. This was `rcvd`, NOT packaging (OpenRC/systemd send SIGTERM
  fine).
  - `server.go` `Stop()`: reordered — close `udpConn` + `tcpList` FIRST, then
    `wg.Wait()`, then `resolver.Close()` (upstream QUIC/TLS drained last). Read
    loops already return on a Close-induced error, so no spin. Sub-millisecond
    graceful stop now.
  - Test `TestStopIsGraceful` — starts a real server, asserts `Stop()` returns in
    <1s with a 5s timeout. Verified FAILS at 5.00s on the pre-fix ordering, PASSES
    at 0.02s fixed.
- **NOTE (14):** verified in code that the Issue 14 fix (min-latency skew —
  `RecordLatency` now gated on `err==nil` at both call sites) is present. No code
  change here (already shipping in the live build).
- **NOTE (10):** verified in code that the Issue 10 fix (`ip` dial-target
  field; `host`=SNI, `dialHost`=dial across doq/dot/doh resolvers) is present and
  in production. No code change.
- **CODE:** Issue 24 — loopback-only-SAN fixed + new `tls_cert_hosts` config
  field. The self-signed (`tls_cert_autogen`) cert now carries a SAN that
  actually matches the address clients connect to — previously a LAN-facing
  Mode-2 endpoint got a localhost-only SAN that no remote client could validate.
  - `upstream.go` `autogenSANHosts()`: SAN hosts derived from the configured
    `listen_doh/dot/doq` host parts, plus operator-configured `tls_cert_hosts`,
    plus loopback (127.0.0.1 + localhost); unspecified binds (0.0.0.0 / ::)
    skipped (not meaningful in a SAN). `generateSelfSignedCert()` splits hosts
    into IP-SANs vs DNS-SANs (RFC-6125 IP-ID + DNS-ID).
  - `config.go`: NEW `UpstreamConfig` field `tls_cert_hosts []string` — extra
    hostnames/IPs for the self-signed SAN (e.g. a tunnel name, or a LAN hostname
    when clients connect by a name that isn't the bind address). Ignored unless
    `tls_cert_autogen` is set (real certs come from `tls_automation` / your own
    cert files).
  - Tests: `cert_test.go` — SAN derivation, loopback present, 0.0.0.0 skipped,
    `tls_cert_hosts` entries land in SAN, non-loopback IP SAN present +
    `VerifyHostname` passes.
- **FIX (tests):** removed a stale unused import in `doh_test.go` that was a
  BUILD ERROR — it failed compilation of the ENTIRE `internal/upstream` test
  package, so every test in it (including the Issue 24 cert-SAN regression tests above)
  had silently never run. Removing it restored the package build.
- **BUILD:** `go.mod` `go` directive 1.26.2 → 1.26.4 — raises the toolchain floor
  to the patched release. Guards against a future build on an older toolchain
  producing a binary vulnerable to a `crypto/x509` `VerifyHostname` quadratic
  blowup on huge SAN lists / a `mime` header CPU-exhaustion issue. Deployed
  binaries were already built with go1.26.4; this is a regression guardrail.
- **BUILD:** the Alpine arm64 build script now passes `-s -w` (strip), matching
  the amd64/macOS scripts. The arm64 artifact dropped ~16.7 MB → ~11.6 MB; it was
  previously the only build shipping with debug info.
- **NOTE (17):** verified in code that the Issue 17 fix (DoQ session resumption
  — persistent `tls.ClientSessionCache` in `resolver/doq.go`, session-resumption
  only / no 0-RTT) is present. No code change here. A secondary cleanup (hardcoded
  5s per-query budget → config field) remains open.

## 2026-06-27

- **CODE:** Issue 23 resolution implemented — `FallbackResolver` wired into the
  run path. Previously `main.go` built ONE resolver from the FIRST upstream only;
  multi-upstream fallback was dead code, `Fallback events` was stuck at 0, and the
  stats "Connections" block had no data source. Now:
  - `main.go` `buildUpstreamChain()`: one `UpstreamState` per (upstream × enabled
    protocol), DoQ→DoT→DoH within an upstream, upstreams in config order → a
    `FallbackResolver` over the whole chain, health checks started, closed on
    shutdown. Single-upstream config = one-entry chain (same behavior, now
    observable).
  - `resolver/fallback.go`: `Resolve` returns a real error
    (`ErrAllUpstreamsFailed`) when all upstreams fail — not the old nil-error
    SERVFAIL — so the server's fail-closed/serve-stale path is unchanged (never
    cleartext). Stats wired in → `UpstreamFallbacks` increments on post-primary
    success. Added `UpstreamNames()` for chain-ordered status.
  - statistics: new `UpstreamConnInfo` + `StatusFunc` threaded through to the
    render. The MODE-1 "Connections" block now shows live UP/SLOW/DOWN +
    consecutive errors + last error; `last_error` is a transport string — never a
    queried name (privacy invariant re-checked).
  - Tests: `fallback_test.go` (fail-over, all-fail-errors, UP→DOWN→UP, skip-DOWN,
    event counts) + a live-per-upstream-health render test. Verified live with a
    multi-upstream config: a blackholed DoQ primary failed over to DoT, Fallback
    events incremented, Connections showed DoQ DOWN + last error / DoT, DoH UP.

## 2026-06-26

- **CODE:** Issue 27 probable fix — response-bucket accounting decoupled from
  cacheability. The `--stats` QUERIES block previously left some sent responses in
  no bucket (Success+SERVFAIL+NXDOMAIN < Total) because Success/SERVFAIL
  increments lived inside cache/validate branches; the gap only surfaced over
  multi-day runs. Now exactly ONE response bucket is recorded per sent reply,
  keyed on rcode, at the send point.
  - `statistics.go`: new `OtherResponses` counter + `RecordResponse(rcode)` helper
    (NOERROR→Success, SERVFAIL→Servfail, NXDOMAIN→Nxdomain, else→Other). Render
    gained an "Other rcode" line (shown only when >0) and an "Unaccounted" line
    (shown only when buckets don't sum to Total — any residual gap is now VISIBLE,
    never silent).
  - `server.go` (Mode 1 UDP+TCP): removed scattered/cache-coupled increments;
    `RecordResponse` called once per send. `upstream/{doh,dot,doq}.go` (Mode 2):
    same — DoH buckets in `writeResponse`, DoT/DoQ at send.
  - Tests: bucket coverage + counter-conservation, including an end-to-end
    real-UDP test covering the previously-unbucketed REFUSED case.

## 2026-06-17

- **CODE:** DNS-01 ACME token now has THREE explicit, mutually-exclusive sources
  (was: inline TOML only). For production/IaC + container deploys the token no
  longer has to live in the config file. In `[tls_automation]` set EXACTLY ONE of:
  - `dns_api_token` — inline literal (unchanged; one-off deploys)
  - `dns_api_token_env` — NAME of an env var to read (`os.Getenv`; unset/empty =
    error). The launcher (podman `--env-file` / compose `env_file` / systemd
    `EnvironmentFile`) owns putting it in the environment; `rcvd` does NOT parse a
    file in this mode.
  - `dns_api_token_file` — path to a dotenv (`KEY=value`) file `rcvd` parses;
    requires `dns_api_token_key` to name the line. Relative path resolves next to
    the config file; absolute as-is. Parser skips blank/`#` lines, optional
    leading `export `, strips one quote layer; warns (stderr) if the file is
    group/other-readable.

  Setting 2+ sources = hard startup error (no precedence/fallback — "where the
  secret came from" is unambiguous by design). All three resolve into the existing
  `DNSAPIToken` field in `config.Load`, so the TLS + upstream packages are
  unchanged.
- **CODE:** `dns_provider` + `challenge` now validated at CONFIG LOAD (was: lazily
  at first cert issuance). `challenge` must be `""`/`"http"`/`"dns01"`; `dns01`
  requires a supported `dns_provider` + a resolved token; DNS-01 token keys are
  rejected (orphaned) under any non-dns01 challenge. A new shared allowlist
  `config.SupportedDNSProviders` (MVP: cloudflare) is the single source of truth —
  both the load-time check and the solver's "unsupported dns_provider" error
  reference it, so they can't drift.
- **TEST:** 14 new config cases (each token source alone, env-unset, file-missing,
  missing-key, file-without-key, key-without-file, 2-source conflict, no-token,
  unsupported/missing provider, invalid challenge, orphaned keys under http).
- **DOCS/TEST:** `docs/CONFIG.md` DNS-01 subsection (challenge + 3-source token
  table + security note); a named-tunnel container example switched to the env-var
  source (`.env.example` added; `.env` is gitignored).
- **CODE:** `root_key_file` now fully wired (was declared in config but silently
  ignored). `dnssec.LoadTrustAnchorsFromFile` reads the file and auto-detects
  format: IANA `root-anchors.xml` (DS records, same as embedded) or BIND-style
  `root.key` (DNSKEY records, converted to SHA-256 DS-equivalent). A
  missing/unreadable path fails at config load (`os.Stat` check in `Validate`),
  not silently at runtime. When unset, the embedded IANA anchor is used unchanged
  — no behavior change for existing deployments.
- **DOCS:** `docs/CONFIG.md` `[dnssec]` section rewritten to explain the
  embedded-vs-file choice, file formats, and the KSK-rollover rationale for using
  `root_key_file` in packaged/long-lived deployments. Manpage updated + re-rendered.
- **TEST:** 4 new dnssec tests (XML file round-trip, BIND `root.key` DNSKEY→DS
  conversion with the keytag verified, missing file error, empty `root.key`
  error), plus a real system-`root.key` fixture (both current IANA KSKs) exercised
  end-to-end.
- **DOCS:** `docs/CONFIG.md` `root_key_file` section gains a verified platform-path
  table — Debian/Ubuntu/Mint (`/usr/share/dns/root.key`, `dns-root-data`) and
  Alpine (`/usr/share/dnssec-root/trusted-key.key`, `dnssec-root`) confirmed live;
  FreeBSD/NetBSD/macOS paths listed as unverified.

## 2026-06-12

- **DOCS:** `rcvd(1)` manpage — first draft complete. Markdown source at
  `man/rcvd.1.md`; rendered roff at `man/rcvd.1` via `go-md2man` (pure Go, no
  pandoc/groff — the same tool Docker/Podman/containerd use). Sections: NAME,
  SYNOPSIS, DESCRIPTION (Mode-1/Mode-2 explained), OPTIONS (all flags), COMMON
  MISTAKES (the `-config` usage footgun — the immediate motivation for this page),
  EXAMPLES (8 copy-paste invocations), FILES, CONFIGURATION, EXIT STATUS, SEE
  ALSO, AUTHORS, CREDITS (quic-go, certmagic, go-md2man).
- **CODE:** FIX silent positional-arg drop on action flags. `rcvd`'s action flags
  (`--stats`, `--audit`, `--verify-upstream`, `--verify-self`) are BOOLEAN and
  take no value, and Go's `flag` stops parsing at the first non-flag token — so
  `rcvd --verify-self /etc/rcvd/rcvd.toml` SILENTLY DROPPED the path, fell back to
  the default `rcvd.toml`, and failed with a confusing `open rcvd.toml: no such
  file` that never mentioned the path the user typed (observed live on the router).
  - GUARD: `main.go` now does a `flag.NArg() > 0` check immediately after
    `flag.Parse()`. A leftover positional is a hard error (exit 2) that NAMES the
    stray arg and shows the correct form. Catches all four action flags at once.
  - HELPER `configHintPath(extra, configPath)`: makes the error message ACTIONABLE
    — when the stray positional looks like a config (ends in `.toml`), the hint
    echoes THAT exact path back as the `-config` value, turning a "huh?" into
    copy-paste-able guidance.
  - TEST: `main_test.go` — table test over `configHintPath` (.toml echoed, non-toml
    → default, non-toml → custom `-config` preserved). Verified live on the router:
    `rcvd --verify-self /etc/rcvd/rcvd.toml` now prints the clear named-arg error.
- **CODE:** NEW `--verify-self` — reports the TLS cert THIS instance presents on
  its Mode-2 listeners. The inward mirror of `--verify-upstream`: where that shows
  the cert each UPSTREAM presents to `rcvd` (outward), `--verify-self` answers
  "what am I presenting to my clients, is it valid, when does it expire, and is it
  the real CA cert or still the self-signed autogen?" — without reaching for
  `openssl s_client`.
  - APPROACH: probes THIS instance's own live DoH/DoT/DoQ listeners with a real TLS
    handshake, so it sees the cert actually served regardless of source — in-memory
    `tls_cert_autogen` self-signed, certmagic/ACME materialized on first handshake,
    or a bring-your-own file. (`internal/verify/self.go`.)
  - Two deliberate differences from the upstream probes: (1) `InsecureSkipVerify` —
    we RETRIEVE and report the cert (including a self-signed one that would
    otherwise abort the handshake), NOT trust it; `classifySelfCert()` then labels
    it SELF-SIGNED vs CA-ISSUED (with issuer CN) from the chain. (2) Correct ALPN
    per listener: DoH offers `h2` (`rcvd`'s DoH server strictly requires it and
    rejects otherwise), DoQ `doq`, DoT none.
  - Reports per endpoint: Subject/Issuer/SANs, validity + days remaining, key type,
    SHA-256 fingerprint, plus the cert-source line + expiry warning. Optional
    `-server-name` flag sets the probe SNI. Exits non-zero if any endpoint probe
    fails.
  - TEST: `self_test.go` — endpoint derivation, self-signed-vs-CA classification,
    issuer-CN parsing, and the Mode-2-disabled / no-listener guards. VERIFIED live
    in a clean throwaway podman container (Mode-2 autogen DoH + DoT): reported the
    self-signed leaf + "Cert source: SELF-SIGNED" on both listeners, ALPN `h2` on
    DoH.
  - NOTE: the live container test CAUGHT two real probe bugs before merge — a plain
    TLS dial got rejected by the strict-h2 DoH server (fixed: offer `h2`), and
    skip-verify was needed to read the self-signed cert at all (fixed). Pure-unit
    tests would not have surfaced either.
- **CODE:** NEW `--audit` — live POSTURE view for operators. Where `--stats`
  answers "what HAS happened since startup" (counters), `--audit` answers "what is
  this running `rcvd`'s posture RIGHT NOW" — the verifiable, point-in-time security
  stance, without reaching for tcpdump/nmap/ss. The operational half of "V for
  Verifiable". Pass-1 scope = posture only: LISTENERS (addr/proto/mode +
  loopback-only confirmation), NO-CLEARTEXT POSTURE (port-53 loopback enforced,
  cleartext-fallback disabled, inbound-plaintext loopback-only), CACHE POSTURE
  (mode + neg-cache/serve-stale on/off with bounds).
  - PRIVACY: same constraint as `--stats` — NO per-client IPs, NO domain names, NO
    query content. Reports what `rcvd` is configured to do / guaranteeing, never
    who is querying.
  - PLUMBING: shares the SAME Unix socket as `--stats` (not a new one). The socket
    handler reads a one-line request verb: "AUDIT" → posture, EOF/"STATS" → stats.
    A back-compat fix half-closes the write side of the legacy no-verb path so
    `--stats` stays instant.
  - TEST: `audit_test.go` — 7 tests (loopback/non-loopback Mode-1, Mode-2 TLS-only
    endpoints, aggressive-vs-standard cache posture, cache-disabled, real-socket
    verb switch). VERIFIED live in a clean throwaway podman container.

## 2026-06-11

- **CODE:** `--stats` now shows the active CACHE MODE (operator-facing). The
  QUERIES → Cache block leads with a `Mode:` line + a descriptor DERIVED from the
  live cache's real capabilities (negative caching, serve-stale window) so it
  can't drift from behavior — e.g. `aggressive (neg-cache on, serve-stale ≤1h)` vs
  `standard (positive-only, no serve-stale)`. Also surfaces `Served stale:` in the
  Cache block when it has fired. Motivation: an operator needs to see the mode next
  to the hit rate to interpret it (a 0% rate under aggressive is now obviously
  wrong).
- **CODE:** FIX DoH "HTTP/2" listener silently serving HTTP/1.1 + HARD-CLOSE h1.1
  (Issue 26). The DoH TCP listener advertised "HTTP/2 over TCP" but used a
  `tls.Config` with EMPTY `NextProtos` served via `http.Server.Serve` over a
  manually TLS-wrapped listener — which does NOT auto-enable h2 — so every client
  ALPN-negotiated nothing and fell back to HTTP/1.1. The "h2" listener was really
  serving h1.1.
  - FIX: dedicated TCP-listener `tls.Config` (CLONE of the shared one, so the
    h3/QUIC server's own "h3" ALPN is untouched) + `http2.ConfigureServer` +
    `NextProtos = ["h2"]`.
  - HARD-CLOSE h1.1 (strict-by-design, no incidental/untested fallback): pinning
    `NextProtos` is NOT enough — Go treats an ALPN MISMATCH as non-fatal and
    completes the handshake, after which `http.Server` serves h1.1. Added
    `GetConfigForClient` that FAILS the handshake unless the client offers "h2". An
    h1.1-only client now gets a TLS alert and never reaches the DoH handler — only
    h2 (TCP) and h3 (QUIC) are reachable, both tested. Rationale: a reachable but
    UNTESTED transport path (h1.1 smuggling/header/keep-alive surface) is an abuse
    vector, not "cosmetic" — close it rather than ship an untested fallback.
  - TEST: `TestDOHListenerNegotiatesH2NotDowngrade` — 3 h2-capable clients incl.
    h1.1-listed-FIRST → assert `NegotiatedProtocol=="h2"`; 2 reject cases
    (h1.1-only, no-ALPN) → assert the TLS dial FAILS, not a 200; + a full HTTP/2
    round-trip asserting `ProtoMajor==2`.
  - VERIFIED live (container): h2→HTTP/2 200, h3→HTTP/3 200, h1.1-only→curl
    code=000 / openssl `tlsv1 alert internal error` (was 200 pre-fix). This work
    ALSO produced the FIRST end-to-end DoH3 (HTTP/3 over QUIC) validation in a real
    deployment (curl `--http3-only` → HTTP/3 200, real DNS answer; `Alt-Svc` h3
    advertised).
- **CODE:** FIX aggressive cache mode caching NOTHING (Issue 25, HIGH).
  `internal/cache/cache.go` `Put()` positive-response path treated `ttl_min` as a
  REJECT threshold: `if ttl < c.ttlMin { return }` — so any response with a record
  TTL below the floor was dropped, never cached. The "aggressive" preset sets
  `ttl_min = 300`, but most real-world TTLs are < 300s (example.com A ≈ 60–120s,
  and AdGuard hands out decremented TTLs lower still), so aggressive mode silently
  cached almost nothing → Size 0, 0% hit rate, every query went upstream. Because
  all router configs used `mode = "aggressive"`, production caching was effectively
  OFF on the June-8/9 builds.
  - FIX (clamp-up, chosen semantics): `if ttl < c.ttlMin { ttl = c.ttlMin }` —
    extend short TTLs UP to the floor instead of rejecting. Aggressive now HOLDS a
    120s record for 300s, which is the whole point of aggressive caching. One-line
    change + clarifying comment. `ttl_max` clamp (cap) and the negative-cache path
    are unchanged.
  - TESTS: the existing `TestCacheTTLRespect` "Test 1" had ENCODED the bug
    (asserted a MISS for TTL < ttl_min) — corrected to assert a HIT. Added
    regression test `TestAggressiveTTLMinExtendsNotRejects`: Put a 120s-TTL record
    under `ttl_min=300` → assert HIT AND that the entry's expiry is ≈300s
    (extended), not 120s (proves clamp-up). The green suite previously only used
    TTLs ≥ the floor, which is why it never caught this.
  - VERIFIED in a clean Alpine/podman container (post-fix build, AdGuard DoQ
    upstream): aggressive mode, example.com ×5 → Size 1, Hit rate 80% (4/5),
    Upstream 1, warm = 0ms (was Size 0 / 0% / all upstream / ~42ms).
  - NOTE: discovered while building a container test to chase a SUSPECTED
    dual-mode shared-cache bug; the real defect was this single-mode
    aggressive-cache bug. A follow-up dual-mode run (Mode-1 warm → Mode-2 DoH on
    the same names, 36-query interleave) then PROVED the shared cache works
    (upstream stayed flat at 5, hit rate 84.8%, 0 SERVFAIL) — DISPROVING the
    original shared-cache-bug hypothesis.

## 2026-06-10 (2)

- **CODE:** two fixes that emerged DURING the dual-mode shared-cache testing.
  - `tls_cert_autogen` SAN fix — the self-signed cert was hardcoded to
    localhost/127.0.0.1 and IGNORED `listen_doh`, so a LAN-facing Mode-2 DoH
    endpoint (e.g. `192.0.2.1:8443`) presented a cert no remote client could
    validate → a browser or `curl` without `-k` couldn't connect. FIX: new
    `autogenSANHosts(cfg)` collects the host of each configured
    `ListenDoH/DoT/DoQ` (skips unspecified 0.0.0.0/::, always adds loopback);
    `generateSelfSignedCert` now takes `[]string` hosts and splits them into
    IP-SANs vs DNS-name-SANs. New `cert_test.go` asserts the SAN includes a
    non-loopback listen IP and that `VerifyHostname("192.0.2.1")` passes (the exact
    check a browser does). (CN is deprecated for hostname verification — clients
    validate SAN only — so the fix is SAN-centric by design.)
  - `--stats` section ORDER + conditional rendering. (1) MODE-1 FORWARDER now
    ALWAYS renders before MODE-2 SERVER (was Mode-2-first), so a Mode-1-only
    operator's view never shifts when they later enable Mode 2 — the new section
    appends BELOW the familiar one. (2) Each mode's section now renders ONLY when
    that mode is enabled; previously MODE-1 rendered unconditionally and would show
    an all-zero block on a Mode-2-only server. New test covers mode-1-only,
    mode-2-only, and dual (asserts M1-before-M2).
- **INVESTIGATION (no code change):** chased "`rcvd` returns NOERROR for an
  authoritatively-NXDOMAIN name" → NOT an `rcvd` bug. Root cause = COMPACT DENIAL
  OF EXISTENCE (signed NODATA; some Cloudflare-hosted zones). `rcvd` correctly
  RELAYS the upstream's NOERROR+AD. Affects negative-cache testing: use a
  classic-NSEC zone (e.g. `iana.org`) for a true-NXDOMAIN test; a Cloudflare NODATA
  zone is a NODATA test, not an NXDOMAIN test.

## 2026-06-10

- **DOCS/PUBLIC:** Whitepaper published at `rcvd.net` (Hugo site, GitLab Pages,
  custom domain, DNSSEC-signed end-to-end). The design went on the public record
  ahead of the source release (July 2026).
- 🎉 **SHARED CACHE PROVEN on bare metal — the dual-mode "killer feature"
  validated.** A single dual-mode `rcvd` process on the router demonstrably shares
  ONE in-memory aggressive cache across Mode 1 (LAN/POSIX forwarder) and Mode 2
  (DoH server). Driven from a client workstation (the real client) via a new CLI
  DoH driver. Decisive result: a Mode-2 DoH query warmed `example.net` (0.125s
  upstream fetch), then the immediate Mode-1 read (`dig` → dnsmasq → `rcvd`) of the
  SAME name returned in 0 msec — a hit on the entry the DoH path just created.
  Confirmed in reverse too (Mode-1-warmed name → DoH-served 0.027s). One cache,
  both client classes. Envisioned ~May 18, validated ~3 weeks later. 0 SERVFAIL,
  DNSSEC AD-flag set. (dnsmasq cache-size=0 on the router, so the 0 msec is an
  `rcvd` hit, not dnsmasq.)
- **FINDING (not an `rcvd` bug):** browser DoH (Firefox) won't use a self-signed
  cert — its DoH (TRR) path requires a CA-trusted cert and ignores manual cert
  exceptions. `curl` proves the endpoint serves DoH fine (HTTP 200); the browser
  silently refuses. So a REAL browser-DoH test is gated on certmagic/ACME (a real
  cert). The shared-cache proof did NOT need the browser; the CLI DoH client stood
  in.
- **cert SAN fix CONFIRMED working live:** `tls_cert_autogen` now covers the
  `listen_doh` address; `curl` TLS result 18 = self-signed (expected), no hostname
  mismatch.

## 2026-06-09 (4)

- 🎉 **MILESTONE — FIRST live DUAL-MODE (Mode 1 + Mode 2 in ONE process) on bare
  metal.** Dual-mode was envisioned + marked code-complete back on May 18, 2026;
  this is its first REAL deployment + stress test, on the live Alpine aarch64
  router — not a container, not a lab toy, the actual LAN resolver. (The Mode-1
  forwarder had already been live on this router since May 29 — see that entry;
  the "first" here is specifically running BOTH modes together in one process.)
  - Config: Mode 1 (127.0.0.1:5354, dnsmasq→here, the untouched production
    forwarder) + Mode 2 (DoH on the LAN interface, `tls_cert_autogen` self-signed)
    in ONE process, sharing ONE aggressive cache. Verified in code that both modes
    receive the SAME `*cache.Cache` object (`main.go` passes `dnsCache` into both
    `server.NewServer` and `upstream.New`), so the "one warm cache across LAN POSIX
    clients + a web browser" claim is structurally real, not aspirational.
  - GOAL of the test: previously a workstation's browser pointed at EXTERNAL DoH,
    so browser DNS and POSIX DNS never shared a cache. This points the browser
    DIRECTLY at the same `rcvd` that serves the LAN → both client classes hit one
    aggressive cache. First Mode-1+Mode-2 hybrid stress test.
  - Brought up clean: Active Modes MODE-1 on / MODE-2 on; the MODE-2 SERVER stats
    section renders on bare metal (re-confirms the Issue 22 counter-wiring). Cold
    start, 0 errors.
  - Deliberately NO ACME/Let's Encrypt (certmagic DNS-01 still unvalidated
    anywhere) — self-signed + browser exception is enough to prove the shared cache
    without that dependency.
  - Cosmetic-only note: the OpenRC start banner's crude config grep mashed the
    inline TOML comment on the `listen =` line into the printed value — the `rcvd`
    process parsed the config correctly and bound the right addr; only the banner
    display is wrong. Low-priority init-script cleanup.

## 2026-06-09 (3)

- **PRIVACY:** removed `query_log` entirely + scrubbed domain names from the
  operational log. A privacy DNS engine must not ship a feature whose purpose is to
  record what was queried, and must not leak queried names into any log. Two
  distinct fixes:
  - `query_log` REMOVED (was an inert stub — config existed, zero implementation):
    deleted the `QueryLogConfig` struct + the `Config.QueryLog` field, removed the
    empty `internal/query_log/` directory. No backward-compat (pre-1.0): a config
    carrying a `[query_log]` block now HARD-FAILS at startup via strict-unknown-key
    validation ("unknown config keys: [query_log ...]") — loud, not silent. Docs
    scrubbed accordingly.
  - OPERATIONAL-LOG DOMAIN LEAK fixed (the real exposure): `server.go` logged the
    queried name on three failure paths — "resolve error for %v", "DNSSEC
    validation failed for %v", and "serving stale (bounded) for %v". On an upstream
    outage / DNSSEC problem / cache flap these accumulated real query content in the
    operational log (no client IP, but the domains themselves — would not survive a
    privacy audit). All three now log the EVENT + error only, never
    `query.Question`. (The TCP-path equivalents already omitted the name.)
  - Verified: a `[query_log]` config is rejected at startup.

## 2026-06-09 (2)

- Cache mode/manual mutual-exclusion REFINED + arm64 build DEPLOYED to the router.
  - Refinement (design call): the convenience preset (`mode`) and hand-set knobs
    are now strictly one-or-the-other. An advanced operator may still set arbitrary
    custom values (`ttl_min`, `ttl_max`, `neg_ttl_max`, `serve_stale_max_s`) — BUT
    ONLY when they do NOT also select a `mode`. Selecting a `mode` AND a manual
    TTL/neg/stale key is a hard startup error. (Earlier same-day design used
    per-field overrides; replaced because "manual 0 vs unset" was ambiguous —
    refusing the combination removes the ambiguity. `max_size` stays exempt; bare
    `[cache]` = standard.) Enforced in `config.Load` via `toml.MetaData.IsDefined`.
  - Caught + fixed a config that the bulk "mode=aggressive" edit had left invalid
    (a config with `mode` + manual `ttl_min`/`ttl_max`, now a conflict) → removed
    the manual TTLs so the preset owns them.
  - DEPLOYED: aarch64 build installed on the router with the new aggressive-mode
    config. First live run of: (a) cache modes / aggressive, (b) the new
    operator-focused `--stats` template, (c) a DoH3-capable binary (DoH3 unused
    here — Mode-1 DoQ forwarder). 22m baseline: 19 queries, 100% success, 0
    SERVFAIL, 100% DNSSEC, all DoQ; cache cold (15.8% hit, 5 entries). Aggressive
    neg-cache + serve-stale will show effect as the cache warms / on any upstream
    blip.

## 2026-06-09

- Cache modes — light / standard / aggressive (config key `[cache] mode`). Turns
  the single fixed cache behavior into three operator-convenience presets tuning
  two axes: TTL handling + negative/stale caching. The preset and the manual knobs
  are MUTUALLY EXCLUSIVE — setting `mode` together with any of them is a hard
  startup error (`max_size` is exempt; it's orthogonal). Rationale: presets serve
  operators who want sane defaults; manual tuning serves advanced operators;
  combining them was ambiguous, so we refuse it rather than guess. A bare `[cache]`
  = standard (historical default).
  - `light`: ttl_min 0, ttl_max 1h, no negative caching, no serve-stale (fresher
    data)
  - `standard`: ttl_min 60, ttl_max 24h, no negative caching, no serve-stale
    (today)
  - `aggressive`: ttl_min 300, ttl_max 7d, negative caching ≤300s, serve-stale ≤1h
  - NEW BEHAVIOR (aggressive only):
    - Negative caching — NXDOMAIN / NODATA now cached using the SOA TTL (RFC 2308),
      capped at `neg_ttl_max`. Previously ONLY NOERROR-with-answers was cached. Off
      in light/standard.
    - Serve-stale — on all-upstream-failure, if a bounded-stale (but previously
      DNSSEC-validated) answer exists within `serve_stale_max_s` of expiry, serve
      it instead of SERVFAIL. NEVER emits cleartext (only freshness is relaxed; the
      transport guarantee is intact). Every served-stale response increments
      `stats.StaleServed` and shows in `--stats` — never silent ("V for
      Verifiable").
  - BUG FOUND + FIXED during impl: `cache.Get` lazy-deletes expired entries on
    access; the request path calls `Get` (miss) BEFORE the failure path calls
    `GetStale` — so the expired entry would have been deleted and serve-stale would
    silently never fire. Fixed: `Get` now KEEPS the expired entry when serve-stale
    is enabled (still reports a miss); a later `Put` overwrites it, else
    eviction/age-out reclaims it. Unchanged when serve-stale is off.
  - API: `cache.New(...)` positional signature → `cache.New(cache.Options{...})`.
    New `cache.GetStale()`, `NegativeCachingEnabled()`, `ServeStaleEnabled()`. All
    call sites migrated.
  - NOT touched: cache size per mode, prefetch (still a documented no-op), LRU
    eviction.

## 2026-06-08 (3)

- Port-53 cleartext-reject test case — a podman container test that proves `rcvd`'s
  zero-cleartext guarantee is verifiable, not just documented. "V for Verifiable."
  - New config: a Mode-1 resolver pointed at Quad9 DoQ (valid upstreams) but with
    `listen = "0.0.0.0:53"` (explicitly forbidden). The upstreams are intentionally
    good — the test verifies `rcvd` rejects the config BEFORE reaching upstream
    logic, not because the upstream failed.
  - Correct outcome is a non-zero exit and the validation error on stdout — no port
    is ever bound, no Quad9 connection is attempted. `run-test.sh` works locally
    (no container required) AND as a container smoke test.
  - Validated live: `podman run --rm rcvd-port53-reject-test` exits 1 with:
    `binding port 53 on a non-loopback interface is not allowed — rcvd must not
    accept cleartext DNS from the network. Use a loopback address (127.0.0.1:53 or
    [::1]:53) and let your router/firewall forward external port 53 traffic to it`.
  - This is the "V" in RCVD: the zero-cleartext design guarantee is now
    machine-verifiable in a reproducible container — any developer or auditor can
    run it.

## 2026-06-08 (2)

- `Validate()` port-53 loopback enforcement — `config.Validate()` now rejects a
  resolver listen address that binds port 53 on a non-loopback interface (0.0.0.0:53,
  any LAN IP). Binding port 53 on the network makes `rcvd` a cleartext-accepting
  stub visible to other hosts, which violates the zero-cleartext design. Loopback
  (127.0.0.1:53, [::1]:53) is explicitly allowed — that is the correct router
  deployment (dnsmasq → `rcvd` on loopback:53).
  - Hard error: `net.IP.IsLoopback()` check in `Validate()` on the parsed host when
    port == "53". The error message explains the constraint and the correct fix.
  - New `Warnings() []string` method: a non-loopback, non-53 listen (e.g.
    `192.0.2.1:5300`) emits an advisory warning at startup — not a hard error, but
    logged prominently so the admin knows they are binding on a
    trusted-but-not-loopback interface.
  - Tests: loopback:53 allowed, non-loopback:53 rejected, non-loopback:non-53
    produces warning, loopback:non-53 produces no warning.
  - Keeps the whitepaper claim honest: "port 53 on loopback only" is now
    code-enforced, not merely a default.

## 2026-06-08

- DoH3 (DNS-over-HTTPS over HTTP/3 / QUIC) — added as a first-class DoH transport
  variant on BOTH sides. Previously `rcvd`'s DoH was HTTP/2-over-TCP only (stdlib
  `net/http`) on both the Mode-2 server and the Mode-1 upstream client; no `http3`
  import existed (quic-go was used only for DoQ).
  - SERVER (`internal/upstream/doh.go`): the DoH listener now optionally runs a
    quic-go `http3.Server` over UDP/QUIC ALONGSIDE the always-on HTTP/2-over-TCP
    `http.Server`, on the same addr/port, sharing ONE `http.Handler` (the
    `/dns-query` mux) — so request handling is identical across h2/h3, only the
    transport differs. When h3 is on, HTTP/2 responses carry an `Alt-Svc: h3=...`
    header so capable clients upgrade to QUIC. Enabled via `[upstream_service] doh3
    = true`.
  - CLIENT (`internal/resolver/doh.go`): `NewHTTPResolver` gained a `useH3` param
    selecting a quic-go `http3.Transport` (RoundTripper) instead of the stdlib
    `http.Transport`. The h3 path keeps the same pinned-IP dial + hostname-SNI
    behavior via the `Transport.Dial` hook. Per-upstream `doh3 = true` (requires
    `doh = true`).
  - TEST: new `TestDOHListenerDoH3RoundTrip` does a REAL end-to-end HTTP/3 DoH
    round-trip (self-signed cert, `http3.Transport` client) and asserts
    `resp.ProtoMajor==3` + a valid DNS answer.
  - SIZE: static binary grew (http3 + qpack pulled in).
  - DOCS: whitepaper §6.1 (DoH row + escape-hatch prose), new §6.4 (DoH over
    HTTP/2 and HTTP/3), and §10 implementation status updated to reflect DoH3 as
    implemented+tested.
  - MOTIVATION: prominent encrypted-DNS clients (e.g. the Cloudflare 1.1.1.1 app)
    and browsers prefer HTTP/3; an h2-only DoH endpoint silently downgraded them.
    DoH3 is also the strongest port-443 escape hatch (QUIC-on-443, indistinguishable
    from HTTP/3 web traffic, vs DoQ's identifiable :853).

## 2026-06-07

- **[FIELD VALIDATION — no code change; same build as 2026-06-06, new containers
  only]** Second Cloudflare Quick Tunnel Mode-2 DoH run (Firefox → cloudflared →
  nginx sidecar → `rcvd` HTTPS self-signed → DoQ upstream → DNSSEC). Stats over the
  socket at ~21m uptime: Mode-2-ONLY (MODE-1 off), DoH served 410, Success
  (NOERROR) 410 (100.0%), SERVFAIL 0, upstream errors 0. Cache hit rate 30.0% (123
  hits / 287 misses, size 166/1024) — the shared-cache feature visibly offloading:
  410 served but only 287 upstream DoQ dials. DNSSEC 287 validated / 0 bogus / 100%
  validation rate. Confirms (a) the Issue 22 counter-wiring fix in the wild on a
  Mode-2-only instance (Total 410 = DoH served 410 = Success 410, not the old
  "Total 0"), and (b) the Pass-1 stats redesign renders correctly live. Cleaner
  than the 2026-06-06 run (0 SERVFAIL vs 13/399).

## 2026-06-06

- Stats output redesign — Pass 1 (`Render()` rewrite to an operator-focused
  layout). New mode-labeled sections: header (Version/Uptime/Config/Socket/Active
  Modes), SERVICE HEALTH (success rate), QUERIES (Total + nested Responses +
  Cache), MODE-2 SERVER (client-facing served counts + latency, shown only when
  Mode 2 enabled), MODE-1 FORWARDER (upstream queries/errors/fallback/by-protocol),
  DNSSEC, FILTERING. Replaces the old flat layout. All percentages use a
  divide-by-zero-safe `pct()` helper. DNSSEC "Validation rate" = validated /
  (validated + failed) i.e. % of SIGNED responses that passed — unsigned reported
  separately, NOT in the denominator. Verified live in the Quick Tunnel container
  with Firefox: Total 30 / Upstream 22 = 8 browser queries served from cache
  (shared-cache feature visible at a glance).
- Mode 2 now shares Mode 1's cache (killer feature). There is only ONE cache object
  per instance (created in `main.go`); Mode 1 used it, Mode 2 did not — every
  Mode-2 (browser/DoH) query hit the upstream even if already cached. Wired the
  shared `*cache.Cache` through `upstream.New` → `Service` → the DoH/DoT/DoQ
  listeners. Each Mode-2 handler now: `cache.Get` before resolving (HIT = serve
  instantly, count CacheHits+Success, no upstream call); on miss resolve upstream;
  `cache.Put` on a successful (NOERROR) response. The cache was already
  concurrency-safe (Mode-1 UDP+TCP goroutines), so sharing across modes needs no
  new locking. DO-bit cache-key separation means DNSSEC-aware vs non-DNSSEC clients
  still get distinct entries. Verified live: 3 identical DoH queries → Total 3,
  Cache Hits 2, Misses 1, Upstream 1 (only the miss went upstream).
- Stats: Mode-2 aggregate counter-wiring fix (Issue 22). The aggregate counters
  (TotalQueries, SuccessResponses, UpstreamQueries, UpstreamErrors) were incremented
  ONLY in the Mode-1 resolver path (`server.go`); the Mode-2 upstream handlers only
  incremented per-protocol `*Served` + `ServfailResponses`. Result: a Mode-2 server
  that served 399 DoH queries reported Total 0 / Success 0 / Upstream 0. Fixed by
  adding the aggregate increments to all three Mode-2 handlers.
- Stats: TotalQueries now counted at INGRESS in Mode 2 (positionally consistent
  with Mode 1). Moved the Mode-2 TotalQueries (+ per-protocol `*Served`) increment
  to just after the query unpacks — BEFORE the resolve step — so "Total" means the
  same thing in both modes.
- Stats: per-instance metadata in the output header (plumbing only). Added
  `statistics.InstanceInfo` (ConfigPath, SocketPath, Mode1Enabled, Mode2Enabled)
  threaded through to the render. Header now shows Config, Socket, and "Active
  Modes: MODE-1 <on/off>  MODE-2 <on/off>".
- DoH server: support RFC 8484 GET requests (in addition to POST).
  `internal/upstream/doh.go` now accepts GET with a base64url-encoded (unpadded)
  DNS message in the `?dns=` query parameter, decoding it into the same resolve
  path as POST. WHY: browsers default to GET for HTTP-cache friendliness; `rcvd`
  previously only accepted POST, so Firefox got HTTP 405 for every query ("server
  not found") while CLI tools (which POST) worked. This was found during the Quick
  Tunnel browser test.
- Logging: support `file = "stdout"` (and `"stderr"`) in `[logging]`.
  Container-friendly so `podman logs` / `docker logs` capture `rcvd` output
  (previously `rcvd` only logged to a file).
- First Mode-2 (upstream service) end-to-end validation — self-signed DoH via the
  3-container Cloudflare Quick Tunnel stack (`rcvd` HTTPS + nginx sidecar +
  cloudflared). A DoH query over the public URL returned 200/NOERROR; stats: DoH
  Served, DoQ upstream, DNSSEC validated, 0 SERVFAIL. `rcvd` stayed HTTPS-only
  throughout.

## 2026-06-05

- Mode-2-only startup fix (Issue 20): `main.go` was starting the Mode-1 resolver
  unconditionally and hard-exiting on `[resolver] enabled=false` ("resolver mode
  not enabled"), so Mode-2-only deployments could never start. Now Mode-1 starts
  only when `Resolver.Enabled`; errors clearly if neither mode is enabled.
- Issue 21 (plain-HTTP DoH) closed WONTFIX — keep `rcvd` HTTPS-only; the Quick
  Tunnel plan uses an nginx sidecar for the plain-HTTP hop instead.
- Startup config-path identity logging: `rcvd` logs the absolute config path +
  socket at startup; the OpenRC banner prints `config=<path>`. Disambiguates
  co-running instances.

## 2026-06-04 / 06-05

- certmagic DNS-01 challenge support: `challenge="dns01"` + `dns_provider` /
  `dns_api_token` (Cloudflare via libdns) — certs issue with NO inbound port
  (tunnel/CGNAT-safe). Compiles; NOT yet validated against a live ACME flow.
- DoH limit-reads DoS hardening (Issue 19): bounded `io.ReadAll` on DoH
  server/client bodies + the stats socket (`io.LimitReader`, `dns.MaxMsgSize`).

## 2026-06-03

- DoQ session resumption fix (Issue 17): added a TLS `ClientSessionCache` so cold
  QUIC re-dials resume at 1-RTT instead of paying a full handshake every time. This
  fixed a burst-SERVFAIL failure mode on the router where cold re-dials timed out in
  bursts — **691 SERVFAILs, ~56% of queries** in the worst window. After the fix:
  **0 SERVFAIL over 11K+ queries**, with max latency dropping from ~5.1s to ~275ms.
  It reads like a one-line config change, but it turned an intermittently-failing
  resolver into a stable one.

## 2026-06-01 / 06-02

- Statistics output: dedicated Blocklist section in `--stats`.
- File logging support (`LoggingConfig.File`) deployed to the router (confirmed in
  production early June).

## 2026-05-25 / 05-29

- **MILESTONE — FIRST live LAN-router deployment (May 29).** `rcvd` went into
  service as the actual encrypted forwarder on a live Alpine aarch64
  single-board-computer router, with `dnsmasq` forwarding to `rcvd` on
  `127.0.0.1:5354` (Mode 1). This is the origin of the "the router" deployment
  referenced throughout the later entries — the box carried real LAN DNS traffic
  from here on. End-to-end integration validated on the spot: `dig` example.com
  → 239ms (cache miss, upstream to AdGuard DoQ), then a `dig` via dnsmasq moments
  later → 0ms (cache HIT — served from `rcvd`'s cache, not dnsmasq, which runs
  cache-size=0). Stats confirmed Total 2 / hits 1 / misses 1 / upstream 1; TTL
  respected (121s remaining on both); DNSSEC validated on the cached response.
  (The June-9 dual-mode milestone below is the first time BOTH modes ran in one
  process — the Mode-1 forwarder had already been live on this router for weeks.)
- `--verify-upstream` (May 25): on-demand TLS probe of every configured upstream —
  cert chain, SANs, hostname match, expiry, SHA256 fingerprint. The "V" in `rcvd`,
  inspectable. Exit 0/1.
- Async blocklist loading (May 25): DNS available immediately on start; a
  328K-entry load no longer blocks queries.
- `InsecureSkipVerify` removed (May 25): all three resolvers now validate upstream
  certs against the system CA pool.
- Cache DO-bit cache-key separation (May 27): DNSSEC-aware vs non-DNSSEC clients get
  distinct cache entries. (This is what later made Mode-1/Mode-2 cache sharing
  safe.)
- Uptime bug fix (May 27): a monotonic `startTime` replaces Unix-epoch (immune to
  NTP corrections).

## 2026-05-15 / 05-21

- certmagic TLS automation (Phase 4.2, May 15–18): on-demand Let's Encrypt via
  certmagic; `[tls_automation]` config; `DecisionFunc` domain allowlist
  (anti-ACME-abuse). Standalone HTTPS, no Caddy/nginx required.
- Built-in statistics (Phase 3.4.1, May 21): ~25 sync/atomic counters, Unix-socket
  IPC, privacy-safe (no per-client IP, no domain names stored), opt-in via
  `stats_enabled`. `rcvd --stats`.
- **Earliest-known arm64 build (forensic note).** A preserved aarch64 binary
  dated **2026-05-21 18:23** pins working arm64 cross-compilation for the
  single-board-computer router to **≤ May 21** — ELF aarch64, statically linked,
  with debug info / not yet stripped (it predates the `-s -w` strip later added to
  the arm64 build script). It contains NO `--stats` symbols, confirming it was
  built from a tree just BEFORE the same-day statistics commit above. As it was
  the one kept (likely not the first arm64 attempt), working arm64 + early router
  bring-up almost certainly began in the **May 18–21 window** — over a week before
  the first validated router run (see the May-29 first-router entry). The exact
  first-arm64 date itself is unrecorded. The artifact was fingerprinted and its
  Go BuildID, SHA-1, and SHA-256 recorded when it was set aside, so its identity is
  fixed under chain-of-custody even though this early cross-compile isn't
  reproducible from the public tree. The point isn't the digest — it's the method:
  the build date is pinned not by a claim but by what the binary provably does and
  doesn't contain (statically linked, unstripped, pre-`--stats`).

## 2026-05-18

- DNSSEC: full cryptographic validation wired (Phase 3.1) — the "verifiable" in
  `rcvd` is not a slogan, it's a code path. Every signed answer is cryptographically
  checked, not trusted on faith: RRSIG signatures are verified via miekg/dns across
  RSA, ECDSA, and Ed25519; the chain of trust anchors at the IANA root keys, which
  are **embedded in the binary** (`//go:embed root-anchors.xml`) rather than fetched
  at runtime — so validation works on a cold box with no prior state and nothing to
  poison. Each DNSKEY is checked against the parent's DS digest up to that root
  anchor. The failure mode is the strict one: a validation failure returns SERVFAIL
  and **fails closed** — `rcvd` would rather return nothing than return an answer it
  cannot prove. On success the AD (Authenticated Data) flag is set so downstream
  clients can see the answer was validated. Wired into BOTH modes from the start, so
  a forwarding client and an upstream-service client get the same guarantee.
- Mode 2 (upstream service) COMPLETE (Phase 4.1): DoT/DoH/DoQ servers listening for
  clients; shares resolver + cache + blocklist with Mode 1; dual-mode (Mode 1 +
  Mode 2 simultaneously); self-signed autogen cert for testing.
- Init/packaging: systemd unit + OpenRC init script created.
- Decision: recursive resolution is a SEPARATE binary (`rvd`), not an `rcvd` mode —
  root servers need cleartext :53, which violates `rcvd`'s zero-cleartext guarantee.

## 2026-05-13 / 05-14

- Phase 2 protocols COMPLETE: DoT (RFC 7858) + DoH (RFC 8484) resolvers; protocol
  fallback state machine (DoQ → DoT → DoH) with tiered health checks. Phase 2.5
  multi-upstream fallback validated.
- Quad9 DoQ integration verified (May 13). Config cleanup; AdGuard DoQ confirmed
  working.

## 2026-05-11

- Phase 1 Foundation COMPLETE: project scaffolding, TOML config system
  (BurntSushi/toml, fail-fast on unknown keys), DoQ core (RFC 9250, quic-go, ALPN
  "doq", connection pooling), UDP/TCP server listener, static binary
  (`CGO_ENABLED=0`). Enforced from day one: no cleartext fallback — SERVFAIL on
  failure.
- Early research, design, and development of `rcvd` begins.

## 2026-05-08

Early research + foundational design decisions (pre-code). Locked the choices that
shaped everything after:

- Name: `rcvd` = Resilient, Cryptographic, Verifiable DNS. WireGuard-style: one
  binary, mode-specific config files; you configure which mode(s) to run (resolver
  / upstream-service / both).
- Default port 5300 (NOT 53). Binding :53 needs elevated privileges and collides
  with systemd-resolved's stub (127.0.0.53:53). Port 5300 needs no capabilities and
  coexists — systemd-resolved keeps :53 and forwards to `rcvd` on 5300. (:53 still
  possible via `CAP_NET_BIND_SERVICE` / iptables redirect where wanted.)
- Protocol priority DoQ → DoT → DoH (configurable). DoQ preferred (1-RTT, no
  head-of-line blocking); DoH is the port-443 escape hatch, not the default.
- NON-NEGOTIABLE from the start: ZERO cleartext DNS allowed to exit. All upstream encrypted;
  SERVFAIL (never cleartext fallback) if all encrypted upstreams fail — an explicit,
  documented divergence from RFC 9250 §5.2.
- Recursive resolution will be a SEPARATE binary (`rvd`), not an `rcvd` mode:
  root/TLD servers speak plain :53 only, so recursion requires cleartext, which
  would violate the zero-cleartext guarantee.
- Blocklist format: CHOSE two DNS-native formats, auto-detected. The plain domain
  list (preferred; one name per line, e.g. OISD's `domainswild`) and the hosts-file
  format (`0.0.0.0 example.com`, e.g. Steven Black's `hosts`); both with wildcard
  support (`*.example.com`) and RFC 1123 hostname validation. Picked these because
  every entry IS a domain name. The resolver matches them at query time directly,
  no parsing gymnastics. Deliberately NOT ABP/EasyList/EasyPrivacy: those are
  browser-centric. Their rules target URL paths, query strings, and DOM
  element/cosmetic selectors, none of which a typical DNS resolver can see 
  (it only ever gets a domain name). So even after pre-parsing, most of each rule 
  has nothing for DNS to act on.
