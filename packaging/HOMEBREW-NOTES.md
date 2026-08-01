# Homebrew Packaging Notes

Homebrew is expected to be the **most common way to install rcvd on macOS**, so its behavior
directly shapes the macOS install/UX story. This note tracks Homebrew release changes that affect
how rcvd is distributed and installed. Pairs with the launchd service files in `packaging/launchd/`
and `Notes/MacOS-26-ARM-notes.md`.

> Status: forward-looking. This is planning so the eventual formula +
> tap are built against current Homebrew behavior, not stale assumptions.

---

## Homebrew 6.0.0 (released 2026-06-11) — what matters for rcvd

Source: https://brew.sh/2026/06/11/homebrew-6.0.0/

### 🔐 Tap trust — THE big one for rcvd (action required when we ship a tap)
Homebrew 6.0.0 adds **tap trust**: a third-party tap can run arbitrary, unsandboxed Ruby on the
user's machine, so Homebrew now **requires taps (and tap-qualified formulae/casks) to be explicitly
trusted before their code is evaluated or run.** Official Homebrew taps are trusted by default;
**third-party taps are not.**

Why this matters for rcvd:
- rcvd will almost certainly ship via a **third-party tap first** (e.g. `brew tap rcvd-dns/rcvd`
  then `brew install rcvd`), NOT homebrew-core — so OUR tap will be **untrusted by default**. New
  users will hit a trust prompt/flag before install unless we document the trust step.
- Practical impact on install instructions: a plain `brew tap rcvd-dns/rcvd && brew install rcvd`
  may now be FLAGGED (untrusted) before any code runs. We must document the trust flow:
  - `brew tap` gained tap-trust management commands; a tap can be **trusted by its remote URL**.
  - `brew trust` gained `--json=v1`; `brew tap-info` gained a `trusted` field (use these to verify).
  - Homebrew **stops auto-tapping untrusted taps** — so anything relying on implicit auto-tap breaks.
  - `brew bundle` honors a `trusted:` option and `brew bundle dump` records trusted entries / marks
    custom-remote taps as trusted — relevant if we ever ship a Brewfile for a full rcvd setup.
- TODO when publishing: write the exact, copy-pasteable trust + install sequence in the macOS install
  docs, and decide whether to pursue homebrew-core inclusion (trusted-by-default, no trust step) vs.
  staying a self-hosted tap (faster to iterate, but users must trust it). See Tap-Trust docs on
  docs.brew.sh.

### Internal JSON API now default
The smaller, single-download internal JSON API is now the default (was opt-in via
`HOMEBREW_USE_INTERNAL_API` since 5.0.0; that var is now deprecated). `brew update` is faster and
hits the network less. No rcvd action — just means users on 6.0.0 update faster; don't reference the
deprecated env var in any docs.

### 🐧 Linux sandbox (Bubblewrap)
6.0.0 adds a Bubblewrap sandbox for build/test/postinstall on Linux, aligning with macOS. Caveat: the
release notes say it's **on by default for developers** — so it bites the CI / `brew test-bot` /
`--build-from-source` path, not a normal end-user bottle install (which doesn't build, so never enters
that phase). That matches what we see in practice: a plain `brew install` doesn't visibly sandbox.
Relevant only if/when we distribute rcvd via **Linuxbrew** and our formula has a build/test/postinstall
phase — it must then work under Bubblewrap (no unsandboxed network/file assumptions). Not macOS-facing.

### macOS 27 (Golden Gate) + survey-informed defaults
Initial support for macOS 27. When we test rcvd's macOS install, include macOS 27 alongside the
macOS 26 ARM notes. No direct formula impact yet.

---

## Path reminders for the formula/launchd (don't conflate Intel vs ARM prefixes)
- Intel Homebrew prefix: `/usr/local/...` (matches the current `packaging/launchd/*.plist`, which
  hardcode `/usr/local/bin/rcvd`, `/usr/local/etc/rcvd/rcvd.toml`, `/usr/local/var/log/rcvd`).
- **Apple-silicon Homebrew prefix: `/opt/homebrew/...`** — a formula should use `HOMEBREW_PREFIX`
  rather than hardcoding `/usr/local`, and the launchd plists may need an ARM variant with the
  `/opt/homebrew` paths (the arm64 plist still uses `/usr/local` today — flag for the formula work).
- DoQ UDP buffer tuning on macOS uses `net.inet.udp.recvspace` / `net.inet.udp.sendspace` (NOT Linux
  `net.core.*`) — see the launchd plist comments + `Notes/MacOS-26-ARM-notes.md`.

## Action checklist (when rcvd is ready to publish on Homebrew)
- [ ] Decide: self-hosted tap (untrusted-by-default → document trust) vs. homebrew-core (trusted).
- [ ] Write copy-pasteable macOS install incl. the **tap-trust** step for 6.0.0+ users.
- [ ] Formula uses `HOMEBREW_PREFIX` (Intel `/usr/local` vs ARM `/opt/homebrew`).
- [ ] Reconcile launchd plist paths with the chosen prefix (add ARM `/opt/homebrew` variant if needed).
- [ ] Test install on macOS 26 (ARM) AND macOS 27 (Golden Gate).
- [ ] If a Brewfile is offered, mark the rcvd tap `trusted:` and verify `brew bundle` flow.
