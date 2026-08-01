// SPDX-License-Identifier: MIT
package resolver

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"fmt"

	"github.com/rcvd-dns/rcvd/internal/config"
)

// SPKI public-key pinning using the "sha256//BASE64" format.
//
// https://curl.se/docs/manpage.html#--pinnedpubkey
// The double-slash prefix is the format defined by curl's --pinnedpubkey flag
// and adopted as a de-facto standard alongside RFC 7469 
// (HTTP Public Key Pinning / HPKP). The algorithm name ("sha256") is separated 
// from the base64 value by "//". rcvd uses the same format so pins generated 
// with `curl --pinnedpubkey` or openssl are directly usable in rcvd config without 
// conversion.
//
// The pin is a SHA-256 over the peer LEAF certificate's DER-encoded SubjectPublicKeyInfo 
// i.e. it binds to the KEY, not the whole certificate, so a server may re-issue its 
// cert (new dates/SANs) with the SAME keypair and the pin stays stable.
//
// SECURITY POSTURE — READ BEFORE TOUCHING pinnedTLSConfig BELOW.
//
// When an upstream sets `pinned_pubkey`, rcvd verifies that upstream by EXACT KEY
// MATCH instead of by CA chain. This is the ONLY place in the codebase that sets
// tls.Config.InsecureSkipVerify = true, and it is reachable ONLY when a pin that
// already passed parsePin() at config-load is present. It exists so a self-signed
// LAN peer (an rcvd Mode-2 router) can be trusted with one config line and no OS
// trust-store install.
//
// The pin verifier is NOT the sole defense — defense in depth, each gate
// independent and fail-closed:
//  1. The pin is parsed/validated at CONFIG LOAD (parsePin). A malformed pin is a
//     hard startup error; the InsecureSkipVerify path is never constructed for an
//     empty or bad pin — those fall through to normal CA validation.
//  2. Hostname is verified INSIDE the closure (leaf.VerifyHostname) BEFORE the pin
//     compare. We replaced only the CA-chain link, not hostname checking.
//  3. Constant-time compare, fail-closed by construction: the closure returns an
//     error unless EVERY check passes. Any early return yields a non-nil error →
//     handshake aborts → SERVFAIL, never cleartext.
//  4. Belt checks: non-empty peer chain, and the decoded pin is exactly 32 bytes
//     (SHA-256) — a truncated/empty pin cannot accidentally match.
//
// https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning
// OWASP discourages pinning in general but that targets the WEB/HPKP case 
// (different parties, TOFU (Trust On First Use), rotation lockout). 
// Ours is the carve-out: same party controls both ends, SPKI pin over a stable 
// self-signed cert, no TOFU — the pin is provisioned out-of-band in config), 
// fail-closed by design — pinning fits here.
//

// The pin FORMAT (parse + produce) lives in the low-level config package as
// config.ParsePin / config.SPKIPin — the single source of truth shared with the
// config loader (validatePinnedPubKey), so the startup check and this live verifier
// can never drift. This file owns only the TLS-handshake ENFORCEMENT below.

// pinnedTLSConfig applies SPKI-pin verification to a *tls.Config IN PLACE and
// returns it, but ONLY when pin != "". When pin == "" the config is returned
// untouched (normal CA validation, InsecureSkipVerify stays false).
//
// host is the expected TLS ServerName; it is checked against the leaf cert's
// SANs inside the verifier because CA-chain verification (which normally does the
// hostname check) is turned off on this path.
//
// The pin string MUST already have passed config.ParsePin() at config load; we
// re-parse defensively and, on the (unreachable-by-design) chance it is now
// invalid, we leave CA validation ON rather than opening an unverified
// connection — fail safe.
func pinnedTLSConfig(conf *tls.Config, host, pin string) *tls.Config {
	if pin == "" {
		return conf // default path: unchanged, CA validation as before
	}
	want, err := config.ParsePin(pin)
	if err != nil {
		// Should be impossible (validated at load). Do NOT weaken TLS: keep CA
		// validation on and let the normal handshake decide. Never open a hole.
		return conf
	}

	// Replace CA-chain trust with exact-key trust for THIS upstream only.
	conf.InsecureSkipVerify = true // < the only InsecureSkipVerify in the codebase; pin-gated, see file header
	conf.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("pin: no peer certificate presented")
		}
		leaf := cs.PeerCertificates[0]

		// (2) Hostname MUST still match — CA chain check is off, so we do it here.
		if err := leaf.VerifyHostname(host); err != nil {
			return fmt.Errorf("pin: hostname verification failed: %w", err)
		}

		// (3)+(4) Exact SPKI key match, constant-time, fail-closed.
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(sum[:], want) != 1 {
			return fmt.Errorf("pin: peer public key does not match pinned_pubkey")
		}
		return nil
	}
	return conf
}
