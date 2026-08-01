#!/bin/sh
# verify-anchors.sh — prove the committed DNSSEC root trust anchor is genuine.
#
# rcvd embeds IANA's DNSSEC root trust anchor (internal/dnssec/root-anchors.xml)
# at compile time. For a DNSSEC-validating tool, a trust anchor is only as good as
# its chain of custody: a "random XML in the repo" is worthless; a file we can
# PROVE came from IANA is a real anchor. This script provides that proof.
#
# How IANA lets us verify it (this is the part people get wrong):
#   * IANA does NOT PGP-sign root-anchors.xml.
#   * It ships root-anchors.p7s — a PKCS#7 / CMS *detached S/MIME signature* — and
#     icannbundle.pem, the ICANN CA the signature chains to.
#   So verification is `openssl cms -verify` against the ICANN CA, NOT gpg.
#
# TRANSPORT NOTE (why plain HTTPS curl is fine here): the trust root of this check
# is the S/MIME signature over the anchor, verified against a PINNED copy of the
# ICANN CA bundle — NOT the TLS connection. A MITM on data.iana.org cannot forge a
# valid signature without ICANN's key, and cannot swap the CA without failing the
# pin below. HTTPS is just delivery; the crypto is what we trust.
#
# Two independent checks, both must pass:
#   1. CMS signature verify: root-anchors.p7s over root-anchors.xml, trust-anchored
#      at the pinned ICANN CA bundle.  (openssl cms -verify -binary)
#   2. Offline cross-check: the well-known KSK-2017 / KSK-2024 digests are present.
#   Then: every digest IANA currently publishes is also in our COMMITTED file
#   (catches a stale anchor after a KSK rollover).
#
# Runs in CI on BOTH upstream origins (rcvd is mirrored so it depends on no single
# host/jurisdiction) — GitLab .gitlab/.gitlab-ci.yml and GitHub
# .github/workflows/release.yml, job `verify-anchors` in each — and locally.
#
# USAGE:
#   sh scripts/verify-anchors.sh            # verify the committed anchor (CI + local)
#   sh scripts/verify-anchors.sh --update   # refresh committed anchor from IANA, then verify
#
# Exits non-zero on ANY mismatch — a failing anchor must block a release.
#
# UPDATE ON KSK ROLLOVER: run with --update, review the root-anchors.xml diff by
# hand, re-run the ICANN CA pin (see ICANN_CA_BUNDLE_SHA256 below) if ICANN rotates
# its CA, and update internal/dnssec/README.md's "last synced" line.
set -eu

DNSSEC_DIR="${DNSSEC_DIR:-internal/dnssec}"
REPO_ANCHOR="${DNSSEC_DIR}/root-anchors.xml"
BASE_URL="https://data.iana.org/root-anchors"

# SHA-256 of the WHOLE icannbundle.pem (it legitimately contains two CA certs:
# "ICANN Root CA" and "ICANN Root CA v2" — CMS chains to whichever applies, so we
# pin the bundle rather than a single cert). Re-pin only on an ICANN CA rollover.
# Verified against https://data.iana.org/root-anchors/icannbundle.pem on 2026-07-13.
ICANN_CA_BUNDLE_SHA256="18ce7215812d1a2cad8d9d4d3d7c26f7235a9b5ec6f0c1e214e15230fd4f9e24"

# Well-known KSK DS digests (SHA-256, DigestType 2) — offline cross-check constants.
KSK_2017_DIGEST="E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"  # tag 20326
KSK_2024_DIGEST="683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"  # tag 38696

update=0
offline=0
case "${1:-}" in
  --update)  update=1 ;;
  --offline) offline=1 ;;
esac

command -v openssl >/dev/null 2>&1 || { echo "FAIL: openssl not found" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The verification files (.p7s signature + .pem CA) are LOCAL CACHE, gitignored
# (see .gitignore). If they're already on disk next to root-anchors.xml, use them
# — this lets you re-verify FULLY OFFLINE with no network. On a clean checkout
# (CI), they're absent, so we fetch fresh from IANA. `--offline` forces the local
# path and fails loudly if a file is missing (never silently reaches the network).
# Three IANA files feed the check, cached LOCALLY (gitignored) next to the anchor:
#   root-anchors.xml — IANA's OWN copy (what the signature actually signs; NOT the
#                      committed repo file, which may carry extra historical KSKs).
#   root-anchors.p7s — IANA's detached CMS signature over that .xml.
#   icannbundle.pem  — the ICANN CA the signature chains to.
# If all three are on disk, we verify FULLY OFFLINE. On a clean checkout (CI) they're
# absent, so we fetch fresh from IANA. `--offline` forces local + fails if any missing.
LOCAL_IANA_XML="${DNSSEC_DIR}/root-anchors.iana.xml"   # IANA's own copy, cached for offline
LOCAL_P7S="${DNSSEC_DIR}/root-anchors.p7s"
LOCAL_PEM="${DNSSEC_DIR}/icannbundle.pem"

have_local=0
[ -f "$LOCAL_IANA_XML" ] && [ -f "$LOCAL_P7S" ] && [ -f "$LOCAL_PEM" ] && have_local=1

if [ "$offline" -eq 1 ] || { [ "$have_local" -eq 1 ] && [ "$update" -eq 0 ]; }; then
  if [ "$have_local" -eq 0 ]; then
    echo "FAIL: --offline requested but local cache incomplete in ${DNSSEC_DIR}/:" >&2
    for f in "$LOCAL_IANA_XML" "$LOCAL_P7S" "$LOCAL_PEM"; do
      [ -f "$f" ] || echo "  missing: $f" >&2
    done
    echo "  Run once WITHOUT --offline to fetch + cache them from IANA." >&2
    exit 1
  fi
  echo ">> using LOCAL cached IANA anchor + signature + CA bundle (offline verify)"
  cp "$LOCAL_IANA_XML" "${work}/root-anchors.xml"
  cp "$LOCAL_P7S"      "${work}/root-anchors.p7s"
  cp "$LOCAL_PEM"      "${work}/icannbundle.pem"
else
  command -v curl >/dev/null 2>&1 || { echo "FAIL: curl not found (needed to fetch from IANA)" >&2; exit 1; }
  echo ">> fetching IANA anchor + signature + CA bundle (no usable local cache)"
  curl -fsSL "${BASE_URL}/root-anchors.xml"  -o "${work}/root-anchors.xml"
  curl -fsSL "${BASE_URL}/root-anchors.p7s"  -o "${work}/root-anchors.p7s"
  curl -fsSL "${BASE_URL}/icannbundle.pem"   -o "${work}/icannbundle.pem"
  # Cache all three locally (gitignored) so future runs can verify fully offline.
  cp "${work}/root-anchors.xml"  "$LOCAL_IANA_XML"
  cp "${work}/root-anchors.p7s"  "$LOCAL_P7S"
  cp "${work}/icannbundle.pem"   "$LOCAL_PEM"
  echo "   cached IANA anchor + signature + CA bundle to ${DNSSEC_DIR}/ (gitignored)"
fi

echo ">> pinning the ICANN CA bundle"
got_ca="$(sha256sum "${work}/icannbundle.pem" | awk '{print $1}')"
if [ "$got_ca" != "$ICANN_CA_BUNDLE_SHA256" ]; then
  echo "FAIL: icannbundle.pem fingerprint mismatch — possible CA rollover or tampering" >&2
  echo "  got:  $got_ca"  >&2
  echo "  want: $ICANN_CA_BUNDLE_SHA256" >&2
  echo "  If ICANN legitimately rolled its CA, re-pin after manual review." >&2
  exit 1
fi

echo ">> verifying the CMS (S/MIME) detached signature over the IANA anchor"
# -binary is REQUIRED: without it OpenSSL's text canonicalization mangles the
# content and the verify fails even on a genuine file. (Confirmed empirically.)
if ! openssl cms -verify \
      -CAfile "${work}/icannbundle.pem" \
      -inform DER -in "${work}/root-anchors.p7s" \
      -content "${work}/root-anchors.xml" \
      -binary -purpose any \
      -out /dev/null 2>"${work}/cms.err"; then
  echo "FAIL: CMS signature verification failed — IANA anchor not authentic" >&2
  cat "${work}/cms.err" >&2
  exit 1
fi
echo "   signature OK — IANA's anchor is authentic"

echo ">> cross-checking well-known KSK digests are present in the signed anchor"
for digest in "$KSK_2017_DIGEST" "$KSK_2024_DIGEST"; do
  if ! grep -qi "$digest" "${work}/root-anchors.xml"; then
    echo "FAIL: expected KSK digest ${digest} not in signed IANA anchor" >&2
    exit 1
  fi
done
echo "   known KSK digests present"

if [ "$update" -eq 1 ]; then
  echo ">> --update: writing verified IANA anchor to ${REPO_ANCHOR}"
  cp "${work}/root-anchors.xml" "$REPO_ANCHOR"
  echo "   updated. Review the diff, update internal/dnssec/README.md, then commit."
fi

echo ">> checking the COMMITTED repo anchor carries every currently-valid IANA digest"
# The committed file MAY contain extra (expired/historical) KeyDigests — fine, the
# parser skips them. What must hold: every digest IANA CURRENTLY publishes is also
# in our committed file, so we never ship a stale/missing current anchor.
missing=0
for digest in $(grep -oiE '[0-9A-Fa-f]{64}' "${work}/root-anchors.xml"); do
  if ! grep -qi "$digest" "$REPO_ANCHOR"; then
    echo "FAIL: committed ${REPO_ANCHOR} is MISSING a current IANA digest: ${digest}" >&2
    echo "      Likely a KSK rollover — run: sh scripts/verify-anchors.sh --update" >&2
    missing=1
  fi
done
[ "$missing" -eq 0 ] || exit 1

echo "OK: committed root anchor verified against IANA's signed anchor."
