# DNSSEC root trust anchor

`root-anchors.xml` is the IANA DNSSEC root trust anchor (root KSK DS records),
embedded into the binary at compile time (`//go:embed`, see `anchors.go`).

- Source: <https://data.iana.org/root-anchors/root-anchors.xml>
- Last synced: 2026-07-13
- Verified against IANA's detached CMS/S-MIME signature (`root-anchors.p7s`)
  chaining to the pinned ICANN CA bundle (`icannbundle.pem`).

## Files

| File | Committed | Role |
|------|-----------|------|
| `root-anchors.xml` | yes | the anchor; compiled into the binary |
| `root-anchors.iana.xml` | no (gitignored) | IANA's own copy — what the signature signs |
| `root-anchors.p7s` | no (gitignored) | IANA's detached CMS signature |
| `icannbundle.pem` | no (gitignored) | the ICANN CA the signature chains to |

Only `root-anchors.xml` is required to build. The other three are a local
verification cache, created on first `verify-anchors.sh` run and reused for
offline verification. A clean checkout (CI) fetches them fresh from IANA.

## Verify

```sh
sh scripts/verify-anchors.sh            # local cache if present, else fetch from IANA
sh scripts/verify-anchors.sh --offline  # cache only; fail if missing, no network
```

The script: fetches or reads IANA's anchor + signature + CA bundle; pins the CA
bundle by SHA-256; verifies the CMS signature (`openssl cms -verify -binary`);
cross-checks the KSK-2017 (tag 20326) and KSK-2024 (tag 38696) digests; and
confirms the committed `root-anchors.xml` carries every currently-valid IANA
digest.

Runs in CI on both origins, gating the build/release:

- GitLab — `.gitlab/.gitlab-ci.yml`, job `verify-anchors`
- GitHub — `.github/workflows/release.yml`, job `verify-anchors`

Note: IANA does not PGP-sign the anchor. The signature is PKCS#7/CMS (S-MIME),
verified with `openssl cms` — not `gpg`.

## KSK rollover

```sh
sh scripts/verify-anchors.sh --update   # fetch + verify + rewrite the anchor
```

Review the diff, update "Last synced" above, and commit. The committed file may
retain expired `<KeyDigest>` entries; `ParseRootAnchors` skips anchors outside
their validity window. If ICANN rotates its CA, re-pin `ICANN_CA_BUNDLE_SHA256`
in `scripts/verify-anchors.sh` after review.
