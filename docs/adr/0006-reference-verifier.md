# 0006. Reference verifier in Go, with a fixed default policy

## Status
Accepted, 2026-11-24.

## Context
ADR 0002 moves every decision to the backend, and ADR 0005 makes the message verifiable. Both
are only useful if integrators verify correctly: attestation parsing is fiddly ASN.1, and the
common mistakes (trusting any root, skipping the challenge, accepting software attestation)
quietly turn the whole scheme into a formality.

## Decision
Ship `server/`, a small Go service and library that:

- issues 32-byte single-use challenges with a two-minute lifetime (`POST /v1/challenge`);
- verifies a message (`POST /v1/verify`): certificate chain to Google's attestation roots
  (matched by public key), revocation list, challenge, security level, app package and signing
  digest, ECDSA signature over the report, root of trust;
- applies a default policy and returns `allow`, `review` or `deny` with every reason.

Default policy:

| Outcome | When |
| --- | --- |
| deny | invalid or untrusted chain, revoked certificate, unknown or reused challenge, software attestation, wrong package or signer, bad signature, any HOOK or TAMPER signal, a failed Play Integrity check |
| review | ROOT or DEBUG signals, probes that did not run, no attestation, unlocked bootloader or unverified boot, revocation list not loaded yet, Play Integrity configured but no token |
| allow | none of the above |

Go because the standard library covers X.509, ASN.1, ECDSA and HTTP with no dependencies, and
the result is one static binary. The policy is code, not configuration: changing it should be
a reviewed diff with tests.

Play Integrity is behind a `Decoder` interface. `GoogleDecoder` calls the API with a client
authenticated by a service account key (`IRIS_PLAY_INTEGRITY_CREDENTIALS`), using the OAuth 2.0
JWT bearer grant written against the standard library. Without the key the verifier reports
"Play Integrity not configured".

## Consequences
- Challenges live in memory by default, which is correct for one instance only. Several
  instances use Redis (`IRIS_REDIS_URL`) through a minimal RESP client, to keep the no-dependency
  rule. If the store cannot answer, the message goes to review: freshness was not checked.
- `/v1/challenge` and `/v1/verify` are rate limited per client IP, so filling the challenge
  store or burning CPU on chain checks takes many addresses.
- Emulators chain to "Droid Unregistered Device CA" and attest in software, so testing against
  one needs `IRIS_EXTRA_ROOTS_PEM` and `IRIS_ALLOW_SOFTWARE_ATTESTATION=true`. Both log a
  warning at startup and must never be set in production.
- Google's roots are embedded and dated; when Google rotates them, the file and its test change
  together.
