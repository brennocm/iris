# iris-verifier

Reference backend for Iris: issues attestation challenges and turns signed Iris messages into
`allow`, `review` or `deny`. Design and policy: [ADR 0006](../docs/adr/0006-reference-verifier.md).

## Run

```sh
IRIS_PACKAGE_NAME=com.example.app \
IRIS_SIGNING_CERT_SHA256=AB:CD:... \
  go run ./cmd/iris-verifier
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `IRIS_PACKAGE_NAME` | required | Package the attestation must name |
| `IRIS_SIGNING_CERT_SHA256` | empty (warns) | Comma-separated SHA-256 of the app signing certificates |
| `PORT` | 8080 | Listen port |
| `IRIS_STATUS_SOURCE` | Google's status URL | Revocation list URL or file; `off` disables it |
| `IRIS_REDIS_URL` | unset (memory) | `redis://[user:password@]host:port[/db]` or `rediss://` (TLS). Required with more than one instance |
| `IRIS_PLAY_INTEGRITY_CREDENTIALS` | unset | Path to a Google service account JSON key linked to the app in Play Console; enables Play Integrity checks |
| `IRIS_RATE_LIMIT_PER_MINUTE` | 30 | Requests per minute per client on `/v1/challenge` and `/v1/verify` |
| `IRIS_RATE_LIMIT_BURST` | 10 | Burst size per client |
| `IRIS_CLIENT_IP_HEADER` | unset (TCP peer) | Header with the client IP set by your proxy, e.g. `X-Forwarded-For`; only when all traffic goes through it |
| `IRIS_EXTRA_ROOTS_PEM` | unset | Extra trusted roots, for emulators and test devices only |
| `IRIS_ALLOW_SOFTWARE_ATTESTATION` | false | Accept software attestation, for emulators only |

With Docker:

```sh
docker build -t iris-verifier .
docker run -p 8080:8080 -e IRIS_PACKAGE_NAME=com.example.app iris-verifier
```

The image is distroless, static and runs as a non-root user. Mount the Play Integrity key as a
secret file; never bake it into the image.

## API

`POST /v1/challenge` returns `{"challenge": "<base64, 32 bytes>", "expires_in": 120}`. Pass the
decoded bytes to `Iris.inspectAndSign`.

`POST /v1/verify` takes `{"message": <IrisMessage.toJson()>, "integrity_token": "..."}` and
returns:

```json
{"action":"deny","reasons":["HOOK-001 (maps): /memfd:frida-agent-64.so (deleted)"]}
```

`GET /healthz` answers 204 while the process runs. `GET /readyz` answers 204 once the
revocation list is loaded and the Redis store (if any) answers, 503 otherwise. Requests over
the rate limit get 429 with `Retry-After`. Logs are JSON on stdout and never include report
contents.

## Layout

- `internal/attestation`: chain verification, KeyDescription parsing, revocation list, embedded
  Google roots. `attestationtest` builds synthetic chains for tests.
- `internal/verifier`: message checks and the policy.
- `internal/challenge`: single-use challenge stores: in memory, or Redis (`SET NX PX` to issue,
  `DEL` to consume, so two instances can never both accept one challenge).
- `internal/integrity`: Play Integrity verdict checks, the API client and service account auth
  (OAuth 2.0 JWT bearer).
- `internal/ratelimit`: per-client token bucket with bounded memory.
- `internal/report`: the SDK's report format.
