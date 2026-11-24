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
| `IRIS_EXTRA_ROOTS_PEM` | unset | Extra trusted roots, for emulators and test devices only |
| `IRIS_ALLOW_SOFTWARE_ATTESTATION` | false | Accept software attestation, for emulators only |

## API

`POST /v1/challenge` returns `{"challenge": "<base64, 32 bytes>", "expires_in": 120}`. Pass the
decoded bytes to `Iris.inspectAndSign`.

`POST /v1/verify` takes `{"message": <IrisMessage.toJson()>, "integrity_token": "..."}` and
returns:

```json
{"action":"deny","reasons":["HOOK-001 (maps): /memfd:frida-agent-64.so (deleted)"]}
```

`GET /healthz` answers 204. Logs are JSON on stdout and never include report contents.

## Layout

- `internal/attestation`: chain verification, KeyDescription parsing, revocation list, embedded
  Google roots. `attestationtest` builds synthetic chains for tests.
- `internal/verifier`: message checks and the policy.
- `internal/challenge`: single-use challenge store (in memory, one instance).
- `internal/integrity`: Play Integrity verdict checks and the API client.
- `internal/report`: the SDK's report format.
