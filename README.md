<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/iris-logo-dark.svg">
    <img src="docs/assets/iris-logo-light.svg" alt="Iris" width="260">
  </picture>
</p>

# Iris

[![ci](https://github.com/brennocm/iris/actions/workflows/ci.yml/badge.svg)](https://github.com/brennocm/iris/actions/workflows/ci.yml)

Android runtime self-protection SDK. Iris looks for root, instrumentation (Frida, Xposed,
LSPosed), debuggers and repackaging, and returns what it found as a report for your backend.
It never blocks or kills the app: the decision belongs on the server, next to a Play Integrity
verdict.

> **Status:** early (v0.1, not on Maven Central). Tested on an Android 14 emulator, clean,
> rooted and with Frida injected ([results](docs/scenarios.md)); not yet on real devices. The
> verifier does not call the Play Integrity API yet. Do not rely on it in production.

Write-up: [Iris: an Android self-protection SDK that decides nothing](https://brennocm.github.io/articles/en-us/iris.html)
([português](https://brennocm.github.io/articles/pt-br/iris.html)).

## Why signals and not a verdict

Every client-side check ends in a boolean, and whoever controls the device controls it. The
[OWASP UnCrackable write-up](https://brennocm.github.io/articles/en-us/uncrackable.html) shows
root detection, anti-debugging and Frida detection falling to one hook each. Iris raises
the cost of that (file reads go to the kernel by direct syscall, so hooking libc does not blind
them) and reports probes it could not run, so a blinded check leaves a trace instead of a pass.
The rest is the backend's job. Details in [the threat model](docs/threat-model.md).

## The name

In Greek myth, Iris is the messenger who carries word between the gods and everyone else. Iris
does not judge or act; she delivers. The SDK has the same job: it carries what it saw on the
device to the server, and the server decides.

## What it checks

| Code | Evidence of | How |
| --- | --- | --- |
| ROOT-001 | su / Magisk binaries | `faccessat` on known paths, by direct syscall |
| ROOT-002 | test-keys system image | `Build.TAGS` |
| ROOT-003 | Magisk mounts | `/proc/self/mounts` |
| HOOK-001 | Frida, Xposed, LSPosed, Substrate libraries | `/proc/self/maps` |
| HOOK-002 | Frida agent threads | `/proc/self/task/*/comm` |
| DEBUG-001 | ptrace tracer | `TracerPid` in `/proc/self/status` |
| DEBUG-002 | debuggable build | `FLAG_DEBUGGABLE` |
| DEBUG-003 | Java debugger | `Debug.isDebuggerConnected()` |
| TAMPER-001 | repackaged APK | signer SHA-256 against your pins |
| HOOK-003 | frida-server running | port 27042 in `/proc/net/tcp*`, or a loopback connect |
| HOOK-004 | inline hooks in libc | function prologues in memory against the libc file on disk |
| HOOK-005 | Java methods replaced by Frida | Java methods that report the native modifier |
| HOOK-006 | Xposed, LSPosed and forks | hooker classes on stacks, framework classes loadable |
| ENV-001 | emulator build | `Build` fields (`ranchu`, `sdk_gphone`, Genymotion, ...) |
| ENV-002 | emulator hardware | QEMU and goldfish device files |

## Usage

```kotlin
val iris = Iris(
    IrisConfig(
        // Play Console > App integrity > App signing key certificate (SHA-256)
        signingCertSha256 = setOf("AB:CD:…"),
    ),
)

// Off the main thread: it reads several files under /proc and uses the keystore.
val challenge = api.getChallenge()                      // from the verifier, single use
val message = iris.inspectAndSign(context, challenge)
api.verify(message.toJson(), playIntegrityToken)         // requestHash = message.requestHash()
```

`inspectAndSign` signs the report with a fresh Android Keystore key whose attestation carries
the challenge, the app's package and signer, and the device's boot state, all vouched for by
the secure hardware ([ADR 0005](docs/adr/0005-report-binding-key-attestation.md)). Use
`message.requestHash()` as the Play Integrity request hash so the verdict is bound to this
report. `iris.inspect(context)` still returns the bare report when you only want to log it.

The report:

```json
{"schema":1,
 "signals":[{"id":"HOOK-001","probe":"maps","evidence":"/memfd:frida-agent-64.so (deleted)"}],
 "unavailable":[{"probe":"tracer","reason":"could not read /proc/self/status"}]}
```

Treat `unavailable` as suspicious, not as clean. The SDK never throws into the host app: a
missing `libiris.so`, an oversized `/proc` file or a keystore failure shows up as an
unavailable probe or as `attestation_error` in the message.

## Verifying on the server

[`server/`](server/README.md) is a reference verifier in Go with no dependencies outside the
standard library. It issues challenges, checks the attestation chain against Google's roots and
revocation list, the challenge, the app identity, the signature and the root of trust, then
applies a default policy: HOOK and TAMPER signals deny, ROOT, DEBUG and ENV signals and
blinded probes go to review ([ADR 0006](docs/adr/0006-reference-verifier.md)). With a service
account key it also checks the Play Integrity verdict. It ships as a distroless Docker image,
rate limits per client and shares challenges through Redis when it runs as several instances.

## Results on an emulator

Android 14 (API 34, `google_apis` x86_64), sample app, verifier trusting the emulator's test
root for the run. Full steps in [docs/scenarios.md](docs/scenarios.md).

| Scenario | Report | Decision |
| --- | --- | --- |
| Clean | ENV-001, ENV-002 (it is an emulator) | review (software attestation, no hardware root of trust) |
| Clean, Google roots only | ENV-001, ENV-002 | deny (emulator chain is not Google's production root) |
| Frida injected, libc hooked to hide it | HOOK-001, HOOK-002, HOOK-004 on `openat`, `read`, `strstr` | deny |
| Something listening on 27042, SELinux enforcing | HOOK-003 through the loopback connect | deny |

The Frida run used a script that hooks libc `openat`, `read` and `strstr` to hide the agent.
Iris reads `/proc` with raw syscalls, so the hooks never saw its reads, and the hooks
themselves show up as `jmp` instructions where the file has the functions' prologues.

## What it does not do

It cannot stop someone who controls the process: hooking the SDK's own Kotlin methods or
patching `libiris.so` gets past every probe, and the signed message proves freshness, app
identity and boot state, not that the report is honest. Name matching misses a renamed Frida,
and Magisk DenyList hides its mounts. See [the threat model](docs/threat-model.md).

## Building

Requires [mise](https://mise.jdx.dev) (it pins JDK 17 and Go) and an Android SDK with platform 35,
NDK 27.0.12077973 and CMake 3.22.1 (`ANDROID_HOME` set).

```sh
mise install
mise run check       # format (ktlint, gofmt), compile, unit tests, lint, Go vet and tests
mise run check:all   # plus release builds for all four ABIs and the Go race detector
mise run fix         # apply ktlint and gofmt

./gradlew :iris:connectedDebugAndroidTest   # device tests, with an emulator running
scripts/e2e.sh                              # challenge -> sample app -> verifier
scripts/e2e-ci.sh                           # the same, twice, with the expected decisions asserted
```

CI runs `check:all` (with a real Redis for the challenge store tests), `govulncheck`, a build
and smoke test of the verifier's Docker image, and on an emulator the device tests and
`scripts/e2e-ci.sh` for every push.

## Layout

- `core/`: detection rules and report format, pure Kotlin, tested on the JVM.
- `iris/`: the Android library; `src/main/cpp/` has the native probes, `src/androidTest/` the
  device tests.
- `sample/`: a minimal app used by the device scenarios.
- `server/`: the reference verifier (Go).
- `scripts/`: the end-to-end script and the Frida script used in [the scenarios](docs/scenarios.md).
- `docs/adr/`: design decisions. `SPEC.md`: scope and roadmap.

## License

Apache-2.0.
