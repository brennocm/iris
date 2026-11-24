# Iris

Android runtime self-protection SDK. Iris looks for root, instrumentation (Frida, Xposed,
LSPosed), debuggers and repackaging, and returns what it found as a report for your backend.
It never blocks or kills the app: the decision belongs on the server, next to a Play Integrity
verdict.

> **Status:** early (v0.1, unpublished). The probes build and the detection logic is
> unit-tested, but they have not yet been exercised on rooted and instrumented devices. Do not
> rely on it in production yet.

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

## Usage

```kotlin
val iris = Iris(
    IrisConfig(
        // Play Console > App integrity > App signing key certificate (SHA-256)
        signingCertSha256 = setOf("AB:CD:…"),
    ),
)

// Off the main thread: it reads several files under /proc.
val report = iris.inspect(context)
api.sendEnvironmentReport(report.toJson(), playIntegrityToken)
```

The report:

```json
{"schema":1,
 "signals":[{"id":"HOOK-001","probe":"maps","evidence":"/data/local/tmp/re.frida.server/frida-agent-64.so"}],
 "unavailable":[{"probe":"tracer","reason":"could not read /proc/self/status"}]}
```

Treat `unavailable` as suspicious, not as clean.

## Building

Requires [mise](https://mise.jdx.dev) (it pins JDK 17) and an Android SDK with platform 35,
NDK 27.0.12077973 and CMake 3.22.1 (`ANDROID_HOME` set).

```sh
mise install
mise run check       # compile, unit tests, lint
mise run check:all   # plus the release AAR for all four ABIs
```

## Layout

- `core/`: detection rules and report format, pure Kotlin, tested on the JVM.
- `iris/`: the Android library; `src/main/cpp/` has the native probes.
- `docs/adr/`: design decisions. `SPEC.md`: scope and roadmap.

## License

Apache-2.0.
