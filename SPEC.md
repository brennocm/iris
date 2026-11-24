# Iris: specification

## Problem

Mobile apps that move money or hold personal data want to know when they run on a rooted
device, under Frida or Xposed, under a debugger, or after being repackaged. Client-side checks
alone are easy to bypass: each one ends in a boolean that whoever controls the device can flip.

## What Iris is

An Android library that collects evidence (signals) about the runtime environment and returns
a report for the app's backend, which combines it with a Play Integrity verdict and decides.
The SDK raises the cost of tampering and feeds server-side decisions; it does not try to be
unbreakable.

## Users

Android developers and the security team behind them. The report is designed to be logged,
correlated and acted on by a backend.

## Scope of v0.1

| Probe | Signal | How |
| --- | --- | --- |
| su paths | ROOT-001 | `faccessat` by direct syscall on known su/Magisk paths |
| Build tags | ROOT-002 | `Build.TAGS` contains `test-keys` |
| Mounts | ROOT-003 | Magisk entries in `/proc/self/mounts` |
| Maps | HOOK-001 | Frida/Xposed/LSPosed/Substrate libraries in `/proc/self/maps` |
| Threads | HOOK-002 | Frida thread names in `/proc/self/task/*/comm` |
| Tracer | DEBUG-001 | `TracerPid` in `/proc/self/status` |
| Debuggable | DEBUG-002 | `FLAG_DEBUGGABLE` |
| Java debugger | DEBUG-003 | `Debug.isDebuggerConnected()` |
| Signing cert | TAMPER-001 | APK signer SHA-256 against developer pins |

The report can be sent alone (`inspect`) or signed with a fresh, attested Keystore key bound to
a server challenge (`inspectAndSign`, ADR 0005). `server/` verifies signed messages and applies
a default policy (ADR 0006).

## Non-goals

- Deciding, blocking or killing the app on the client.
- Obfuscation, packing or anti-disassembly of the SDK itself.
- Stopping an attacker with root and full instrumentation. Nothing on the device can.
- Collecting device identifiers or personal data.

## Roadmap

Done in v0.1: sample app and emulator scenarios (docs/scenarios.md), report binding with key
attestation, the reference verifier.

1. Wire `GoogleDecoder` into the verifier binary (service account auth) and test against a
   real Play Integrity token.
2. Run the scenarios on real devices: a locked stock phone, Magisk with DenyList, LSPosed.
3. A shared challenge store for verifiers running as several instances.
4. More signals: emulator traits, Frida ports, inline-hook checks on libc prologues, ART method
   hook detection.
5. Formatter/linter (ktlint) in `mise run check`; Maven Central publishing.
