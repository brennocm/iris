# Threat model

## Assets

- The app's server-side business decisions (payments, account changes, promotions).
- The integrity of the report the SDK produces.

## Adversary

Someone who controls the device the app runs on. They can root it (Magisk with DenyList and
Zygisk modules), inject Frida in spawn or attach mode, use Xposed/LSPosed, attach a debugger,
or decompile, modify and re-sign the APK. They can read and change anything in the app's
process, including this SDK.

## What Iris can do

- Detect default and lazy setups: stock Frida server and gadget names, visible Magisk mounts,
  a ptrace tracer, a repackaged APK, a debuggable build.
- Avoid the cheapest bypass seen in practice: hooking libc functions (`open`, `read`,
  `strstr`) used by the checks. File access goes to the kernel directly on 64-bit ABIs.
- Report "could not check" separately from "checked and clean", so a backend can treat a
  blinded probe as suspicious.

## What Iris cannot do

- Resist an attacker who hooks the SDK's own Kotlin methods or patches `libiris.so`.
  Any client-side result can be forged by someone with full control of the process.
- See Magisk when DenyList hides it, or Frida when its artifacts are renamed.
- Prove anything to the backend by itself. Until report binding (SPEC roadmap item 3) lands, a
  report is unauthenticated evidence; Play Integrity is the attested part.

## Consequences for integrators

1. Never gate a security decision on the client. Send the report and decide on the server.
2. Treat `unavailable` probes as signal, not as clean.
3. Combine with Play Integrity verified server-side, rate limits and business-level anomaly
   detection.

## MASVS mapping

| Control | Covered by |
| --- | --- |
| MASVS-RESILIENCE-1 (platform integrity) | ROOT-001, ROOT-002, ROOT-003 |
| MASVS-RESILIENCE-2 (anti-tampering) | TAMPER-001 |
| MASVS-RESILIENCE-4 (anti-dynamic analysis) | HOOK-001, HOOK-002, DEBUG-001..003 |
| MASVS-RESILIENCE-3 (anti-static analysis) | Out of scope (non-goal) |
