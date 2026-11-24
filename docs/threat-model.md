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
- Turn that bypass into evidence: libc functions whose prologue in memory differs from the
  file are reported (HOOK-004), and Java methods replaced through Frida's bridge show up as
  native (HOOK-005).
- Spot emulators and a frida-server left on its default port.
- Report "could not check" separately from "checked and clean", so a backend can treat a
  blinded probe as suspicious.

## What Iris cannot do

- Resist an attacker who hooks the SDK's own Kotlin methods or patches `libiris.so`.
  Any client-side result can be forged by someone with full control of the process.
  Hooks placed further into a function than the first 16 bytes, on functions outside the
  checked list, or with ART hooking libraries that keep the method's flags (LSPlant does)
  are not seen by HOOK-004 and HOOK-005.
- See Magisk when DenyList hides it, or Frida when its artifacts are renamed.
- Prove that a report is honest. `inspectAndSign` proves freshness, app identity and boot
  state through key attestation (ADR 0005), but an attacker in the process can sign a clean
  report with the same API. The signals stay evidence; the attested fields are the strong part.
- Detect root on a device that keeps its bootloader locked and hides from the app, or on a
  leaked attestation keybox. Revocation and Play Integrity narrow this, they do not close it.

## Consequences for integrators

1. Never gate a security decision on the client. Send the report and decide on the server.
2. Treat `unavailable` probes as signal, not as clean.
3. Verify the signed message server-side (`server/` or an equivalent), and combine it with Play
   Integrity, rate limits and business-level anomaly detection.
4. Never set `IRIS_ALLOW_SOFTWARE_ATTESTATION` or extra roots in production.

## MASVS mapping

| Control | Covered by |
| --- | --- |
| MASVS-RESILIENCE-1 (platform integrity) | ROOT-001, ROOT-002, ROOT-003 |
| MASVS-RESILIENCE-2 (anti-tampering) | TAMPER-001 |
| MASVS-RESILIENCE-4 (anti-dynamic analysis) | HOOK-001..006, DEBUG-001..003 |
| MASVS-RESILIENCE-1 (emulator) | ENV-001, ENV-002 |
| MASVS-RESILIENCE-3 (anti-static analysis) | Out of scope (non-goal) |
