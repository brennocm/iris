# 0005. Bind the report to a fresh, attested Keystore key

## Status
Accepted, 2026-11-24.

## Context
A report on its own is unauthenticated JSON: it can be replayed from a clean device, built by a
script that never ran the app, or edited in transit by a proxy on the device. Play Integrity
covers part of this, but it is optional, rate limited and absent on devices without Play
services.

## Decision
`Iris.inspectAndSign(context, challenge)` runs the probes, then:

1. creates a new EC P-256 key in Android Keystore with `setAttestationChallenge(challenge)`,
   in StrongBox when the device has it and in the TEE otherwise;
2. signs the report bytes with SHA256withECDSA;
3. returns the report, the signature and the key's attestation certificate chain as an
   `IrisMessage`, and deletes the key.

The challenge comes from the backend and is single use. The key is single use too, so no
long-lived key sits on the device for an attacker to reuse.

If the keystore fails (old or broken devices), the message carries the report with an empty
chain and `attestation_error`. The backend treats that as a missing check, not as a pass.

## What this proves, and what it does not
The attestation is produced by the secure hardware, outside the app's process, so these facts
hold even when the app is hooked:

- the message was created after the backend issued the challenge (no replay);
- the key lives in the TEE or StrongBox (on a real device);
- which package created it and the SHA-256 of its signing certificate, as the platform sees
  them, so a repackaged APK is caught even if TAMPER-001 is hooked;
- the bootloader lock state and verified boot state, which flag most rooted devices.

It does **not** prove the report is honest. An attacker who controls the process can call the
same keystore API and sign a clean report. The signature binds the report to the attested
facts above; the signals inside it stay evidence. This is also why the backend weighs root of
trust and app identity more heavily than the client-side signals.

## Consequences
- One extra round trip to get a challenge, and about 50 to 300 ms of keystore work (StrongBox
  is the slow end), so integrators should call it on sensitive actions, not on every screen.
- Emulators and some devices attest in software or to test roots. The reference verifier
  rejects those unless explicitly configured for testing (ADR 0006).
- The leaf certificate's validity dates are not checked: many devices ship placeholder dates.
  Revocation comes from Google's status list instead.
