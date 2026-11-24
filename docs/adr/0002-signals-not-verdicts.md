# 0002. Report signals; never decide on the client

## Status
Accepted, 2026-11-24.

## Context
Every client-side protection ends in a boolean or an `exit()`, and whoever controls the device
controls both. Reversing the OWASP UnCrackable apps showed it level by level: root checks,
debugger traps and Frida detection each fell to one hook, and the obfuscated secret to one
emulated function.

## Decision
`Palisade.inspect()` returns a `Report` of signals and unavailable probes, serialized as
versioned JSON. It has no `isSafe()` and never blocks, crashes or alters app behaviour. The
backend combines the report with a Play Integrity verdict and decides.

A probe that cannot run is reported as unavailable, never as clean: an attacker who blinds a
probe should leave a trace, not a pass.

## Consequences
- Integrators need a backend change to get value; the README says so up front.
- The report is unauthenticated until report binding (SPEC roadmap) lands, so it is evidence
  to correlate, not proof.
