# 0007. Publish to Maven Central with the vanniktech plugin

## Status
Accepted, 2026-11-24.

## Context
Integrators expect `implementation("group:artifact:version")`. Since OSSRH shut down, Maven
Central takes uploads only through the Central Portal API, and every artifact needs a POM with
license, SCM and developer, a sources jar, a javadoc jar and a GPG signature. Doing that with
plain `maven-publish` and `signing` means writing the Portal upload (bundle, poll, release)
ourselves.

## Decision
Use `com.vanniktech.maven.publish` 0.30.0, the plugin most Android libraries use for the Portal.
It is a build-time dependency only; nothing reaches the AAR. Releases run from a `v*` tag in
`.github/workflows/release.yml`, behind a GitHub environment with a required reviewer, and stop
at a validated deployment that the owner publishes by hand. Signing is enabled only when a key
is provided, so `check:all` can publish to a local staging repository and keep the setup tested.

The AAR's javadoc jar holds a README: AGP 8.7's bundled Dokka cannot read `:core`'s sealed types
(PermittedSubclasses needs ASM 9). The KDoc ships in the sources jar.

## Consequences
- A release needs the owner's Central Portal token and GPG key (docs/releasing.md); the agent
  never has them.
- Upgrading AGP may restore a real javadoc jar; revisit then.
