# Releasing to Maven Central

Two artifacts are published under the group `io.github.brennocm.iris`:

| Artifact | What |
| --- | --- |
| `iris` (AAR) | The Android library, with `libiris.so` for arm64-v8a, armeabi-v7a, x86_64 and x86 |
| `iris-core` (JAR) | Rules and report format, a dependency of `iris` |

```kotlin
dependencies {
    implementation("io.github.brennocm.iris:iris:0.1.0")
}
```

Publishing uses [`com.vanniktech.maven.publish`](https://github.com/vanniktech/gradle-maven-publish-plugin)
against the Central Portal (OSSRH is shut down). Coordinates and POM metadata live in
`gradle.properties` and each module's `gradle.properties`.

## One-time setup (owner)

1. Sign in at <https://central.sonatype.com> with the GitHub account and verify the namespace
   `io.github.brennocm` (GitHub namespaces verify automatically by repository).
2. Generate a user token (Account > Generate User Token). It is a username and a password, not
   the account login.
3. Create a GPG key used only for releases, and publish its public half:
   ```sh
   gpg --quick-gen-key 'Iris releases' rsa4096 sign 2y
   gpg --keyserver keyserver.ubuntu.com --send-keys <KEY_ID>
   gpg --armor --export-secret-keys <KEY_ID>   # value for SIGNING_KEY
   ```
4. In GitHub, create the environment `maven-central` (Settings > Environments) with yourself as
   required reviewer, and add these secrets to it, not to the repository:
   `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD` (the token), `SIGNING_KEY`,
   `SIGNING_KEY_PASSWORD`.

## Each release

1. Set `VERSION_NAME` in `gradle.properties`, update the README, commit, and make sure CI is
   green on that commit.
2. Tag and push: `git tag v0.1.0 && git push origin v0.1.0`.
3. Approve the `release` workflow run when GitHub asks (the environment's reviewer rule).
4. The workflow runs `check:all`, signs and uploads. In the Central Portal (Deployments), check
   the validated deployment and press Publish. Releases are permanent: a version can never be
   replaced, only superseded.

## Checking the output without publishing

```sh
./gradlew publishAllPublicationsToStagingRepository
find build/staging-repo -type f
```

`check:all` runs this too, unsigned, so a broken publishing setup fails CI. With
`ORG_GRADLE_PROJECT_signingInMemoryKey` set, every artifact also gets an `.asc` signature.
