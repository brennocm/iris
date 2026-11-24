# Device scenarios

How Iris was exercised on an emulator, and what it reported. Rerun these after changing a probe.

## Setup

- AVD: Android 14 (API 34), `google_apis` x86_64 image. It is a `userdebug` build, so
  `adb root` works, and `/system/xbin/su` exists.
- The sample app (`sample/`, release build, not debuggable) and the verifier from `server/`.
- `scripts/e2e.sh` asks the verifier for a challenge, launches the sample with it, collects the
  signed message from logcat and posts it to `/v1/verify`.

```sh
./gradlew :sample:assembleRelease && adb install -r sample/build/outputs/apk/release/sample-release.apk
openssl x509 -inform der -in <emulator root cert> -out emulator-root.pem   # see "Attestation" below
IRIS_PACKAGE_NAME=io.github.brennocm.iris.sample \
IRIS_EXTRA_ROOTS_PEM=emulator-root.pem IRIS_ALLOW_SOFTWARE_ATTESTATION=true \
  go run ./server/cmd/iris-verifier &
scripts/e2e.sh
```

Instrumented tests (`iris/src/androidTest`) run with `./gradlew :iris:connectedDebugAndroidTest`
and in CI on the same image.

## Results (2026-11-24, emulator API 34)

| Scenario | Report | Verifier |
| --- | --- | --- |
| Clean launch, Google roots only | no signals, nothing unavailable | **deny**: chain does not end at a trusted root |
| Clean launch, emulator root trusted | no signals, nothing unavailable | **review**: software attestation, no hardware root of trust |
| `adb root`, su present | no signals (see below) | not posted; the attestation is the same as the clean run |
| Frida injected, libc hooks hiding it | HOOK-001 `frida-agent-64.so`, HOOK-002 `gmain`, `gdbus`, `gum-js-loop` | **deny** |

### Root

`adb root` restarts adbd as root; it gives the app nothing, and the app cannot see the emulator's
`su`. SELinux denies `untrusted_app` the search of `/system/xbin`, so `faccessat` answers EACCES
for `su` and for a name that does not exist alike. Iris now checks a control name in the same
directory before reading EACCES as "present" (`PathState.fromAccess`), so this case stays
"cannot tell" instead of a false positive or a false clean. On a device where the directory is
searchable and only the file is denied, the same check reports ROOT-001.

What does flag this emulator is attestation: no hardware root of trust. On real hardware the
equivalent is an unlocked bootloader, which the verifier sends to review.

### Frida

`frida-inject` (17.27.5, Android x86_64) attached to the running sample with
`scripts/frida-hide.js`, which hooks libc `openat`, `read` and `strstr` to strip "frida" from
`/proc/self/maps` and make string matches fail, the usual bypass. The sample then inspected
again in the same process (`FRESH=0 scripts/e2e.sh`):

```sh
adb root
adb push frida-inject /data/local/tmp/ && adb push scripts/frida-hide.js /data/local/tmp/
adb shell setenforce 0     # frida-inject on the emulator; restore with setenforce 1
adb shell "/data/local/tmp/frida-inject -p $(adb shell pidof io.github.brennocm.iris.sample) -s /data/local/tmp/frida-hide.js -e &"
FRESH=0 scripts/e2e.sh
```

Iris reads `/proc` with raw syscalls, so the hooks never ran on its reads and both HOOK
signals fired. A script that hooks the syscall instruction itself or patches `libiris.so` would
get past this; that is the limit described in the threat model.

### Attestation

The emulator chain is leaf, "TEE" intermediate, then "Droid Unregistered Device CA" (Google
Test LLC), with attestation security level Software. The verifier rejects it by default. To
trust it for a test run, save the last certificate of a message's `chain` as PEM and pass it in
`IRIS_EXTRA_ROOTS_PEM`.
