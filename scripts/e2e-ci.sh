#!/usr/bin/env bash
# End-to-end check for CI, on an emulator with nothing injected:
#   1. with Google's roots only, the verifier must deny the emulator's test attestation;
#   2. trusting the emulator's test root (checked to be "Droid Unregistered Device CA") and
#      software attestation, it must answer review, with no HOOK or TAMPER signal.
# Needs adb with one device, go, curl, python3 and openssl.
set -euo pipefail
cd "$(dirname "$0")/.."
ADB=${ADB:-adb}
PORT=${E2E_PORT:-18080}
work=$(mktemp -d)
pid=""
stop() { [ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null; pid=""; }
trap 'stop; rm -rf "$work"' EXIT
fail() { echo "e2e: $*" >&2; [ -f "$work/verifier.log" ] && tail -20 "$work/verifier.log" >&2; exit 1; }

(cd server && CGO_ENABLED=0 go build -o "$work/iris-verifier" ./cmd/iris-verifier)
./gradlew --console=plain -q :sample:assembleDebug
"$ADB" install -r sample/build/outputs/apk/debug/sample-debug.apk >/dev/null

start() {
  stop
  env PORT="$PORT" IRIS_PACKAGE_NAME=io.github.brennocm.iris.sample IRIS_RATE_LIMIT_BURST=100 "$@" \
    "$work/iris-verifier" >"$work/verifier.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 90); do
    curl -fs -o /dev/null "http://127.0.0.1:$PORT/readyz" && return
    sleep 1
  done
  fail "verifier not ready"
}
run() { VERIFIER="http://127.0.0.1:$PORT" ADB="$ADB" MESSAGE_OUT="$work/message.json" scripts/e2e.sh >"$1"; }
field() { python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }

start
run "$work/google-only.json"
[ "$(field "$work/google-only.json" action)" = deny ] || fail "expected deny with Google roots only: $(cat "$work/google-only.json")"
echo "e2e: Google roots only -> deny"

python3 -I - "$work/message.json" "$work/root.pem" <<'PY'
import base64, json, sys, textwrap
chain = json.load(open(sys.argv[1]))["chain"]
b64 = "\n".join(textwrap.wrap(chain[-1], 64))
open(sys.argv[2], "w").write(f"-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n")
PY
subject=$(openssl x509 -in "$work/root.pem" -noout -subject)
case "$subject" in
  *"Droid Unregistered Device CA"*) ;;
  *) fail "refusing to trust an unexpected root: $subject" ;;
esac

start IRIS_EXTRA_ROOTS_PEM="$work/root.pem" IRIS_ALLOW_SOFTWARE_ATTESTATION=true
run "$work/emulator-root.json"
cat "$work/emulator-root.json"; echo
[ "$(field "$work/emulator-root.json" action)" = review ] || fail "expected review with the emulator root trusted"
if python3 -I -c 'import json,sys;sys.exit(0 if any(r.startswith(("HOOK-","TAMPER-")) for r in json.load(open(sys.argv[1]))["reasons"]) else 1)' "$work/emulator-root.json"; then
  fail "HOOK or TAMPER signal on a clean emulator"
fi
echo "e2e: emulator root trusted -> review, no HOOK/TAMPER"
