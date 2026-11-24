#!/usr/bin/env bash
# End-to-end run against a connected device or emulator:
#   challenge from the verifier -> Iris.inspectAndSign in the sample app -> verdict.
# Needs a running iris-verifier (VERIFIER, default http://127.0.0.1:8080), the sample app
# installed, adb (ADB, default "adb"), curl and python3. FRESH=0 reuses the running app process
# instead of restarting it (needed after injecting into it, as in the Frida scenario).
# MESSAGE_OUT=file also saves the signed message the app produced.
set -euo pipefail
VERIFIER=${VERIFIER:-http://127.0.0.1:8080}
ADB=${ADB:-adb}
APP=io.github.brennocm.iris.sample
restart=-S
[ "${FRESH:-1}" = 0 ] && restart=""

challenge_b64=$(curl -fsS -X POST "$VERIFIER/v1/challenge" | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["challenge"])')
challenge_hex=$(python3 -I -c 'import base64,sys;print(base64.b64decode(sys.argv[1]).hex())' "$challenge_b64")

"$ADB" logcat -c
"$ADB" shell am start -W $restart -n "$APP/.MainActivity" --es challenge "$challenge_hex" >/dev/null

# The sample logs the message in numbered chunks; wait for the last one.
message=""
for _ in $(seq 1 30); do
  log=$("$ADB" logcat -d -s IrisSample:I | tr -d '\r')
  message=$(printf '%s\n' "$log" | python3 -I -c '
import re,sys
parts={}; total=None
for line in sys.stdin:
    m=re.search(r"message (\d+)/(\d+) (.*)$", line)
    if m: parts[int(m[1])]=m[3]; total=int(m[2])
if total and len(parts)==total: print("".join(parts[i] for i in range(1,total+1)))
')
  [ -n "$message" ] && break
  sleep 1
done
[ -n "$message" ] || { echo "no message from the sample app" >&2; exit 1; }

[ -n "${MESSAGE_OUT:-}" ] && printf '%s' "$message" >"$MESSAGE_OUT"
printf '{"message":%s}' "$message" | curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @- "$VERIFIER/v1/verify"
