#!/data/data/com.termux/files/usr/bin/bash
# test/portal-hit-vs-fake-portal.sh
# Proves the click-through engine in both directions:
#   weak portal   (validation only in JS)      -> must end GRANTED, exit 0
#   strict portal (server-side voucher check)  -> must end NOT GRANTED, exit 1
# The verdict is taken from the egress probe, so a portal that merely *lies*
# about success cannot make this test pass.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

run_case() {
  local label="$1" port="$2" strict="$3" want="$4"
  local out="$HOME/tmp/ph-$port.out"
  mkdir -p "$HOME/tmp"
  if [ "$strict" = "1" ]; then
    STRICT=1 node test/fake-portal.mjs "$port" >"$HOME/tmp/fp-$port.log" 2>&1 &
  else
    node test/fake-portal.mjs "$port" >"$HOME/tmp/fp-$port.log" 2>&1 &
  fi
  local pid=$!
  for _ in $(seq 1 40); do
    curl -s -o /dev/null -m 2 "http://127.0.0.1:$port/" && break
    sleep 0.2
  done
  bash scripts/portal-hit.sh "http://127.0.0.1:$port/" "http://127.0.0.1:$port/generate_204" >"$out" 2>&1
  local code=$?
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  if [ "$want" = "GRANTED" ]; then
    if [ $code -eq 0 ] && grep -q '^GRANTED' "$out"; then
      echo "PASS  $label -> GRANTED (exit 0)"
      return 0
    fi
  else
    if [ $code -eq 1 ] && grep -q '^NOT GRANTED' "$out"; then
      local n
      n=$(grep -cE '^ *[0-9]+ +(GET|POST)' "$out" 2>/dev/null || true)
      echo "PASS  $label -> NOT GRANTED (exit 1), ${n:-0} attempt(s) fired"
      return 0
    fi
  fi
  echo "FAIL  $label -> wanted $want, exit was $code"
  sed -n '/attempts/,$p' "$out" | head -12
  return 1
}

# MikroTik-shaped portal: /login with username+password+dst.
run_mikrotik() {
  local label="$1" port="$2" accept="$3" want_attempt="$4" mac="${5:-}"
  local out="$HOME/tmp/ph-$port.out"
  MIKROTIK=1 ACCEPT_USER="$accept" node test/fake-portal.mjs "$port" >"$HOME/tmp/fp-$port.log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 40); do curl -s -o /dev/null -m 2 "http://127.0.0.1:$port/" && break; sleep 0.2; done
  PORTAL_MAC="$mac" bash scripts/portal-hit.sh "http://127.0.0.1:$port/" "http://127.0.0.1:$port/generate_204" >"$out" 2>&1
  local code=$?
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  local got
  got=$(sed -n 's/.*granted by attempt \([0-9]*\).*/\1/p' "$out" | head -1)
  if [ $code -eq 0 ] && [ "$got" = "$want_attempt" ]; then
    echo "PASS  $label -> granted by attempt $got (expected $want_attempt)"
    return 0
  fi
  echo "FAIL  $label -> exit $code, granted by '${got:-none}', expected $want_attempt"
  sed -n '/attempts/,/verdict/p' "$out" | head -12
  return 1
}

rc=0
run_case "weak portal (JS-only validation)" 18080 0 GRANTED || rc=1
run_case "strict portal (server-side voucher)" 18081 1 NOTGRANTED || rc=1
run_mikrotik "mikrotik: anonymous login accepted (attempt 1 = empty creds)" 18082 "" 1 || rc=1
run_mikrotik "mikrotik: only T-<MAC> trial login works" 18083 "T-aa-bb-cc-dd-ee-ff" 6 "aa:bb:cc:dd:ee:ff" || rc=1
exit $rc
