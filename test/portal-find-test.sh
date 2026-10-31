#!/data/data/com.termux/files/usr/bin/bash
# test/portal-find-test.sh
# Proves universal discovery in both directions, with no real portal involved:
#   a local gateway that 302s  -> must be reported as a portal candidate
#   a local server that 204s   -> must be reported as open (no candidates)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
rc=0

start() { # $1 port, $2 mode
  if [ "$2" = "portal" ]; then
    MIKROTIK=1 ACCEPT_USER=nobody node test/fake-portal.mjs "$1" >"$HOME/tmp/pf-$1.log" 2>&1 &
  else
    node -e "require('http').createServer((q,r)=>{r.writeHead(204,{'content-length':'0'});r.end()}).listen($1,'127.0.0.1')" >"$HOME/tmp/pf-$1.log" 2>&1 &
  fi
  echo $!
  for _ in $(seq 1 40); do curl -s -o /dev/null -m 2 "http://127.0.0.1:$1/" && break; sleep 0.2; done
}

mkdir -p "$HOME/tmp"
pid=$(start 18095 portal)
out=$(PROBE_SET="http://127.0.0.1:18095/generate_204|204;http://127.0.0.1:18095/generate_204|204" bash "$HOME/portal/portal-find.sh" 2>&1)
kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
url=$(printf '%s' "$out" | PROBE_SET="" bash "$HOME/portal/portal-find.sh" --url -q 2>/dev/null)
if printf '%s' "$out" | grep -q 'portal'; then
  echo "PASS  redirecting gateway -> reported as portal"
else
  echo "FAIL  redirecting gateway not reported"; printf '%s\n' "$out" | head -8; rc=1
fi
if printf '%s' "$out" | grep -q '127.0.0.1:18095/$'; then
  echo "PASS  portal URL resolved from the Location header"
else
  echo "FAIL  could not resolve the portal URL from the redirect"; printf '%s\n' "$out" | tail -6; rc=1
fi

pid=$(start 18096 open)
out=$(PROBE_SET="http://127.0.0.1:18096/generate_204|204" bash "$HOME/portal/portal-find.sh" 2>&1)
kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
if printf '%s' "$out" | grep -q 'No portal found'; then
  echo "PASS  204 gateway -> correctly reported as open"
else
  echo "FAIL  204 gateway misread as a portal"; printf '%s\n' "$out" | tail -6; rc=1
fi
exit $rc
