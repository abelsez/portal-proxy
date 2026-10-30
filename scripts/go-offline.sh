#!/data/data/com.termux/files/usr/bin/bash
# scripts/go-offline.sh
#
# One command for a captive-portal network. Nothing here needs the internet,
# root, sudo or a second device. It writes everything to ~/portal/logs so you
# can paste one file afterwards instead of re-typing results.
#
#   bash ~/portal/go-offline.sh http://wau.wifi/login
#   PORTAL_MAC=aa:bb:cc:dd:ee:ff bash ~/portal/go-offline.sh http://wau.wifi/login
#   SKIP_NOWIFI=1 bash ~/portal/go-offline.sh http://wau.wifi/login   # skip diagnosis
set -uo pipefail

PORTAL="${1:-http://wau.wifi/login}"
BASE="${PORTAL%%/login*}"
EGRESS="${2:-${EGRESS:-http://connectivitycheck.gstatic.com/generate_204}}"
LOG="$HOME/portal/logs"
mkdir -p "$LOG"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$LOG/run-$STAMP.txt"
MAC="${PORTAL_MAC:-}"
[ -s "$HOME/portal/mac.txt" ] && [ -z "$MAC" ] && MAC="$(tr -d ' \n\r' < "$HOME/portal/mac.txt")"
export PORTAL_MAC="$MAC"

# tee everything: the transcript is the artefact
exec > >(tee "$OUT") 2>&1
echo "run: $STAMP   log: $OUT"

hr() { printf -- '-- %s %s\n' "$1" "$(printf '%.0s-' $(seq 1 $((60 - ${#1}))))"; }

hr "link"
command -v termux-wifi-connectioninfo >/dev/null && timeout 10 termux-wifi-connectioninfo | tr -d '\n ' | sed 's/","/",\n"/g' | head -8
[ -n "$MAC" ] && echo "mac (typed): $MAC" || echo "mac (typed): none — trial-login attempts will be skipped"

hr "am I really on the portal network"
PHOST="$(printf '%s' "$PORTAL" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')"
if python3 -c "import socket,sys;socket.setdefaulttimeout(4);socket.gethostbyname('$PHOST')" 2>/dev/null; then
  echo "portal host $PHOST resolves  -> you are on that network"
  ONPORTAL=1
else
  echo "portal host $PHOST does NOT resolve -> you are NOT on that network"
  echo "  (still on home wifi, or the phone fell back to mobile data)"
  ONPORTAL=0
fi
ip4="$(timeout 8 termux-wifi-connectioninfo 2>/dev/null | sed -n 's/.*"ip": *"\([^"]*\)".*/\1/p')"
[ -n "$ip4" ] && echo "local IPv4     : $ip4"

hr "walled or open"
code="$(curl -s -o /dev/null -m 8 -w '%{http_code}' "$EGRESS")"
echo "egress $EGRESS -> $code   ($([ "$code" = 204 ] && echo OPEN || echo WALLED))"
if [ "$code" = 204 ] && [ "${ONPORTAL:-0}" = 1 ]; then
  echo
  echo "!! 204 while sitting on the portal network means one of:"
  echo "   a) mobile data is still up and the phone routes around the portal,"
  echo "   b) this device was already authorised earlier (trial/MAC cache)."
  echo "   Turn mobile data OFF, forget the network, rejoin, and run this again."
fi

hr "portal fingerprint (read-only)"
curl -sS -m 12 -D "$LOG/hdr-$STAMP.txt" -o "$LOG/portal-$STAMP.html" "$PORTAL" || true
sed -n '1,12p' "$LOG/hdr-$STAMP.txt"
echo "saved: $LOG/portal-$STAMP.html  ($(wc -c < "$LOG/portal-$STAMP.html" 2>/dev/null || echo 0) bytes)"
for sig in mikrotik nomadix aruba clearpass cisco meraki purple captiveiq socialwifi witopia pfSense coeo; do
  grep -qi "$sig" "$LOG/portal-$STAMP.html" 2>/dev/null && echo "signature: $sig"
done
grep -oE '<form[^>]*>' "$LOG/portal-$STAMP.html" 2>/dev/null | head -3

hr "nowifi diagnose (read-only)"
if [ "${SKIP_NOWIFI:-0}" = "1" ]; then
  echo "skipped"
elif command -v nowifi >/dev/null 2>&1; then
  timeout 120 nowifi diagnose -r json -o "$LOG/nowifi-$STAMP.json" 2>&1 | tail -8
else
  echo "nowifi not on PATH"
fi

hr "click-through ladder"
bash "$(dirname "$0")/portal-hit.sh" "$PORTAL" "$EGRESS" | tail -30
RC=${PIPESTATUS[0]}

hr "verdict"
code="$(curl -s -o /dev/null -m 8 -w '%{http_code}' "$EGRESS")"
if [ "$code" = 204 ]; then
  echo "OPEN now. Internet works from this phone."
  echo "If the ladder did not grant it, something else did (trial expiry, MAC cache,"
  echo "a second window) — check the log before believing the ladder caused it."
else
  echo "STILL WALLED ($code)."
  echo "Next, in this order:"
  echo "  1. node ~/portal/serve-local.mjs   then open http://127.0.0.1:8000/ in Chrome"
  echo "     -> detection verdict + 'copy as curl' for the real form"
  echo "  2. nowifi forensics  (read-only evidence pack if it cannot be bypassed)"
  echo "  3. accept it: the rungs that remain need root or a tunnel domain we do not own."
fi
echo
echo "full transcript: $OUT"
