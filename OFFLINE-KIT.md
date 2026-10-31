# ~/portal — offline captive-portal kit (no root, no sudo, no internet needed)

## What is here
| file | use |
|---|---|
| `go-offline.sh` | one command: link info, walled/open check, portal fingerprint, nowifi diagnose, click-through ladder, verdict, full transcript |
| `portal-hit.sh` | the ladder on its own (if you only want to shoot) |
| `bypass.html` | browser panel: detection verdict, relay reachability, form parse, "copy as curl" |
| `serve-local.mjs` | serves `bypass.html` on http://127.0.0.1:8000 (Chrome cannot open file:// from Termux) |
| `mac.txt` | put your device MAC here (one line) so MikroTik trial attempts can run |
| `logs/` | every run is saved here; paste `run-*.txt` afterwards |

## Universal: you never need to know the portal's name
`portal-find.sh` asks six canonical probes (>204, apple "Success", msft "Microsoft Connect Test",
gstatic/gstatic-2/hicloud 204, example.com "Example Domain") what the gateway does with them:

| gateway behaviour | verdict |
|---|---|
| 30x with a Location | portal at that Location (relative redirects resolved) |
| 200 whose body is wrong | inline interception, portal is the URL you asked for |
| expected answer | that probe is open |

`go-offline.sh` with **no arguments** calls it and proceeds; `bash ~/portal/portal-find.sh --url`
prints just the URL. Name-agnostic by construction: `wau.wifi`, `edymax2.spot`, `10.0.0.1`, any host.

## The commands, in order

1) MAC (optional but worth it — MikroTik trial login uses it). Settings → Wi-Fi →
   the network → Privacy → the randomized MAC, e.g. `da:1f:2c:33:44:55`.

    printf '%s\n' 'da:1f:2c:33:44:55' > ~/portal/mac.txt

2) On any captive portal network, one command (no URL needed):

    bash ~/portal/go-offline.sh

   If the login URL is different, use it. `https://` portals: same command, https URL.
   Skip the slow diagnosis with `SKIP_NOWIFI=1 bash ~/portal/go-offline.sh <url>`.

3) Optional, in a second Termux session, for the browser rungs:

    node ~/portal/serve-local.mjs
    # then open http://127.0.0.1:8000/ in Chrome

4) Paste the result back: `~/portal/logs/run-*.txt`

## How to read the verdict
- `egress ... -> 204 (OPEN)` — online. If the ladder also printed GRANTED, check the
  log: something else may have opened it (trial timer, MAC cache, a second tab).
- `GRANTED` — the gateway accepted a request it should have refused, proven by the
  204 probe, not by the portal's own page.
- `NOT GRANTED (exit 1)` — auth is enforced server-side. The remaining rungs need
  root or a tunnel domain: accept it and say so. `nowifi forensics` gives you the
  read-only evidence pack.

## What will NOT work here, and why (do not re-test)
- `nowifi` / `sudo nowifi` — no root in Termux; only `nowifi diagnose` and
  `nowifi forensics` are read-only and usable.
- DNS/ICMP/NTP tunnels — raw sockets + a domain with NS delegation that we do not own.
- MAC clone/rotate, DHCP option 121, second interface — NET_ADMIN.
- WS/H2/H3/MASQUE/WebTransport tunnels — need a persistent server; Netlify Functions
  are request-scoped (10 s max).

## Live deployment (verified 2026-10-30T23:45Z)
- site: **https://portal-proxy-kestrel.netlify.app**  (id `527edffd-1359-43e0-af95-5d81232a88a2`, account abelsez)
- relay: `https://portal-proxy-kestrel.netlify.app/proxy/<absolute-url>`, `https://portal-proxy-kestrel.netlify.app/proxy/<percent-encoded>`, `https://portal-proxy-kestrel.netlify.app/proxy/b64/<base64url>`
- panel: `https://portal-proxy-kestrel.netlify.app/bypass.html`   health: `https://portal-proxy-kestrel.netlify.app/proxy/healthz` (key fingerprint = rotation canary)
- one bug the local harness could not see: after a 200 rewrite Netlify keeps the ORIGINAL
  path in `event.path`, so `/proxy/x` reached the handler as `/proxy/x`, not
  `/.netlify/functions/proxy/x`. Fixed in `restOfPath()`; the harness now tests both shapes.
- redeploy: `netlify deploy --prod --site 527edffd-1359-43e0-af95-5d81232a88a2`
