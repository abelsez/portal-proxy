// netlify/functions/proxy.js
//
// Serverless HTTP proxy (CommonJS, Netlify Functions Node 18+).
// Public surface:
//   GET|POST|... /proxy/<absolute-url>            -> proxied
//   GET|POST|... /proxy/https%3A%2F%2Fhost%2Fx    -> proxied (percent-encoded target)
//   GET|POST|... /proxy/b64/<base64url(url)>      -> proxied (escape hatch for odd URLs)
//   GET          /proxy/healthz                   -> config + key fingerprint (no secret leaked)
//
// NETLIFY_API_KEY is read from process.env ONLY here. It is never sent upstream,
// never echoed back, and never embedded in a response body. Its only uses are:
//   1. fail-closed check that the env var is actually wired to this deploy,
//   2. leak-guard: any inbound Authorization header carrying that value is dropped,
//   3. a truncated SHA-256 fingerprint exposed by /healthz so you can prove a
//      rotation took effect without ever moving the secret.
'use strict';

const crypto = require('node:crypto');

const FUNCTION_PREFIX = '/.netlify/functions/proxy';

// RFC 7230 §6.1 hop-by-hop headers + what a lambda must never forward verbatim.
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'trailers',
  'transfer-encoding',
  'upgrade',
  'http2-settings',
  'host',
  'content-length',
]);

// Headers injected by Netlify's edge that describe *our* edge, not the client.
const EDGE_PREFIXES = ['x-nf-', 'x-forwarded-', 'x-netlify-', 'x-bb-'];

// Response headers we always recompute or must not copy.
const STRIP_RESPONSE = new Set([
  ...HOP_BY_HOP,
  'content-encoding', // upstream gzip would be double-decoded by undici -> corrupt body
  'set-cookie',       // handled separately (multi-value)
]);

// Headers that break a proxied page from a different origin. Off by default
// because a captive-portal page with its own CSP renders blank otherwise.
const SECURITY_HEADERS = [
  'content-security-policy',
  'content-security-policy-report-only',
  'x-frame-options',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
  'strict-transport-security',
];

const TEXTY =
  /^(text\/|application\/(json|javascript|ecmascript|xml|x-www-form-urlencoded|ld\+json|x-ndjson|graphql)|image\/svg\+xml)/i;

const num = (v, d) => {
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? n : d;
};

const env = () => ({
  key: process.env.NETLIFY_API_KEY || '',
  allowlist: (process.env.PROXY_ALLOWLIST || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean),
  allowPrivate: process.env.PROXY_ALLOW_PRIVATE === '1',
  stripSecurity: process.env.PROXY_KEEP_SECURITY_HEADERS !== '1',
  sharedToken: process.env.PROXY_TOKEN || '',
  timeoutMs: num(process.env.PROXY_TIMEOUT_MS, 8000), // Netlify sync limit is 10 s
  maxBytes: num(process.env.PROXY_MAX_BYTES, 5500000), // Netlify response cap is 6 MB
});

function json(statusCode, code, message, extra = {}) {
  return {
    statusCode,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'access-control-allow-origin': '*',
      'x-proxy-error': code,
    },
    body: JSON.stringify({ ok: false, error: { code, message }, ...extra }, null, 2),
  };
}

const err = {
  missingKey: () =>
    json(500, 'missing_key', 'NETLIFY_API_KEY is not set on this deploy. Set it in Site configuration -> Environment variables, then redeploy.'),
  missingTarget: () =>
    json(400, 'missing_target', 'No target URL. Use /proxy/https://example.com/path, /proxy/<percent-encoded-url>, or /proxy/b64/<base64url>.'),
  badTarget: (why) => json(400, 'bad_target', `Target URL is not parseable: ${why}`),
  scheme: (scheme) =>
    json(400, 'scheme_not_allowed', `Scheme "${scheme}" is not allowed. Only http and https are proxied.`),
  hostBlocked: (host) =>
    json(403, 'host_not_allowed', `Host "${host}" is not in PROXY_ALLOWLIST.`),
  privateHost: (host) =>
    json(403, 'private_host_blocked', `Host "${host}" is loopback/link-local/private. Set PROXY_ALLOW_PRIVATE=1 to allow it deliberately.`),
  unauthorized: () => json(401, 'unauthorized', 'PROXY_TOKEN is set on this deploy; send it as the x-proxy-token header or ?__pt= query value.'),
  tooLarge: (n) => json(502, 'payload_too_large', `Upstream response exceeds PROXY_MAX_BYTES (${n} bytes).`),
  upstream: (why, extra) => json(502, 'upstream_error', `Upstream request failed: ${why}`, extra),
};

function isPrivateHost(host) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (h === '0.0.0.0' || h === '::1' || h === '::' || h === '0') return true;

  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true; // link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a === 192 && b === 0) return true;
    if (a >= 224) return true;
    return false;
  }

  if (h.includes(':')) {
    // IPv6 literal. Unique-local, link-local, v4-mapped, unspecified.
    if (h.startsWith('fc') || h.startsWith('fd')) return true;
    if (h.startsWith('fe80')) return true;
    if (h.startsWith('::ffff:')) return true;
    return false;
  }
  return false;
}

function allowlistAllows(cfg, url) {
  if (cfg.allowlist.length === 0) return true;
  const host = url.hostname.toLowerCase();
  const hostPort = url.host.toLowerCase();
  return cfg.allowlist.some((entry) => {
    if (entry === host || entry === hostPort) return true;
    if (entry.startsWith('*.')) {
      const bare = entry.slice(2);
      return host === bare || host.endsWith(`.${bare}`);
    }
    if (entry.startsWith('.')) return host.endsWith(entry);
    return false;
  });
}

// The path after the function prefix, with Netlify's cosmetic damage repaired:
// it may arrive percent-encoded, with "//" collapsed to "/", or as base64url.
// Matches any function name, so the streaming twin in proxy-stream.mjs can share it.
const FUNCTION_RE = /^\/\.netlify\/functions\/[^/]+\/?/;
function restOfPath(eventPath) {
  let rest = String(eventPath || '');
  if (rest.startsWith(FUNCTION_PREFIX)) rest = rest.slice(FUNCTION_PREFIX.length);
  rest = rest.replace(FUNCTION_RE, '').replace(/^\/+/, '');
  return rest;
}

function b64urlDecode(s) {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const buf = Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
  return buf.toString('utf8');
}

function extractTarget(event) {
  const cfg = env();
  const rest = restOfPath(event.path);
  const rawQuery = typeof event.rawQuery === 'string' ? event.rawQuery : '';

  if (!rest) return { error: err.missingTarget() };

  let candidate = rest;
  let guard = 0;

  // /proxy/b64/<base64url> — for URLs that no path rewriting survives intact.
  if (/^b64\//i.test(candidate)) {
    try {
      candidate = b64urlDecode(candidate.slice(4).split('/')[0] || '');
    } catch {
      return { error: err.badTarget('base64url decode failed') };
    }
  }

  // Percent-encoded absolute URL: /proxy/https%3A%2F%2Fhost%2Fpath
  while (/%[0-9a-f]{2}/i.test(candidate) && guard++ < 3) {
    try {
      const decoded = decodeURIComponent(candidate);
      if (decoded === candidate) break;
      candidate = decoded;
    } catch {
      break; // malformed %-sequence: keep what we have, URL() will judge it
    }
  }

  // Netlify collapses repeated slashes in the path, so "https://host" can arrive
  // as "https:/host" or even "https:host". Repair exactly one separator.
  candidate = candidate.replace(/^(https?):\/{0,3}/i, (_, s) => `${s.toLowerCase()}://`);

  // A bare "<base64url>" (no slash) that decodes to a URL.
  if (!/^https?:\/\//i.test(candidate) && /^[A-Za-z0-9_-]{12,}$/.test(candidate)) {
    const maybe = b64urlDecode(candidate);
    if (/^https?:\/\//i.test(maybe)) candidate = maybe;
  }

  if (!/^[a-z][a-z0-9+.-]*:/i.test(candidate)) {
    return { error: err.badTarget('missing scheme; an absolute http(s) URL is required') };
  }

  // Re-attach the query string Netlify split off, unless the target carried one.
  if (!candidate.includes('?') && rawQuery) {
    let q = rawQuery;
    if (cfg.sharedToken) {
      const params = new URLSearchParams(q);
      if (params.has('__pt')) {
        params.delete('__pt');
        q = params.toString();
      }
    }
    if (q) candidate += `?${q}`;
  }

  let url;
  try {
    url = new URL(candidate);
  } catch (e) {
    return { error: err.badTarget(String(e && e.message ? e.message : e)) };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { error: err.scheme(url.protocol.replace(/:$/, '')) };
  }
  url.username = '';
  url.password = '';
  return { url, cfg };
}

function buildRequestHeaders(event, cfg) {
  const out = new Headers();
  const inbound = event.headers || {};
  for (const [name, value] of Object.entries(inbound)) {
    const lk = name.toLowerCase();
    if (HOP_BY_HOP.has(lk)) continue;
    if (lk === 'accept-encoding') continue; // we buffer; ask for identity
    if (lk === '__pt' || lk === 'x-proxy-token') continue;
    if (EDGE_PREFIXES.some((p) => lk.startsWith(p))) continue;
    if (lk === 'x-real-ip' || lk === 'forwarded') continue;
    if (value === undefined || value === null) continue;
    const v = Array.isArray(value) ? value.join(', ') : String(value);
    // Leak guard: never let a Netlify credential ride along to a third party.
    if (cfg.key && v.includes(cfg.key)) continue;
    out.set(lk, v);
  }
  // Tell the upstream who is really calling, so portal logs/debugging make sense.
  const clientIp = (event.headers || {})['x-nf-client-connection-ip'];
  if (clientIp) out.set('x-forwarded-for', clientIp);
  out.set('accept-encoding', 'identity'); // no gzip -> no content-encoding mismatch
  return out;
}

function buildResponseHeaders(upstream, cfg, target) {
  const out = {};
  const cookies = [];
  for (const [name, value] of upstream.headers) {
    const lk = name.toLowerCase();
    if (lk === 'set-cookie') {
      cookies.push(value);
      continue;
    }
    if (STRIP_RESPONSE.has(lk)) continue;
    if (cfg.stripSecurity && SECURITY_HEADERS.includes(lk)) continue;
    out[lk] = value;
  }
  out['cache-control'] = 'no-store';
  out['access-control-allow-origin'] = '*';
  out['access-control-expose-headers'] = '*';
  out['x-proxy-target'] = `${target.protocol}//${target.host}${target.pathname}`;
  out['x-proxy-upstream-status'] = String(upstream.status);
  if (cookies.length) out['set-cookie'] = cookies.join(', ');
  return out;
}

function tokenOk(event, cfg) {
  if (!cfg.sharedToken) return true;
  const h = event.headers || {};
  const sent = h['x-proxy-token'] || h['X-Proxy-Token'] || '';
  if (sent && sent === cfg.sharedToken) return true;
  const q = new URLSearchParams(event.rawQuery || '');
  const fromQuery = q.get('__pt') || '';
  return fromQuery === cfg.sharedToken;
}

function fingerprint(key) {
  return key ? crypto.createHash('sha256').update(key).digest('hex').slice(0, 8) : 'unset';
}

function health(event, cfg) {
  const rest = restOfPath(event.path).toLowerCase();
  if (rest !== 'healthz' && rest !== 'healthz/') return null;
  return {
    statusCode: 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'access-control-allow-origin': '*',
    },
    body: JSON.stringify(
      {
        ok: true,
        service: 'portal-proxy',
        key_present: Boolean(cfg.key),
        key_fingerprint: fingerprint(cfg.key), // 8 hex of SHA-256: rotation canary, not the secret
        allowlist: cfg.allowlist.length ? cfg.allowlist : null,
        allowlist_mode: cfg.allowlist.length ? 'restricted' : 'open',
        private_hosts: cfg.allowPrivate ? 'allowed' : 'blocked',
        shared_token_required: Boolean(cfg.sharedToken),
        strip_security_headers: cfg.stripSecurity,
        timeout_ms: cfg.timeoutMs,
        max_bytes: cfg.maxBytes,
        runtime: process.version,
      },
      null,
      2
    ),
  };
}

exports.handler = async function handler(event) {
  const cfg = env();

  const probe = health(event, cfg);
  if (probe) return probe;

  if (!cfg.key) return err.missingKey();
  if (!tokenOk(event, cfg)) return err.unauthorized();

  const parsed = extractTarget(event);
  if (parsed.error) return parsed.error;
  const { url } = parsed;

  if (!cfg.allowPrivate && isPrivateHost(url.hostname)) return err.privateHost(url.hostname);
  if (!allowlistAllows(cfg, url)) return err.hostBlocked(url.hostname);

  const method = (event.httpMethod || 'GET').toUpperCase();
  let body;
  if (method !== 'GET' && method !== 'HEAD') {
    body = event.isBase64Encoded ? Buffer.from(event.body || '', 'base64') : event.body || undefined;
    if (body && body.length === 0) body = undefined;
  }

  let upstream;
  const started = Date.now();
  try {
    upstream = await fetch(url.toString(), {
      method,
      headers: buildRequestHeaders(event, cfg),
      body,
      redirect: 'manual', // the browser must see 3xx: portal redirects are the signal
      signal: AbortSignal.timeout(cfg.timeoutMs),
      // undici v6 needs this for methods like PATCH/PROPFIND not to be mangled
      duplex: 'half',
    });
  } catch (e) {
    const name = (e && e.name) || 'Error';
    const reason = name === 'TimeoutError' ? `timed out after ${cfg.timeoutMs} ms` : (e && e.message) || String(e);
    return err.upstream(reason, { target: `${url.protocol}//${url.host}` });
  }

  const declared = Number(upstream.headers.get('content-length') || 0);
  if (declared && declared > cfg.maxBytes) return err.tooLarge(declared);

  const headers = buildResponseHeaders(upstream, cfg, url);
  headers['x-proxy-ms'] = String(Date.now() - started);

  if (method === 'HEAD' || upstream.status === 204 || upstream.status === 304) {
    return { statusCode: upstream.status, headers, body: '' };
  }

  let buf;
  try {
    buf = Buffer.from(await upstream.arrayBuffer());
  } catch (e) {
    return err.upstream(`body read failed: ${(e && e.message) || e}`);
  }
  if (buf.length > cfg.maxBytes) return err.tooLarge(buf.length);

  const contentType = upstream.headers.get('content-type') || '';
  const asText = !buf.length || TEXTY.test(contentType);

  return {
    statusCode: upstream.status,
    headers,
    body: buf.length === 0 ? '' : asText ? buf.toString('utf8') : buf.toString('base64'),
    isBase64Encoded: buf.length > 0 && !asText,
  };
};

// Exported for the local harness (and any future streaming sibling). Not part of
// the HTTP surface: nothing here is reachable from a request.
exports._internals = {
  env,
  err,
  json,
  restOfPath,
  extractTarget,
  buildRequestHeaders,
  buildResponseHeaders,
  isPrivateHost,
  allowlistAllows,
  tokenOk,
  fingerprint,
  STRIP_RESPONSE,
  SECURITY_HEADERS,
};
