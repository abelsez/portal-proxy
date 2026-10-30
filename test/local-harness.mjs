// test/local-harness.mjs
//
// Runs the real Netlify handler against a real local upstream, with no Netlify
// runtime involved. Proves the parsing/forwarding/error paths before you spend a
// deploy on them.
//
//   node test/local-harness.mjs
//
// Nothing here reads, prints or writes a real Netlify token: NETLIFY_API_KEY is
// set to a throwaway value for the duration of the process.
import http from 'node:http';
import zlib from 'node:zlib';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { handler } = require('../netlify/functions/proxy.js');

const REAL_KEY_LOOKS_LIKE = 'nfp_TEST_ONLY_DO_NOT_USE_000000000000000000';
process.env.NETLIFY_API_KEY = REAL_KEY_LOOKS_LIKE;
delete process.env.PROXY_ALLOWLIST;
delete process.env.PROXY_ALLOW_PRIVATE;
delete process.env.PROXY_TOKEN;

const upstream = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks).toString('utf8');
    if (req.url.startsWith('/generate_204')) {
      res.writeHead(204, { 'content-length': '0' });
      return res.end();
    }
    if (req.url.startsWith('/binary')) {
      const buf = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0x80, 0x81]);
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(buf.length) });
      return res.end(buf);
    }
    if (req.url.startsWith('/gzip')) {
      // A real gzip body: undici decodes it, we must strip content-encoding or
      // the client decodes an already-decoded body and shows garbage.
      const gz = zlib.gzipSync(Buffer.from('compressed portal page'));
      res.writeHead(200, { 'content-type': 'text/html', 'content-encoding': 'gzip', 'content-length': String(gz.length) });
      return res.end(gz);
    }
    if (req.url.startsWith('/lyinggzip')) {
      // Upstream claims gzip but sends plain text: undici's decoder throws.
      // Documented behaviour: clean JSON 502, never a half-corrupt body.
      res.writeHead(200, { 'content-type': 'text/plain', 'content-encoding': 'gzip' });
      return res.end('not really gzipped');
    }
    const code = req.url.startsWith('/boom') ? 503 : req.url.startsWith('/missing') ? 404 : 200;
    res.writeHead(code, { 'content-type': 'text/html; charset=utf-8', 'x-upstream': 'yes' });
    res.end(
      JSON.stringify({
        method: req.method,
        url: req.url,
        body,
        sawAuth: req.headers.authorization || null,
        acceptEncoding: req.headers['accept-encoding'] || null,
        host: req.headers.host,
      })
    );
  });
});

const listen = () => new Promise((r) => upstream.listen(0, '127.0.0.1', () => r(upstream.address().port)));
const close = () => new Promise((r) => upstream.close(r));

let pass = 0;
let fail = 0;
const rows = [];

function ev(path, { method = 'GET', headers = {}, body = null, rawQuery = '' } = {}) {
  return { path, httpMethod: method, headers, body, rawQuery, isBase64Encoded: false };
}

async function check(name, event, expect) {
  const t0 = Date.now();
  const res = await handler(event);
  const ms = Date.now() - t0;
  const problems = [];
  for (const [k, v] of Object.entries(expect)) {
    if (k === 'json') {
      let parsed;
      try {
        parsed = JSON.parse(res.body);
      } catch {
        problems.push(`body is not JSON: ${String(res.body).slice(0, 80)}`);
        continue;
      }
      for (const [jk, jv] of Object.entries(v)) {
        const got = jk.split('.').reduce((o, p) => (o == null ? o : o[p]), parsed);
        if (got !== jv) problems.push(`${jk}: expected ${JSON.stringify(jv)} got ${JSON.stringify(got)}`);
      }
    } else if (k === 'bodyIncludes') {
      const hay = res.isBase64Encoded ? Buffer.from(res.body, 'base64').toString('utf8') : String(res.body);
      for (const needle of Array.isArray(v) ? v : [v]) {
        if (!hay.includes(needle)) problems.push(`body missing ${JSON.stringify(needle)} -> ${hay.slice(0, 160)}`);
      }
    } else if (k === 'bodyExcludes') {
      const hay = res.isBase64Encoded ? Buffer.from(res.body, 'base64').toString('utf8') : String(res.body);
      if (hay.includes(v)) problems.push(`body leaked ${JSON.stringify(v)}`);
    } else if (k === 'header') {
      const got = res.headers[v[0].toLowerCase()];
      if (got !== v[1]) problems.push(`header ${v[0]}: expected ${JSON.stringify(v[1])} got ${JSON.stringify(got)}`);
    } else if (k === 'headerAbsent') {
      if (res.headers[v.toLowerCase()] !== undefined) problems.push(`header ${v} should be absent`);
    } else if (res[k] !== v) {
      problems.push(`${k}: expected ${JSON.stringify(v)} got ${JSON.stringify(res[k])}`);
    }
  }
  const ok = problems.length === 0;
  ok ? pass++ : fail++;
  rows.push({ name, status: res.statusCode, ms, ok, problems });
  return res;
}

const port = await listen();
const base = `http://127.0.0.1:${port}`;
const p = (s) => `/.netlify/functions/proxy/${s}`;
const pub = (s) => `/proxy/${s}`; // what Netlify's 200 rewrite actually leaves in event.path

try {
  // --- config / parsing -----------------------------------------------------
  const saved = process.env.NETLIFY_API_KEY;
  delete process.env.NETLIFY_API_KEY;
  await check('missing key -> 500 missing_key', ev(p(base + '/hello')), {
    statusCode: 500,
    json: { 'error.code': 'missing_key' },
  });
  process.env.NETLIFY_API_KEY = saved;

  await check('healthz -> fingerprint, no secret', ev(p('healthz')), {
    statusCode: 200,
    json: { ok: true, key_present: true },
    bodyExcludes: saved,
  });

  await check('no target -> 400', ev('/.netlify/functions/proxy'), {
    statusCode: 400,
    json: { 'error.code': 'missing_target' },
  });

  await check('no target with trailing slash -> 400', ev('/.netlify/functions/proxy/'), {
    statusCode: 400,
    json: { 'error.code': 'missing_target' },
  });

  await check('file:// scheme -> 400', ev(p('file:///etc/passwd')), {
    statusCode: 400,
    json: { 'error.code': 'scheme_not_allowed' },
  });

  // --- the public /proxy/* shape (regression: the deployed rewrite preserves it)
  process.env.PROXY_ALLOW_PRIVATE = '1'; // targets below are on loopback
  await check('public /proxy/<target> -> 200', ev(pub(base + '/publicshape')), {
    statusCode: 200,
    bodyIncludes: '"/publicshape"',
  });
  await check('public /proxy/healthz -> healthz JSON', ev(pub('healthz')), {
    statusCode: 200,
    json: { ok: true, key_present: true },
  });
  await check('public /proxy/ (empty) -> 400 missing_target', ev(pub('')), {
    statusCode: 400,
    json: { 'error.code': 'missing_target' },
  });
  await check('public /proxy/https%3A%2F%2F... -> 200', ev(pub(encodeURIComponent(base + '/encodedpub'))), {
    statusCode: 200,
    bodyIncludes: '/encodedpub',
  });

  // --- success paths --------------------------------------------------------
  process.env.PROXY_ALLOW_PRIVATE = '1';
  await check('plain absolute target -> 200', ev(p(base + '/hello')), {
    statusCode: 200,
    header: ['x-upstream', 'yes'],
    bodyIncludes: ['"method":"GET"', '"acceptEncoding":"identity"'],
  });

  await check('percent-encoded target -> 200', ev(p(encodeURIComponent(base + '/enc'))), {
    statusCode: 200,
    bodyIncludes: '"url":"/enc"',
  });

  await check('collapsed-slash target -> 200', ev(p(base.replace('http://', 'http:/') + '/collapsed')), {
    statusCode: 200,
    bodyIncludes: '/collapsed',
  });

  const b64 = Buffer.from(base + '/b64path').toString('base64url');
  await check('base64url target -> 200', ev(p('b64/' + b64)), {
    statusCode: 200,
    bodyIncludes: '/b64path',
  });

  await check('query string forwarded', ev(p(base + '/search'), { rawQuery: 'q=portal&x=1' }), {
    statusCode: 200,
    bodyIncludes: '"url":"/search?q=portal&x=1"',
  });

  await check('target query wins over rawQuery', ev(p(base + '/s?already=1'), { rawQuery: 'dropped=1' }), {
    statusCode: 200,
    bodyIncludes: 'already=1',
    bodyExcludes: 'dropped=1',
  });

  await check('POST body + method forwarded', ev(p(base + '/submit'), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'user=abc&pass=def',
  }), {
    statusCode: 200,
    bodyIncludes: ['"method":"POST"', 'user=abc&pass=def'],
  });

  await check('upstream 404 passes through', ev(p(base + '/missing')), {
    statusCode: 404,
    bodyIncludes: '"url":"/missing"',
  });

  await check('real gzip decoded + content-encoding stripped', ev(p(base + '/gzip')), {
    statusCode: 200,
    headerAbsent: 'content-encoding',
    bodyIncludes: 'compressed portal page',
  });

  await check('upstream lies about gzip -> clean 502, no corrupt body', ev(p(base + '/lyinggzip')), {
    statusCode: 502,
    json: { 'error.code': 'upstream_error' },
  });

  const bin = await check('binary -> base64 out', ev(p(base + '/binary')), {
    statusCode: 200,
    isBase64Encoded: true,
  });
  const binBytes = Buffer.from(bin.body, 'base64');
  rows.push({
    name: 'binary bytes round-trip',
    status: 200,
    ms: 0,
    ok: binBytes.equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0x80, 0x81])),
    problems: [],
  });
  rows[rows.length - 1].ok ? pass++ : fail++;

  await check('204 empty body, no crash', ev(p(base + '/generate_204')), {
    statusCode: 204,
    body: '',
  });

  // --- leak guard -----------------------------------------------------------
  await check('inbound Authorization carrying the key is dropped', ev(p(base + '/echoauth'), {
    headers: { authorization: 'Bearer ' + REAL_KEY_LOOKS_LIKE },
  }), {
    statusCode: 200,
    bodyIncludes: '"sawAuth":null',
    bodyExcludes: REAL_KEY_LOOKS_LIKE,
  });

  await check('normal Authorization passes through', ev(p(base + '/echoauth2'), {
    headers: { authorization: 'Bearer target-issued-token' },
  }), {
    statusCode: 200,
    bodyIncludes: 'target-issued-token',
  });

  // --- policy ---------------------------------------------------------------
  process.env.PROXY_ALLOWLIST = 'example.com,*.wifi.test';
  await check('allowlist blocks unknown host -> 403', ev(p(base + '/hello')), {
    statusCode: 403,
    json: { 'error.code': 'host_not_allowed' },
  });
  await check('allowlist wildcard would allow sub.wifi.test', ev(p('http://sub.wifi.test/x')), {
    statusCode: 502, // allowed by policy, then DNS fails -> proves it got past the gate
    json: { 'error.code': 'upstream_error' },
  });
  delete process.env.PROXY_ALLOWLIST;

  delete process.env.PROXY_ALLOW_PRIVATE;
  await check('loopback blocked by default -> 403', ev(p(base + '/hello')), {
    statusCode: 403,
    json: { 'error.code': 'private_host_blocked' },
  });
  await check('169.254.169.254 metadata blocked -> 403', ev(p('http://169.254.169.254/latest/meta-data/')), {
    statusCode: 403,
    json: { 'error.code': 'private_host_blocked' },
  });

  process.env.PROXY_ALLOW_PRIVATE = '1';
  await check('dead port -> 502 upstream_error', ev(p('http://127.0.0.1:1/nope')), {
    statusCode: 502,
    json: { 'error.code': 'upstream_error' },
  });

  process.env.PROXY_TOKEN = 'shared-secret';
  await check('shared token required -> 401', ev(p(base + '/hello')), {
    statusCode: 401,
    json: { 'error.code': 'unauthorized' },
  });
  await check('shared token via header -> 200', ev(p(base + '/hello'), {
    headers: { 'x-proxy-token': 'shared-secret' },
  }), { statusCode: 200 });
  await check('shared token via query -> 200 and not forwarded', ev(p(base + '/hello'), {
    rawQuery: '__pt=shared-secret',
  }), { statusCode: 200, bodyExcludes: '__pt' });
  delete process.env.PROXY_TOKEN;
} finally {
  await close();
}

const pad = (s, n) => String(s) + ' '.repeat(Math.max(0, n - String(s).length));
console.log(pad('case', 52) + pad('code', 6) + pad('ms', 6) + 'verdict');
for (const r of rows) {
  console.log(pad(r.name, 52) + pad(r.status, 6) + pad(r.ms, 6) + (r.ok ? 'PASS' : 'FAIL ' + r.problems.join(' | ')));
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
