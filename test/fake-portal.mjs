// test/fake-portal.mjs
//
// A deliberately weak captive portal: the email field is validated ONLY by the
// page's own JavaScript, and the gateway treats any non-empty email POST as a
// grant. This is the real-world pattern nowifi's technique #4 targets, and it
// lets the click-through engine be tested end to end without touching a hotel.
//
//   node test/fake-portal.mjs            -> serves on 127.0.0.1:8088
//   node test/fake-portal.mjs 9099       -> pick a port
//
// Endpoints:
//   GET  /                  portal page with a real <form>
//   POST /authorize         empty email => 200 "invalid"; any email => grant + 302
//   GET  /generate_204      204 when granted, otherwise 302 to / (what a walled
//                           garden does to the Android connectivity check)
//   GET  /welcome           post-grant landing page
import http from 'node:http';
import crypto from 'node:crypto';

const port = Number(process.argv[2] || 8088);
// STRICT=1 -> the gateway validates server-side and refuses everything that is
// not a real voucher. This is the case the click-through engine must NOT win.
const STRICT = process.env.STRICT === '1';
// MIKROTIK=1 serves the shape a MikroTik hotspot actually uses: /login with
// username + password + hidden dst. ACCEPT_USER picks who is let through, so the
// credential ladder can be tested in order ('' = anonymous, 'admin', 'T-<mac>').
const MIKROTIK = process.env.MIKROTIK === '1';
// MIKROTIK_MD5=1 reproduces RouterOS "md5 mode": the page hashes the password
// with a literal prefix/suffix and the router only accepts the hash.
const MD5 = process.env.MIKROTIK_MD5 === '1';
const PREFIX = '\x77';
const SUFFIX = '\x02\xcf';
const ACCEPT_USER = process.env.ACCEPT_USER ?? null;
let granted = false;
let grants = 0;
const log = [];

const page = () => `<!doctype html><html><head><title>Guest WiFi - Sign in</title>
<script>
function check(f){ // <-- the entire security model
  if(!f.email.value.includes('@')){ document.getElementById('err').textContent='Enter a valid email'; return false; }
  return true;
}
</script></head><body>
<h1>Free WiFi</h1><p id="err"></p>
<form action="/authorize" method="post" onsubmit="return check(this)">
  <input type="hidden" name="orig_url" value="http://connectivitycheck.gstatic.com/generate_204">
  <input type="hidden" name="session" value="sess-7f3a">
  <input type="text" name="email" value="" placeholder="email">
  <input type="checkbox" name="terms" value="on">
  <input type="submit" name="submit" value="Connect">
</form></body></html>`;

const md5hex = (str) => crypto.createHash('md5').update(str, 'latin1').digest('hex');

const md5Page = (err) => `<!doctype html><html><head><title>hotspot</title>
<script>
function doLogin(){ document.sendin.password.value = hexMD5("\\167" + document.sendin.password.value + "\\002\\317"); document.sendin.submit(); return false; }
</script></head><body><h1>Sign in</h1><p>${err}</p>
<form name="sendin" action="/login" method="post">
  <input type="hidden" name="username" value="">
  <input type="hidden" name="password" value="">
  <input type="hidden" name="dst" value="http://connectivitycheck.gstatic.com/generate_204">
  <input type="submit" name="submit" value="Login" onclick="return doLogin()">
</form></body></html>`;

const mikrotikPage = (err) => `<!doctype html><html><head><title>wau.wifi hotspot</title></head><body>
<h1>wau.wifi</h1><p>${err}</p>
<form name="login" action="/login" method="post">
  <input type="hidden" name="dst" value="http://connectivitycheck.gstatic.com/generate_204">
  <input type="hidden" name="popup" value="true">
  <input type="text" name="username" value="">
  <input type="password" name="password" value="">
  <input type="submit" name="submit" value="Login">
</form></body></html>`;

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${port}`);
  const entry = { at: new Date().toISOString().slice(11, 19), method: req.method, path: url.pathname, ua: req.headers['user-agent'] || '' };
  log.push(entry);

  if ((MIKROTIK || MD5) && url.pathname === '/login' && req.method === 'POST') {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const form = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
      entry.username = form.get('username');
      entry.dst = form.get('dst');
      const pwOk = MD5 ? form.get('password') === md5hex(PREFIX + 'guest' + SUFFIX) : true;
      entry.pw = form.get('password');
      if (ACCEPT_USER !== null && form.get('username') === ACCEPT_USER && pwOk) {
        granted = true; grants++;
        res.writeHead(302, { location: '/welcome' });
        return res.end();
      }
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(mikrotikPage('invalid username or password'));
    });
    return;
  }

  if (url.pathname === '/login' && (MIKROTIK || MD5) && req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(MD5 ? md5Page('') : mikrotikPage(''));
  }
  if (url.pathname === '/' && MD5) {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(md5Page(''));
  }

  if (url.pathname === '/' && MIKROTIK) {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(mikrotikPage(''));
  }

  if (url.pathname === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(page());
  }

  if (url.pathname === '/authorize' && req.method === 'POST') {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const form = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
      entry.email = form.get('email');
      entry.terms = form.get('terms');
      // A voucher field that exists nowhere in the page: no template can guess it.
      if (STRICT && form.get('voucher') !== 'V-1234') {
        res.writeHead(403, { 'content-type': 'text/html' });
        return res.end(page().replace('Enter a valid email', 'Payment required'));
      }
      if (!form.get('email')) {
        res.writeHead(200, { 'content-type': 'text/html' });
        return res.end(page().replace('Enter a valid email', 'Email required'));
      }
      granted = true;
      grants++;
      res.writeHead(302, { location: '/welcome', 'set-cookie': 'guest=1; Path=/' });
      res.end();
    });
    return;
  }

  if (url.pathname === '/generate_204') {
    if (granted) {
      res.writeHead(204, { 'content-length': '0' });
      return res.end();
    }
    res.writeHead(302, { location: '/' });
    return res.end();
  }

  if (url.pathname === '/welcome') {
    res.writeHead(200, { 'content-type': 'text/html' });
    return res.end('<h1>You are online</h1>');
  }

  if (url.pathname === '/__state') {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ granted, grants, attempts: log }, null, 2));
  }

  res.writeHead(404, { 'content-type': 'text/plain' });
  res.end('nope');
});

server.listen(port, '127.0.0.1', () => {
  console.log(`fake portal on http://127.0.0.1:${port}  (egress: /generate_204, state: /__state)`);
});
