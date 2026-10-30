// test/bypass-logic-test.mjs
//
// Runs the *shipped* inline script from public/bypass.html inside a fake DOM and
// a fake network. Nothing is reimplemented here: the file is parsed out of the
// HTML, so the test breaks if the page does.
//
//   node test/bypass-logic-test.mjs
import fs from 'node:fs';
import vm from 'node:vm';

const html = fs.readFileSync(new URL('../public/bypass.html', import.meta.url), 'utf8');
const script = html.slice(html.lastIndexOf('<script>') + 8, html.lastIndexOf('</script>'));

class El {
  constructor(id = '') {
    this.id = id;
    this.value = '';
    this.className = '';
    this.innerHTML = '';
    this.children = [];
    this.attrs = {};
    this.onclick = null;
    this._text = '';
  }
  get textContent() {
    return this._text + this.children.map((c) => c.textContent).join('');
  }
  set textContent(v) {
    this._text = String(v);
    this.children = [];
  }
  appendChild(n) {
    this.children.push(n);
    return n;
  }
  submit() {
    this.submitted = (this.submitted || 0) + 1;
  }
  click() {
    if (this.onclick) this.onclick();
  }
}

const ids = ['relay', 'portal', 'html', 'parse', 'fire', 'curl', 'run', 'relaycheck', 'save', 'out0', 'out1', 'sink', 'autoform'];
const els = Object.fromEntries(ids.map((i) => [i, new El(i)]));

let fetchImpl = async () => ({ type: 'opaque', status: 0 });
const document = {
  getElementById: (id) => els[id] || new El(id),
  createElement: (tag) => new El(tag),
};

const sandbox = {
  document,
  localStorage: { store: {}, getItem(k) { return this.store[k] ?? null; }, setItem(k, v) { this.store[k] = v; } },
  location: { protocol: 'file:', origin: 'null' },
  navigator: {},
  AbortController,
  setTimeout: (fn, ms) => setTimeout(fn, Math.min(ms, 5)),
  clearTimeout,
  console,
  fetch: (...a) => fetchImpl(...a),
  URL,
  Promise,
};
vm.createContext(sandbox);
vm.runInContext(script, sandbox, { filename: 'bypass.html#inline' });

let pass = 0;
let fail = 0;
const check = (name, cond, detail = '') => {
  if (cond) { pass++; console.log('PASS  ' + name); }
  else { fail++; console.log('FAIL  ' + name + (detail ? '  -> ' + detail : '')); }
};
const flush = () => new Promise((r) => setTimeout(r, 60));

// --- 1. detection verdicts, driven by the fetch primitive -------------------
const probeMatrix = [
  ['all redirected', async () => ({ type: 'opaqueredirect' }), 'PORTAL'],
  ['all direct', async () => ({ type: 'opaque' }), 'OPEN'],
  ['everything dead', async () => { throw new TypeError('Failed to fetch'); }, 'DEAD'],
  ['http redirect, https blocked', async (url) => {
    if (String(url).startsWith('https:')) throw new TypeError('cert');
    return { type: 'opaqueredirect' };
  }, 'PORTAL'],
];

for (const [label, impl, want] of probeMatrix) {
  fetchImpl = impl;
  els.out0.textContent = '';
  els.run.onclick();
  await flush();
  const text = els.out0.textContent;
  check(`verdict "${want}" when ${label}`, text.includes('verdict: ' + want), text.slice(-220));
}

// --- 2. form extraction from a real portal page ----------------------------
els.out1.textContent = '';
els.portal.value = 'http://10.0.0.1/login?url=x';
els.html.value = `<!doctype html><form action="/authorize" method="post" onsubmit="return check(this)">
  <input type="hidden" name="orig_url" value="http://connectivitycheck.gstatic.com/generate_204">
  <input type="hidden" name="session" value="sess-7f3a">
  <input type="text" name="email" value="">
  <input type="checkbox" name="terms" value="on">
  <input type="submit" name="submit" value="Connect">
</form>`;
els.parse.onclick();
await flush();
let t = els.out1.textContent;
check('form 1 resolved to an absolute action', t.includes('POST http://10.0.0.1/authorize'), t);
check('hidden fields preserved', t.includes('orig_url=http://connectivitycheck.gstatic.com/generate_204 (hidden)'), t);
check('checkbox recognised', t.includes('terms[checkbox]'), t);
check('JS-only submit handler flagged', t.includes('client-side submit handler'), t);
check('HTML5 required not falsely claimed', !t.includes('HTML5 `required`'), t);

// --- 3. curl generation must contain the real payload ----------------------
els.out1.textContent = '';
els.curl.onclick();
await flush();
t = els.out1.textContent;
check('curl targets the real action', t.includes('"http://10.0.0.1/authorize"'), t);
check('curl carries guest creds', t.includes('email=guest%40example.com'), t);
check('curl carries the preserved hidden field', t.includes('session=sess-7f3a'), t);
check('curl ends with an egress proof, not the portal page', t.includes('generate_204'), t);

// --- 4. firing submits a form from the device, not the relay ---------------
els.out1.textContent = '';
els.fire.onclick();
check('a form was submitted', els.autoform.submitted === 1, String(els.autoform.submitted));
check('autoform posts to the portal action', els.autoform.action === 'http://10.0.0.1/authorize', els.autoform.action);
const names = els.autoform.children.map((c) => c.name + '=' + c.value);
check('autoform carries email + terms', names.includes('email=guest@example.com') && names.includes('terms=on'), names.join('&'));
check('fire is fire-and-forget (no readable response claimed)', els.out1.textContent.includes('fired POST'), els.out1.textContent);
await flush(); // let the deferred re-detection settle before the next section reads out0
els.out0.textContent = '';

// --- 5. relay check must not lie when a portal answers in place of it ------
fetchImpl = async () => ({ status: 200, text: async () => '<html>Sign in to WiFi</html>' });
els.out0.textContent = '';
els.relay.value = 'https://example.netlify.app';
els.relaycheck.onclick();
await flush();
check('portal-in-place-of-relay is reported as not-your-relay', els.out0.textContent.includes('not JSON'), els.out0.textContent);

fetchImpl = async () => ({ status: 200, text: async () => JSON.stringify({ ok: true, key_present: true, key_fingerprint: 'a1b2c3d4', allowlist_mode: 'open', private_hosts: 'blocked', runtime: 'v20' }) });
els.out0.textContent = '';
els.relaycheck.onclick();
await flush();
check('healthy relay reported REACHABLE', els.out0.textContent.includes('REACHABLE'), els.out0.textContent);

fetchImpl = async () => { throw new TypeError('Failed to fetch'); };
els.out0.textContent = '';
els.relaycheck.onclick();
await flush();
check('blocked relay reported UNREACHABLE with the honest reason', els.out0.textContent.includes('UNREACHABLE'), els.out0.textContent);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
