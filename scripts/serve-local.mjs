// scripts/serve-local.mjs
//
// Serves public/ over http://127.0.0.1:8000 so bypass.html can be opened in
// Chrome while you are offline and behind a portal. Chrome on Android refuses
// file:// URLs from Termux's private dir, and a portal will not let you fetch
// your own file from the internet, so loopback is the only path that works.
//
//   node scripts/serve-local.mjs [port]
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(new URL('../public', import.meta.url).pathname);
const port = Number(process.argv[2] || 8000);
const types = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
};

http
  .createServer((req, res) => {
    let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (p === '/') p = '/bypass.html';
    const file = path.join(root, path.normalize(p).replace(/^(\.\.[/\\])+/, ''));
    if (!file.startsWith(root)) {
      res.writeHead(403).end('no');
      return;
    }
    fs.readFile(file, (e, buf) => {
      if (e) {
        res.writeHead(404, { 'content-type': 'text/plain' }).end('not found: ' + p);
        return;
      }
      res.writeHead(200, { 'content-type': types[path.extname(file)] || 'application/octet-stream', 'cache-control': 'no-store' });
      res.end(buf);
    });
  })
  .listen(port, '127.0.0.1', () => {
    console.log(`offline panel: http://127.0.0.1:${port}/  (index: ${root})`);
    console.log('open that URL in Chrome, keep this process running, Ctrl+C to stop.');
  });
