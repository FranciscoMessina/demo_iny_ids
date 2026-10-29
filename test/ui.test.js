import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { startUi } from '../src/ui/server.js';
import { scenarios } from '../src/ui/public/scenarios.js';

let ui;
before(async () => {
  ui = await startUi();
});
after(() => ui.close());

const proxy = (target, path, init, token = ui.token) => fetch(`${ui.url}/proxy/${token}/${target}${path}`, init);

// fetch no permite cambiar Host; con http.request sí.
const withHost = (host) =>
  new Promise((resolve, reject) => {
    const { port } = new URL(ui.url);
    http
      .get({ host: '127.0.0.1', port, path: '/', headers: { host } }, (res) => {
        res.resume();
        resolve(res.statusCode);
      })
      .on('error', reject);
  });

test('la página se sirve con el token inyectado y cabeceras de seguridad', async () => {
  const r = await fetch(ui.url);
  const html = await r.text();
  assert.equal(r.status, 200);
  assert.ok(html.includes(ui.token));
  assert.ok(!html.includes('__TOKEN__'));
  assert.match(r.headers.get('content-security-policy'), /default-src 'self'/);
});

test('rechaza un Host ajeno (DNS rebinding)', async () => {
  assert.equal(await withHost('evil.example.com'), 403);
  assert.equal(await withHost('127.0.0.1'), 403); // sin puerto
});

test('el proxy exige el token correcto', async () => {
  assert.equal((await proxy('vulnerable', '/calc?expr=1', {}, 'deadbeef')).status, 403);
  assert.equal((await proxy('vulnerable', '/calc?expr=1', {}, '')).status, 403);
});

test('los servidores internos rechazan peticiones directas sin token', async () => {
  for (const base of Object.values(ui.bases)) {
    assert.equal((await fetch(`${base}/calc?expr=1`)).status, 403);
  }
});

test('el proxy solo expone las rutas de la demo y los métodos GET/POST', async () => {
  assert.equal((await proxy('vulnerable', '/admin')).status, 404);
  assert.equal((await proxy('vulnerable', '/etc/passwd')).status, 403);
  assert.equal((await proxy('vulnerable', '/calc?expr=1', { method: 'DELETE' })).status, 405);
  assert.equal((await proxy('otro', '/calc')).status, 403);
});

test('cada escenario de la UI: el ataque funciona en el vulnerable y es bloqueado en el seguro', async () => {
  for (const s of scenarios) {
    for (const [target, expectExploited] of [['vulnerable', true], ['secure', false]]) {
      for (const [mode, values] of [['legit', s.legit], ['attack', s.attack]]) {
        const req = s.request(values);
        const r = await proxy(target, req.path, {
          method: req.method,
          headers: req.body ? { 'Content-Type': 'application/json' } : {},
          body: req.body ? JSON.stringify(req.body) : undefined,
        });
        const text = await r.text();
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {}
        const res = { status: r.status, text, json };
        if (mode === 'legit') assert.equal(r.status, 200, `${s.id} legit en ${target}`);
        else assert.equal(s.exploited(res, values), expectExploited, `${s.id} ataque en ${target}: ${text}`);
      }
    }
  }
});

test('la CSP del seguro llega al iframe sin frame-ancestors none, y la original queda en X-Original-CSP', async () => {
  const r = await proxy('secure', '/hello?name=x');
  assert.match(r.headers.get('content-security-policy'), /frame-ancestors 'self'/);
  assert.match(r.headers.get('x-original-csp'), /frame-ancestors 'none'/);
});
