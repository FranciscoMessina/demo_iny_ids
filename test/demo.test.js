import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createVulnerableServer } from '../src/vulnerable/server.js';
import { createSecureServer } from '../src/secure/server.js';
import { evaluate } from '../src/secure/calc.js';
import { escapeHtml } from '../src/secure/escape.js';
import { scenarios } from '../attacks/scenarios.js';

const servers = {};
const listen = (s) => new Promise((r) => s.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${s.address().port}`)));

before(async () => {
  servers.vulnerable = createVulnerableServer();
  servers.secure = createSecureServer();
  servers.vulnerableBase = await listen(servers.vulnerable);
  servers.secureBase = await listen(servers.secure);
});

after(() => {
  servers.vulnerable.close();
  servers.secure.close();
});

for (const s of scenarios) {
  test(`${s.id}: el uso legítimo funciona en ambos servidores`, async () => {
    assert.ok(await s.legit(servers.vulnerableBase), 'vulnerable');
    assert.ok(await s.legit(servers.secureBase), 'seguro');
  });

  test(`${s.id}: el ataque FUNCIONA en el servidor vulnerable`, async () => {
    const { exploited, evidence } = await s.attack(servers.vulnerableBase);
    assert.ok(exploited, evidence);
  });

  test(`${s.id}: el ataque es BLOQUEADO en el servidor seguro`, async () => {
    const { exploited, evidence } = await s.attack(servers.secureBase);
    assert.equal(exploited, false, evidence);
  });
}

test('calc segura: evalúa aritmética y rechaza todo lo demás', () => {
  assert.equal(evaluate('2 + 3 * (4 - 1)'), 11);
  assert.equal(evaluate('-(2+3)'), -5);
  for (const bad of ['process.exit()', '1; 2', '2 +', '(1', '1/0', '', 'a'.repeat(101)]) {
    assert.throws(() => evaluate(bad), undefined, bad);
  }
});

test('escapeHtml neutraliza caracteres de marcado', () => {
  assert.equal(escapeHtml(`<img src=x onerror="a('b')">&`), '&lt;img src=x onerror=&quot;a(&#39;b&#39;)&quot;&gt;&amp;');
});

test('el servidor seguro no filtra detalles de errores SQL ni el hash', async () => {
  const r = await fetch(`${servers.secureBase}/products?category=${encodeURIComponent("'")}`);
  assert.equal(r.status, 200);
  assert.equal(await r.text(), '[]');
  const login = await fetch(`${servers.secureBase}/login`, {
    method: 'POST',
    body: JSON.stringify({ username: 'alice', password: 'alice123' }),
  });
  assert.ok(!(await login.text()).includes('password'));
});

test('el servidor seguro rechaza tipos inesperados (NoSQL-style / objetos)', async () => {
  const r = await fetch(`${servers.secureBase}/login`, {
    method: 'POST',
    body: JSON.stringify({ username: { $ne: null }, password: ['x'] }),
  });
  assert.equal(r.status, 400);
});
