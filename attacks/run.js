// Lanza los mismos ataques contra el servidor vulnerable y el seguro, y compara resultados.
import { createVulnerableServer } from '../src/vulnerable/server.js';
import { createSecureServer } from '../src/secure/server.js';
import { scenarios } from './scenarios.js';

const c = { red: '\x1b[31m', green: '\x1b[32m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };

const listen = (server) =>
  new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`)));

const short = (text) => text.replace(/\s+/g, ' ').slice(0, 110) + (text.length > 110 ? '…' : '');

const targets = [
  { name: 'VULNERABLE', server: createVulnerableServer() },
  { name: 'SEGURO', server: createSecureServer() },
];
for (const t of targets) t.base = await listen(t.server);

for (const s of scenarios) {
  console.log(`\n${c.bold}▶ ${s.title}${c.reset}`);
  console.log(`${c.dim}  payload → ${s.payload}${c.reset}`);
  for (const { name, base } of targets) {
    const legitOk = await s.legit(base);
    const { exploited, evidence } = await s.attack(base);
    const verdict = exploited ? `${c.red}✘ ATAQUE EXITOSO${c.reset}` : `${c.green}✔ ataque bloqueado${c.reset}`;
    console.log(`  ${name.padEnd(10)} ${verdict}  ${c.dim}(uso legítimo: ${legitOk ? 'ok' : 'FALLA'})${c.reset}`);
    console.log(`  ${c.dim}${''.padEnd(10)} respuesta: ${short(evidence)}${c.reset}`);
  }
}

for (const t of targets) t.server.close();
console.log();
