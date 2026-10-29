// Servidor de la interfaz web. Sirve la página y levanta (en puertos efímeros) el servidor
// vulnerable y el seguro; el navegador solo habla con este servidor, que actúa de proxy.
//
// Como el servidor vulnerable ejecuta comandos de verdad, se protege de otras páginas web
// abiertas en el mismo navegador (CSRF / DNS rebinding):
//   - valida la cabecera Host (solo 127.0.0.1 / localhost con el puerto real),
//   - exige un token aleatorio por ejecución en las rutas /proxy,
//   - los servidores internos rechazan cualquier petición que no traiga ese token.
import http from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { createVulnerableServer } from '../vulnerable/server.js';
import { createSecureServer } from '../secure/server.js';

const file = (rel) => new URL(rel, import.meta.url);
const STATIC = {
  '/': { file: file('./public/index.html'), type: 'text/html; charset=utf-8', template: true },
  '/app.js': { file: file('./public/app.js'), type: 'text/javascript; charset=utf-8' },
  '/scenarios.js': { file: file('./public/scenarios.js'), type: 'text/javascript; charset=utf-8' },
  '/style.css': { file: file('./public/style.css'), type: 'text/css; charset=utf-8' },
  '/icon.svg': { file: file('../../assets/icon.svg'), type: 'image/svg+xml' },
};
const PROXY_ROUTES = new Set(['/login', '/products', '/wordcount', '/calc', '/hello']);
const PAGE_CSP = "default-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'";

const listen = (server, port = 0) =>
  new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server.address().port));
  });

// Envuelve el listener original para exigir el token antes de procesar nada.
function requireToken(server, token) {
  const handlers = server.listeners('request');
  server.removeAllListeners('request');
  server.on('request', (req, res) => {
    if (req.headers['x-demo-token'] !== token) {
      res.writeHead(403).end();
      return;
    }
    for (const handler of handlers) handler.call(server, req, res);
  });
}

const deny = (res, status, msg = 'Prohibido') =>
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' }).end(msg);

async function readBody(req, maxBytes = 4096) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw new Error('Body demasiado grande');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

export async function startUi({ port = 0 } = {}) {
  const token = randomBytes(16).toString('hex');
  const tokenBuf = Buffer.from(token);
  const tokenOk = (candidate) => {
    const buf = Buffer.from(candidate);
    return buf.length === tokenBuf.length && timingSafeEqual(buf, tokenBuf);
  };

  const servers = { vulnerable: createVulnerableServer(), secure: createSecureServer() };
  const bases = {};
  for (const [name, server] of Object.entries(servers)) {
    requireToken(server, token);
    bases[name] = `http://127.0.0.1:${await listen(server)}`;
  }

  async function proxy(req, res, url) {
    const m = /^\/proxy\/([0-9a-f]+)\/(vulnerable|secure)(\/[a-z]+)$/.exec(url.pathname);
    if (!m || !tokenOk(m[1])) return deny(res, 403);
    const [, , target, route] = m;
    if (!PROXY_ROUTES.has(route)) return deny(res, 404, 'No encontrado');
    if (req.method !== 'GET' && req.method !== 'POST') return deny(res, 405, 'Método no permitido');

    let body;
    try {
      body = req.method === 'POST' ? await readBody(req) : undefined;
    } catch {
      return deny(res, 413, 'Body demasiado grande');
    }

    const upstream = await fetch(`${bases[target]}${route}${url.search}`, {
      method: req.method,
      headers: { 'x-demo-token': token, ...(body && { 'content-type': 'application/json' }) },
      body,
    });
    const headers = {
      'Content-Type': upstream.headers.get('content-type') ?? 'text/plain; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
    };
    // La CSP del servidor seguro prohíbe ser embebido (frame-ancestors 'none'); para poder mostrar la
    // página en el iframe de la demo se relaja solo eso y se conserva la original en X-Original-CSP.
    const csp = upstream.headers.get('content-security-policy');
    if (csp) {
      headers['Content-Security-Policy'] = csp.replace(/frame-ancestors[^;]*/, "frame-ancestors 'self'");
      headers['X-Original-CSP'] = csp;
    }
    res.writeHead(upstream.status, headers).end(await upstream.text());
  }

  const ui = http.createServer(async (req, res) => {
    try {
      const { port: actual } = ui.address();
      if (req.headers.host !== `127.0.0.1:${actual}` && req.headers.host !== `localhost:${actual}`) {
        return deny(res, 403);
      }
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname.startsWith('/proxy/')) return await proxy(req, res, url);

      const entry = STATIC[url.pathname];
      if (req.method !== 'GET' || !entry) return deny(res, 404, 'No encontrado');
      let content = await readFile(entry.file);
      if (entry.template) content = content.toString('utf8').replace('__TOKEN__', token);
      res.writeHead(200, {
        'Content-Type': entry.type,
        'Content-Security-Policy': PAGE_CSP,
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-store',
      });
      res.end(content);
    } catch (err) {
      console.error('[ui]', err.message);
      if (!res.headersSent) deny(res, 502, 'Error interno');
    }
  });
  const actualPort = await listen(ui, port);

  const all = [ui, ...Object.values(servers)];
  return {
    url: `http://127.0.0.1:${actualPort}`,
    token,
    bases,
    close: () => Promise.all(all.map((s) => new Promise((r) => (s.close(r), s.closeAllConnections())))),
  };
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const { url } = await startUi({ port: Number(process.env.PORT ?? 8080) });
  console.log(`Interfaz web en ${url}`);
}
