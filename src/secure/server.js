// Misma API que el servidor vulnerable, con las defensas aplicadas.
import http from 'node:http';
import { execFile } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createDb, verifyPassword, hashPassword } from '../shared/db.js';
import { send, readJson } from '../shared/http.js';
import { evaluate } from './calc.js';
import { escapeHtml } from './escape.js';

const WC = fileURLToPath(new URL('../shared/wc.js', import.meta.url));
const DATA_DIR = fileURLToPath(new URL('../../data', import.meta.url));

process.env.SECRET_KEY ??= 'sk_demo_9f8e7d6c5b4a';

// Hash ficticio para igualar el tiempo de respuesta cuando el usuario no existe.
const DUMMY_HASH = hashPassword('dummy');

const SAFE_FILE = /^[a-z0-9_-]{1,40}\.txt$/i;
const isShortString = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max;

const SECURITY_HEADERS = {
  // Aun si algo se escapara, el navegador no ejecutaría scripts ni cargaría recursos externos.
  'Content-Security-Policy': "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
};

const bad = (res, msg = 'Solicitud inválida') => send(res, 400, { error: msg }, SECURITY_HEADERS);

export function createSecureServer() {
  const db = createDb({ hashed: true });
  // Consultas preparadas una sola vez: el SQL queda fijo, los datos viajan aparte.
  const findUser = db.prepare('SELECT id, username, role, password FROM users WHERE username = ?');
  const findProducts = db.prepare('SELECT id, name, category, price FROM products WHERE category = ?');

  return http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const q = url.searchParams;

    try {
      // 1) Validación de tipos + consulta parametrizada + comparación en tiempo constante.
      if (req.method === 'POST' && url.pathname === '/login') {
        const { username, password } = await readJson(req);
        if (!isShortString(username, 64) || !isShortString(password, 128)) return bad(res);
        const row = findUser.get(username);
        const valid = verifyPassword(password, row?.password ?? DUMMY_HASH) && row;
        if (!valid) return send(res, 401, { ok: false }, SECURITY_HEADERS); // mismo mensaje exista o no el usuario
        const { password: _omit, ...user } = row; // nunca devolver el hash
        return send(res, 200, { ok: true, user }, SECURITY_HEADERS);
      }

      // 2) Parámetro enlazado: ' UNION SELECT ... es solo un texto que no coincide con ninguna categoría.
      if (url.pathname === '/products') {
        const category = q.get('category');
        if (!isShortString(category, 100)) return bad(res);
        return send(res, 200, findProducts.all(category), SECURITY_HEADERS);
      }

      // 3) Lista blanca del nombre + execFile (sin shell) + argumentos separados.
      if (url.pathname === '/wordcount') {
        const file = q.get('file');
        if (!SAFE_FILE.test(file ?? '')) return bad(res, 'Nombre de archivo no permitido');
        return execFile(process.execPath, [WC, file], { cwd: DATA_DIR, timeout: 3000 }, (err, stdout) =>
          err ? send(res, 404, { error: 'Archivo no disponible' }, SECURITY_HEADERS) : send(res, 200, { output: stdout }, SECURITY_HEADERS),
        );
      }

      // 4) Nada de eval: un parser propio que solo entiende números y + - * / ( ).
      if (url.pathname === '/calc') {
        try {
          return send(res, 200, { result: String(evaluate(q.get('expr'))) }, SECURITY_HEADERS);
        } catch {
          return bad(res, 'Expresión inválida');
        }
      }

      // 5) Escapar según el contexto de salida (HTML) + CSP como segunda capa.
      if (url.pathname === '/hello') {
        const name = q.get('name') ?? '';
        if (name.length > 50) return bad(res);
        return send(res, 200, `<h1>Hola, ${escapeHtml(name)}!</h1>`, SECURITY_HEADERS);
      }

      send(res, 404, { error: 'No encontrado' }, SECURITY_HEADERS);
    } catch (err) {
      // Errores genéricos al cliente; el detalle queda solo en el log del servidor.
      console.error('[error]', err.message);
      send(res, err.status === 413 ? 413 : 500, { error: 'Error interno' }, SECURITY_HEADERS);
    }
  });
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const port = Number(process.env.PORT ?? 3001);
  createSecureServer().listen(port, '127.0.0.1', () =>
    console.log(`🛡️  Servidor SEGURO en http://127.0.0.1:${port}`),
  );
}
