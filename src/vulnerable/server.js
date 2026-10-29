// ⚠️  SERVIDOR INTENCIONALMENTE VULNERABLE — SOLO PARA FINES EDUCATIVOS.
// No lo expongas a una red real ni copies estos patrones.
import http from 'node:http';
import { exec } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createDb } from '../shared/db.js';
import { send, readJson } from '../shared/http.js';

const WC = fileURLToPath(new URL('../shared/wc.js', import.meta.url));
const DATA_DIR = fileURLToPath(new URL('../../data', import.meta.url));

// Secreto que cualquier código ejecutado dentro del proceso puede leer.
process.env.SECRET_KEY ??= 'sk_demo_9f8e7d6c5b4a';

export function createVulnerableServer() {
  const db = createDb({ hashed: false });

  return http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const q = url.searchParams;

    try {
      // 1) SQL INJECTION (autenticación): la entrada se concatena en la consulta.
      //    username = admin'--   convierte la consulta en:  ... WHERE username='admin'--' AND password='...'
      if (req.method === 'POST' && url.pathname === '/login') {
        const { username, password } = await readJson(req);
        const user = db
          .prepare(`SELECT id, username, role FROM users WHERE username = '${username}' AND password = '${password}'`)
          .get();
        return user ? send(res, 200, { ok: true, user }) : send(res, 401, { ok: false });
      }

      // 2) SQL INJECTION (UNION): permite leer otras tablas.
      if (url.pathname === '/products') {
        const rows = db
          .prepare(`SELECT id, name, category, price FROM products WHERE category = '${q.get('category')}'`)
          .all();
        return send(res, 200, rows);
      }

      // 3) COMMAND INJECTION: la entrada llega a un shell (cmd.exe / sh).
      //    file = notes.txt && whoami   ejecuta un segundo comando.
      if (url.pathname === '/wordcount') {
        const file = q.get('file');
        return exec(`"${process.execPath}" "${WC}" ${file}`, { cwd: DATA_DIR }, (err, stdout, stderr) =>
          send(res, 200, { output: stdout + stderr }),
        );
      }

      // 4) CODE INJECTION: eval() ejecuta JavaScript arbitrario con los permisos del proceso.
      //    expr = process.env.SECRET_KEY   filtra secretos; con más código se puede hacer cualquier cosa.
      if (url.pathname === '/calc') {
        const result = eval(q.get('expr'));
        return send(res, 200, { result: String(result) });
      }

      // 5) XSS REFLEJADO: la entrada se inserta tal cual en el HTML.
      if (url.pathname === '/hello') {
        return send(res, 200, `<h1>Hola, ${q.get('name')}!</h1>`);
      }

      send(res, 404, { error: 'No encontrado' });
    } catch (err) {
      // Fuga de información: se devuelve el mensaje interno (revela estructura de la consulta).
      send(res, err.status ?? 500, { error: err.message });
    }
  });
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const port = Number(process.env.PORT ?? 3000);
  createVulnerableServer().listen(port, '127.0.0.1', () =>
    console.log(`⚠️  Servidor VULNERABLE en http://127.0.0.1:${port}`),
  );
}
