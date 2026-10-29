// Definición de los escenarios de la interfaz.
//   fields    campos editables
//   legit     valores de uso normal       attack  valores del ataque
//   request   petición que se envía a ambos servidores
//   view      "lo que ejecuta el servidor" como lista de partes: texto fijo o { inj } (entrada del usuario)
//   hint      explicación contextual que depende de la entrada
//   exploited decide si el ataque funcionó, a partir de la respuesta
//   code      fragmento de código vulnerable vs. seguro

const inj = (value) => ({ inj: value });
const qs = (params) => new URLSearchParams(params).toString();
const escapeHtml = (t) =>
  t.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const SAFE_FILE = /^[a-z0-9_-]{1,40}\.txt$/i;
const ARITHMETIC = /^[\d\s+\-*/().]+$/;
const SENSITIVE = ['S3cr3t-Adm1n!', 'alice123'];

export const scenarios = [
  {
    id: 'sqli-login',
    title: 'SQL Injection: saltarse el login',
    kind: 'Inyección SQL',
    explain:
      'El servidor arma la consulta SQL concatenando lo que escribe el usuario. Un apóstrofe cierra el texto y `--` convierte el resto de la consulta en un comentario, así que la contraseña ni se comprueba.',
    impact: 'Acceso como administrador sin conocer su contraseña.',
    fields: [
      { name: 'username', label: 'Usuario' },
      { name: 'password', label: 'Contraseña' },
    ],
    legit: { username: 'alice', password: 'alice123' },
    attack: { username: "admin'--", password: 'cualquiera' },
    request: (v) => ({ method: 'POST', path: '/login', body: { username: v.username, password: v.password } }),
    view: {
      vulnerable: (v) => [
        "SELECT id, username, role FROM users\nWHERE username = '",
        inj(v.username),
        "' AND password = '",
        inj(v.password),
        "'",
      ],
      secure: (v) => [
        'SELECT id, username, role, password FROM users\nWHERE username = ?\n\nparámetros enlazados: [ ',
        inj(JSON.stringify(v.username)),
        ' ]\n\nverifyPassword(contraseña, hash)   // scrypt + timingSafeEqual',
      ],
    },
    hint: {
      vulnerable: (v) =>
        v.username.includes('--') ? 'Todo lo que sigue a `--` es un comentario: la condición de contraseña desaparece.' : null,
      secure: (v) =>
        v.username.includes("'") ? 'El apóstrofe es un carácter más del nombre de usuario: no existe ese usuario.' : null,
    },
    exploited: (res) => res.status === 200 && res.json?.ok === true,
    code: {
      vulnerable: `const user = db.prepare(
  \`SELECT id, username, role FROM users
   WHERE username = '\${username}' AND password = '\${password}'\`
).get();`,
      secure: `const findUser = db.prepare(
  'SELECT id, username, role, password FROM users WHERE username = ?');

if (!isShortString(username, 64)) return bad(res);   // tipo y largo
const row = findUser.get(username);                  // dato aparte del SQL
verifyPassword(password, row?.password ?? DUMMY_HASH); // hash + tiempo constante`,
    },
  },

  {
    id: 'sqli-union',
    title: 'SQL Injection (UNION): robar datos',
    kind: 'Inyección SQL',
    explain:
      'Con `UNION SELECT` el atacante añade una segunda consulta y obtiene datos de otra tabla dentro de una respuesta que parecía inocente (un listado de productos).',
    impact: 'Fuga de usuarios y contraseñas. Con contraseñas hasheadas el daño sería mucho menor.',
    fields: [{ name: 'category', label: 'Categoría' }],
    legit: { category: 'perifericos' },
    attack: { category: "x' UNION SELECT id,username,password,0 FROM users--" },
    request: (v) => ({ method: 'GET', path: `/products?${qs({ category: v.category })}` }),
    view: {
      vulnerable: (v) => [
        "SELECT id, name, category, price FROM products\nWHERE category = '",
        inj(v.category),
        "'",
      ],
      secure: (v) => [
        'SELECT id, name, category, price FROM products\nWHERE category = ?\n\nparámetros enlazados: [ ',
        inj(JSON.stringify(v.category)),
        ' ]',
      ],
    },
    hint: {
      vulnerable: (v) => (/union/i.test(v.category) ? 'La consulta del atacante se une a la original y devuelve filas de `users`.' : null),
      secure: (v) =>
        /union/i.test(v.category) ? 'Se busca una categoría con ese texto literal. No hay ninguna: lista vacía.' : null,
    },
    exploited: (res) => SENSITIVE.some((s) => res.text.includes(s)),
    code: {
      vulnerable: `db.prepare(
  \`SELECT id, name, category, price FROM products
   WHERE category = '\${q.get('category')}'\`
).all();`,
      secure: `const findProducts = db.prepare(
  'SELECT id, name, category, price FROM products WHERE category = ?');

findProducts.all(category);   // el valor nunca se interpreta como SQL`,
    },
  },

  {
    id: 'cmd-injection',
    title: 'Command Injection: ejecutar comandos',
    kind: 'Inyección de comandos',
    explain:
      'El servidor invoca una herramienta externa armando una línea de texto para el shell. Operadores como `&&`, `;` o `|` permiten encadenar comandos propios.',
    impact: 'Ejecución de comandos arbitrarios con los permisos del servidor (aquí: `whoami`).',
    fields: [{ name: 'file', label: 'Archivo a analizar' }],
    legit: { file: 'notes.txt' },
    attack: { file: 'notes.txt && echo INYECTADO && whoami' },
    request: (v) => ({ method: 'GET', path: `/wordcount?${qs({ file: v.file })}` }),
    view: {
      vulnerable: (v) => ['shell> node wc.js ', inj(v.file)],
      secure: (v) =>
        SAFE_FILE.test(v.file)
          ? ['execFile("node", ["wc.js", ', inj(JSON.stringify(v.file)), '])   // sin shell']
          : [
              '✗ ',
              inj(v.file),
              '\n  no cumple /^[a-z0-9_-]{1,40}\\.txt$/i\n  → 400, no se ejecuta ningún proceso',
            ],
    },
    hint: {
      vulnerable: (v) => (/[;&|`$<>]/.test(v.file) ? 'El shell interpreta el operador y ejecuta cada comando por separado.' : null),
      secure: (v) =>
        SAFE_FILE.test(v.file) ? null : 'La lista blanca rechaza el nombre antes de lanzar nada. Aun si pasara, no hay shell que lo interprete.',
    },
    exploited: (res) => (res.json?.output ?? '').trim().split(/\r?\n/).filter(Boolean).length > 1,
    code: {
      vulnerable: `exec(\`"\${process.execPath}" "\${WC}" \${file}\`, { cwd: DATA_DIR }, cb);`,
      secure: `const SAFE_FILE = /^[a-z0-9_-]{1,40}\\.txt$/i;
if (!SAFE_FILE.test(file)) return bad(res);          // lista blanca

execFile(process.execPath, [WC, file],               // sin shell,
         { cwd: DATA_DIR, timeout: 3000 }, cb);      // argumentos separados`,
    },
  },

  {
    id: 'code-injection',
    title: 'Code Injection (eval): ejecutar JavaScript',
    kind: 'Inyección de código',
    explain:
      '`eval()` ejecuta como código el texto que recibe. Una "calculadora" que lo usa permite al atacante correr cualquier JavaScript dentro del proceso del servidor.',
    impact: 'Lectura de secretos (variables de entorno, archivos) y control total del proceso.',
    fields: [{ name: 'expr', label: 'Expresión' }],
    legit: { expr: '2+3*(4-1)' },
    attack: { expr: 'process.env.SECRET_KEY' },
    request: (v) => ({ method: 'GET', path: `/calc?${qs({ expr: v.expr })}` }),
    view: {
      vulnerable: (v) => ['eval("', inj(v.expr), '")'],
      secure: (v) =>
        ARITHMETIC.test(v.expr)
          ? ['evaluate("', inj(v.expr), '")   // parser: solo números y + - * / ( )']
          : ['✗ evaluate("', inj(v.expr), '")\n  contiene caracteres que no son aritmética → 400'],
    },
    hint: {
      vulnerable: (v) => (ARITHMETIC.test(v.expr) ? null : 'No es aritmética: se ejecuta como JavaScript con acceso a `process`.'),
      secure: (v) => (ARITHMETIC.test(v.expr) ? null : 'El tokenizador solo conoce números y operadores; no hay forma de llegar a `process`.'),
    },
    exploited: (res, v) => res.status === 200 && !ARITHMETIC.test(v.expr),
    code: {
      vulnerable: `const result = eval(q.get('expr'));`,
      secure: `// calc.js: tokeniza y evalúa con descenso recursivo
const TOKEN = /\\s*(\\d+(?:\\.\\d+)?|[-+*/()])/y;
...
evaluate(expr);   // solo entiende números, + - * / y paréntesis`,
    },
  },

  {
    id: 'xss',
    title: 'XSS reflejado: inyectar HTML y JavaScript',
    kind: 'Cross-Site Scripting',
    explain:
      'El servidor inserta tu texto tal cual en la página. El navegador no distingue entre el HTML del sitio y el del atacante, y ejecuta su script. Debajo se renderiza la respuesta real en un iframe aislado.',
    impact: 'Robo de sesión, suplantación de la interfaz, acciones en nombre de la víctima.',
    fields: [{ name: 'name', label: 'Nombre' }],
    legit: { name: 'Ana' },
    attack: { name: `<img src=x onerror="document.body.innerHTML='<h1>💥 JavaScript ejecutado en tu navegador</h1>'">` },
    render: 'html',
    request: (v) => ({ method: 'GET', path: `/hello?${qs({ name: v.name })}` }),
    view: {
      vulnerable: (v) => ['<h1>Hola, ', inj(v.name), '!</h1>'],
      secure: (v) => [
        '<h1>Hola, ',
        inj(escapeHtml(v.name)),
        "!</h1>\n\nContent-Security-Policy: default-src 'none'; ...",
      ],
    },
    hint: {
      vulnerable: (v) => (/[<>]/.test(v.name) ? 'El navegador interpreta la etiqueta: `onerror` se dispara y ejecuta el JavaScript.' : null),
      secure: (v) => (/[<>]/.test(v.name) ? 'Los caracteres especiales se convierten en entidades: se muestran como texto, no se ejecutan.' : null),
    },
    exploited: (res, v) => /[<>]/.test(v.name) && res.text.includes(v.name),
    code: {
      vulnerable: `send(res, 200, \`<h1>Hola, \${q.get('name')}!</h1>\`);`,
      secure: `const escapeHtml = (t) => String(t).replace(/[&<>"']/g, (c) => ENTITIES[c]);

send(res, 200, \`<h1>Hola, \${escapeHtml(name)}!</h1>\`, {
  'Content-Security-Policy': "default-src 'none'; ...",   // segunda capa
});`,
    },
  },
];
