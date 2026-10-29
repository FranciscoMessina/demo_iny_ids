import { scenarios } from './scenarios.js';

// Todo el contenido dinámico (payloads, respuestas) se inserta con nodos de texto, nunca con innerHTML.

const token = document.querySelector('meta[name="demo-token"]').content;
const SIDES = [
  { key: 'vulnerable', label: 'Servidor vulnerable', short: 'V' },
  { key: 'secure', label: 'Servidor seguro', short: 'S' },
];
const VERDICT_ICON = { exploited: '✘', blocked: '✔', ok: '✔', fail: '!' };

const state = {
  id: scenarios[0].id,
  values: Object.fromEntries(scenarios.map((s) => [s.id, { ...s.attack }])),
  results: {}, // id -> { req, sides: { vulnerable, secure } }
};
const current = () => scenarios.find((s) => s.id === state.id);

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  el.append(...kids.flat().filter((k) => k != null && k !== false));
  return el;
}

// Texto con `código` inline -> nodos <code>.
const rich = (text) => text.split('`').map((part, i) => (i % 2 ? h('code', {}, part) : part));
const parts = (list) => list.map((p) => (typeof p === 'string' ? p : h('mark', {}, p.inj)));
const isLegit = (s, v) => Object.keys(s.legit).every((k) => v[k] === s.legit[k]);

// ---------- Red ----------

async function call(target, req) {
  const url = `/proxy/${token}/${target}${req.path}`;
  try {
    const r = await fetch(url, {
      method: req.method,
      headers: req.body ? { 'Content-Type': 'application/json' } : {},
      body: req.body ? JSON.stringify(req.body) : undefined,
    });
    const text = await r.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {}
    return { status: r.status, text, json, csp: r.headers.get('x-original-csp'), url };
  } catch (err) {
    return { status: 0, text: String(err), json: null, csp: null, url };
  }
}

function verdictOf(s, values, res) {
  if (res.status === 0) return { kind: 'fail', text: 'Sin respuesta' };
  if (isLegit(s, values)) {
    return res.status === 200
      ? { kind: 'ok', text: 'Funciona con normalidad' }
      : { kind: 'fail', text: 'Falló el uso legítimo' };
  }
  return s.exploited(res, values) ? { kind: 'exploited', text: 'Ataque exitoso' } : { kind: 'blocked', text: 'Ataque bloqueado' };
}

async function run(s) {
  const values = { ...state.values[s.id] };
  const req = s.request(values);
  const [vulnerable, secure] = await Promise.all(SIDES.map((side) => call(side.key, req)));
  const pack = (res) => ({ res, verdict: verdictOf(s, values, res) });
  state.results[s.id] = { req, sides: { vulnerable: pack(vulnerable), secure: pack(secure) } };
  refresh(s);
}

async function runAll() {
  const button = document.getElementById('run-all');
  button.disabled = true;
  for (const s of scenarios) {
    state.values[s.id] = { ...s.attack };
    await run(s);
  }
  button.disabled = false;
}

function preset(s, kind) {
  state.values[s.id] = { ...s[kind] };
  renderMain();
  run(s);
}

function refresh(s) {
  renderNav();
  renderScore();
  if (s.id === state.id) renderResults();
}

// ---------- Vistas ----------

function renderScore() {
  const box = document.getElementById('score');
  box.replaceChildren(
    ...SIDES.map((side) => {
      const verdicts = Object.values(state.results).map((r) => r.sides[side.key].verdict.kind);
      const exploited = verdicts.filter((k) => k === 'exploited').length;
      const blocked = verdicts.filter((k) => k === 'blocked').length;
      const total = exploited + blocked;
      return h(
        'div',
        { class: `pill ${side.key}` },
        h('span', { class: 'pill-label' }, side.label),
        h('strong', {}, total ? `${exploited} explotado${exploited === 1 ? '' : 's'}` : '—'),
        total ? h('span', { class: 'pill-sub' }, `${blocked} bloqueado${blocked === 1 ? '' : 's'}`) : null,
      );
    }),
  );
}

function renderNav() {
  document.getElementById('nav').replaceChildren(
    ...scenarios.map((s, i) =>
      h(
        'button',
        {
          type: 'button',
          class: `nav-item${s.id === state.id ? ' active' : ''}`,
          'aria-current': s.id === state.id ? 'true' : null,
          onclick: () => {
            state.id = s.id;
            renderNav();
            renderMain();
          },
        },
        h('span', { class: 'nav-num' }, String(i + 1)),
        h('span', { class: 'nav-text' }, h('span', { class: 'nav-kind' }, s.kind), s.title.split(':')[0]),
        h(
          'span',
          { class: 'chips' },
          ...SIDES.map((side) => {
            const v = state.results[s.id]?.sides[side.key].verdict;
            return h(
              'span',
              { class: `chip ${v ? v.kind : 'idle'}`, title: `${side.label}: ${v ? v.text : 'sin ejecutar'}` },
              `${side.short} ${v ? VERDICT_ICON[v.kind] : '·'}`,
            );
          }),
        ),
      ),
    ),
  );
}

function renderMain() {
  const s = current();
  const values = state.values[s.id];

  const form = h(
    'form',
    {
      class: 'form',
      onsubmit: (e) => {
        e.preventDefault();
        run(s);
      },
    },
    ...s.fields.map((f) =>
      h(
        'label',
        { class: 'field' },
        h('span', {}, f.label),
        h('input', {
          type: 'text',
          name: f.name,
          value: values[f.name],
          spellcheck: 'false',
          autocomplete: 'off',
          oninput: (e) => {
            values[f.name] = e.target.value;
            renderExec();
          },
        }),
      ),
    ),
    h(
      'div',
      { class: 'actions' },
      h('button', { type: 'button', class: 'btn', onclick: () => preset(s, 'legit') }, 'Probar uso legítimo'),
      h('button', { type: 'button', class: 'btn danger', onclick: () => preset(s, 'attack') }, 'Lanzar ataque'),
      h('button', { type: 'submit', class: 'btn ghost' }, 'Enviar valores actuales'),
    ),
  );

  const cards = SIDES.map((side) =>
    h(
      'article',
      { class: `card ${side.key}`, 'data-side': side.key },
      h('header', {}, h('h3', {}, side.label), h('span', { class: 'badge idle' }, 'Sin ejecutar')),
      h('section', {}, h('h4', {}, 'Lo que ejecuta el servidor'), h('pre', { class: 'exec' }), h('p', { class: 'hint' })),
      h('section', { class: 'result' }),
    ),
  );

  document.getElementById('main').replaceChildren(
    h(
      'section',
      { class: 'intro' },
      h('p', { class: 'kicker' }, s.kind),
      h('h2', {}, s.title),
      h('p', {}, rich(s.explain)),
      h('p', { class: 'impact' }, h('strong', {}, 'Impacto: '), s.impact),
    ),
    form,
    h('div', { class: 'request', id: 'request' }),
    h('div', { class: 'versus' }, ...cards),
    h(
      'details',
      { class: 'code', open: true },
      h('summary', {}, 'Ver el código: qué cambia'),
      h(
        'div',
        { class: 'code-grid' },
        h('div', {}, h('h4', { class: 'vulnerable' }, 'Vulnerable'), h('pre', {}, s.code.vulnerable)),
        h('div', {}, h('h4', { class: 'secure' }, 'Seguro'), h('pre', {}, s.code.secure)),
      ),
    ),
  );

  renderExec();
  renderResults();
}

// "Lo que ejecuta el servidor" se actualiza mientras escribes, sin enviar nada.
function renderExec() {
  const s = current();
  const values = state.values[s.id];
  for (const side of SIDES) {
    const card = document.querySelector(`.card.${side.key}`);
    card.querySelector('.exec').replaceChildren(...parts(s.view[side.key](values)));
    const hint = s.hint[side.key](values);
    const el = card.querySelector('.hint');
    el.replaceChildren(...(hint ? rich(hint) : []));
    el.hidden = !hint;
  }
}

function renderResults() {
  const s = current();
  const result = state.results[s.id];
  const request = document.getElementById('request');

  if (!result) {
    request.hidden = true;
    for (const side of SIDES) {
      const card = document.querySelector(`.card.${side.key}`);
      setBadge(card, { kind: 'idle', text: 'Sin ejecutar' });
      card.querySelector('.result').replaceChildren(h('p', { class: 'muted' }, 'Pulsa «Lanzar ataque» o «Probar uso legítimo».'));
    }
    return;
  }

  request.hidden = false;
  request.replaceChildren(
    h('span', { class: 'label' }, 'Petición enviada a ambos'),
    h('code', {}, `${result.req.method} ${result.req.path}`, result.req.body ? `  ${JSON.stringify(result.req.body)}` : ''),
  );

  for (const side of SIDES) {
    const { res, verdict } = result.sides[side.key];
    const card = document.querySelector(`.card.${side.key}`);
    setBadge(card, verdict);
    const body = res.json ? JSON.stringify(res.json, null, 2) : res.text;
    card.querySelector('.result').replaceChildren(
      h('h4', {}, 'Respuesta ', h('span', { class: `status s${Math.floor(res.status / 100)}` }, `HTTP ${res.status || 'error'}`)),
      h('pre', { class: 'body' }, body),
      res.csp ? h('p', { class: 'csp' }, h('strong', {}, 'Content-Security-Policy: '), res.csp) : null,
      s.render === 'html' && res.status ? frame(side, res.url) : null,
    );
  }
}

// La respuesta real se muestra en un iframe aislado (sandbox sin same-origin ni top-navigation).
function frame(side, url) {
  return h(
    'div',
    { class: 'frame' },
    h('span', { class: 'label' }, 'Así lo ve el navegador'),
    h('iframe', { src: url, sandbox: 'allow-scripts', title: `Página renderizada por el ${side.label.toLowerCase()}`, loading: 'eager' }),
  );
}

function setBadge(card, verdict) {
  const badge = card.querySelector('.badge');
  badge.className = `badge ${verdict.kind}`;
  badge.replaceChildren(VERDICT_ICON[verdict.kind] ? `${VERDICT_ICON[verdict.kind]} ${verdict.text}` : verdict.text);
}

document.getElementById('run-all').addEventListener('click', runAll);
renderNav();
renderScore();
renderMain();
