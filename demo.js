#!/usr/bin/env node
// Demo educativa de COMMAND INJECTION en un caso real: la herramienta "Diagnóstico de red"
// (ping) de un panel de hosting ficticio. Un solo archivo de servidor, sin dependencias.
//
//   node demo.js        versión VULNERABLE en http://127.0.0.1:8080
//                       versión CORREGIDA  en http://127.0.0.1:8081   (sirven demo.html)
//   PORT=9000 node demo.js
//
// ⚠️  La versión vulnerable ejecuta comandos reales en tu equipo. Los servidores escuchan solo en
// 127.0.0.1, validan la cabecera Host y exigen un token aleatorio para que otra página abierta en tu
// navegador no pueda usarlos. Úsalo únicamente con fines educativos.
'use strict';
const http = require('node:http');
const net = require('node:net');
const { exec, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

const WIN = process.platform === 'win32';
const CONTADOR = WIN ? '-n' : '-c'; // ping -n 2 (Windows) / ping -c 2 (Linux, macOS)
const TIMEOUT_MS = 10_000;
// Operadores que el shell de cada plataforma interpreta (solo para etiquetar el intento en la demo).
const OPERADORES = WIN ? /[&|<>\r\n^]/ : /[;&|`$<>\r\n]/;
const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;

let appdir; // directorio temporal que hace de carpeta de la aplicación

// ───────────────────────── Versión VULNERABLE ─────────────────────────
// El dominio escrito por el usuario se concatena en una línea de texto que interpreta un shell.
// Con  host = "127.0.0.1 && whoami"  el shell ejecuta DOS comandos: ping y whoami.

async function pingVulnerable(host) {
  const comando = `ping ${CONTADOR} 2 ${host}`;
  return {
    vista: [`shell> ping ${CONTADOR} 2 `, { inj: host }],
    salida: await capturar(execAsync(comando, { cwd: appdir, timeout: TIMEOUT_MS, encoding: 'buffer' })),
  };
}

// ───────────────────────── Versión CORREGIDA ─────────────────────────
// Capa 1: lista blanca. Solo se aceptan IPs (net.isIP) o nombres de dominio bien formados.
//         Además impide argumentos tipo "-t" (un dominio no puede empezar con "-").
// Capa 2: execFile no usa shell y pasa cada argumento por separado: "&&", ";", "|" son solo texto.

async function pingSeguro(host, { listaBlanca = true } = {}) {
  const valido = net.isIP(host) !== 0 || HOSTNAME.test(host);
  if (listaBlanca && !valido) {
    return {
      vista: ['✗ ', { inj: host }, '\n  no es una IP ni un dominio válido\n  → no se ejecuta ningún proceso'],
      salida: '',
      mensaje: 'Ingresa un dominio o una dirección IP válidos.',
      rechazado: true,
    };
  }
  return {
    vista: [`execFile("ping", ["${CONTADOR}", "2", `, { inj: JSON.stringify(host) }, '])   // sin shell'],
    salida: await capturar(execFileAsync('ping', [CONTADOR, '2', host], { cwd: appdir, timeout: TIMEOUT_MS, encoding: 'buffer' })),
  };
}

// ───────────────────────── Utilidades ─────────────────────────

// La consola de Windows usa cp850/cp437; Node no la decodifica, así que se traducen los acentos habituales.
const CP850 = { 0x80: 'Ç', 0x81: 'ü', 0x82: 'é', 0xa0: 'á', 0xa1: 'í', 0xa2: 'ó', 0xa3: 'ú', 0xa4: 'ñ', 0xa5: 'Ñ',
  0xa8: '¿', 0xad: '¡', 0xb5: 'Á', 0xd6: 'Í', 0xe0: 'Ó', 0xe9: 'Ú', 0x90: 'É' };

function decodificar(buf) {
  if (!buf) return '';
  const texto = WIN ? Array.from(buf, (b) => (b < 0x80 ? String.fromCharCode(b) : (CP850[b] ?? '?'))).join('') : buf.toString('utf8');
  return texto.replace(/\r\n/g, '\n');
}

async function capturar(promesa) {
  try {
    const { stdout, stderr } = await promesa;
    return decodificar(Buffer.concat([stdout, stderr])).trim();
  } catch (err) {
    if (err.killed) return 'La prueba tardó demasiado y se canceló.';
    return decodificar(Buffer.concat([err.stdout ?? Buffer.alloc(0), err.stderr ?? Buffer.alloc(0)])).trim() || err.message;
  }
}

// ───────────────────────── Servidores web ─────────────────────────

function crearServidor({ modo, plantilla, token, urlOtraVersion }) {
  const responder = (res, status, cuerpo, headers = {}) => {
    const esJson = typeof cuerpo !== 'string';
    res.writeHead(status, {
      'Content-Type': esJson ? 'application/json; charset=utf-8' : 'text/html; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
      ...headers,
    });
    res.end(esJson ? JSON.stringify(cuerpo) : cuerpo);
  };

  const server = http.createServer(async (req, res) => {
    try {
      const { port } = server.address();
      if (req.headers.host !== `127.0.0.1:${port}` && req.headers.host !== `localhost:${port}`) {
        return responder(res, 403, 'Prohibido');
      }
      if (req.method !== 'GET') return responder(res, 405, 'Método no permitido');
      const url = new URL(req.url, 'http://localhost');

      if (url.pathname === '/') {
        const nonce = crypto.randomBytes(12).toString('base64');
        const html = plantilla
          .replaceAll('__NONCE__', nonce)
          .replaceAll('__TOKEN__', token)
          .replaceAll('__PLATFORM__', process.platform)
          .replaceAll('__MODE__', modo)
          .replaceAll('__OTHER_URL__', urlOtraVersion);
        return responder(res, 200, html, {
          'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
        });
      }

      const m = /^\/api\/([0-9a-f]+)\/ping$/.exec(url.pathname);
      if (!m) return responder(res, 404, { error: 'No encontrado' });
      const enviado = Buffer.from(m[1]);
      const esperado = Buffer.from(token);
      if (enviado.length !== esperado.length || !crypto.timingSafeEqual(enviado, esperado)) {
        return responder(res, 403, { error: 'Token inválido' });
      }

      const host = url.searchParams.get('host') ?? '';
      if (host.length > 300) return responder(res, 400, { error: 'Entrada demasiado larga' });

      const resultado =
        modo === 'vulnerable'
          ? await pingVulnerable(host)
          : await pingSeguro(host, { listaBlanca: url.searchParams.get('lista') !== '0' });
      // Etiqueta didáctica: en la versión vulnerable, un operador del shell significa que se ejecutó otro comando.
      resultado.explotado = modo === 'vulnerable' && OPERADORES.test(host);
      responder(res, 200, resultado);
    } catch (err) {
      console.error('[error]', err.message);
      if (!res.headersSent) responder(res, 500, { error: 'Error interno' });
    }
  });
  return server;
}

function escuchar(server, puerto) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(puerto, '127.0.0.1', resolve);
  });
}

// ───────────────────────── Arranque ─────────────────────────

async function main() {
  // Carpeta de la "aplicación" con archivos inocuos, para que un listado de directorio tenga algo que mostrar.
  appdir = fs.mkdtempSync(path.join(os.tmpdir(), 'nubeo-app-'));
  fs.writeFileSync(path.join(appdir, 'server.js'), "// Panel de cliente Nubeo (demo)\nconsole.log('ok');\n");
  fs.writeFileSync(path.join(appdir, 'package.json'), '{ "name": "panel-nubeo", "version": "3.2.1" }\n');
  fs.writeFileSync(path.join(appdir, 'LEEME.txt'), 'Aplicación ficticia usada solo para la demo.\n');
  fs.mkdirSync(path.join(appdir, 'logs'));
  const limpiar = () => fs.rmSync(appdir, { recursive: true, force: true });
  process.on('exit', limpiar);
  for (const senal of ['SIGINT', 'SIGTERM']) process.on(senal, () => process.exit(0));

  const base = Number(process.env.PORT ?? 8080);
  const token = crypto.randomBytes(16).toString('hex');
  const plantilla = fs.readFileSync(path.join(__dirname, 'demo.html'), 'utf8');
  const url = (puerto) => `http://127.0.0.1:${puerto}`;

  const vulnerable = crearServidor({ modo: 'vulnerable', plantilla, token, urlOtraVersion: url(base + 1) });
  const corregida = crearServidor({ modo: 'secure', plantilla, token, urlOtraVersion: url(base) });
  try {
    await escuchar(vulnerable, base);
    await escuchar(corregida, base + 1);
  } catch (err) {
    console.error(err.code === 'EADDRINUSE' ? `Puerto ocupado. Prueba con PORT=9000 node demo.js` : err.message);
    process.exit(1);
  }
  console.log(`Versión VULNERABLE: ${url(base)}`);
  console.log(`Versión CORREGIDA:  ${url(base + 1)}`);
  console.log('Ctrl+C para salir.');
}

main();
