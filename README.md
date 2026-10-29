<img src="assets/icon.svg" width="64" height="64" alt="">

# demo-inyeccion

Demo educativa de **inyección maliciosa de código**: el mismo conjunto de ataques se lanza contra un servidor **vulnerable** y contra uno **seguro** que aplica buenas prácticas. Todo en JavaScript puro, **sin dependencias** (solo módulos incluidos en Node).

> ⚠️ El servidor vulnerable es intencionalmente inseguro. Úsalo solo en local (escucha en `127.0.0.1`) y con fines de aprendizaje.

## Requisitos

Node.js ≥ 22.13 (usa `node:sqlite`, `fetch` y `node:test` integrados). Probado con Node 24.

## Uso

```bash
npm run ui          # interfaz web en http://127.0.0.1:8080 (recomendado para presentar la demo)
npm run attack      # lanza los 5 ataques contra ambos servidores y compara resultados
npm test            # los mismos escenarios como tests automáticos
npm run vulnerable  # servidor vulnerable en http://127.0.0.1:3000 (para probar a mano)
npm run secure      # servidor seguro     en http://127.0.0.1:3001
```

### Interfaz web

`npm run ui` abre un laboratorio en el navegador (puerto 8080, o `PORT=9000 npm run ui`). Para cada ataque muestra:

- **Lo que ejecuta cada servidor**, con tu entrada resaltada en amarillo y actualizada mientras escribes (la consulta SQL, el comando de shell, el `eval`, el HTML resultante).
- Botones **Probar uso legítimo** y **Lanzar ataque**, o edita el payload y pulsa *Enviar valores actuales*.
- La **respuesta real** de ambos servidores con un veredicto (`Ataque exitoso` / `Ataque bloqueado`).
- En XSS, la página resultante **renderizada en un iframe aislado**: en el vulnerable verás el JavaScript ejecutarse.
- El **código vulnerable vs. seguro** al lado, y un marcador global con **Ejecutar todos los ataques**.

La UI levanta los dos servidores internamente (puertos efímeros) y hace de proxy, así que no necesitas arrancarlos aparte. Como el servidor vulnerable ejecuta comandos reales, la UI valida la cabecera `Host`, exige un token aleatorio por ejecución y los servidores internos rechazan peticiones sin él; así otra pestaña del navegador no puede usarlos para atacar tu equipo.

### Línea de comandos

`npm run attack` imprime, para cada ataque, `✘ ATAQUE EXITOSO` o `✔ ataque bloqueado` junto con la respuesta real del servidor. También verifica que el **uso legítimo** siga funcionando en ambos.

## Casos

| # | Ataque | Payload | En el vulnerable | Defensa en el seguro |
|---|--------|---------|------------------|----------------------|
| 1 | SQL Injection (login) | `username: admin'--` | Entra como admin sin contraseña | Consultas parametrizadas, validación de tipos, hash `scrypt` + `timingSafeEqual`, mismo error exista o no el usuario |
| 2 | SQL Injection (UNION) | `x' UNION SELECT id,username,password,0 FROM users--` | Vuelca usuarios y contraseñas | Parámetro enlazado (`?`): el payload es solo texto; las contraseñas además están hasheadas |
| 3 | Command Injection | `notes.txt && echo INYECTADO && whoami` | Ejecuta comandos en el SO | Lista blanca (regex) del nombre + `execFile` **sin shell** y con argumentos separados |
| 4 | Code Injection (`eval`) | `process.env.SECRET_KEY` | Filtra el secreto del proceso | Sin `eval`: parser aritmético propio (`src/secure/calc.js`) |
| 5 | XSS reflejado | `<script>alert(document.cookie)</script>` | El script se inserta en el HTML | Escape de salida (`escapeHtml`) + cabecera `Content-Security-Policy` |

### Pruebas manuales (con `npm run vulnerable` / `npm run secure`)

```bash
# Login bypass
curl -X POST localhost:3000/login -d "{\"username\":\"admin'--\",\"password\":\"x\"}"

# Volcado de usuarios
curl "localhost:3000/products?category=x'%20UNION%20SELECT%20id,username,password,0%20FROM%20users--"

# Ejecución de comandos
curl "localhost:3000/wordcount?file=notes.txt%20%26%26%20whoami"

# eval
curl "localhost:3000/calc?expr=process.env.SECRET_KEY"

# XSS (abrir en el navegador)
http://localhost:3000/hello?name=<script>alert(1)</script>
```

Cambia el puerto a `3001` para ver cómo responde el servidor seguro.

## Estructura

```
attacks/scenarios.js     Escenarios: uso legítimo + ataque (compartidos por runner y tests)
attacks/run.js           Levanta ambos servidores y compara resultados
src/vulnerable/server.js Código inseguro, con cada falla comentada
src/secure/server.js     Misma API con defensas; calc.js y escape.js son sus helpers
src/ui/server.js         Servidor de la interfaz: estáticos + proxy protegido hacia ambos servidores
src/ui/public/           Frontend (HTML/CSS/JS sin framework); scenarios.js define cada ataque
src/shared/              BD SQLite en memoria, helpers HTTP y la herramienta externa wc.js
test/                    Tests con node:test (servidores, escenarios y seguridad del proxy de la UI)
```

Se recomienda leer `src/vulnerable/server.js` y `src/secure/server.js` lado a lado: las rutas son las mismas.

## Buenas prácticas, en resumen

1. **Separa datos de código**: consultas parametrizadas, `execFile` con array de argumentos, nunca concatenar entrada en SQL/shell/HTML.
2. **No ejecutes texto como código**: evita `eval`, `new Function`, `vm` con entrada no confiable.
3. **Valida en el borde** (tipo, longitud, formato) con listas blancas; es una capa extra, no sustituye a las anteriores.
4. **Codifica la salida según el contexto** (HTML, atributo, URL, JS) y añade CSP como segunda línea de defensa.
5. **Mínimo privilegio y mínima información**: errores genéricos al cliente, secretos fuera del alcance del código expuesto, contraseñas siempre hasheadas con sal.

## Limitaciones

Es una demo: no incluye autenticación de sesión, límites de peticiones, HTTPS ni otras defensas de producción. Las defensas del servidor seguro son ilustrativas y están elegidas para cada ataque concreto.
