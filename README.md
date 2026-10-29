<img src="assets/icon.svg" width="64" height="64" alt="">

# demo-inyeccion

Demo educativa de **Command Injection** en un caso realista: la herramienta de **«Diagnóstico de red» (ping)** del panel de cliente de un hosting ficticio (*Nubeo*). Es un patrón que se ha encontrado muchas veces en paneles de hosting, routers y equipos de monitoreo. JavaScript puro, sin dependencias.

| Archivo | Qué es |
|---------|--------|
| `demo.js` | Servidor: versión vulnerable y versión corregida de la herramienta de ping |
| `demo.html` | La página (panel de cliente) y el «Modo clase» con el material didáctico |

Requiere Node.js ≥ 18 (probado con Node 24).

## Uso

```bash
node demo.js
```

| Versión | URL |
|---------|-----|
| Vulnerable | http://127.0.0.1:8080 |
| Corregida | http://127.0.0.1:8081 |

Para cambiar el puerto base: `PORT=9000 node demo.js` (usa 9000 y 9001). Termina con Ctrl+C.

> `demo.html` no funciona abriéndolo con doble clic: un navegador no puede ejecutar comandos del sistema, así que `demo.js` tiene que servirlo. En la versión vulnerable los comandos inyectados **se ejecutan de verdad** en tu equipo (con los ejemplos incluidos son inocuos: `whoami`, `hostname`, listar archivos).

## La página

Se ve como un panel real: cabecera, estado del servidor y una tarjeta «Prueba de conectividad (ping)» donde cualquier usuario escribe un dominio o IP y ve el resultado.

El botón **🎓 Modo clase** (abajo a la derecha) abre un panel lateral, separado de la página, con:

- La versión que estás viendo y un enlace a la otra.
- **Ejemplos con un clic**: uso normal, `&& whoami`, listar archivos, `hostname` y una tubería `|`.
- **Lo que ejecutó el servidor**, con la entrada del usuario resaltada, y un veredicto (*Ataque exitoso* / *Ataque bloqueado* / *Funciona con normalidad*).
- El código con el defecto o el corregido, y un guion sugerido para la exposición.

## El defecto y la corrección

**Vulnerable** (`pingVulnerable`): el destino se concatena en una línea que interpreta el shell.

```js
exec(`ping ${CONTADOR} 2 ${host}`)
// host = "127.0.0.1 && whoami"  →  se ejecutan DOS comandos
```

**Corregida** (`pingSeguro`), dos capas independientes:

1. **Lista blanca**: solo se acepta una IP (`net.isIP`) o un nombre de dominio bien formado. Además impide inyectar *opciones* de `ping` (un dominio no puede empezar con `-`).
2. **Sin shell**: `execFile('ping', [flag, '2', host])` pasa cada argumento por separado; `&&`, `;` o `|` son caracteres del nombre, no operadores.

En el Modo clase de la versión corregida, la casilla *«Desactivar la lista blanca»* anula la capa 1 para comprobar que la capa 2 sola también neutraliza el ataque (defensa en profundidad).

## Seguridad de la propia demo

Los servidores escuchan solo en `127.0.0.1`, validan la cabecera `Host` (contra DNS rebinding), exigen un token aleatorio generado en cada arranque para usar la API y la página lleva una CSP con nonce. Así otra pestaña del navegador no puede usar tu demo para ejecutar comandos en tu equipo. La carpeta de la «aplicación» (archivos de relleno inocuos) es un directorio temporal que se borra al salir con Ctrl+C.

## Buenas prácticas, en resumen

1. **No pases entrada del usuario a un shell.** Usa `execFile`/`spawn` con un array de argumentos, sin `shell: true`.
2. **Valida con listas blancas** (formato, longitud, conjunto permitido) antes de usar el dato; cuida también la *inyección de argumentos* (valores que empiezan con `-`).
3. Si puedes, **no ejecutes procesos**: usa una librería o API nativa para la tarea.
4. **Mínimo privilegio**: el proceso que ejecuta herramientas externas no debería tener más permisos de los necesarios.
5. Añade `timeout` y limita el tamaño de la entrada.
