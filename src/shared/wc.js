// Mini herramienta externa: cuenta palabras de un archivo.
// Los servidores la invocan como si fuera un binario del sistema (wc, ffmpeg, etc.).
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

const file = process.argv[2];
try {
  const words = readFileSync(file, 'utf8').split(/\s+/).filter(Boolean).length;
  console.log(`${basename(file)}: ${words} palabras`);
} catch {
  console.error('No se pudo leer el archivo');
  process.exit(1);
}
