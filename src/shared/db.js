import { DatabaseSync } from 'node:sqlite';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

// Hash con scrypt (incluido en Node): "salt:hash" en hexadecimal.
export function hashPassword(password, salt = randomBytes(16)) {
  const hash = scryptSync(password, salt, 32);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

export function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const expected = Buffer.from(hashHex, 'hex');
  const actual = scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length);
  return timingSafeEqual(actual, expected);
}

const USERS = [
  ['admin', 'S3cr3t-Adm1n!', 'admin'],
  ['alice', 'alice123', 'user'],
];

const PRODUCTS = [
  ['Teclado mecánico', 'perifericos', 59.9],
  ['Mouse inalámbrico', 'perifericos', 24.5],
  ['Monitor 27"', 'pantallas', 229],
  ['Webcam HD', 'pantallas', 39],
];

// hashed=false  -> contraseñas en texto plano (app "legacy" vulnerable)
// hashed=true   -> contraseñas hasheadas con scrypt (app corregida)
export function createDb({ hashed }) {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT);
    CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL);
  `);
  const addUser = db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)');
  for (const [u, p, r] of USERS) addUser.run(u, hashed ? hashPassword(p) : p, r);
  const addProduct = db.prepare('INSERT INTO products (name, category, price) VALUES (?, ?, ?)');
  for (const [n, c, p] of PRODUCTS) addProduct.run(n, c, p);
  return db;
}
