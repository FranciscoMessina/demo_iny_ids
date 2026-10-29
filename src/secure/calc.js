// Calculadora segura: tokeniza y evalúa con descenso recursivo.
// Solo reconoce números, + - * / y paréntesis: no hay forma de llegar a código JavaScript.
const TOKEN = /\s*(\d+(?:\.\d+)?|[-+*/()])/y;
const MAX_LENGTH = 100;

export function evaluate(expr) {
  if (typeof expr !== 'string' || expr.length === 0 || expr.length > MAX_LENGTH) throw new Error('inválida');

  const tokens = [];
  let pos = 0;
  while (pos < expr.length) {
    TOKEN.lastIndex = pos;
    const m = TOKEN.exec(expr);
    if (!m) {
      if (expr.slice(pos).trim() === '') break; // solo espacios al final
      throw new Error('carácter no permitido');
    }
    tokens.push(m[1]);
    pos = TOKEN.lastIndex;
  }

  let i = 0;
  const parseExpr = () => {
    let v = parseTerm();
    while (tokens[i] === '+' || tokens[i] === '-') v = tokens[i++] === '+' ? v + parseTerm() : v - parseTerm();
    return v;
  };
  const parseTerm = () => {
    let v = parseFactor();
    while (tokens[i] === '*' || tokens[i] === '/') v = tokens[i++] === '*' ? v * parseFactor() : v / parseFactor();
    return v;
  };
  const parseFactor = () => {
    const t = tokens[i++];
    if (t === '-') return -parseFactor();
    if (t === '(') {
      const v = parseExpr();
      if (tokens[i++] !== ')') throw new Error('paréntesis sin cerrar');
      return v;
    }
    if (t !== undefined && /^\d/.test(t)) return Number(t);
    throw new Error('sintaxis');
  };

  const result = parseExpr();
  if (i !== tokens.length || !Number.isFinite(result)) throw new Error('inválida');
  return result;
}
