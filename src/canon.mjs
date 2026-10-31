// Canonical JSON, Black box v1.
//
// One JSON value has exactly one byte string. The rules:
//
//   1. Objects: members sorted by key, comparing keys as UTF-16 code units
//      (the default JavaScript string sort). No duplicate keys.
//   2. No whitespace anywhere: no spaces, no newlines.
//   3. Strings are escaped exactly as JSON.stringify does it (ECMAScript
//      QuoteJSONString): `"` `\` and U+0000..U+001F are escaped, \b \f \n \r \t
//      use the short form, other control characters use lowercase \u00XX, lone
//      surrogates use \udXXX, every other character is written as itself.
//   4. Numbers are written as JSON.stringify writes them (ECMAScript
//      Number::toString): 1, 0.1, 1e+21, 1e-7. -0 becomes 0. NaN and
//      Infinity are rejected.
//   5. true, false and null are written as themselves. Arrays keep their order.
//   6. Anything that is not JSON is rejected with an error: undefined,
//      functions, symbols, BigInt, Date, Map and other non-plain objects.
//      toJSON() is not honoured.
//   7. The canonical text is hashed as UTF-8.
//
// For the values the exporter emits, these rules give the same output as
// RFC 8785 (JSON Canonicalization Scheme): JCS also sorts by UTF-16 code
// units, uses ECMAScript number serialisation and JSON.stringify string
// escaping. test/canon.test.mjs runs the RFC 8785 section 3.2.2 example.
//
// This file has no imports so that the browser verifier loads the same code.

export function canon(value) {
  return write(value, '$');
}

function write(v, path) {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'boolean':
      return v ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(v)) throw new TypeError(`canon: non-finite number at ${path}`);
      return JSON.stringify(v); // -0 -> "0"
    case 'string':
      return JSON.stringify(v);
    case 'object':
      break;
    default:
      throw new TypeError(`canon: ${typeof v} is not JSON at ${path}`);
  }
  if (Array.isArray(v)) {
    const out = [];
    for (let i = 0; i < v.length; i++) {
      if (!(i in v)) throw new TypeError(`canon: sparse array at ${path}[${i}]`);
      out.push(write(v[i], `${path}[${i}]`));
    }
    return '[' + out.join(',') + ']';
  }
  const proto = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) {
    throw new TypeError(`canon: non-plain object at ${path}`);
  }
  const keys = Object.keys(v).sort();
  const out = [];
  for (const k of keys) {
    out.push(JSON.stringify(k) + ':' + write(v[k], `${path}.${k}`));
  }
  return '{' + out.join(',') + '}';
}

// True when `line` is already the canonical form of the JSON it contains.
export function isCanonicalLine(line) {
  try {
    return canon(JSON.parse(line)) === line;
  } catch {
    return false;
  }
}
