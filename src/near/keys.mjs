// ed25519 keys for NEAR with node:crypto only, plus base58 (Bitcoin alphabet,
// which NEAR uses for keys, block hashes and tx hashes).
//
//   public key string   "ed25519:" + base58(32-byte public key)
//   secret key string   "ed25519:" + base58(32-byte seed || 32-byte public key)
//   implicit account id hex(32-byte public key), 64 lowercase hex characters
//   tx signature        ed25519 over sha256(borsh(Transaction)), 64 bytes

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify, randomBytes } from 'node:crypto';

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const INDEX = new Map([...ALPHABET].map((c, i) => [c, i]));

export function base58Encode(bytes) {
  bytes = Uint8Array.from(bytes);
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  // repeated division of the big-endian number by 58
  const digits = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let s = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) s += ALPHABET[digits[i]];
  return s;
}

export function base58Decode(str) {
  if (typeof str !== 'string') throw new TypeError('base58: not a string');
  let zeros = 0;
  while (zeros < str.length && str[zeros] === '1') zeros++;
  const bytes = []; // little-endian accumulator
  for (let i = zeros; i < str.length; i++) {
    const v = INDEX.get(str[i]);
    if (v === undefined) throw new Error(`base58: invalid character ${JSON.stringify(str[i])}`);
    let carry = v;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[out.length - 1 - i] = bytes[i];
  return out;
}

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function b64urlToBytes(s) {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

export function toHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

// A key pair from a 32-byte seed.
export function keyPairFromSeed(seed) {
  if (seed.length !== 32) throw new Error('ed25519 seed must be 32 bytes');
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
  const publicKey = b64urlToBytes(createPublicKey(privateKey).export({ format: 'jwk' }).x);
  return makePair(Uint8Array.from(seed), publicKey, privateKey);
}

export function generateKeyPair() {
  const { privateKey } = generateKeyPairSync('ed25519');
  const seed = b64urlToBytes(privateKey.export({ format: 'jwk' }).d);
  return keyPairFromSeed(seed);
}

// "ed25519:<base58 of 64 bytes seed||pub>" (near-cli format) or of a 32-byte seed.
export function keyPairFromString(secret) {
  const [type, data] = parseTyped(secret);
  if (type !== 'ed25519') throw new Error(`unsupported key type ${type}`);
  const raw = base58Decode(data);
  if (raw.length !== 64 && raw.length !== 32) throw new Error(`ed25519 secret key must be 32 or 64 bytes, got ${raw.length}`);
  const pair = keyPairFromSeed(raw.slice(0, 32));
  if (raw.length === 64 && toHex(raw.slice(32)) !== toHex(pair.publicKey)) {
    throw new Error('secret key: embedded public key does not match the seed');
  }
  return pair;
}

function makePair(seed, publicKey, privateKey) {
  return {
    publicKey, // 32 bytes
    publicKeyString: 'ed25519:' + base58Encode(publicKey),
    implicitAccountId: toHex(publicKey),
    // The secret is reachable only through these two functions, never printed.
    secretKeyString: () => 'ed25519:' + base58Encode(Uint8Array.from([...seed, ...publicKey])),
    sign: (message) => new Uint8Array(edSign(null, Buffer.from(message), privateKey)),
    toJSON: () => ({ publicKey: 'ed25519:' + base58Encode(publicKey) }),
  };
}

export function parseTyped(s) {
  const i = s.indexOf(':');
  return i < 0 ? ['ed25519', s] : [s.slice(0, i), s.slice(i + 1)];
}

export function publicKeyFromString(s) {
  const [type, data] = parseTyped(s);
  if (type !== 'ed25519') throw new Error(`unsupported key type ${type}`);
  const raw = base58Decode(data);
  if (raw.length !== 32) throw new Error('ed25519 public key must be 32 bytes');
  return raw;
}

export function verifySignature(message, signature, publicKey) {
  const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(publicKey)]), format: 'der', type: 'spki' });
  return edVerify(null, Buffer.from(message), key, Buffer.from(signature));
}

export function randomSeed() {
  return new Uint8Array(randomBytes(32));
}
