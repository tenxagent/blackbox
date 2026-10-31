// Hand-rolled Borsh for NEAR transactions (TransactionV0), no near-api-js.
//
// Borsh rules used here: integers little-endian (u8, u32, u64, u128); a string
// is u32 byte length + UTF-8 bytes; Vec<T> is u32 count + items; [u8; 32] is the
// 32 bytes as they are; an enum is a u8 variant index + the variant's fields.
//
// Transaction {                       (nearcore core/primitives TransactionV0)
//   signer_id:   string
//   public_key:  PublicKey  = u8 key type (0 = ED25519) + [u8; 32]
//   nonce:       u64
//   receiver_id: string
//   block_hash:  [u8; 32]
//   actions:     Vec<Action>
// }
// Action variants (u8 index):
//   0 CreateAccount  {}
//   1 DeployContract { code: Vec<u8> }
//   2 FunctionCall   { method_name: string, args: Vec<u8>, gas: u64, deposit: u128 }
//   3 Transfer       { deposit: u128 }
//   4 Stake          { stake: u128, public_key: PublicKey }
//   5 AddKey         { public_key: PublicKey, access_key: AccessKey }
//   6 DeleteKey      { public_key: PublicKey }
//   7 DeleteAccount  { beneficiary_id: string }
// AccessKey { nonce: u64, permission: u8 0 = FunctionCall { allowance: Option<u128>,
//   receiver_id: string, method_names: Vec<string> } | 1 = FullAccess }
// Signature = u8 key type (0 = ED25519) + [u8; 64]
// SignedTransaction = Transaction + Signature
//
// The signature and the tx hash are both over sha256(borsh(Transaction)).
// Only V0 is written: no leading 0x01 (that prefix marks TransactionV1).
// Test vectors: test/near.test.mjs (from near-api-js, cited there).

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

export class Writer {
  constructor() { this.parts = []; this.length = 0; }
  push(bytes) { this.parts.push(bytes); this.length += bytes.length; return this; }
  u8(n) { return this.push(Uint8Array.of(checkInt(n, 8))); }
  u32(n) { return this.uint(n, 4); }
  u64(n) { return this.uint(n, 8); }
  u128(n) { return this.uint(n, 16); }
  uint(n, size) {
    let v = BigInt(n);
    if (v < 0n || v >= 1n << BigInt(8 * size)) throw new RangeError(`u${8 * size} out of range: ${n}`);
    const b = new Uint8Array(size);
    for (let i = 0; i < size; i++) { b[i] = Number(v & 0xffn); v >>= 8n; }
    return this.push(b);
  }
  fixed(bytes, size) {
    if (bytes.length !== size) throw new RangeError(`expected ${size} bytes, got ${bytes.length}`);
    return this.push(Uint8Array.from(bytes));
  }
  bytes(bytes) { this.u32(bytes.length); return this.push(Uint8Array.from(bytes)); }
  string(s) { return this.bytes(textEncoder.encode(s)); }
  vec(items, writeItem) { this.u32(items.length); for (const it of items) writeItem(this, it); return this; }
  option(v, writeValue) { if (v === null || v === undefined) return this.u8(0); this.u8(1); writeValue(this, v); return this; }
  toBytes() {
    const out = new Uint8Array(this.length);
    let o = 0;
    for (const p of this.parts) { out.set(p, o); o += p.length; }
    return out;
  }
}

function checkInt(n, bits) {
  if (!Number.isInteger(n) || n < 0 || n >= 2 ** bits) throw new RangeError(`u${bits} out of range: ${n}`);
  return n;
}

export const KEY_TYPE_ED25519 = 0;

function writePublicKey(w, pk) {
  w.u8(KEY_TYPE_ED25519);
  w.fixed(pk, 32);
}

function writeAccessKey(w, ak) {
  w.u64(ak.nonce ?? 0n);
  if (ak.permission === 'FullAccess') return w.u8(1);
  const fc = ak.permission.functionCall;
  w.u8(0);
  w.option(fc.allowance, (w2, a) => w2.u128(a));
  w.string(fc.receiverId);
  w.vec(fc.methodNames, (w2, m) => w2.string(m));
}

// Action objects: exactly one key, e.g. { functionCall: {...} } or { transfer: {...} }.
export function writeAction(w, action) {
  const [kind] = Object.keys(action);
  const a = action[kind];
  switch (kind) {
    case 'createAccount': return w.u8(0);
    case 'deployContract': w.u8(1); return w.bytes(a.code);
    case 'functionCall':
      w.u8(2);
      w.string(a.methodName);
      w.bytes(a.args);
      w.u64(a.gas);
      return w.u128(a.deposit);
    case 'transfer': w.u8(3); return w.u128(a.deposit);
    case 'stake': w.u8(4); w.u128(a.stake); return writePublicKey(w, a.publicKey);
    case 'addKey': w.u8(5); writePublicKey(w, a.publicKey); return writeAccessKey(w, a.accessKey);
    case 'deleteKey': w.u8(6); return writePublicKey(w, a.publicKey);
    case 'deleteAccount': w.u8(7); return w.string(a.beneficiaryId);
    default: throw new Error(`unsupported action ${kind}`);
  }
}

export function serializeTransaction(tx) {
  const w = new Writer();
  w.string(tx.signerId);
  writePublicKey(w, tx.publicKey);
  w.u64(tx.nonce);
  w.string(tx.receiverId);
  w.fixed(tx.blockHash, 32);
  w.vec(tx.actions, writeAction);
  return w.toBytes();
}

export function serializeSignedTransaction(txBytes, signature) {
  const w = new Writer();
  w.push(Uint8Array.from(txBytes));
  w.u8(KEY_TYPE_ED25519);
  w.fixed(signature, 64);
  return w.toBytes();
}

// ---------------------------------------------------------------- reader
// Decodes the subset above; used by tests to round-trip the vectors.
export class Reader {
  constructor(bytes) { this.b = Uint8Array.from(bytes); this.o = 0; }
  take(n) {
    if (this.o + n > this.b.length) throw new RangeError('borsh: read past end');
    const s = this.b.slice(this.o, this.o + n); this.o += n; return s;
  }
  u8() { return this.take(1)[0]; }
  uint(size) { const s = this.take(size); let v = 0n; for (let i = size - 1; i >= 0; i--) v = (v << 8n) | BigInt(s[i]); return v; }
  u32() { return Number(this.uint(4)); }
  u64() { return this.uint(8); }
  u128() { return this.uint(16); }
  bytes() { return this.take(this.u32()); }
  string() { return textDecoder.decode(this.bytes()); }
  vec(readItem) { const n = this.u32(); const out = []; for (let i = 0; i < n; i++) out.push(readItem(this)); return out; }
  done() { return this.o === this.b.length; }
}

function readPublicKey(r) {
  const t = r.u8();
  if (t !== KEY_TYPE_ED25519) throw new Error(`unsupported key type ${t}`);
  return r.take(32);
}

function readAccessKey(r) {
  const nonce = r.u64();
  const tag = r.u8();
  if (tag === 1) return { nonce, permission: 'FullAccess' };
  if (tag !== 0) throw new Error(`decode: unsupported access key permission ${tag}`);
  const allowance = r.u8() ? r.u128() : null;
  return { nonce, permission: { functionCall: { allowance, receiverId: r.string(), methodNames: r.vec(x => x.string()) } } };
}

function readAction(r) {
  const tag = r.u8();
  switch (tag) {
    case 0: return { createAccount: {} };
    case 1: return { deployContract: { code: r.bytes() } };
    case 2: return { functionCall: { methodName: r.string(), args: r.bytes(), gas: r.u64(), deposit: r.u128() } };
    case 3: return { transfer: { deposit: r.u128() } };
    case 4: return { stake: { stake: r.u128(), publicKey: readPublicKey(r) } };
    case 5: return { addKey: { publicKey: readPublicKey(r), accessKey: readAccessKey(r) } };
    case 6: return { deleteKey: { publicKey: readPublicKey(r) } };
    case 7: return { deleteAccount: { beneficiaryId: r.string() } };
    default: throw new Error(`decode: unsupported action tag ${tag}`);
  }
}

export function decodeTransaction(bytes) {
  const r = new Reader(bytes);
  const tx = {
    signerId: r.string(),
    publicKey: readPublicKey(r),
    nonce: r.u64(),
    receiverId: r.string(),
    blockHash: r.take(32),
    actions: r.vec(readAction),
  };
  return { tx, rest: r.b.slice(r.o) };
}

export function decodeSignedTransaction(bytes) {
  const { tx, rest } = decodeTransaction(bytes);
  const r = new Reader(rest);
  const keyType = r.u8();
  if (keyType !== KEY_TYPE_ED25519) throw new Error(`unsupported signature type ${keyType}`);
  const signature = r.take(64);
  if (!r.done()) throw new Error('trailing bytes after signature');
  return { tx, signature, txBytes: bytes.slice(0, bytes.length - 65) };
}
