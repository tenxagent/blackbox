// Inspects the registry wasm: size, sha256, NEAR code hash, imports, exports, and a full decode of every
// function body to prove it uses only WebAssembly MVP (1.0) instructions and types.
// Node stdlib only.
//
//   node contract/scripts/inspect-wasm.mjs [path/to/blackbox_registry.wasm] [--sizes] [--json]
//
// Exits 1 if anything is off:
// - imports must be exactly EXPECTED_IMPORTS, all functions from module "env" (so no storage_remove, no
//   promise_* / deploy / key actions: the code has no way to delete state or change itself);
// - exports must be exactly EXPECTED_EXPORTS (memory + the seven methods);
// - every opcode, block type and function type must be MVP: no multi-value (nearcore rejects it), no
//   sign-extension, saturating truncation, bulk memory, reference types, SIMD, threads, tail calls or
//   exceptions; no start function; at most one table and one non-shared 32-bit memory.
// --sizes lists the largest function bodies (needs a name section, i.e. an unstripped build).
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { base58Encode } from '../../src/near/keys.mjs';

export const EXPECTED_IMPORTS = [
  'attached_deposit', 'block_index', 'block_timestamp', 'input', 'log_utf8', 'panic_utf8', 'predecessor_account_id',
  'read_register', 'register_len', 'storage_has_key', 'storage_read', 'storage_usage', 'storage_write', 'value_return',
];
export const EXPECTED_EXPORTS = ['anchor', 'get_agent', 'get_agents', 'get_anchors', 'memory', 'new', 'register', 'storage_deposit'];
export const YOCTO_PER_BYTE = 10n ** 19n;

const VALTYPES = new Set([0x7f, 0x7e, 0x7d, 0x7c]); // i32 i64 f32 f64
const SECTION_NAMES = ['custom', 'type', 'import', 'function', 'table', 'memory', 'global', 'export', 'start', 'element', 'code', 'data', 'datacount'];

class R {
  constructor(bytes, pos = 0, end = bytes.length) { this.b = bytes; this.p = pos; this.end = end; }
  u8() { if (this.p >= this.end) throw new Error('unexpected end'); return this.b[this.p++]; }
  uleb() { let r = 0n, s = 0n, x; do { x = this.u8(); r |= BigInt(x & 0x7f) << s; s += 7n; } while (x & 0x80); return r; }
  u32() { return Number(this.uleb()); }
  sleb() { let s = 0n, x; do { x = this.u8(); s += 7n; } while (x & 0x80); }
  bytes(n) { if (this.p + n > this.end) throw new Error('unexpected end'); const v = this.b.subarray(this.p, this.p + n); this.p += n; return v; }
  name() { return new TextDecoder().decode(this.bytes(this.u32())); }
}

// Decodes one function body, returns the number of instructions; pushes non-MVP findings to `problems`.
function decodeBody(r, fi, problems) {
  const where = (op) => `function ${fi}: opcode 0x${op.toString(16).padStart(2, '0')} at byte ${r.p - 1}`;
  for (let groups = r.u32(); groups > 0; groups--) {
    r.u32();
    const t = r.u8();
    if (!VALTYPES.has(t)) problems.push(`function ${fi}: non-MVP local type 0x${t.toString(16)}`);
  }
  let n = 0, depth = 1;
  while (r.p < r.end) {
    const op = r.u8();
    n++;
    if (op === 0x02 || op === 0x03 || op === 0x04) { // block / loop / if: blocktype
      const bt = r.u8();
      if (bt !== 0x40 && !VALTYPES.has(bt)) problems.push(`${where(op)}: block type 0x${bt.toString(16)} (multi-value)`);
      depth++;
    } else if (op === 0x0b) { // end
      depth--;
      if (depth === 0) { if (r.p !== r.end) problems.push(`function ${fi}: bytes after the final end`); return n; }
    } else if (op === 0x00 || op === 0x01 || op === 0x05 || op === 0x0f || op === 0x1a || op === 0x1b) {
      // unreachable nop else return drop select
    } else if (op === 0x0c || op === 0x0d || op === 0x10 || (op >= 0x20 && op <= 0x24)) {
      r.u32(); // br br_if call local.* global.*
    } else if (op === 0x0e) { // br_table
      for (let k = r.u32(); k >= 0; k--) r.u32();
    } else if (op === 0x11) { // call_indirect typeidx table(0x00)
      r.u32();
      if (r.u8() !== 0) problems.push(`${where(op)}: call_indirect on a table other than 0`);
    } else if (op >= 0x28 && op <= 0x3e) { // loads / stores: memarg
      r.u32(); r.u32();
    } else if (op === 0x3f || op === 0x40) { // memory.size / memory.grow
      if (r.u8() !== 0) problems.push(`${where(op)}: memory index other than 0`);
    } else if (op === 0x41 || op === 0x42) {
      r.sleb();
    } else if (op === 0x43) {
      r.bytes(4);
    } else if (op === 0x44) {
      r.bytes(8);
    } else if (op >= 0x45 && op <= 0xbf) {
      // numeric, no immediates
    } else {
      problems.push(`${where(op)} is not WebAssembly MVP`);
      return n; // cannot decode further reliably
    }
  }
  problems.push(`function ${fi}: body has no final end`);
  return n;
}

function constExpr(r, problems, what) {
  const op = r.u8();
  if (op === 0x41 || op === 0x42) r.sleb();
  else if (op === 0x43) r.bytes(4);
  else if (op === 0x44) r.bytes(8);
  else if (op === 0x23) r.u32();
  else problems.push(`${what}: non-MVP init expression 0x${op.toString(16)}`);
  if (r.u8() !== 0x0b) problems.push(`${what}: init expression longer than one instruction`);
}

export function inspectWasm(bytes) {
  bytes = new Uint8Array(bytes);
  const problems = [];
  const sha = createHash('sha256').update(bytes).digest();
  const mod = new WebAssembly.Module(bytes); // also validates the module
  const imports = WebAssembly.Module.imports(mod);
  const exports = WebAssembly.Module.exports(mod);

  for (const i of imports) {
    if (i.module !== 'env' || i.kind !== 'function') problems.push(`import ${i.module}.${i.name} (${i.kind}) is not an env function`);
  }
  const importNames = imports.map((i) => i.name).sort();
  const exportNames = exports.map((e) => e.name).sort();
  if (JSON.stringify(importNames) !== JSON.stringify(EXPECTED_IMPORTS)) problems.push(`imports differ: ${importNames.join(', ')}`);
  if (JSON.stringify(exportNames) !== JSON.stringify(EXPECTED_EXPORTS)) problems.push(`exports differ: ${exportNames.join(', ')}`);
  for (const e of exports) {
    if (e.name !== 'memory' && e.kind !== 'function') problems.push(`export ${e.name} is a ${e.kind}`);
  }

  const r = new R(bytes);
  if (bytes[0] !== 0 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) problems.push('bad magic');
  if (bytes[4] !== 1 || bytes[5] || bytes[6] || bytes[7]) problems.push('not wasm version 1');
  r.p = 8;
  const sections = [];
  const funcNames = new Map();
  let importedFuncs = 0, bodies = [], instructions = 0;
  while (r.p < bytes.length) {
    const id = r.u8();
    const size = r.u32();
    const start = r.p, end = r.p + size;
    const s = new R(bytes, start, end);
    const label = SECTION_NAMES[id] ?? `unknown(${id})`;
    if (id === 0) {
      const name = s.name();
      sections.push({ id, name: `custom:${name}`, size });
      if (name === 'name') {
        while (s.p < end) {
          const sub = s.u8(), len = s.u32(), subEnd = s.p + len;
          if (sub === 1) for (let k = s.u32(); k > 0; k--) { const idx = s.u32(); funcNames.set(idx, s.name()); }
          s.p = subEnd;
        }
      }
    } else {
      sections.push({ id, name: label, size });
    }
    if (id === 1) {
      for (let k = s.u32(), t = 0; k > 0; k--, t++) {
        if (s.u8() !== 0x60) problems.push(`type ${t}: not a function type`);
        const np = s.u32();
        for (let j = 0; j < np; j++) if (!VALTYPES.has(s.u8())) problems.push(`type ${t}: non-MVP param type`);
        const nr = s.u32();
        if (nr > 1) problems.push(`type ${t}: ${nr} results (multi-value)`);
        for (let j = 0; j < nr; j++) if (!VALTYPES.has(s.u8())) problems.push(`type ${t}: non-MVP result type`);
      }
    } else if (id === 2) {
      for (let k = s.u32(); k > 0; k--) {
        s.name(); s.name();
        const kind = s.u8();
        if (kind === 0) { s.u32(); importedFuncs++; } else problems.push(`import of kind ${kind}`);
      }
    } else if (id === 4) {
      const n = s.u32();
      if (n > 1) problems.push(`${n} tables (MVP allows one)`);
      for (let k = n; k > 0; k--) {
        if (s.u8() !== 0x70) problems.push('table of a non-funcref type');
        const flags = s.u8(); s.u32(); if (flags & 1) s.u32();
      }
    } else if (id === 5) {
      const n = s.u32();
      if (n > 1) problems.push(`${n} memories`);
      for (let k = n; k > 0; k--) {
        const flags = s.u8();
        if (flags & ~1) problems.push(`memory flags 0x${flags.toString(16)} (shared or memory64)`);
        s.u32(); if (flags & 1) s.u32();
      }
    } else if (id === 6) {
      for (let k = s.u32(), g = 0; k > 0; k--, g++) {
        if (!VALTYPES.has(s.u8())) problems.push(`global ${g}: non-MVP type`);
        s.u8();
        constExpr(s, problems, `global ${g}`);
      }
    } else if (id === 8) {
      problems.push('start section (code would run at deploy time)');
    } else if (id === 9) {
      for (let k = s.u32(); k > 0; k--) {
        const flags = s.u32();
        if (flags !== 0) { problems.push(`element segment flags ${flags} (reference types / bulk memory)`); break; }
        constExpr(s, problems, 'element offset');
        for (let j = s.u32(); j > 0; j--) s.u32();
      }
    } else if (id === 10) {
      for (let k = s.u32(), fi = importedFuncs; k > 0; k--, fi++) {
        const len = s.u32();
        const body = new R(bytes, s.p, s.p + len);
        try {
          instructions += decodeBody(body, fi, problems);
        } catch (e) {
          problems.push(`function ${fi}: ${e.message}`);
        }
        bodies.push({ index: fi, size: len, name: null });
        s.p += len;
      }
    } else if (id === 11) {
      for (let k = s.u32(); k > 0; k--) {
        const flags = s.u32();
        if (flags !== 0) { problems.push(`data segment flags ${flags} (bulk memory)`); break; }
        constExpr(s, problems, 'data offset');
        s.bytes(s.u32());
      }
    } else if (id === 12) {
      problems.push('datacount section (bulk memory)');
    } else if (id > 12) {
      problems.push(`unknown section id ${id}`);
    }
    r.p = end;
  }
  for (const b of bodies) b.name = funcNames.get(b.index) ?? null;

  return {
    size: bytes.length,
    sha256: sha.toString('hex'),
    codeHash: base58Encode(sha),
    stakeYocto: BigInt(bytes.length) * YOCTO_PER_BYTE,
    imports: imports.map((i) => `${i.module}.${i.name}`),
    exports: exports.map((e) => `${e.name}:${e.kind}`),
    sections,
    functions: bodies.length,
    instructions,
    bodies,
    problems,
  };
}

function main() {
  const argv = process.argv.slice(2);
  const file = argv.find((a) => !a.startsWith('--')) ?? fileURLToPath(new URL('../res/blackbox_registry.wasm', import.meta.url));
  const info = inspectWasm(readFileSync(file));
  if (argv.includes('--json')) {
    console.log(JSON.stringify(info, (k, v) => (typeof v === 'bigint' ? v.toString() : k === 'bodies' ? undefined : v), 2));
  } else {
    console.log(`file          ${file}`);
    console.log(`size          ${info.size} bytes (storage stake for the code: ${Number(info.stakeYocto / 10n ** 15n) / 1e9} NEAR)`);
    console.log(`sha256        ${info.sha256}`);
    console.log(`code hash     ${info.codeHash}   (base58 of the sha256: what view_account / view_code report)`);
    console.log(`imports (${info.imports.length})  ${info.imports.join(' ')}`);
    console.log(`exports (${info.exports.length})  ${info.exports.join(' ')}`);
    console.log(`sections      ${info.sections.map((s) => `${s.name}=${s.size}`).join(' ')}`);
    console.log(`code          ${info.functions} functions, ${info.instructions} instructions decoded, all checked against the MVP opcode set`);
    if (argv.includes('--sizes')) {
      for (const b of [...info.bodies].sort((a, b) => b.size - a.size).slice(0, 25)) console.log(`  ${String(b.size).padStart(6)}  ${b.name ?? `#${b.index}`}`);
    }
    console.log(info.problems.length ? `\nPROBLEMS:\n  ${info.problems.join('\n  ')}` : '\nOK: env-only imports as expected, exact export list, MVP-only wasm');
  }
  if (info.problems.length) process.exit(1);
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) main();
