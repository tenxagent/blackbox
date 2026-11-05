// The committed registry wasm (contract/res/) against its checks and the hashes in contract/README.md,
// plus the wasm inspector's own negative cases on hand-assembled modules.
import { assert, Skip } from './lib.mjs';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { inspectWasm } from '../contract/scripts/inspect-wasm.mjs';
import { REGISTRY_CODE_HASH as CLI_CODE_HASH } from '../src/registry-cli.mjs';
import { REGISTRY_CODE_HASH as WEB_CODE_HASH } from '../web/verify.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const wasmPath = `${root}contract/res/blackbox_registry.wasm`;

// Minimal module builder: one type, optional imports, one function body.
const leb = (n) => { const o = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; o.push(b); } while (n); return o; };
const str = (s) => [...leb(s.length), ...new TextEncoder().encode(s)];
const section = (id, bytes) => [id, ...leb(bytes.length), ...bytes];
function module({ results = [], imports = [], body = [0x0b], exports = [] }) {
  const type = section(1, [1, 0x60, 0, ...leb(results.length), ...results]);
  const imp = imports.length ? section(2, [...leb(imports.length), ...imports.flatMap((n) => [...str('env'), ...str(n), 0, 0])]) : [];
  const func = section(3, [1, 0]);
  const exp = section(7, [...leb(exports.length), ...exports.flatMap((n) => [...str(n), 0, imports.length])]);
  const code = section(10, [1, ...leb(body.length + 1), 0, ...body]);
  return new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, ...type, ...imp, ...func, ...exp, ...code]);
}

export const tests = [
  {
    name: 'registry wasm: env-only imports, exact exports, MVP-only code, ≤ 30 KB, hashes match contract/README.md and the CLI/web constants',
    fn() {
      if (!existsSync(wasmPath)) throw new Skip('contract/res/blackbox_registry.wasm not built (bash contract/build.sh)');
      const info = inspectWasm(readFileSync(wasmPath));
      assert.deepEqual(info.problems, []);
      assert.ok(info.size <= 30 * 1024, `${info.size} bytes`);
      assert.ok(!info.imports.some((i) => /storage_remove|promise_|deploy|delete_key|add_key/.test(i)), info.imports.join());
      const readme = readFileSync(`${root}contract/README.md`, 'utf8');
      assert.ok(readme.includes(info.sha256), `README does not list sha256 ${info.sha256}`);
      assert.ok(readme.includes(info.codeHash), `README does not list code hash ${info.codeHash}`);
      assert.ok(readme.includes(`${info.size.toLocaleString('en-US')} bytes`), `README does not list the size ${info.size}`);
      // the CLI (step 10) and the web page compare the chain's code hash against these constants ⇒ they must be the hash of THIS wasm
      assert.equal(CLI_CODE_HASH, info.codeHash, 'src/registry-cli.mjs REGISTRY_CODE_HASH is not the hash of contract/res/blackbox_registry.wasm');
      assert.equal(WEB_CODE_HASH, info.codeHash, 'web/verify.js REGISTRY_CODE_HASH is not the hash of contract/res/blackbox_registry.wasm');
      return `${info.size} bytes, code hash ${info.codeHash}`;
    },
  },
  {
    name: 'wasm inspector: flags multi-value, sign-extension, bulk memory, forbidden imports and extra exports',
    fn() {
      const clean = module({ body: [0x0b] });
      const base = inspectWasm(clean).problems.filter((p) => !/^(imports|exports) differ/.test(p));
      assert.deepEqual(base, [], 'a trivial MVP module decodes cleanly');
      const has = (bytes, re) => inspectWasm(bytes).problems.some((p) => re.test(p));
      assert.ok(has(module({ results: [0x7f, 0x7f], body: [0x41, 1, 0x41, 2, 0x0b] }), /multi-value/));
      assert.ok(has(module({ results: [0x7f], body: [0x41, 1, 0xc0, 0x0b] }), /opcode 0xc0 .*not WebAssembly MVP/));
      assert.ok(has(module({ body: [0x43, 0, 0, 0, 0, 0xfc, 0x00, 0x1a, 0x0b] }), /opcode 0xfc .*not WebAssembly MVP/)); // i32.trunc_sat_f32_s
      assert.ok(has(module({ imports: ['storage_remove'] }), /imports differ/));
      assert.ok(has(module({ exports: ['migrate'] }), /exports differ/));
    },
  },
];
