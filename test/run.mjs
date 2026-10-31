// Runs every test/*.test.mjs and prints PASS / FAIL / SKIP per test.
//   node test/run.mjs            all tests (network tests SKIP if offline)
//   node test/run.mjs --offline  skip the tests that touch the network
//   node test/run.mjs chain      only files whose name contains "chain"
import { readdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { Skip } from './lib.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const offline = args.includes('--offline');
const filters = args.filter((a) => !a.startsWith('--'));

const files = readdirSync(here)
  .filter((f) => f.endsWith('.test.mjs'))
  .filter((f) => filters.length === 0 || filters.some((x) => f.includes(x)))
  .sort();

let pass = 0, fail = 0, skip = 0;
for (const f of files) {
  const mod = await import(pathToFileURL(join(here, f)).href);
  for (const t of mod.tests) {
    const label = `${f.replace('.test.mjs', '')}: ${t.name}`;
    if (t.network && offline) {
      console.log(`SKIP ${label} (offline)`);
      skip++;
      continue;
    }
    try {
      const note = await t.fn();
      console.log(`PASS ${label}${note ? ` (${note})` : ''}`);
      pass++;
    } catch (e) {
      if (e instanceof Skip) {
        console.log(`SKIP ${label} (${e.message})`);
        skip++;
      } else {
        console.log(`FAIL ${label}: ${e?.message || e}`);
        fail++;
      }
    }
  }
}
console.log(`\n${pass} passed, ${fail} failed, ${skip} skipped`);
process.exit(fail ? 1 : 0);
