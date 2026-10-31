// examples/minimal-agent: a made-up agent with its own config. Shows that the exporter, the chain and the
// verifiers work for an agent other than claude-10x. Everything in that folder is synthetic.
import { assert } from './lib.mjs';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { exportText, loadConfig, excludedOf, addressHash, ADDRESS_IN_TEXT } from '../src/export.mjs';
import { buildLines, verifyLines, verifySparse, splitLines } from '../src/chain.mjs';
import { canon, isCanonicalLine } from '../src/canon.mjs';
import { checkRecords } from '../web/verify.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const dir = path.join(root, 'examples/minimal-agent');
const read = (p) => readFileSync(path.join(dir, p), 'utf8');
const config = loadConfig(path.join(dir, 'blackbox.config.json'));
const exported = () => exportText(read('ledger.jsonl'), { config });
const node = (args) => spawnSync(process.execPath, args, { cwd: root, encoding: 'utf8', timeout: 60000 });

export const tests = [
  {
    name: 'export of the synthetic ledger matches expected/records.jsonl and manifest.json byte for byte',
    fn() {
      const { lines, manifest } = exported();
      assert.equal(lines.join('\n') + '\n', read('expected/records.jsonl'));
      assert.equal(JSON.stringify(manifest, null, 1) + '\n', read('expected/manifest.json'));
      assert.ok(lines.every(isCanonicalLine));
      return `${manifest.source.linesRead} ledger lines -> ${lines.length} records`;
    },
  },
  {
    name: 'filter and privacy rules applied (telemetry, private engine, excluded address, reduced rows, secrets, paths)',
    fn() {
      const { lines, manifest: m } = exported();
      const recs = lines.map((l) => JSON.parse(l));
      const text = lines.join('\n');
      // the last ledger line has no newline yet (still being written): not read
      assert.equal(m.source.linesRead, 18);
      assert.deepEqual(m.droppedByReason, { 'privacy:engine-personal': 1, 'privacy:operator-wallet': 1, telemetry: 3, unparseable: 1 });
      assert.deepEqual(m.keptByCategory, { application: 1, error: 1, lifecycle: 2, money: 3, refusal: 2, sim: 2, unclassified: 1 });
      assert.deepEqual(m.unclassifiedTypes, { rebalance_plan: 1 });
      // nothing from the private engine, no excluded address, no secret values
      assert.ok(!recs.some((r) => r.row.engine === 'personal'));
      const excluded = excludedOf(config);
      for (const a of text.matchAll(ADDRESS_IN_TEXT)) assert.ok(!excluded.has(addressHash(a[0])), a[0]);
      for (const s of ['FAKE-KEY-0000', 'FAKE.SESSION.TOKEN', 'agent@example.com', 'example-dao', '"bids"', 'gasUsed']) assert.ok(!text.includes(s), s);
      // the stack trace keeps its text, the local paths become <path>; a URL that contains /home/ is kept
      const err = recs.find((r) => r.cat === 'error');
      assert.equal(err.row.stack, 'Error: RPC timeout after 10 s\n    at send (<path>:42:7)\n    at async main (<path>:10:3)');
      assert.equal(err.row.docs, 'https://example.com/home/user/rpc-timeouts');
      assert.deepEqual(err.stripped, ['stack~path']);
      // reduced engine: only the listed fields; the names (not the values) of the removed ones are recorded
      const app = recs.find((r) => r.row.engine === 'signup');
      assert.deepEqual(app.row, { action: 'applied', engine: 'signup', t: '2026-11-01T09:45:00.000Z', type: 'application' });
      assert.deepEqual(app.stripped, ['project', 'email', 'form']);
      // tx hashes from tx and txs[], lowercased; the token address (public chain data) is kept
      assert.deepEqual(recs.filter((r) => r.txs.length).map((r) => [r.seq, r.txs.length]), [[3, 1], [4, 1], [10, 2]]);
      assert.equal(recs[9].txs[0], '0x' + 'beef'.repeat(16));
      assert.equal(recs[2].row.token, '0x' + '7e57'.repeat(10));
      assert.deepEqual(recs[3].stripped, ['apiKey', 'resp']);
    },
  },
  {
    name: 'chain over the records matches expected heads/checkpoints, verifies, and finds a changed record',
    async fn() {
      const lines = splitLines(read('expected/records.jsonl'));
      const heads = splitLines(read('expected/heads.txt'));
      const cp = JSON.parse(read('expected/checkpoints.json'));
      assert.equal(cp.agentId, config.agentId);
      const res = await buildLines(lines, { agentId: config.agentId });
      assert.deepEqual(res.heads, heads);
      assert.deepEqual(res.checkpoints, cp.checkpoints);
      assert.deepEqual(res.final, cp.final);
      assert.deepEqual(await verifyLines(lines, heads, { agentId: cp.agentId }), { ok: true, index: -1, reason: 'all heads match' });
      const claims = [{ seq: 0, head: cp.genesis }, ...cp.checkpoints, cp.final];
      assert.equal((await verifySparse(lines, claims, { agentId: cp.agentId })).okThrough, lines.length);
      // the heads belong to this agent: claude-10x's agentId gives another genesis
      assert.equal((await verifyLines(lines, heads)).index, 0);
      // one changed field in record 5 (the refusal): exact seq from heads.txt, interval from the checkpoints
      const bad = [...lines];
      const r5 = JSON.parse(bad[4]);
      r5.row.why = 'slippage was fine';
      bad[4] = canon(r5);
      assert.equal((await verifyLines(bad, heads, { agentId: cp.agentId })).index, 5);
      assert.deepEqual((await verifySparse(bad, claims, { agentId: cp.agentId })).firstBad, { after: 0, upTo: 8 });
      // the browser verifier, given the example's checkpoints, agrees
      const page = await checkRecords(read('expected/records.jsonl'), cp);
      assert.equal(page.structural, null);
      assert.equal(page.sparse.ok, true);
      assert.equal((await checkRecords(bad.join('\n') + '\n', cp)).sparse.ok, false);
    },
  },
  {
    name: 'the CLIs end to end (export --config --ledger --out, chain build --config --dir, chain verify --dir)',
    fn() {
      const tmp = mkdtempSync(path.join(tmpdir(), 'bb-example-'));
      try {
        const cfgArg = ['--config', 'examples/minimal-agent/blackbox.config.json'];
        const ex = node(['src/export.mjs', ...cfgArg, '--ledger', 'examples/minimal-agent/ledger.jsonl', '--out', tmp]);
        assert.equal(ex.status, 0, ex.stderr);
        assert.match(ex.stdout, /KEPT 12 records \(3 carry a tx hash\)/);
        const b = node(['src/chain.mjs', 'build', ...cfgArg, '--dir', tmp]);
        assert.equal(b.status, 0, b.stderr);
        for (const f of ['records.jsonl', 'manifest.json', 'checkpoints.json', 'heads.txt']) {
          assert.equal(readFileSync(path.join(tmp, f), 'utf8'), read(`expected/${f}`), f);
        }
        const v = node(['src/chain.mjs', 'verify', '--dir', tmp]);
        assert.equal(v.status, 0, v.stdout + v.stderr);
        assert.match(v.stdout, /heads\.txt: +OK, all 12 heads match/);
        const t = node(['src/chain.mjs', 'tamper', '--dir', tmp, '--seq', '7', '--out', path.join(tmp, 'bad.jsonl')]);
        assert.equal(t.status, 0, t.stderr);
        const vb = node(['src/chain.mjs', 'verify', '--dir', tmp, '--records', path.join(tmp, 'bad.jsonl')]);
        assert.equal(vb.status, 1);
        assert.match(vb.stdout, /FIRST MISMATCH at seq 7/);
        // a config that is not valid stops the export before anything is written
        writeFileSync(path.join(tmp, 'bad.config.json'), JSON.stringify({ agentId: config.agentId, telemetry: {} }));
        const bc = node(['src/export.mjs', '--config', path.join(tmp, 'bad.config.json'), '--ledger', 'examples/minimal-agent/ledger.jsonl', '--out', path.join(tmp, 'x')]);
        assert.equal(bc.status, 2);
        assert.match(bc.stderr, /unknown field "telemetry"/);
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
    },
  },
];
