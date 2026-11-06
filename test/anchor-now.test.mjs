// src/anchor-now.mjs: the pre-send anchor's own checks (prefix of the published records, the decision is in the export, the
// registry's strictly increasing seq), and the CLI refusing an export that does not extend the published records.
import { assert } from './lib.mjs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { prefixProblem, findBySrc, registryPlan } from '../src/anchor-now.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const rec = (seq, src) => JSON.stringify({ seq, src, cat: 'gate', row: { action: 'gate_allow' } });
const H = (c) => c.repeat(64);

export const tests = [
  {
    name: 'the published records must be a whole-line byte prefix of the fresh export',
    fn() {
      const pub = 'a\nb\n';
      assert.equal(prefixProblem(pub, 'a\nb\nc\n'), null);
      assert.equal(prefixProblem(pub, pub), null);
      assert.equal(prefixProblem('', 'a\n'), null);
      assert.match(prefixProblem(pub, 'a\nB\nc\n'), /differs from the published records at line 2/);
      assert.match(prefixProblem(pub, 'a\n'), /line 2/);                 // the export lost a published record
      assert.match(prefixProblem('a\nb', 'a\nbc\n'), /newline/);          // a cut mid-line is not a prefix of records
    },
  },
  {
    name: 'finds the decision by the sha256 of its raw ledger line, rejects a malformed one',
    fn() {
      const lines = [rec(1, H('1')), rec(2, H('2')), rec(3, H('3'))];
      assert.equal(findBySrc(lines, H('2')).seq, 2);
      assert.equal(findBySrc(lines, H('9')), null);
      assert.throws(() => findBySrc(lines, 'abc'), /64 lowercase hex/);
      assert.throws(() => findBySrc(lines, undefined), /64 lowercase hex/);
    },
  },
  {
    name: 'registry plan — write a higher seq, skip the same seq + head, refuse a higher or conflicting one',
    fn() {
      assert.equal(registryPlan(null, 5, H('a')), 'write');
      assert.equal(registryPlan({ seq: 4, head: H('b') }, 5, H('a')), 'write');
      assert.equal(registryPlan({ seq: 5, head: H('a') }, 5, H('a')), 'already');
      assert.match(registryPlan({ seq: 5, head: H('b') }, 5, H('a')), /another head/);
      assert.match(registryPlan({ seq: 6, head: H('b') }, 5, H('a')), /already holds seq 6/);
    },
  },
  {
    name: 'CLI: refuses (exit 1, ok:false) an export that does not extend the published records, before any network',
    fn() {
      const r = spawnSync(process.execPath, ['src/anchor-now.mjs', '--config', 'examples/minimal-agent/blackbox.config.json', '--include-src', H('0')],
        { cwd: root, encoding: 'utf8', env: { PATH: process.env.PATH, BLACKBOX_LEDGER: 'examples/minimal-agent/ledger.jsonl' }, timeout: 60000 });
      assert.equal(r.status, 1, r.stderr);
      const o = JSON.parse(r.stdout.trim().split('\n').pop());
      assert.equal(o.ok, false);
      assert.match(o.why, /differs from the published records/);
      const s = spawnSync(process.execPath, ['src/anchor-now.mjs', '--include-src', H('0'), '--send'], { cwd: root, encoding: 'utf8', env: { PATH: process.env.PATH, BLACKBOX_LEDGER: 'x' }, timeout: 20000 });
      assert.match(JSON.parse(s.stdout.trim()).why, /i-understand-mainnet/);
    },
  },
];
