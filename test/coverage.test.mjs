// src/coverage.mjs reconcile(): which of the wallet's nonces are explained by a record's own tx hash, which by a
// recorded mint/crank batch (nonce0 + rungs, ending at the next known nonce), and which are left over.
import { assert } from './lib.mjs';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { reconcile } from '../src/coverage.mjs';

const known = (...ns) => new Map(ns.map((n) => [n, `tx ${n}`]));

export const tests = [
  {
    name: 'every nonce explained by a tx hash ⇒ no gaps',
    fn() {
      const r = reconcile(known(0, 1, 2, 3), [], 4);
      assert.deepEqual([r.explainedTx, r.explainedBatch, r.unexplained, r.gaps.length], [4, 0, 0, 0]);
    },
  },
  {
    name: 'a batch covers nonce0 … up to the next known nonce, never past nonce0 + rungs',
    fn() {
      // batch at 2 with 10 rungs, next known tx at 5 ⇒ 2,3,4 from the batch; 6..9 are not covered (only 3 rungs were sent)
      const r = reconcile(known(0, 1, 5), [{ nonce0: 2, rungs: 10, seq: 7 }], 10);
      assert.equal(r.explainedBatch, 3);
      assert.deepEqual(r.gaps, [{ from: 6, to: 9 }]);
      // a short batch: 2 rungs from 6 cover 6,7 only
      const r2 = reconcile(known(0, 1, 5), [{ nonce0: 2, rungs: 10, seq: 7 }, { nonce0: 6, rungs: 2, seq: 9 }], 10);
      assert.deepEqual(r2.gaps, [{ from: 8, to: 9 }]);
    },
  },
  {
    name: 'consecutive unexplained nonces merge into one range; totals add up',
    fn() {
      const r = reconcile(known(1, 4), [], 7);
      assert.deepEqual(r.gaps, [{ from: 0, to: 0 }, { from: 2, to: 3 }, { from: 5, to: 6 }]);
      assert.equal(r.explainedTx + r.explainedBatch + r.unexplained, r.total);
    },
  },
  {
    name: 'committed data/coverage.json is internally consistent',
    fn() {
      const p = fileURLToPath(new URL('../data/coverage.json', import.meta.url));
      if (!existsSync(p)) return;
      const c = JSON.parse(readFileSync(p, 'utf8'));
      assert.equal(c.explainedTx + c.explainedBatch + c.unexplained, c.total);
      assert.equal(c.gaps.reduce((s, g) => s + g.n, 0), c.unexplained);
    },
  },
];
