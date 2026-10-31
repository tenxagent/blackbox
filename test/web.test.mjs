// The browser verifier's logic, run in Node (same module the page loads).
import { assert, netOrSkip } from './lib.mjs';
import { readFileSync } from 'node:fs';
import { checkRecords, describe, readNearAnchor } from '../web/verify.js';
import { canon } from '../src/canon.mjs';

const text = readFileSync(new URL('../data/records.jsonl', import.meta.url), 'utf8');
const cp = JSON.parse(readFileSync(new URL('../data/checkpoints.json', import.meta.url), 'utf8'));

export const tests = [
  {
    name: 'page check: committed records => chain OK up to the last seq',
    async fn() {
      const r = await checkRecords(text, cp);
      assert.equal(r.structural, null);
      assert.equal(r.sparse.ok, true);
      assert.equal(r.sparse.okThrough, cp.final.seq);
    },
  },
  {
    name: 'page check: one changed record => exact seq from the structural check or the checkpoint interval',
    async fn() {
      const lines = text.split('\n').filter(Boolean);
      const rec = JSON.parse(lines[499]);
      rec.row.t = '2020-01-01T00:00:00.000Z'; // still canonical, content changed
      const bad = [...lines];
      bad[499] = canon(rec);
      const r = await checkRecords(bad.join('\n') + '\n', cp);
      assert.equal(r.sparse.ok, false);
      assert.ok(r.sparse.firstBad.after < 500 && r.sparse.firstBad.upTo >= 500);
      const dropped = await checkRecords(lines.filter((_, i) => i !== 99).join('\n') + '\n', cp);
      assert.deepEqual(dropped.structural?.seq, 100);
      const hand = [...lines];
      hand[9] = hand[9].replace('{', '{ ');
      assert.equal((await checkRecords(hand.join('\n') + '\n', cp)).structural.seq, 10);
    },
  },
  {
    name: 'plain-word descriptions exist for every committed record (no undefined/NaN)',
    fn() {
      for (const l of text.split('\n').filter(Boolean)) {
        const d = describe(JSON.parse(l));
        assert.ok(d.length > 5 && !/undefined|NaN/.test(d), d);
      }
    },
  },
  {
    name: 'page NEAR read: SocialDB get through fastnear (no anchor under a fresh account)',
    network: true,
    async fn() {
      return netOrSkip(async () => {
        assert.equal(await readNearAnchor('testnet', 'a'.repeat(64)), null);
      });
    },
  },
];
