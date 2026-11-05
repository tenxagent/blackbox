// The browser verifier's logic, run in Node (same module the page loads).
import { assert, netOrSkip } from './lib.mjs';
import { readFileSync } from 'node:fs';
import { checkRecords, describe, readNearAnchor, coverageSummary } from '../web/verify.js';
import { canon } from '../src/canon.mjs';

const text = readFileSync(new URL('../data/records.jsonl', import.meta.url), 'utf8');
const cp = JSON.parse(readFileSync(new URL('../data/checkpoints.json', import.meta.url), 'utf8'));

export const tests = [
  {
    name: 'decision list: gate rows read as allowed / REFUSED / bypassed',
    fn() {
      const g = (row) => describe({ row: { type: 'gate', ...row } });
      assert.ok(g({ action: 'gate_allow', pendingUsd: 3, what: 'relay swap', anchorAgeH: 3.4, spent24h: 0 }).startsWith('Pre-sign gate allowed $3.00 (relay swap)'));
      assert.ok(g({ action: 'gate_refuse', pendingUsd: 3, reasons: ['newest anchor is 21.0 h old'] }).includes('REFUSED $3.00: newest anchor is 21.0 h old.'));
      assert.ok(g({ action: 'gate_bypass', pendingUsd: 1 }).includes('bypassed by hand'));
    },
  },
  {
    name: 'coverage panel: committed numbers in the text, never green with unaccounted txs, live nonce delta',
    fn() {
      const cov = JSON.parse(readFileSync(new URL('../data/coverage.json', import.meta.url), 'utf8'));
      const s = coverageSummary(cov);
      assert.ok(s.text.includes(`Of the ${cov.total} transactions`) && s.text.includes(`${cov.unexplained} (`));
      assert.equal(s.state, cov.unexplained === 0 ? 'ok' : 'idle');
      assert.equal(coverageSummary({ ...cov, unexplained: 0 }).state, 'ok');
      assert.ok(coverageSummary(cov, cov.total + 3).text.includes('has sent 3 more since'));
      assert.ok(coverageSummary(cov, cov.total).text.includes(`Live nonce ${cov.total}: current.`));
      assert.ok(coverageSummary(cov, false).text.includes('could not be read'));
    },
  },
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
