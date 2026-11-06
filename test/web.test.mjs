// The browser verifier's logic, run in Node (same module the page loads).
import { assert, netOrSkip } from './lib.mjs';
import { readFileSync } from 'node:fs';
import { checkRecords, describe, readNearAnchor, coverageSummary, nearRpc } from '../web/verify.js';
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
      assert.ok(g({ action: 'gate_allow', pendingUsd: 1, anchorAgeH: 3.7, spent24h: 0 }).endsWith('$0 already allowed in 24 h.'));   // was "$0."
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
    name: 'plain-word descriptions exist for every committed record (no undefined/NaN, no empty slot)',
    fn() {
      for (const l of text.split('\n').filter(Boolean)) {
        const d = describe(JSON.parse(l));
        // an empty slot shows up as "()", a double space, " ." or a bare "$" (e.g. "bounty  vs gas  → wait", "$0.")
        assert.ok(d.length > 5 && !/undefined|NaN|null|\(\s*\)|\s\.$|(^|\s)\$[ .]|  /.test(d), d);
      }
    },
  },
  {
    name: 'decision list: money and NEAR rows say what moved, not just the action name',
    fn() {
      const live = (row) => describe({ row: { type: 'live', ...row } });
      assert.equal(live({ action: 'relay_swap', chain: 'robinhood', from: 'USDG', to: 'ETH', amount: '1', received: '0.000444044331860622' }),
        'Swapped 1 USDG for 0.000444 ETH through Relay on Robinhood Chain.');
      assert.equal(live({ action: 'near_fund_done', status: 'SUCCESS', details: { amountInFormatted: '1.0', amountOutFormatted: '0.271814462645214675369177' } }),
        'NEAR Intents finished the swap (SUCCESS): 1.0 USDG in, 0.2718 NEAR out.');
      assert.ok(live({ action: 'registry_storage_deposit', near: 0.04, anchorsLeft: 41 }).startsWith('Prepaid 0.04 NEAR of registry storage (room for about 41 anchors)'));
      assert.equal(describe({ row: { type: 'flock_sim', ok: false, err: '{"message":"execution reverted: FMG: SLIPPAGE","code":3}' } }),
        'Simulated a reinvest: the call would fail (reverted: FMG: SLIPPAGE) → wait.');
      assert.ok(describe({ row: { type: 'live_intent', action: 'near_fund', usdg: '1', downside: '-$1' } }).startsWith('About to send (written before signing): near fund, 1 USDG; worst case -$1'));
      assert.ok(describe({ row: { type: 'vanta_err', engine: 'vanta', err: 'fetch failed' } }).includes('not a decision'));
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
  {
    name: 'page NEAR reads: a rate limit or a dead endpoint moves on to the next RPC; a contract error does not',
    async fn() {
      const net = { rpcs: ['https://a.example', 'https://b.example', 'https://c.example'] }, seen = [];
      const fake = (replies) => async (url) => { seen.push(new URL(url).host); const r = replies[new URL(url).host]; if (r === 'down') throw new Error('fetch failed');
        return { status: r.status ?? 200, json: async () => r.body }; };
      const ok = await nearRpc(net, 'block', {}, fake({ 'a.example': { status: 429, body: {} }, 'b.example': { body: { error: { code: -429, message: 'Rate limits exceeded' } } }, 'c.example': { body: { result: { x: 1 } } } }));
      assert.deepEqual(ok, { x: 1 }); assert.deepEqual(seen, ['a.example', 'b.example', 'c.example']);
      seen.length = 0;
      await assert.rejects(nearRpc(net, 'query', {}, fake({ 'a.example': { body: { result: { error: 'wasm execution failed' } } } })), /wasm execution failed/);
      assert.deepEqual(seen, ['a.example']);
      await assert.rejects(nearRpc(net, 'block', {}, fake({ 'a.example': 'down', 'b.example': 'down', 'c.example': 'down' })), /every endpoint/);
    },
  },
];
