import { assert, netOrSkip } from './lib.mjs';
import { readFileSync } from 'node:fs';
import { proveTx, txRecords, sample, rpc, chainOf, AGENT_WALLET, RH_CHAIN_ID } from '../src/rh-proof.mjs';

const lines = readFileSync(new URL('../data/records.jsonl', import.meta.url), 'utf8').split('\n').filter(Boolean);

export const tests = [
  {
    name: 'chainOf: an explicit chain wins; termix and sleeve imply their chain; anything else claims none',
    fn() {
      assert.deepEqual(chainOf({ engine: 'sleeve', chain: 'hyperevm' }), { chain: 'hyperevm', implied: false });
      assert.deepEqual(chainOf({ engine: 'sleeve' }), { chain: 'elysium', implied: true });
      assert.deepEqual(chainOf({ engine: 'termix' }), { chain: 'bsc', implied: true });
      assert.deepEqual(chainOf({ engine: 'flock' }), { chain: null, implied: false });
      const offRh = txRecords(lines).filter((x) => chainOf(x.rec.row).chain && chainOf(x.rec.row).chain !== 'robinhood').map((x) => x.rec.seq);
      for (const seq of [2701, 2714, 2954]) assert.ok(offRh.includes(seq), `sleeve buy seq ${seq} must not count as a Robinhood Chain record`);
      return `${offRh.length} tx records name or imply another chain`;
    },
  },
  {
    name: 'committed data/rh-proof.json refers to real records and tx hashes',
    fn() {
      const proof = JSON.parse(readFileSync(new URL('../data/rh-proof.json', import.meta.url), 'utf8'));
      const bySeq = new Map(lines.map((l) => { const r = JSON.parse(l); return [r.seq, r]; }));
      for (const p of proof.results) assert.ok(bySeq.get(p.seq)?.txs.includes(p.tx), `seq ${p.seq}`);
      assert.equal(proof.results.length, txRecords(lines).length);
      return `${proof.counts.verified} verified, ${proof.counts.not_on_rh || 0} not on RH`;
    },
  },
  {
    name: 'sampling is repeatable with a seed',
    fn() {
      const items = txRecords(lines);
      assert.deepEqual(sample(items, 5, 42).map((x) => x.tx), sample(items, 5, 42).map((x) => x.tx));
    },
  },
  {
    name: 'Robinhood Chain: 3 sampled tx records have receipts from the agent wallet',
    network: true,
    async fn() {
      return netOrSkip(async () => {
        assert.equal(parseInt(await rpc('eth_chainId', []), 16), RH_CHAIN_ID);
        // only records that claim Robinhood Chain (explicitly or by default); a sleeve/termix tx in the sample made this flaky (11-05)
        const items = txRecords(lines).filter((x) => (chainOf(x.rec.row).chain ?? 'robinhood') === 'robinhood');
        const out = [];
        for (const { rec, tx } of sample(items, 3, Date.now() % 1e6)) {
          const r = await proveTx(rec, tx);
          if (r.result === 'rpc_error') throw new Error(`fetch failed: ${r.error}`);
          assert.equal(r.from, AGENT_WALLET, `seq ${rec.seq}`);
          assert.ok(['verified', 'reverted'].includes(r.result));
          out.push(`seq ${r.seq} block ${r.block}`);
        }
        return out.join(', ');
      });
    },
  },
];
