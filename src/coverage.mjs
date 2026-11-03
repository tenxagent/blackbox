// Coverage: how many of the agent wallet's Robinhood Chain transactions does the black box account for?
//
//   node src/coverage.mjs            prints the reconciliation; writes data/coverage.json
//
// The black box records DECISIONS and their outcomes. Most are single transactions (a listing, a sale, a
// reinvest call) and carry the tx hash. Two engines sign a numbered BATCH instead: the mint "ladder" and the
// crank race pre-sign N transactions with consecutive nonces (nonce0 … nonce0+N−1) and send one per block
// until one lands; the rest revert cheaply or are never sent. Those rungs are recorded as one
// mintarm_signed / crank_signed record with nonce0 and rungs, not as N hashes.
//
// This script reconciles the wallet's on-chain nonce (public RPC, eth_getTransactionCount) with the records:
//   1. every record tx hash proven to be the agent's (data/rh-proof.json, result verified/reverted)
//      ⇒ its exact nonce via eth_getTransactionByHash
//   2. every batch record ⇒ the nonce range [nonce0, end), where end = the next nonce known from 1. or a later
//      batch, capped at nonce0 + rungs (rungs that were never sent do not consume nonces)
//   3. nonces in neither set are UNEXPLAINED and listed as ranges with the records just before and after them.
// Read-only. Requests are sequential with a 250 ms pause.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { AGENT_WALLET, RH_RPC } from './rh-proof.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let id = 0;
async function rpc(method, params) {
  for (let k = 0; k < 3; k++) {
    try {
      const r = await fetch(RH_RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(20_000),
        body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }) });
      const j = await r.json(); if (j.error) throw new Error(j.error.message); return j.result;
    } catch (e) { if (k === 2) throw e; await sleep(1500); }
  }
}

/** Pure reconciliation (unit-tested): known = Map(nonce → label), batches = [{nonce0, rungs, seq, t}], total = chain nonce. */
export function reconcile(known, batches, total) {
  const explained = new Map(known);
  const starts = [...new Set([...known.keys(), ...batches.map((b) => b.nonce0)])].sort((a, b) => a - b);
  for (const b of batches) {
    const nextKnown = starts.find((n) => n > b.nonce0) ?? total;
    const end = Math.min(b.nonce0 + b.rungs, nextKnown, total);
    for (let n = b.nonce0; n < end; n++) if (!explained.has(n)) explained.set(n, `batch seq ${b.seq}`);
  }
  const gaps = [];
  for (let n = 0; n < total; n++) {
    if (explained.has(n)) continue;
    const g = gaps[gaps.length - 1];
    if (g && g.to === n - 1) g.to = n; else gaps.push({ from: n, to: n });
  }
  const byKind = { tx: 0, batch: 0 };
  for (const v of explained.values()) v.startsWith('batch') ? byKind.batch++ : byKind.tx++;
  return { total, explainedTx: byKind.tx, explainedBatch: byKind.batch, unexplained: total - explained.size, gaps };
}

async function main() {
  const proof = JSON.parse(readFileSync(path.join(ROOT, 'data', 'rh-proof.json'), 'utf8'));
  const records = readFileSync(path.join(ROOT, 'data', 'records.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  const total = parseInt(await rpc('eth_getTransactionCount', [AGENT_WALLET, 'latest']), 16);
  const known = new Map();
  const mine = proof.results.filter((r) => ['verified', 'reverted'].includes(r.result) && String(r.from).toLowerCase() === AGENT_WALLET);
  for (const r of mine) {
    const tx = await rpc('eth_getTransactionByHash', [r.tx]); await sleep(250);
    if (tx && String(tx.from).toLowerCase() === AGENT_WALLET) known.set(parseInt(tx.nonce, 16), `tx seq ${r.seq} ${r.what ?? ''}`.trim());
  }
  const batches = records.filter((r) => ['mintarm_signed', 'crank_signed'].includes(r.row.type) && Number.isInteger(r.row.nonce0))
    .map((r) => ({ nonce0: r.row.nonce0, rungs: Number(r.row.rungs) || 1, seq: r.seq, t: r.row.t }));
  const res = reconcile(known, batches, total);
  // context for each gap: the last record before and the first after (by time of the nearest known nonce)
  const near = (n, dir) => { const ks = [...known.keys(), ...batches.map((b) => b.nonce0)].filter((k) => (dir < 0 ? k < n : k > n)).sort((a, b) => dir < 0 ? b - a : a - b); return ks[0] ?? null; };
  res.gaps = res.gaps.map((g) => ({ ...g, n: g.to - g.from + 1, prevKnownNonce: near(g.from, -1), nextKnownNonce: near(g.to, +1) }));
  const out = { wallet: AGENT_WALLET, rpc: RH_RPC, at: new Date().toISOString(), lastRecordSeq: records[records.length - 1].seq, ...res };
  writeFileSync(path.join(ROOT, 'data', 'coverage.json'), JSON.stringify(out, null, 1) + '\n');
  const pct = (x) => (100 * x / total).toFixed(1) + '%';
  console.log(`wallet ${AGENT_WALLET} on Robinhood Chain: ${total} transactions sent (nonce)`);
  console.log(`  ${res.explainedTx} matched to a record's own tx hash (${pct(res.explainedTx)})`);
  console.log(`  ${res.explainedBatch} inside a recorded mint/crank batch (${pct(res.explainedBatch)})`);
  console.log(`  ${res.unexplained} not accounted for (${pct(res.unexplained)}) in ${res.gaps.length} ranges:`);
  for (const g of res.gaps.slice(0, 40)) console.log(`    nonces ${g.from}–${g.to} (${g.n}) between known nonces ${g.prevKnownNonce} and ${g.nextKnownNonce}`);
  if (res.gaps.length > 40) console.log(`    … ${res.gaps.length - 40} more in data/coverage.json`);
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
