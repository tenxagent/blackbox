// Link money records to their real transactions on Robinhood Chain (chain id 4663).
//
//   node src/rh-proof.mjs              20 random tx records (prints the seed)
//   node src/rh-proof.mjs --seed 7     the same 20 again
//   node src/rh-proof.mjs --n 5        5 random tx records
//   node src/rh-proof.mjs --all        every tx record; writes data/rh-proof.json
//
// For each tx hash in a record it asks the public RPC for
// eth_getTransactionReceipt and the block header, then checks:
//   from     == the agent wallet (the record is the agent's own tx)
//   status      1 = succeeded, 0 = reverted (still the agent's tx)
//   block       number and timestamp; "lag" = record time minus block time
// Result per tx:
//   verified        receipt found, from == agent wallet, status 1
//   reverted        receipt found, from == agent wallet, status 0
//   from_mismatch   receipt found but sent by another address
//   not_on_rh       no receipt on Robinhood Chain. Expected when the record names
//                   another chain (e.g. chain "bsc"); a finding otherwise.
//   rpc_error       the RPC did not answer
// Everything the RPC returns is treated as data. Requests are sequential with a
// pause between them (default 250 ms) to keep the load on the public RPC low.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const AGENT_WALLET = '0x00731cd9e0bc7cad1b54f85187b09b942cd3be04';
export const RH_CHAIN_ID = 4663;
export const RH_RPC = process.env.RH_RPC || 'https://rpc.mainnet.chain.robinhood.com';
export const EXPLORER_TX = 'https://robinhoodchain.blockscout.com/tx/';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function rpc(method, params, { url = RH_RPC, timeoutMs = 15000 } = {}) {
  for (let attempt = 0; ; attempt++) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
      const j = await res.json();
      if (j.error) throw new Error(`rpc error ${j.error.code}: ${String(j.error.message).slice(0, 200)}`);
      return j.result;
    } catch (e) {
      if (attempt >= 2) throw e;
      await sleep(1000 * (attempt + 1));
    }
  }
}

// Engines whose own transactions run on another chain. Their older records carry no `chain` field, and records are
// immutable, so the chain is implied from the engine — but ONLY to explain a tx with no receipt here: termix's bridge
// out of Robinhood Chain (seq 431) was sent here and verifies normally, with no chain label. Checked by hand on
// 2026-11-05 on the chains themselves: termix seq 444 is on BNB Chain; sleeve seqs 2701, 2714 and 2954 are on Elysium;
// all status 1 and sent by the agent wallet.
export const ENGINE_CHAIN = { termix: 'bsc', sleeve: 'elysium' };
export function chainOf(row) {
  if (row.chain) return { chain: row.chain, implied: false };
  const e = Object.keys(ENGINE_CHAIN).find((k) => String(row.engine ?? '').startsWith(k));
  return e ? { chain: ENGINE_CHAIN[e], implied: true } : { chain: null, implied: false };
}

// One tx: receipt + block header -> result object.
export async function proveTx(rec, txHash, opts = {}) {
  const c = chainOf(rec.row);
  const base = { seq: rec.seq, tx: txHash, chain: rec.row.chain ?? null, what: rec.row.action || rec.row.label || rec.row.type };
  let receipt;
  try {
    receipt = await rpc('eth_getTransactionReceipt', [txHash], opts);
  } catch (e) {
    return { ...base, result: 'rpc_error', error: String(e.message).slice(0, 200) };
  }
  if (!receipt) {
    const elsewhere = c.chain && c.chain !== 'robinhood';
    const note = !elsewhere ? 'record names no other chain' : c.implied ? `engine "${rec.row.engine}" runs on ${c.chain} (implied: the record has no chain field)` : `record says chain "${c.chain}"`;
    return { ...base, ...(elsewhere ? { chain: c.chain } : {}), result: 'not_on_rh', note };
  }
  const from = String(receipt.from).toLowerCase();
  const status = Number(receipt.status);
  const block = Number(receipt.blockNumber);
  let blockTime = null, lagSec = null;
  try {
    const hdr = await rpc('eth_getBlockByNumber', [receipt.blockNumber, false], opts);
    blockTime = new Date(Number(hdr.timestamp) * 1000).toISOString();
    const t = Date.parse(rec.row.t);
    if (Number.isFinite(t)) lagSec = Math.round((t - Number(hdr.timestamp) * 1000) / 1000);
  } catch {
    /* header is a bonus; the receipt is the proof */
  }
  const result = from !== AGENT_WALLET ? 'from_mismatch' : status === 1 ? 'verified' : 'reverted';
  return { ...base, result, from, status, block, blockTime, lagSec, to: receipt.to ? String(receipt.to).toLowerCase() : null };
}

export function txRecords(lines) {
  const out = [];
  for (const l of lines) {
    const rec = JSON.parse(l);
    for (const tx of rec.txs || []) out.push({ rec, tx });
  }
  return out;
}

// Small seeded PRNG (mulberry32) so a sample can be repeated with --seed.
function mulberry32(a) {
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function sample(items, n, seed) {
  const rand = mulberry32(seed);
  const a = [...items];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a.slice(0, n).sort((x, y) => x.rec.seq - y.rec.seq);
}

// ---------------------------------------------------------------- CLI
if (process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1])}`).href) {
  const argv = process.argv.slice(2);
  const arg = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : d; };
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const recordsPath = path.resolve(arg('records', path.join(root, 'data/records.jsonl')));
  const all = argv.includes('--all');
  const n = Number(arg('n', 20));
  const seed = Number(arg('seed', Math.floor(Math.random() * 1e9)));
  const pauseMs = Number(arg('pause', 250));

  const chainId = parseInt(await rpc('eth_chainId', []), 16);
  if (chainId !== RH_CHAIN_ID) {
    console.error(`RPC ${RH_RPC} reports chain id ${chainId}, expected ${RH_CHAIN_ID}`);
    process.exit(2);
  }
  const lines = readFileSync(recordsPath, 'utf8').split('\n').filter(Boolean);
  const items = txRecords(lines);
  const pick = all ? items : sample(items, n, seed);
  console.log(`rpc ${RH_RPC} (chain id ${chainId}) · agent wallet ${AGENT_WALLET}`);
  console.log(`${items.length} tx hashes in ${new Set(items.map((x) => x.rec.seq)).size} records; checking ${all ? 'all' : `${pick.length} (seed ${seed})`}\n`);
  const results = [];
  for (const { rec, tx } of pick) {
    const r = await proveTx(rec, tx);
    results.push(r);
    const extra = r.block ? `block ${r.block} ${r.blockTime ?? ''} lag ${r.lagSec ?? '?'}s` : r.note || r.error || '';
    console.log(`${r.result.padEnd(13)} seq ${String(r.seq).padStart(4)}  ${tx.slice(0, 14)}…  ${String(r.what).padEnd(24)} ${extra}`);
    await sleep(pauseMs);
  }
  const count = {};
  for (const r of results) count[r.result] = (count[r.result] || 0) + 1;
  console.log(`\n${Object.entries(count).map(([k, v]) => `${k}: ${v}`).join(' · ')}`);
  if (all) {
    const out = path.join(root, 'data/rh-proof.json');
    writeFileSync(out, JSON.stringify({ rpc: RH_RPC, chainId, agentWallet: AGENT_WALLET, explorerTx: EXPLORER_TX, counts: count, results }, null, 1) + '\n');
    console.log(`wrote ${path.relative(process.cwd(), out)}`);
  }
  process.exit(count.from_mismatch || count.rpc_error ? 1 : 0);
}
