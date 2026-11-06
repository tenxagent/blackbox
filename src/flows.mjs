// Where the money went (2026-11-06): for every gated send since the gate went live, read its transactions on chain and check
// each value that left the agent wallet in them (the "first hop"):
//   - ERC-20 Transfer logs FROM the wallet, Approval logs BY the wallet, and the native value of the tx;
//   - each must go to the agent itself (policy.self) or to a contract on gate.policy.json's allow-list for the same chain, or,
//     for a 1Click deposit, to the deposit address in the record. Then 1Click's own status record for that address must say the
//     quote pays the agent's NEAR account, refunds to the agent's wallet, and names this tx;
//   - the USDG that left the wallet (1 USDG = $1) must not exceed the USD the gate decision before the send was told, and no
//     approval may be larger than that amount.
// Anything else is a finding with the record's seq. This is DETECTION AFTER THE FACT, not prevention: the money has already
// moved, and this names the record (the cycle runs it, so within one cycle). It reads only the first hop: the public Robinhood
// Chain RPC has no traces, so what a router does next (e.g. a Relay swap whose own calldata names another recipient) is not
// seen here. Tokens other than USDG are listed with their amount but not priced.
//
//   node src/flows.mjs            print the check for the committed records (reads the chain and 1Click; nothing is sent)
//   node src/flows.mjs --write    also write data/flows.json (the cycle runs this)
//   exit 0 = no finding, 1 = a finding or a transaction that could not be read
// Everything an RPC or 1Click returns is treated as data.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { gateCoverage, readPolicy, readRows, CHAIN_RPC, GATE_LIVE_SINCE } from './gate.mjs';
import { chainOf, rpc } from './rh-proof.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TRANSFER = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const APPROVAL = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
// the one token priced here: USDG on Robinhood Chain, 6 decimals, $1
export const USD_TOKENS = { 'robinhood:0x5fc5360d0400a0fd4f2af552add042d716f1d168': { symbol: 'USDG', decimals: 6 } };
const MAX_UINT = (1n << 256n) - 1n;
const norm = (a) => String(a ?? '').trim().toLowerCase();
const topicAddr = (t) => '0x' + String(t).slice(26).toLowerCase();
const usdOf = (chain, token, raw) => { const u = USD_TOKENS[`${chain}:${norm(token)}`]; return u ? Number(raw) / 10 ** u.decimals : null; };

/** One tx (eth_getTransactionByHash + receipt) → every value that left `wallet` in it. */
export function outflows(tx, receipt, wallet) {
  const w = norm(wallet), out = [];
  if (BigInt(tx?.value ?? 0) > 0n && norm(tx.from) === w) out.push({ kind: 'native', to: norm(tx.to), amount: BigInt(tx.value).toString() });
  for (const l of receipt?.logs ?? []) {
    const [t0, t1, t2] = l.topics ?? [];
    if (!t1 || !t2 || topicAddr(t1) !== w) continue;
    const amount = l.data && l.data !== '0x' ? BigInt(l.data.slice(0, 66)).toString() : '0';
    if (t0 === TRANSFER) out.push({ kind: 'transfer', token: norm(l.address), to: topicAddr(t2), amount });
    else if (t0 === APPROVAL) out.push({ kind: 'approval', token: norm(l.address), to: topicAddr(t2), amount });
  }
  return out;
}

/** Who is `address` on `chain` for this policy? → {ok, label} */
export function destination(address, chain, policy, rec) {
  const a = norm(address), on = (e) => norm(e.chain) === norm(chain) && norm(e.address) === a;
  const self = (policy.self ?? []).find(on); if (self) return { ok: true, label: 'the agent itself' };
  const allow = (policy.allow ?? []).find(on); if (allow) return { ok: true, label: allow.label };
  if (rec?.row?.depositAddress && norm(rec.row.depositAddress) === a) return { ok: true, label: '1Click deposit address from the record', oneClick: true };
  return { ok: false, label: `not on the policy for ${chain}` };
}

/** 1Click's status record for a deposit address → what it says, and whether that matches the agent. */
export function judgeOneClick(status, { policy, tx }) {
  if (!status || status.error) return { ok: false, why: `1Click has no record of this deposit address (${status?.error ?? 'no answer'})` };
  const qr = status.quoteResponse?.quoteRequest ?? {}, sd = status.swapDetails ?? {};
  const selfOn = (chain) => (policy.self ?? []).filter((s) => s.chain === chain).map((s) => norm(s.address));
  const why = [];
  if (!selfOn('near').includes(norm(qr.recipient))) why.push(`the quote pays ${qr.recipient ?? '(nobody named)'}, not the agent's NEAR account`);
  if (!selfOn('robinhood').includes(norm(qr.refundTo))) why.push(`refunds go to ${qr.refundTo ?? '(nobody named)'}, not the agent's wallet`);
  const origin = (sd.originChainTxHashes ?? []).map((h) => norm(h.hash ?? h));
  if (tx && !origin.includes(norm(tx))) why.push('1Click does not list this tx as the deposit');
  const fees = (qr.appFees ?? []).map((f) => Number(f.fee)).filter(Number.isFinite);
  return { ok: why.length === 0, why: why.join('; ') || null, status: status.status ?? null, recipient: qr.recipient ?? null,
    refundTo: qr.refundTo ? norm(qr.refundTo) : null, appFeeBps: fees.reduce((s, x) => s + x, 0), nearTx: (sd.destinationChainTxHashes ?? []).map((h) => h.hash ?? h) };
}

/** Pure: the gated sends + what the chain and 1Click said → per-send result and findings. read = { 'chain:tx': {tx, receipt} | {error} },
 *  oneClick = { depositAddress (lower case): status | {error} }. */
export function judgeFlows({ records, policy, read, oneClick = {}, wallet, since = GATE_LIVE_SINCE }) {
  const cov = gateCoverage(records, { since });
  const bySeq = new Map(records.map((r) => [r.seq, r]));
  const sends = [], findings = [];
  for (const p of cov.pairs) {
    const rec = bySeq.get(p.seq), g = bySeq.get(p.gateSeq)?.row ?? {};
    const chain = chainOf(rec.row).chain ?? 'robinhood', told = Number(g.pendingUsd);
    const s = { seq: rec.seq, action: rec.row.action, chain, gateSeq: p.gateSeq, gateUsd: Number.isFinite(told) ? told : null, txs: [], usdOut: 0 };
    for (const h of rec.txs ?? []) {
      const r = read[`${chain}:${norm(h)}`];
      if (!r || r.error || !r.receipt) { s.txs.push({ tx: h, result: 'not_read', error: r?.error ?? 'not read' }); findings.push({ seq: rec.seq, tx: h, kind: 'not_read', why: `could not read the tx on ${chain}: ${r?.error ?? 'not read'}` }); continue; }
      const flows = outflows(r.tx, r.receipt, wallet).map((f) => {
        const d = destination(f.to, chain, policy, rec), usd = f.token ? usdOf(chain, f.token, f.amount) : null;
        if (f.kind === 'transfer' && usd !== null) s.usdOut += usd;
        if (f.kind === 'approval' && BigInt(f.amount) === MAX_UINT) findings.push({ seq: rec.seq, tx: h, kind: 'approval_over_gate', why: `unlimited approval to ${f.to}` });
        else if (f.kind === 'approval' && usd !== null && s.gateUsd !== null && usd > s.gateUsd * 1.02 + 0.01)
          findings.push({ seq: rec.seq, tx: h, kind: 'approval_over_gate', why: `approval of $${usd} to ${f.to}; the gate was told $${s.gateUsd}` });
        if (!d.ok) findings.push({ seq: rec.seq, tx: h, kind: 'unlisted_destination', why: `${f.kind} to ${f.to}: ${d.label}` });
        let oc;
        if (d.oneClick) {
          oc = judgeOneClick(oneClick[norm(f.to)], { policy, tx: h });
          if (!oc.ok) findings.push({ seq: rec.seq, tx: h, kind: 'oneclick_mismatch', why: oc.why });
        }
        return { ...f, usd, label: d.label, ok: d.ok && (oc?.ok ?? true), ...(oc ? { oneClick: oc } : {}) };
      });
      s.txs.push({ tx: h, result: Number(r.receipt.status) === 1 ? 'ok' : 'reverted', flows });
    }
    s.usdOut = Math.round(s.usdOut * 1e6) / 1e6;
    if (s.gateUsd !== null && s.usdOut > s.gateUsd * 1.02 + 0.01) findings.push({ seq: rec.seq, kind: 'amount_over_gate', why: `$${s.usdOut} USDG left the wallet; the gate was told $${s.gateUsd}` });
    if (s.gateUsd === null && s.usdOut > 0) findings.push({ seq: rec.seq, kind: 'amount_over_gate', why: `$${s.usdOut} USDG left the wallet; the gate decision states no USD amount` });
    sends.push(s);
  }
  return { since, wallet: norm(wallet), sends: sends.length, txs: sends.reduce((n, s) => n + s.txs.length, 0), findings, results: sends,
    missingGate: cov.missing.map((m) => m.seq) };
}

/** Network side: read every tx of the gated sends and 1Click's record of every deposit address. */
export async function readFlowsInput(records, { since = GATE_LIVE_SINCE, rpcs = CHAIN_RPC, oneClickApi = '1click.chaindefuser.com' } = {}) {
  const cov = gateCoverage(records, { since }), bySeq = new Map(records.map((r) => [r.seq, r])), read = {}, oneClick = {};
  for (const p of cov.pairs) {
    const rec = bySeq.get(p.seq), chain = chainOf(rec.row).chain ?? 'robinhood';
    for (const h of rec.txs ?? []) {
      const key = `${chain}:${norm(h)}`;
      if (!rpcs[chain]) { read[key] = { error: `no RPC for ${chain}` }; continue; }
      try {
        const [tx, receipt] = [await rpc('eth_getTransactionByHash', [h], { url: rpcs[chain] }), await rpc('eth_getTransactionReceipt', [h], { url: rpcs[chain] })];
        read[key] = tx && receipt ? { tx, receipt } : { error: 'no such tx on this chain' };
      } catch (e) { read[key] = { error: String(e.message ?? e).slice(0, 120) }; }
    }
    const dep = rec.row.depositAddress && norm(rec.row.depositAddress);
    if (dep) {
      try {
        const res = await fetch(`https://${oneClickApi}/v0/status?depositAddress=${encodeURIComponent(rec.row.depositAddress)}`, { signal: AbortSignal.timeout(15_000) });
        oneClick[dep] = res.ok ? await res.json() : { error: `HTTP ${res.status}` };
      } catch (e) { oneClick[dep] = { error: String(e.message ?? e).slice(0, 120) }; }
    }
  }
  return { read, oneClick };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const records = readRows(path.join(ROOT, 'data', 'records.jsonl')), policy = readPolicy();
  const wallet = (policy.self ?? []).find((s) => s.chain === 'robinhood')?.address;
  const { read, oneClick } = await readFlowsInput(records);
  const r = judgeFlows({ records, policy, read, oneClick, wallet });
  for (const s of r.results) {
    console.log(`seq ${s.seq} ${s.action} (${s.chain}; gate decision seq ${s.gateSeq} was told $${s.gateUsd}): $${s.usdOut} USDG left the wallet`);
    for (const t of s.txs) {
      if (!t.flows) { console.log(`  ${t.tx.slice(0, 12)}… NOT READ: ${t.error}`); continue; }
      for (const f of t.flows) console.log(`  ${t.tx.slice(0, 12)}… ${f.ok ? 'ok ' : 'BAD'} ${f.kind} ${f.usd !== null && f.usd !== undefined ? `$${f.usd} ` : ''}to ${f.to} (${f.label})${f.oneClick ? ` · 1Click: ${f.oneClick.status}, pays ${f.oneClick.recipient}${f.oneClick.appFeeBps ? `, app fee ${f.oneClick.appFeeBps} bps in the quote` : ''}${f.oneClick.why ? ` · ${f.oneClick.why}` : ''}` : ''}`);
      if (!t.flows.length) console.log(`  ${t.tx.slice(0, 12)}… nothing left the wallet in this tx`);
    }
  }
  console.log(`\n${r.sends} gated send(s), ${r.txs} tx(s) read: ${r.findings.length ? `${r.findings.length} FINDING(S)` : 'every first hop went to the agent or a listed contract'}`);
  for (const f of r.findings) console.log(`  FINDING seq ${f.seq}${f.tx ? ` ${f.tx.slice(0, 12)}…` : ''} ${f.kind}: ${f.why}`);
  if (process.argv.includes('--write')) writeFileSync(path.join(ROOT, 'data', 'flows.json'), JSON.stringify(r, null, 1) + '\n');
  process.exit(r.findings.length ? 1 : 0);
}
