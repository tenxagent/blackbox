// Pre-sign gate: a policy the agent's own code calls right before it signs a transaction that moves value.
// Black box on its own detects tampering after the fact; this turns the same log into two rules that can refuse a send:
//
//   1. Anchor freshness. The newest head in the append-only registry must be younger than maxAnchorAgeH (default 20 h,
//      two missed 8-hourly cycles). If the log is not being anchored, the agent does not spend. If the registry cannot be
//      read, the gate refuses (fail closed); --fail-open skips only this rule, for offline demos.
//   2. Spend cap. The USD of this send plus the USD of every send the gate ALLOWED in the last 24 h must stay within
//      maxDailyUsd (default 30). The gate counts its own approvals (rows with action "gate_allow" and a pendingUsd
//      field) rather than older money records, because those do not carry one uniform USD amount. An approved send
//      that later fails still counts, which errs on the safe side.
//
//   node src/gate.mjs check --pending-usd 3 [--rows data/records.jsonl] [--account ID] [--network mainnet]
//        [--max-anchor-age-h 20] [--max-daily-usd 30] [--fail-open] [--anchor-time ISO] [--now ISO]
//   ⇒ one JSON line {allow, reasons, anchorAgeH, spent24h, pendingUsd}; exit 0 = allow, 1 = refuse, 2 = usage.
// --rows takes a JSONL file of records ({row: {...}}) or of raw ledger rows; --anchor-time skips the NEAR read (tests, demos).
// Limits: this is a policy the agent's own code calls. A compromised key, or an operator who edits the calling code,
// bypasses it. It adds a NEAR RPC read to every gated send by design.

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as rpc from './near/rpc.mjs';
import { getAgentArgs, parseAgent } from './registry.mjs';

export const REGISTRY = '08035588c459e514c632061fb4862fde62297571f1e44716e01bcc9913986e8a';
export const DEFAULT_POLICY = { maxAnchorAgeH: 20, maxDailyUsd: 30 };
const DAY_MS = 24 * 3600e3;

/** USD of the sends the gate allowed in the 24 h before nowMs. rows: records ({row}) or raw ledger rows. Pure. */
export function spentLast24h(rows, nowMs) {
  let sum = 0;
  for (const x of rows) {
    const r = x?.row ?? x;
    if (r?.engine !== 'gate' || r.action !== 'gate_allow' || typeof r.pendingUsd !== 'number') continue;
    const t = Date.parse(r.t);
    if (t <= nowMs && nowMs - t < DAY_MS) sum += r.pendingUsd;
  }
  return sum;
}

/** The decision. anchor = {timeMs} | {error}. Pure (unit-tested in test/gate.test.mjs). */
export function evaluate({ rows, anchor, policy = {}, pendingUsd, nowMs, failOpen = false }) {
  const p = { ...DEFAULT_POLICY, ...policy }, reasons = [], notes = [];
  if (!(typeof pendingUsd === 'number' && Number.isFinite(pendingUsd) && pendingUsd >= 0)) reasons.push('pending USD must be a number ≥ 0');
  let anchorAgeH = null;
  if (!anchor || anchor.error || !Number.isFinite(anchor.timeMs)) {
    const why = `registry anchor not read (${anchor?.error ?? 'no anchor'})`;
    if (failOpen) notes.push(`${why}; --fail-open: rule 1 skipped`); else reasons.push(`${why}: refusing (fail closed)`);
  } else {
    anchorAgeH = (nowMs - anchor.timeMs) / 3.6e6;
    if (anchorAgeH > p.maxAnchorAgeH) reasons.push(`newest anchor is ${anchorAgeH.toFixed(1)} h old (> ${p.maxAnchorAgeH} h): the log is not being anchored`);
  }
  const spent24h = spentLast24h(rows, nowMs);
  if (Number.isFinite(pendingUsd) && spent24h + pendingUsd > p.maxDailyUsd) {
    reasons.push(`$${(spent24h + pendingUsd).toFixed(2)} in 24 h would exceed the $${p.maxDailyUsd} cap ($${spent24h.toFixed(2)} already allowed)`);
  }
  return { allow: reasons.length === 0, reasons, notes, anchorAgeH: anchorAgeH === null ? null : +anchorAgeH.toFixed(2), spent24h: +spent24h.toFixed(2), pendingUsd, policy: p };
}

/** Newest registry anchor of `account` → {timeMs, seq} or {error}. */
export async function readRegistryAnchor(account, network = 'mainnet') {
  try {
    const res = await rpc.callFunction(rpc.rpcUrl(network), REGISTRY, 'get_agent', getAgentArgs(account));
    const agent = parseAgent(res.value);
    if (!agent?.last) return { error: 'agent has no anchors' };
    return { timeMs: Number(agent.last.timestampNs / 1_000_000n), seq: agent.last.seq };
  } catch (e) { return { error: String(e.message ?? e).slice(0, 160) }; }
}

export function readRows(file) {
  return readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
}

async function main() {
  const argv = process.argv.slice(2), opt = (k, d) => { const i = argv.indexOf('--' + k); return i >= 0 ? argv[i + 1] : d; }, has = (k) => argv.includes('--' + k);
  if (argv[0] !== 'check' || opt('pending-usd') === undefined) { console.error('usage: node src/gate.mjs check --pending-usd X [--rows FILE] [--account ID] [--max-anchor-age-h H] [--max-daily-usd USD] [--fail-open] [--anchor-time ISO] [--now ISO]'); process.exit(2); }
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const nowMs = opt('now') ? Date.parse(opt('now')) : Date.now();
  const rows = readRows(path.resolve(opt('rows', path.join(root, 'data', 'records.jsonl'))));
  const policy = {};
  if (opt('max-anchor-age-h') !== undefined) policy.maxAnchorAgeH = Number(opt('max-anchor-age-h'));
  if (opt('max-daily-usd') !== undefined) policy.maxDailyUsd = Number(opt('max-daily-usd'));
  const anchor = opt('anchor-time') ? { timeMs: Date.parse(opt('anchor-time')) } : opt('account') ? await readRegistryAnchor(opt('account'), opt('network', 'mainnet')) : { error: 'no --account and no --anchor-time' };
  const r = evaluate({ rows, anchor, policy, pendingUsd: Number(opt('pending-usd')), nowMs, failOpen: has('fail-open') });
  console.log(JSON.stringify({ ...r, anchorSeq: anchor.seq }));
  process.exit(r.allow ? 0 : 1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
