// Pre-sign gate: a policy the agent's own code calls right before it signs a transaction that moves value.
// Black box on its own detects tampering after the fact; this turns the same log into three rules that can refuse a send:
//
//   1. Anchor freshness. The newest head in the append-only registry must be younger than maxAnchorAgeH (default 20 h,
//      two missed 8-hourly cycles). If the log is not being anchored, the agent does not spend. If the registry cannot be
//      read, the gate refuses (fail closed); --fail-open skips only this rule, for offline demos.
//   2. Spend cap. The USD of this send plus the USD of every send the gate ALLOWED in the last 24 h must stay within
//      maxDailyUsd (default 30). The gate counts its own approvals (rows with action "gate_allow" and a pendingUsd
//      field) rather than older money records, because those do not carry one uniform USD amount. An approved send
//      that later fails still counts, which errs on the safe side.
//   3. Counterparty (2026-11-06). Every address the value reaches must be given: the decoded recipient, spender or
//      router, not only tx.to (for a token transfer tx.to is the token contract). Each one gets a verdict:
//        block  it is on the policy's blocklist (with evidence)                                    ⇒ refuse
//        allow  it is an allow-listed public contract (source + code hash in gate.policy.json; a changed code hash
//               turns it into a warn), OR it came from an API the policy trusts (the caller passes provenance, which
//               is recorded), OR a human approval for it is committed to gate.policy.json, OR the gate approved a
//               send to it before (prior interaction; rows written before 2026-11-06 carry no address)
//        warn   anything else, e.g. an address that arrived in a message ⇒ refuse until a human approves it.
//      No counterparty given ⇒ refuse (fail closed).
//
//   node src/gate.mjs check --pending-usd 3 --to 0xADDR[,0xADDR] [--chain robinhood] [--policy gate.policy.json]
//        [--rows data/records.jsonl] [--account ID] [--network mainnet] [--max-anchor-age-h 20] [--max-daily-usd 30]
//        [--fail-open] [--anchor-time ISO] [--now ISO]
//   ⇒ one JSON line {allow, action, reasons, counterparties, anchorAgeH, spent24h, pendingUsd}; exit 0 = allow, 1 = refuse, 2 = usage.
// --rows takes a JSONL file of records ({row: {...}}) or of raw ledger rows; --anchor-time skips the NEAR read (tests, demos).
// Limits: this is a policy the agent's own code calls. A compromised key, or an operator who edits the calling code or
// gate.policy.json, bypasses it. Provenance is what the caller says; the gate records it but cannot check it. A code hash
// catches a redeployed contract, not an upgradeable proxy whose implementation changes. It adds a NEAR RPC read to every
// gated send by design.

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as rpc from './near/rpc.mjs';
import { getAgentArgs, parseAgent } from './registry.mjs';

export const REGISTRY = '08035588c459e514c632061fb4862fde62297571f1e44716e01bcc9913986e8a';
export const DEFAULT_POLICY = { maxAnchorAgeH: 20, maxDailyUsd: 30 };
export const POLICY_FILE = fileURLToPath(new URL('../gate.policy.json', import.meta.url));
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

const norm = (a) => String(a ?? '').trim().toLowerCase();
const sameChain = (entry, c) => !entry.chain || !c.chain || norm(entry.chain) === norm(c.chain);

/** Addresses the gate approved sends to before nowMs (rows: records or raw ledger rows) → Map(address → count). Pure. */
export function priorApproved(rows, nowMs) {
  const seen = new Map();
  for (const x of rows) {
    const r = x?.row ?? x;
    if (r?.engine !== 'gate' || r.action !== 'gate_allow' || !Array.isArray(r.to) || !(Date.parse(r.t) <= nowMs)) continue;
    for (const a of r.to) seen.set(norm(a), (seen.get(norm(a)) ?? 0) + 1);
  }
  return seen;
}

/** Rule 3 for one counterparty c = {address, chain?, role?, provenance?: {api, ...}}. facts = {codeHash?, nonce?} read by the
 *  caller (optional; {error} when the read failed: an allow-listed entry with a code hash then warns). → {address, chain, role,
 *  verdict: 'allow'|'warn'|'block', why}. Pure. */
export function judgeCounterparty(c, policy, prior, facts = {}) {
  const addr = norm(c.address), out = { address: addr, chain: c.chain ?? null, role: c.role ?? null };
  if (!addr) return { ...out, verdict: 'block', why: 'no address given' };
  const blocked = (policy.block ?? []).find((e) => norm(e.address) === addr && sameChain(e, c));
  if (blocked) return { ...out, verdict: 'block', why: `blocklisted: ${blocked.evidence}` };
  const listed = (policy.allow ?? []).find((e) => norm(e.address) === addr && sameChain(e, c));
  if (listed) {
    if (listed.codeHash && facts.error) return { ...out, verdict: 'warn', why: `${listed.label}: its code could not be read to check the hash (${facts.error})` };
    if (listed.codeHash && facts.codeHash !== undefined && norm(listed.codeHash) !== norm(facts.codeHash)) {
      return { ...out, verdict: 'warn', why: `${listed.label}: code hash changed since it was allow-listed (${listed.codeHash.slice(0, 10)}… → ${facts.codeHash ? `${facts.codeHash.slice(0, 10)}…` : 'no code'})` };
    }
    return { ...out, verdict: 'allow', why: `allow-listed: ${listed.label}` };
  }
  const api = c.provenance?.api && (policy.trustedApis ?? []).find((e) => norm(e.api) === norm(c.provenance.api));
  if (api) return { ...out, verdict: 'allow', why: `from a trusted API: ${api.label}`, provenance: c.provenance };
  const human = (policy.humanApproved ?? []).find((e) => norm(e.address) === addr && sameChain(e, c));
  if (human) return { ...out, verdict: 'allow', why: `approved by a human: ${human.by}, ${human.at}` };
  const n = prior.get(addr) ?? 0;
  if (n > 0) return { ...out, verdict: 'allow', why: `prior interaction: ${n} earlier approved send${n > 1 ? 's' : ''}` };
  const fresh = facts.nonce === 0 && facts.codeHash === null ? '; fresh address (0 txs, no code)' : '';
  return { ...out, verdict: 'warn', why: `unknown counterparty: not allow-listed, not from a trusted API, never approved${fresh} ⇒ ask a human` };
}

/** The decision. anchor = {timeMs} | {error}. to = counterparties (see judgeCounterparty). Pure (test/gate.test.mjs). */
export function evaluate({ rows, anchor, policy = {}, pendingUsd, nowMs, failOpen = false, to, facts = {} }) {
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
  const list = (Array.isArray(to) ? to : to ? [to] : []).map((c) => (typeof c === 'string' ? { address: c } : c));
  let counterparties = [];
  if (!list.length) reasons.push('no counterparty given: rule 3 cannot run (fail closed)');
  else {
    const prior = priorApproved(rows, nowMs);
    counterparties = list.map((c) => judgeCounterparty(c, p, prior, facts[norm(c.address)] ?? {}));
    for (const c of counterparties) if (c.verdict !== 'allow') reasons.push(`${c.verdict.toUpperCase()} ${c.address}${c.role ? ` (${c.role})` : ''}: ${c.why}`);
  }
  // action: what the caller records. Only-warn refusals are 'gate_warn' (waiting for a human), every other refusal 'gate_refuse'.
  const onlyWarn = reasons.length > 0 && counterparties.some((c) => c.verdict === 'warn') && reasons.every((r) => r.startsWith('WARN '));
  const allow = reasons.length === 0;
  const { allow: _a, block: _b, trustedApis: _t, humanApproved: _h, comment: _c, ...limits } = p;
  return { allow, action: allow ? 'gate_allow' : onlyWarn ? 'gate_warn' : 'gate_refuse', reasons, notes, counterparties,
    anchorAgeH: anchorAgeH === null ? null : +anchorAgeH.toFixed(2), spent24h: +spent24h.toFixed(2), pendingUsd, policy: limits };
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

/** gate.policy.json (or another file) → policy object. */
export function readPolicy(file = POLICY_FILE) {
  return JSON.parse(readFileSync(file, 'utf8'));
}

export function readRows(file) {
  return readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
}

async function main() {
  const argv = process.argv.slice(2), opt = (k, d) => { const i = argv.indexOf('--' + k); return i >= 0 ? argv[i + 1] : d; }, has = (k) => argv.includes('--' + k);
  if (argv[0] !== 'check' || opt('pending-usd') === undefined) { console.error('usage: node src/gate.mjs check --pending-usd X --to ADDR[,ADDR] [--chain C] [--policy FILE] [--rows FILE] [--account ID] [--max-anchor-age-h H] [--max-daily-usd USD] [--fail-open] [--anchor-time ISO] [--now ISO]'); process.exit(2); }
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const nowMs = opt('now') ? Date.parse(opt('now')) : Date.now();
  const rows = readRows(path.resolve(opt('rows', path.join(root, 'data', 'records.jsonl'))));
  const policy = readPolicy(opt('policy') ? path.resolve(opt('policy')) : POLICY_FILE);
  if (opt('max-anchor-age-h') !== undefined) policy.maxAnchorAgeH = Number(opt('max-anchor-age-h'));
  if (opt('max-daily-usd') !== undefined) policy.maxDailyUsd = Number(opt('max-daily-usd'));
  const anchor = opt('anchor-time') ? { timeMs: Date.parse(opt('anchor-time')) } : opt('account') ? await readRegistryAnchor(opt('account'), opt('network', 'mainnet')) : { error: 'no --account and no --anchor-time' };
  const to = (opt('to') ?? '').split(',').filter(Boolean).map((address) => ({ address, chain: opt('chain') }));
  const r = evaluate({ rows, anchor, policy, pendingUsd: Number(opt('pending-usd')), nowMs, failOpen: has('fail-open'), to });
  console.log(JSON.stringify({ ...r, anchorSeq: anchor.seq }));
  process.exit(r.allow ? 0 : 1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
