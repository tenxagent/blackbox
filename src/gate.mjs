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
//        allow  it is an allow-listed public contract ON THAT CHAIN (source + code hash in gate.policy.json; the code hash
//               is read with eth_getProof, and a changed, unreadable or unchecked hash turns it into a warn), OR it came
//               from an API the policy trusts (the caller passes provenance, which is recorded), OR a human approval for it
//               is in the published gate.policy.json, OR the gate approved a send to it on that chain before (prior
//               interaction; only rows written since 2026-11-06 carry per-chain counterparties). An entry that forwards
//               value (router, bridge, deposit address) also needs the final recipient, which must be one of policy.self.
//        warn   anything else, e.g. an address that arrived in a message, or no chain given ⇒ refuse until a human approves.
//      No counterparty given ⇒ refuse (fail closed). The agent's wrapper also refuses when the policy file on disk differs
//      from the one published on GitHub main (checkPublished), so an approval counts only once it is public.
//
//   node src/gate.mjs check --pending-usd 3 --to 0xADDR[,0xADDR] --chain robinhood [--recipient ADDR] [--policy gate.policy.json]
//        [--no-code-check] [--require-published]
//        [--rows data/records.jsonl] [--account ID] [--network mainnet] [--max-anchor-age-h 20] [--max-daily-usd 30]
//        [--fail-open] [--anchor-time ISO] [--now ISO]
//   ⇒ one JSON line {allow, action, reasons, counterparties, anchorAgeH, spent24h, pendingUsd}; exit 0 = allow, 1 = refuse, 2 = usage.
//   node src/gate.mjs coverage [--rows data/records.jsonl]
//   ⇒ {sends, covered, bypassed, missing}: did every gated send since the gate went live have a gate decision? exit 1 if not.
// --rows takes a JSONL file of records ({row: {...}}) or of raw ledger rows; --anchor-time skips the NEAR read (tests, demos).
// Limits: this is a policy the agent's own code calls. A compromised key, or an operator who edits the calling code, bypasses
// it; so does anyone who can push gate.policy.json (the agent can too). The counterparties, recipient, provenance and USD
// amount are what the caller says; the gate records them but cannot check them. A code hash catches a redeployed contract,
// not an upgradeable proxy whose implementation changes. It adds a NEAR RPC read to every gated send by design.

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
const blockMatches = (entry, c) => !entry.chain || !c.chain || norm(entry.chain) === norm(c.chain);   // a block entry without a chain blocks everywhere
const sameChain = (entry, c) => !!c.chain && norm(entry.chain) === norm(c.chain);                      // allow / human entries are per chain
const key = (chain, address) => `${norm(chain)}:${norm(address)}`;

/** (chain, address) pairs the gate approved sends to before nowMs → Map('chain:address' → count). Counts only rows that carry
 *  per-counterparty chains (written since 2026-11-06); a row's bare `to` list has no chain and counts for nothing. Pure. */
export function priorApproved(rows, nowMs) {
  const seen = new Map();
  for (const x of rows) {
    const r = x?.row ?? x;
    if (r?.engine !== 'gate' || r.action !== 'gate_allow' || !Array.isArray(r.counterparties) || !(Date.parse(r.t) <= nowMs)) continue;
    for (const c of r.counterparties) if (c?.chain && c.address) seen.set(key(c.chain, c.address), (seen.get(key(c.chain, c.address)) ?? 0) + 1);
  }
  return seen;
}

/** For an entry that forwards value (a router, a bridge, a deposit address): the counterparty must name the final recipient, and
 *  it must be one of the agent's own addresses (policy.self). → null when fine, else the reason. */
function forwardProblem(entry, c, policy) {
  if (!entry.forwards) return null;
  const rcp = norm(c.recipient?.address ?? c.recipient ?? c.provenance?.recipient);
  if (!rcp) return `${entry.label} forwards the value, and no final recipient was given`;
  if (!(policy.self ?? []).some((s) => norm(s.address) === rcp)) return `${entry.label} forwards the value to ${rcp}, which is not one of the agent's own addresses`;
  return null;
}

/** Rule 3 for one counterparty c = {address, chain?, role?, provenance?: {api, ...}}. facts = {codeHash?, nonce?} read by the
 *  caller (optional; {error} when the read failed: an allow-listed entry with a code hash then warns). → {address, chain, role,
 *  verdict: 'allow'|'warn'|'block', why}. Pure. */
export function judgeCounterparty(c, policy, prior, facts = {}) {
  const addr = norm(c.address), out = { address: addr, chain: c.chain ?? null, role: c.role ?? null };
  if (!addr) return { ...out, verdict: 'block', why: 'no address given' };
  const blocked = (policy.block ?? []).find((e) => norm(e.address) === addr && blockMatches(e, c));
  if (blocked) return { ...out, verdict: 'block', why: `blocklisted: ${blocked.evidence}` };
  if (!c.chain) return { ...out, verdict: 'warn', why: 'no chain given: allow-list entries, approvals and prior sends are per chain' };
  const listed = (policy.allow ?? []).find((e) => norm(e.address) === addr && sameChain(e, c));
  if (listed) {
    if (listed.codeHash && facts.error) return { ...out, verdict: 'warn', why: `${listed.label}: its code could not be read to check the hash (${facts.error})` };
    if (listed.codeHash && facts.codeHash === undefined) return { ...out, verdict: 'warn', why: `${listed.label}: code hash not checked (no on-chain read was made)` };
    if (listed.codeHash && norm(listed.codeHash) !== norm(facts.codeHash)) {
      return { ...out, verdict: 'warn', why: `${listed.label}: code hash changed since it was allow-listed (${listed.codeHash.slice(0, 10)}… → ${facts.codeHash ? `${facts.codeHash.slice(0, 10)}…` : 'no code'})` };
    }
    const fwd = forwardProblem(listed, c, policy);
    if (fwd) return { ...out, verdict: 'warn', why: fwd };
    return { ...out, verdict: 'allow', why: `allow-listed: ${listed.label}` };
  }
  const api = c.provenance?.api && (policy.trustedApis ?? []).find((e) => norm(e.api) === norm(c.provenance.api));
  if (api) {
    const fwd = forwardProblem(api, c, policy);
    if (fwd) return { ...out, verdict: 'warn', why: fwd, provenance: c.provenance };
    return { ...out, verdict: 'allow', why: `from a trusted API: ${api.label}`, provenance: c.provenance };
  }
  const human = (policy.humanApproved ?? []).find((e) => norm(e.address) === addr && sameChain(e, c));
  if (human) return { ...out, verdict: 'allow', why: `approved by a human: ${human.by}, ${human.at} (counts only from the published policy)` };
  const n = prior.get(key(c.chain, addr)) ?? 0;
  if (n > 0) return { ...out, verdict: 'allow', why: `prior interaction: ${n} earlier approved send${n > 1 ? 's' : ''}` };
  const fresh = facts.nonce === 0 && facts.codeHash === null ? '; fresh address (0 txs, no code)' : '';
  return { ...out, verdict: 'warn', why: `unknown counterparty: not allow-listed, not from a trusted API, never approved${fresh} ⇒ ask a human` };
}

/** The decision. anchor = {timeMs} | {error}. to = counterparties (see judgeCounterparty). published = the result of
 *  checkPublished() (false/undefined = not checked; {ok:false} refuses). Pure (test/gate.test.mjs). */
export function evaluate({ rows, anchor, policy = {}, pendingUsd, nowMs, failOpen = false, to, facts = {}, published }) {
  const p = { ...DEFAULT_POLICY, ...policy }, reasons = [], notes = [];
  if (published && !published.ok) reasons.push(`policy not usable: ${published.why}`);
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
    counterparties = list.map((c) => judgeCounterparty(c, p, prior, facts[key(c.chain, c.address)] ?? {}));
    for (const c of counterparties) if (c.verdict !== 'allow') reasons.push(`${c.verdict.toUpperCase()} ${c.address}${c.role ? ` (${c.role})` : ''}: ${c.why}`);
  }
  // action: what the caller records. Only-warn refusals are 'gate_warn' (waiting for a human), every other refusal 'gate_refuse'.
  const onlyWarn = reasons.length > 0 && counterparties.some((c) => c.verdict === 'warn') && reasons.every((r) => r.startsWith('WARN '));
  const allow = reasons.length === 0;
  const { allow: _a, block: _b, trustedApis: _t, humanApproved: _h, comment: _c, self: _s, ...limits } = p;
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

// Gate coverage (2026-11-06): the log itself shows whether the gate ran. Every money record of a gated tool written since the
// first gate record must have a gate decision for it (gate_allow, or a recorded gate_bypass) shortly before it, one decision per
// send. Kinds = the money rows the agent's gated tools write (lib/gate.mjs callers in claude-10x).
export const GATED_SENDS = [
  { engine: 'swap', action: 'relay_swap', what: /^relay swap /, tool: 'relay-swap.mjs' },
  { engine: 'flock', action: 'giga_sell', what: /^relay swap /, tool: 'relay-swap.mjs --from giga' },
  { engine: 'nearfund', action: 'near_fund_deposit', what: /^near fund /, tool: 'near-fund.mjs' },
  { engine: 'sleeve', action: 'sleeve_buy', what: /^sleeve buy /, tool: 'sleeve/buy.mjs, sleeve/eleos.mjs' },
];
export const GATE_LIVE_SINCE = '2026-11-05T18:12:53.902Z';   // the first gate record (seq 3394)

/** rows: records or raw ledger rows. → {since, sends, covered, bypassed, missing: [{seq, t, action}]}. Pure. */
export function gateCoverage(rows, { since = GATE_LIVE_SINCE, windowMin = 15 } = {}) {
  const sinceMs = Date.parse(since), used = new Set(), out = { since, windowMin, sends: 0, covered: 0, bypassed: 0, missing: [] };
  const list = rows.map((x, i) => ({ i, seq: x?.seq ?? null, r: x?.row ?? x })).filter((x) => x.r && Date.parse(x.r.t) >= sinceMs);
  for (const s of list) {
    const kind = GATED_SENDS.find((k) => k.engine === s.r.engine && k.action === s.r.action);
    if (!kind) continue;
    out.sends++;
    const t = Date.parse(s.r.t);
    const g = list.filter((x) => x.i < s.i && !used.has(x.i) && x.r.engine === 'gate' && ['gate_allow', 'gate_bypass'].includes(x.r.action)
      && kind.what.test(String(x.r.what ?? '')) && t - Date.parse(x.r.t) <= windowMin * 60e3).pop();
    if (!g) { out.missing.push({ seq: s.seq, t: s.r.t, action: s.r.action }); continue; }
    used.add(g.i);
    if (g.r.action === 'gate_bypass') out.bypassed++; else out.covered++;
  }
  return out;
}

// Code hash + nonce of EVM counterparties, read with eth_getProof (no keccak library needed). A chain with no RPC here is not read.
export const CHAIN_RPC = { robinhood: 'https://rpc.mainnet.chain.robinhood.com', elysium: 'https://rpc-live.elysp.com' };
const EMPTY_CODE = new Set(['0x' + '0'.repeat(64), '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470']);
/** to → { 'chain:address': {codeHash (null = no code), nonce} | {error} }. */
export async function readFacts(to, rpcs = CHAIN_RPC) {
  const facts = {};
  await Promise.all(to.map(async (c) => {
    const url = rpcs[c?.chain], a = norm(c?.address);
    if (!url || !/^0x[0-9a-f]{40}$/.test(a)) return;
    try {
      const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(15_000),
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getProof', params: [a, [], 'latest'] }) });
      const j = await res.json();
      if (!j.result?.codeHash) throw new Error(JSON.stringify(j.error ?? 'no codeHash').slice(0, 80));
      facts[key(c.chain, a)] = { codeHash: EMPTY_CODE.has(norm(j.result.codeHash)) ? null : norm(j.result.codeHash), nonce: Number(BigInt(j.result.nonce)) };
    } catch (e) { facts[key(c.chain, a)] = { error: String(e.message ?? e).slice(0, 80) }; }
  }));
  return facts;
}

// The policy that counts is the PUBLISHED one: an approval added on disk but not pushed to the public repo does not count yet.
export const PUBLISHED_POLICY_URL = 'https://raw.githubusercontent.com/tenxagent/blackbox/main/gate.policy.json';
/** Compare the policy file on disk with the published one. → {ok: true} | {ok: false, why}. Fails closed when unreadable. */
export async function checkPublished(file = POLICY_FILE, url = PUBLISHED_POLICY_URL) {
  try {
    // no cache-buster: raw.githubusercontent.com leaves the query string out of its cache key (tested 2026-11-06: a new ?t= was a HIT)
    const res = await fetch(url, { signal: AbortSignal.timeout(15_000) });
    if (!res.ok) return { ok: false, why: `published policy not readable (HTTP ${res.status})` };
    const pub = await res.text(), disk = readFileSync(file, 'utf8');
    return pub === disk ? { ok: true } : { ok: false, why: 'the policy file on disk differs from the published one (publish it first; GitHub raw can lag ~5 min)' };
  } catch (e) { return { ok: false, why: `published policy not readable (${String(e.message ?? e).slice(0, 80)})` }; }
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
  if (argv[0] === 'coverage') {
    const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
    const c = gateCoverage(readRows(path.resolve(opt('rows', path.join(root, 'data', 'records.jsonl')))));
    console.log(JSON.stringify(c));
    process.exit(c.missing.length ? 1 : 0);
  }
  if (argv[0] !== 'check' || opt('pending-usd') === undefined) { console.error('usage: node src/gate.mjs check --pending-usd X --to ADDR[,ADDR] [--chain C] [--policy FILE] [--rows FILE] [--account ID] [--max-anchor-age-h H] [--max-daily-usd USD] [--fail-open] [--anchor-time ISO] [--now ISO]'); process.exit(2); }
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const nowMs = opt('now') ? Date.parse(opt('now')) : Date.now();
  const rows = readRows(path.resolve(opt('rows', path.join(root, 'data', 'records.jsonl'))));
  const policy = readPolicy(opt('policy') ? path.resolve(opt('policy')) : POLICY_FILE);
  if (opt('max-anchor-age-h') !== undefined) policy.maxAnchorAgeH = Number(opt('max-anchor-age-h'));
  if (opt('max-daily-usd') !== undefined) policy.maxDailyUsd = Number(opt('max-daily-usd'));
  const anchor = opt('anchor-time') ? { timeMs: Date.parse(opt('anchor-time')) } : opt('account') ? await readRegistryAnchor(opt('account'), opt('network', 'mainnet')) : { error: 'no --account and no --anchor-time' };
  const to = (opt('to') ?? '').split(',').filter(Boolean).map((address) => ({ address, chain: opt('chain'), ...(opt('recipient') ? { recipient: opt('recipient') } : {}) }));
  const facts = has('no-code-check') ? {} : await readFacts(to);
  const published = has('require-published') ? await checkPublished(opt('policy') ? path.resolve(opt('policy')) : POLICY_FILE) : undefined;
  const r = evaluate({ rows, anchor, policy, pendingUsd: Number(opt('pending-usd')), nowMs, failOpen: has('fail-open'), to, facts, published });
  console.log(JSON.stringify({ ...r, anchorSeq: anchor.seq }));
  process.exit(r.allow ? 0 : 1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
