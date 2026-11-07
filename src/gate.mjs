// Pre-sign gate: a policy the agent's own code calls right before it signs a transaction that moves value.
// Black box on its own detects tampering after the fact; this turns the same log into three rules that can refuse a send:
//
//   1. Anchor freshness. The newest head in the append-only registry must be younger than maxAnchorAgeH (default 20 h,
//      two missed 8-hourly cycles; only anchors pinned to a published commit count, not pre-send ones). If the log is not being
//      published and anchored, the agent does not spend. If the registry cannot be
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
//        [--fail-open] [--anchor-time ISO] [--now ISO] [--txs FILE]   (FILE: JSON [{chain, to, data, value}], the unsigned txs)
//   ⇒ one JSON line {allow, action, reasons, counterparties, anchorAgeH, spent24h, pendingUsd}; exit 0 = allow, 1 = refuse, 2 = usage.
//   node src/gate.mjs coverage [--rows data/records.jsonl]
//   ⇒ {sends, covered, bypassed, missing}: did every gated send since the gate went live have a gate decision? exit 1 if not.
// --rows takes a JSONL file of records ({row: {...}}) or of raw ledger rows; --anchor-time skips the NEAR read (tests, demos).
// Limits: this is a policy the agent's own code calls. A compromised key, or an operator who edits the calling code, bypasses
// it; so does anyone who can push gate.policy.json (the agent can too). The counterparties, recipient, provenance and USD
// amount are what the caller says; with txs the gate checks them against the transactions' own ERC-20 transfers/approvals and
// USDG amounts, but not a router's calldata or other tokens' prices, and only for the transactions it is shown (flows.mjs
// checks afterwards that the signed tx was one of them). A code hash catches a redeployed contract,
// not an upgradeable proxy whose implementation changes. It adds a NEAR RPC read to every gated send by design.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as rpc from './near/rpc.mjs';
import { readAllAnchors } from './registry.mjs';
import { readShared } from './blocklist.mjs';

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
    // 2026-11-07: a decision records countedUsd when the gate counted more than the caller declared (published price ceilings)
    if (t <= nowMs && nowMs - t < DAY_MS) sum += Math.max(r.pendingUsd, typeof r.countedUsd === 'number' ? r.countedUsd : 0);
  }
  return sum;
}

const norm = (a) => String(a ?? '').trim().toLowerCase();
const blockMatches = (entry, c) => !entry.chain || !c.chain || norm(entry.chain) === norm(c.chain);   // a block entry without a chain blocks everywhere
const sameChain = (entry, c) => !!c.chain && norm(entry.chain) === norm(c.chain);                      // allow / human entries are per chain
const key = (chain, address) => `${norm(chain)}:${norm(address)}`;

/** (chain, address) pairs the gate approved sends to before nowMs → Map('chain:address' → count). Counts only rows that carry
 *  per-counterparty chains (written since 2026-11-06); a row's bare `to` list has no chain and counts for nothing. An address that
 *  was allowed only because a trusted API issued it (a 1Click deposit address: one per quote) never counts (screen 5 Z-3: reusing
 *  it without provenance, or with another recipient, passed through this path). Pure. */
export function priorApproved(rows, nowMs) {
  const seen = new Map();
  for (const x of rows) {
    const r = x?.row ?? x;
    if (r?.engine !== 'gate' || r.action !== 'gate_allow' || !Array.isArray(r.counterparties) || !(Date.parse(r.t) <= nowMs)) continue;
    for (const c of r.counterparties) {
      const viaApi = c?.via === 'api' || c?.provenance || c?.apiRecord || /^from a trusted API/.test(c?.why ?? '');
      if (c?.chain && c.address && !viaApi) seen.set(key(c.chain, c.address), (seen.get(key(c.chain, c.address)) ?? 0) + 1);
    }
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
  if (blocked) return { ...out, verdict: 'block', why: blocked.reporter
    ? `blocklisted by ${blocked.reporter} (shared list, reported ${String(blocked.reportedAt).slice(0, 10)}): ${blocked.evidence}`
    : `blocklisted: ${blocked.evidence}` };
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
    return { ...out, verdict: 'allow', via: 'allowlist', why: `allow-listed: ${listed.label}` };
  }
  const api = c.provenance?.api && (policy.trustedApis ?? []).find((e) => norm(e.api) === norm(c.provenance.api));
  if (api?.status) {   // 2026-11-06: the API's own record of this address decides, not the caller's label (readApiFacts)
    if (facts.apiError) return { ...out, verdict: 'warn', why: `${api.label}: its own record of this address could not be read (${facts.apiError})`, provenance: c.provenance };
    const rec = facts.api;
    if (!rec) return { ...out, verdict: 'warn', why: `${api.label}: its own record of this address was not read`, provenance: c.provenance };
    if (rec.notFound) return { ...out, verdict: 'warn', why: `${api.label}: it has no record of this address (it never issued it)`, provenance: c.provenance };
    const self = (policy.self ?? []).map((x) => norm(x.address)), why = [];
    if (rec.status !== 'PENDING_DEPOSIT') why.push(`its record says ${rec.status ?? 'nothing'}, not a fresh quote waiting for a deposit`);
    if (!self.includes(norm(rec.recipient))) why.push(`its record pays ${rec.recipient ?? '(nobody named)'}, not the agent`);
    if (!self.includes(norm(rec.refundTo))) why.push(`its record refunds to ${rec.refundTo ?? '(nobody named)'}, not the agent`);
    if (why.length) return { ...out, verdict: 'warn', why: `${api.label}: ${why.join('; ')}`, provenance: c.provenance, apiRecord: rec };
    const fwd = forwardProblem(api, { ...c, recipient: rec.recipient }, policy);
    if (fwd) return { ...out, verdict: 'warn', why: fwd, provenance: c.provenance, apiRecord: rec };
    return { ...out, verdict: 'allow', via: 'api', why: `from a trusted API: ${api.label}; its own record (${rec.status}) pays the agent and refunds to it`, provenance: c.provenance, apiRecord: rec };
  }
  if (api) {
    const fwd = forwardProblem(api, c, policy);
    if (fwd) return { ...out, verdict: 'warn', why: fwd, provenance: c.provenance };
    return { ...out, verdict: 'allow', via: 'api', why: `from a trusted API: ${api.label}`, provenance: c.provenance };
  }
  const human = (policy.humanApproved ?? []).find((e) => norm(e.address) === addr && sameChain(e, c));
  if (human) return { ...out, verdict: 'allow', via: 'human', why: `approved by a human: ${human.by}, ${human.at} (counts only from the published policy)` };
  const n = prior.get(key(c.chain, addr)) ?? 0;
  if (n > 0) return { ...out, verdict: 'allow', via: 'prior', why: `prior interaction: ${n} earlier approved send${n > 1 ? 's' : ''}` };
  // 2026-11-07 (the track prompt's 'age and activity' signal): what the chain shows about an unknown payee goes into the reason.
  // Account AGE is not readable from public data on Robinhood Chain (its public RPC keeps no historical state and there is no
  // public explorer API), so the gate reports activity only: transactions sent (nonce), code or not, and the balance.
  let seen = '';
  if (Number.isInteger(facts.nonce)) {
    seen = facts.nonce === 0 && facts.codeHash === null ? '; fresh address (0 txs, no code)'
      : `; on chain: ${facts.nonce} tx${facts.nonce === 1 ? '' : 's'} sent, ${facts.codeHash ? 'a contract' : 'no code'}${facts.balanceWei !== undefined ? `, balance ${(Number(BigInt(facts.balanceWei)) / 1e18).toPrecision(3)} native` : ''}${facts.nonce <= 1 && !facts.codeHash ? ' (barely used)' : ''}`;
  } else if (facts.error) seen = `; on-chain facts unreadable (${facts.error})`;
  return { ...out, verdict: 'warn', why: `unknown counterparty: not allow-listed, not from a trusted API, never approved${seen} ⇒ ask a human`,
    ...(Number.isInteger(facts.nonce) ? { activity: { txsSent: facts.nonce, contract: !!facts.codeHash, ...(facts.balanceWei !== undefined ? { balanceWei: facts.balanceWei } : {}) } } : {}) };
}

// ---- The transactions themselves (2026-11-06, after screen 4: "every allow path trusts the caller") ----
// A caller can also show the gate the exact unsigned transactions it is about to sign: txs = [{chain, to, data, value}]. The gate
// then decodes them itself instead of believing the caller's description: an ERC-20 transfer(to, amount) or approve(spender,
// amount) names its payee or spender in the calldata, any other call (or native value) reaches tx.to. Every address it finds
// must be one the caller declared in `to` (else refuse), an unlimited approval is refused, and the USDG the transactions move
// or approve may not exceed the USD the caller declared (2 % + 1 cent, as in flows.mjs). Only USDG is priced exactly. Since
// 2026-11-07 (escape 29) every other amount, native coin included, is counted at a PUBLISHED price ceiling (gate.policy.json
// priceCeilings: chain, token or "native", decimals, an upper USD price with its source), and rule 2 counts the larger of that and
// the caller's figure; an amount with no ceiling is refused, since the gate cannot bound it. Each tx gets a digest of chain|to|data|value
// that the caller records with the decision, so src/flows.mjs can show afterwards that the transaction on chain is the one the
// gate was shown (kind tx_not_shown_to_gate). What a router or bridge does inside its own calldata (e.g. a Relay swap's final
// recipient) is not decoded: those entries still need the caller's recipient (forwardProblem).
export const PRICED_TOKENS = { 'robinhood:0x5fc5360d0400a0fd4f2af552add042d716f1d168': { symbol: 'USDG', decimals: 6, usd: 1 } };   // USDG = $1
export const TX_BOUND_SINCE = '2026-11-06T13:00:00Z';   // from here the agent's wrappers show the gate every tx (flows.mjs checks it)
// 11-06 anchor-before-send: from here the operator's wrapper anchors each gated decision on SocialDB + the registry (src/anchor-now.mjs)
// BEFORE it signs; flows.mjs then checks that a registry anchor covering the decision is older than the send's block (not_anchored_before_send)
export const ANCHOR_BEFORE_SEND_SINCE = '2026-11-06T15:00:00Z';
export const AGENT_NEAR_ACCOUNT = '00537bf24e164c18f3512de1040d34c88a11f37976a3ef6d4de673dc9cef6590';   // the agent's anchoring account (implicit)
const SELECTOR = { '0xa9059cbb': 'transfer', '0x095ea7b3': 'approve' };
const MAX_UINT = (1n << 256n) - 1n;
const bigOf = (v) => (v === undefined || v === null || v === '' ? 0n : BigInt(v));

/** sha256 of chain|to|data|value, normalized (lower-case hex, value as a decimal integer); nonce and gas are not part of it. */
export function txDigest({ chain, to, data, value }) {
  return createHash('sha256').update(`${norm(chain)}|${norm(to)}|${norm(data || '0x')}|${bigOf(value).toString()}`).digest('hex');
}

/** Published price ceilings → { 'chain:token' | 'chain:native': entry } (entries without a finite usd or integer decimals are ignored). */
export function ceilingMap(list) {
  const m = {};
  for (const c of Array.isArray(list) ? list : []) {
    if (!c?.chain || !c?.token || !(Number.isFinite(c.usd) && c.usd > 0) || !Number.isInteger(c.decimals)) continue;
    m[`${norm(c.chain)}:${norm(c.token)}`] = c;
  }
  return m;
}

/** Pure: decode the unsigned txs → {counterparties, usd (USDG, exact), ceilingUsd (other amounts at the published ceilings),
 *  bounded, unlimited, unpriced (no ceiling: refused by evaluate), errors, shown}. */
export function decodeTxs(txs, ceilings = []) {
  const counterparties = [], unlimited = [], unpriced = [], errors = [], shown = [], bounded = [], cm = ceilingMap(ceilings);
  let usd = 0, ceilingUsd = 0;
  const atCeiling = (i, c, amount, what) => { const u = (Number(amount) / 10 ** c.decimals) * c.usd; ceilingUsd += u; bounded.push(`tx ${i}: ${what} ${Number(amount) / 10 ** c.decimals} ${c.symbol ?? ''} ≤ $${u.toFixed(2)} (ceiling $${c.usd})`); };
  for (const [i, t] of (txs ?? []).entries()) {
    const chain = t?.chain ? norm(t.chain) : null, to = norm(t?.to), data = norm(t?.data || '0x');
    let value;
    try { value = bigOf(t?.value); } catch { errors.push(`tx ${i}: value ${t?.value} is not a number`); continue; }
    if (!chain || !/^0x[0-9a-f]{40}$/.test(to) || !/^0x([0-9a-f]{2})*$/.test(data)) { errors.push(`tx ${i}: needs a chain, a 0x to-address and hex data`); continue; }
    const kind = SELECTOR[data.slice(0, 10)], tok = PRICED_TOKENS[`${chain}:${to}`];
    shown.push({ chain, to, value: value.toString(), selector: data.slice(0, 10), digest: txDigest({ chain, to, data, value }) });
    if (value > 0n) {
      counterparties.push({ address: to, chain, role: 'native value', tx: i });
      const c = cm[`${chain}:native`];
      if (c) atCeiling(i, c, value, 'native'); else unpriced.push(`tx ${i}: ${value} wei of ${chain}'s native coin (no published price ceiling)`);
    }
    if (kind) {
      if (data.length !== 2 + 8 + 128) { errors.push(`tx ${i}: ${kind} calldata has the wrong length`); continue; }
      const who = '0x' + data.slice(34, 74), amount = BigInt('0x' + data.slice(74, 138));
      counterparties.push({ address: who, chain, role: kind === 'transfer' ? 'transfer recipient' : 'approve spender', tx: i });
      if (kind === 'approve' && amount === MAX_UINT) unlimited.push({ spender: who, token: to, symbol: tok?.symbol ?? to });
      else if (tok) usd += Number(amount) / 10 ** tok.decimals * tok.usd;
      else if (amount > 0n) {
        const c = cm[`${chain}:${to}`];
        if (c) atCeiling(i, c, amount, kind); else unpriced.push(`tx ${i}: ${kind} of ${amount} units of token ${to} on ${chain} (no published price ceiling)`);
      }
    } else if (value === 0n) counterparties.push({ address: to, chain, role: 'call target', tx: i });
  }
  return { counterparties, usd: Math.round(usd * 1e6) / 1e6, ceilingUsd: Math.round(ceilingUsd * 1e6) / 1e6, bounded, unlimited, unpriced, errors, shown };
}

/** The decision. anchor = {timeMs} | {error}. to = counterparties (see judgeCounterparty). published = the result of
 *  checkPublished() (false/undefined = not checked; {ok:false} refuses). txs = the unsigned transactions (optional; see
 *  decodeTxs): when given, the gate checks them against `to` and pendingUsd. Pure (test/gate.test.mjs). */
export function evaluate({ rows, anchor, policy = {}, pendingUsd, nowMs, failOpen = false, to, facts = {}, published, txs, shared }) {
  const base = { ...DEFAULT_POLICY, ...policy }, reasons = [], notes = [];
  // 2026-11-07: the shared blocklist (src/blocklist.mjs). When the published policy trusts reporters, their SocialDB reports
  // count as block entries; if they could not be read the gate refuses (fail closed), as it does when the registry is unreadable.
  let sharedEntries = [];
  if ((base.trustedReporters ?? []).length) {
    if (!shared || shared.error) reasons.push(`shared blocklist not read (${shared?.error ?? 'not given'}): refusing (fail closed)`);
    else sharedEntries = shared.entries ?? [];
  }
  const p = sharedEntries.length ? { ...base, block: [...(base.block ?? []), ...sharedEntries] } : base;
  if (published && !published.ok) reasons.push(`policy not usable: ${published.why}`);
  if (!(typeof pendingUsd === 'number' && Number.isFinite(pendingUsd) && pendingUsd >= 0)) reasons.push('pending USD must be a number ≥ 0');
  let anchorAgeH = null;
  if (!anchor || anchor.error || !Number.isFinite(anchor.timeMs)) {
    const why = `registry anchor not read (${anchor?.error ?? 'no anchor'})`;
    if (failOpen) notes.push(`${why}; --fail-open: rule 1 skipped`); else reasons.push(`${why}: refusing (fail closed)`);
  } else {
    anchorAgeH = (nowMs - anchor.timeMs) / 3.6e6;
    if (anchorAgeH > p.maxAnchorAgeH) reasons.push(`newest published anchor is ${anchorAgeH.toFixed(1)} h old (> ${p.maxAnchorAgeH} h): the log is not being published and anchored`);
  }
  const spent24h = spentLast24h(rows, nowMs);
  const list = (Array.isArray(to) ? to : to ? [to] : []).map((c) => (typeof c === 'string' ? { address: c } : c));
  let dec = null;
  if (txs !== undefined) {
    dec = decodeTxs(txs, p.priceCeilings);
    if (!dec.shown.length && !dec.errors.length) reasons.push('no transaction shown (txs is empty): refusing (fail closed)');
    for (const e of dec.errors) reasons.push(`transaction not decodable: ${e}`);
    for (const d of dec.counterparties) {
      if (!list.some((c) => key(c.chain, c.address) === key(d.chain, d.address))) reasons.push(`REFUSE ${d.address} (${d.role}, tx ${d.tx}): the transaction reaches it, but the caller did not declare it`);
    }
    for (const u of dec.unlimited) reasons.push(`REFUSE ${u.spender} (approve spender): unlimited ${u.symbol} approval`);
    if (Number.isFinite(pendingUsd) && dec.usd > pendingUsd * 1.02 + 0.01) reasons.push(`the transactions move or approve $${dec.usd} of USDG; the caller declared $${pendingUsd}`);
    for (const u of dec.unpriced) reasons.push(`REFUSE: the gate cannot bound this spend: ${u}; publish a price ceiling for it (gate.policy.json priceCeilings)`);
  }
  // rule 2 counts the larger of the caller's figure and what the gate counted itself (USDG exactly + other amounts at the ceilings)
  const capUsd = Math.max(Number.isFinite(pendingUsd) ? pendingUsd : 0, (dec?.usd ?? 0) + (dec?.ceilingUsd ?? 0));
  if (Number.isFinite(pendingUsd) && spent24h + capUsd > p.maxDailyUsd) {
    reasons.push(`$${(spent24h + capUsd).toFixed(2)} in 24 h would exceed the $${p.maxDailyUsd} cap ($${spent24h.toFixed(2)} already allowed)`);
  }
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
  const { allow: _a, block: _b, trustedApis: _t, humanApproved: _h, comment: _c, self: _s, priceCeilings: _pc, trustedReporters: _tr, ...limits } = p;
  if (dec?.bounded.length) notes.push(`counted at published price ceilings (an upper bound): ${dec.bounded.join('; ')}`);
  const countedUsd = Math.round(capUsd * 1e6) / 1e6;
  return { allow, action: allow ? 'gate_allow' : onlyWarn ? 'gate_warn' : 'gate_refuse', reasons, notes, counterparties,
    anchorAgeH: anchorAgeH === null ? null : +anchorAgeH.toFixed(2), spent24h: +spent24h.toFixed(2), pendingUsd, policy: limits,
    ...(Number.isFinite(pendingUsd) && countedUsd > pendingUsd ? { countedUsd } : {}),
    ...((base.trustedReporters ?? []).length ? { sharedBlocklist: { reporters: base.trustedReporters.length, entries: sharedEntries.length } } : {}),
    ...(dec ? { shownTxs: dec.shown, shownUsd: dec.usd, ...(dec.bounded.length ? { ceilingUsd: dec.ceilingUsd } : {}) } : {}) };
}

/** A records_url pinned to a commit (what the cycle writes after publishing), not to a branch like main (what a pre-send anchor
 *  writes before its records are published). */
export const isPinned = (url) => /\/[0-9a-f]{40}\/data\/records\.jsonl$/.test(String(url ?? ''));
/** Rule 1 reads the newest PUBLISHED anchor (screen 5 Z-1): pre-send anchors point at main and would otherwise keep the gate
 *  "fresh" while the publishing cycle had stopped. anchors = parsed registry anchors (registry.mjs). Pure. */
export function newestPublished(anchors) {
  const a = [...(anchors ?? [])].reverse().find((x) => isPinned(x.recordsUrl));
  return a ? { timeMs: Number(BigInt(a.timestampNs) / 1_000_000n), seq: a.seq } : { error: 'no anchor pinned to a published commit' };
}
/** Newest published registry anchor of `account` → {timeMs, seq, newestSeq} or {error}. */
export async function readRegistryAnchor(account, network = 'mainnet') {
  try {
    const url = rpc.rpcUrl(network);
    const anchors = await readAllAnchors((m, a) => rpc.callFunction(url, REGISTRY, m, a), account);
    if (!anchors.length) return { error: 'agent has no anchors' };
    return { ...newestPublished(anchors), newestSeq: anchors.at(-1).seq };
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
  const sinceMs = Date.parse(since), used = new Set(), out = { since, windowMin, sends: 0, covered: 0, bypassed: 0, missing: [], pairs: [] };
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
    out.pairs.push({ seq: s.seq, gateSeq: g.seq, action: g.r.action });   // which decision covered which send (src/flows.mjs)
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
      facts[key(c.chain, a)] = { codeHash: EMPTY_CODE.has(norm(j.result.codeHash)) ? null : norm(j.result.codeHash), nonce: Number(BigInt(j.result.nonce)),
        ...(j.result.balance ? { balanceWei: BigInt(j.result.balance).toString() } : {}) };
    } catch (e) { facts[key(c.chain, a)] = { error: String(e.message ?? e).slice(0, 80) }; }
  }));
  return facts;
}

// 2026-11-06: for a counterparty from a trusted API whose policy entry names a status URL (1Click), read the API's own record of
// the address before the send: {api: {status, recipient, refundTo, appFeeBps}}, {api: {notFound: true}} on HTTP 404, or {apiError}. Merged into facts by readAllFacts.
export async function readApiFacts(to, policy = readPolicy()) {
  const facts = {};
  await Promise.all(to.map(async (c) => {
    const e = c?.provenance?.api && (policy.trustedApis ?? []).find((x) => norm(x.api) === norm(c.provenance.api));
    if (!e?.status || !c.address) return;
    try {
      const res = await fetch(e.status + encodeURIComponent(c.address), { signal: AbortSignal.timeout(15_000) });
      if (res.status === 404) { facts[key(c.chain, c.address)] = { api: { notFound: true, status: null } }; return; }   // the API never issued it
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const j = await res.json(), q = j.quoteResponse?.quoteRequest ?? {};
      facts[key(c.chain, c.address)] = { api: { status: j.status ?? null, recipient: q.recipient ?? null, refundTo: q.refundTo ?? null,
        appFeeBps: (q.appFees ?? []).reduce((a, f) => a + (Number(f.fee) || 0), 0) } };
    } catch (err) { facts[key(c.chain, c.address)] = { apiError: String(err.message ?? err).slice(0, 80) }; }
  }));
  return facts;
}

/** readFacts (code hash, nonce) + readApiFacts (trusted APIs' own records), merged per counterparty. */
export async function readAllFacts(to, policy = readPolicy(), rpcs = CHAIN_RPC) {
  const [a, b] = await Promise.all([readFacts(to, rpcs), readApiFacts(to, policy)]);
  const out = { ...a };
  for (const [k, v] of Object.entries(b)) out[k] = { ...(out[k] ?? {}), ...v };
  return out;
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
  const facts = has('no-code-check') ? {} : await readAllFacts(to, policy);
  const published = has('require-published') ? await checkPublished(opt('policy') ? path.resolve(opt('policy')) : POLICY_FILE) : undefined;
  const txs = opt('txs') ? JSON.parse(readFileSync(path.resolve(opt('txs')), 'utf8')) : undefined;   // [{chain, to, data, value}] (2026-11-06)
  const shared = (policy.trustedReporters ?? []).length ? await readShared(policy.trustedReporters, opt('network', 'mainnet')) : undefined;   // 2026-11-07
  const r = evaluate({ rows, anchor, policy, pendingUsd: Number(opt('pending-usd')), nowMs, failOpen: has('fail-open'), to, facts, published, txs, shared });
  console.log(JSON.stringify({ ...r, anchorSeq: anchor.seq }));
  process.exit(r.allow ? 0 : 1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
