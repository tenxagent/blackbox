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

import { REGISTRY, newestPublished, gateCoverage, txDigestInput, decodeTxs as coreDecodeTxs, evaluate as coreEvaluate, CHAIN_RPC, factsFromProof, AGE_CHAIN_IDS, firstSeenFromIndex } from './gate-core.mjs';
export * from './gate-core.mjs';   // 2026-11-07: the pure decision lives in gate-core.mjs (browser-safe); this file adds the I/O

export const POLICY_FILE = fileURLToPath(new URL('../gate.policy.json', import.meta.url));
const norm = (a) => String(a ?? '').trim().toLowerCase();
const key = (chain, address) => `${norm(chain)}:${norm(address)}`;
const sha256hex = (s) => createHash('sha256').update(s).digest('hex');
/** sha256 of chain|to|data|value, normalized (gate-core.mjs txDigestInput); nonce and gas are not part of it. */
export const txDigest = (t) => sha256hex(txDigestInput(t));
/** decodeTxs / evaluate with the Node sha256 digest (the same functions as gate-core.mjs, which leaves the digest to the caller). */
export const decodeTxs = (txs, ceilings = []) => coreDecodeTxs(txs, ceilings, sha256hex);
export const evaluate = (args) => coreEvaluate({ ...args, digest: sha256hex });

/** Newest published registry anchor of `account` → {timeMs, seq, newestSeq} or {error}. */
export async function readRegistryAnchor(account, network = 'mainnet') {
  try {
    const url = rpc.rpcUrl(network);
    const anchors = await readAllAnchors((m, a) => rpc.callFunction(url, REGISTRY, m, a), account);
    if (!anchors.length) return { error: 'agent has no anchors' };
    return { ...newestPublished(anchors), newestSeq: anchors.at(-1).seq };
  } catch (e) { return { error: String(e.message ?? e).slice(0, 160) }; }
}

// Code hash + nonce of EVM counterparties, read with eth_getProof (no keccak library needed). A chain with no RPC here is not read.
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
      facts[key(c.chain, a)] = factsFromProof(j.result);
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

// 2026-11-12: account AGE of unknown payees, from Etherscan's keyless MCP endpoint (the official mcp-keyless.etherscan.io: no key,
// read-only, a shared free service, so calls are few and sequential). Two calls per payee: oldest transaction, oldest token transfer.
export const ETHERSCAN_MCP = 'https://mcp-keyless.etherscan.io/mcp';
/** Open an MCP session → call(tool, args) = the tool's answer parsed as JSON. Throws on any failure (readAgeFacts catches it). */
export async function etherscanMcp(url = ETHERSCAN_MCP) {
  const H = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
  const post = (headers, body, ms) => fetch(url, { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(ms) });
  const init = await post(H, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'blackbox-gate', version: '1' } } }, 15_000);
  const sid = init.headers.get('mcp-session-id'); await init.text();
  if (!init.ok || !sid) throw new Error(`index session not opened (HTTP ${init.status})`);
  const h = { ...H, 'mcp-session-id': sid };
  await (await post(h, { jsonrpc: '2.0', method: 'notifications/initialized' }, 15_000)).text();
  let id = 2;
  return async (name, args) => {
    const t = await (await post(h, { jsonrpc: '2.0', id: id++, method: 'tools/call', params: { name, arguments: args } }, 20_000)).text();
    const m = t.match(/data: (\{.*\})/s), j = JSON.parse(m ? m[1] : t);
    if (j.error) throw new Error(`index error ${String(j.error.message ?? '').slice(0, 60)}`);
    return JSON.parse((j.result?.content ?? []).map((c) => c.text ?? '').join(''));
  };
}
/** to → { 'chain:address': {firstSeenSec, ageReadAtSec} | {firstSeen: null, ageReadAtSec} | {ageError} } for the payees that are
 *  not on the policy's allow or self lists, on chains in AGE_CHAIN_IDS. Never rejects. call = (tool, args) → answer (tests pin it). */
export async function readAgeFacts(to, policy = readPolicy(), call = null) {
  const known = new Set([...(policy.allow ?? []), ...(policy.self ?? [])].map((e) => key(e.chain, e.address)));
  const todo = [...new Map(to.filter((c) => AGE_CHAIN_IDS[c?.chain] && /^0x[0-9a-f]{40}$/.test(norm(c?.address)) && !known.has(key(c.chain, c.address)))
    .map((c) => [key(c.chain, c.address), c])).values()];
  const facts = {};
  if (!todo.length) return facts;
  try {
    const q = call ?? (await etherscanMcp());
    for (const c of todo) {
      const args = { address: norm(c.address), chainid: AGE_CHAIN_IDS[c.chain], page: 1, offset: 1, sort: 'asc' };
      try {
        const answers = [await q('get_transactions', args), await q('get_token_transfers', args)], nowSec = Math.floor(Date.now() / 1000);
        facts[key(c.chain, c.address)] = { ...firstSeenFromIndex(answers, nowSec), ageReadAtSec: nowSec };
      } catch (e) { facts[key(c.chain, c.address)] = { ageError: String(e.message ?? e).slice(0, 80) }; }
    }
  } catch (e) { for (const c of todo) facts[key(c.chain, c.address)] ??= { ageError: String(e.message ?? e).slice(0, 80) }; }
  return facts;
}

/** readFacts (code hash, nonce) + readApiFacts (trusted APIs' own records) + readAgeFacts (account age), merged per counterparty. */
export async function readAllFacts(to, policy = readPolicy(), rpcs = CHAIN_RPC, ageCall = null) {
  const [a, b, c] = await Promise.all([readFacts(to, rpcs), readApiFacts(to, policy), readAgeFacts(to, policy, ageCall)]);
  const out = { ...a };
  for (const src of [b, c]) for (const [k, v] of Object.entries(src)) out[k] = { ...(out[k] ?? {}), ...v };
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
