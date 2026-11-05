// Pure helpers for the append-only anchor registry contract (contract/README.md): build the JSON args of
// its methods, and parse its view results strictly. No I/O. Used by src/registry-cli.mjs, which cycle.mjs runs to anchor.
//
// The contract's JSON conventions: seq, count, block_height, from_index and limit are JSON numbers (seq is
// capped at 2^53 - 1, so they are exact in JavaScript); timestamp_ns and storage_balance are decimal strings
// (they exceed 2^53), parsed here to BigInt.

export const MAX_LIMIT = 100;
export const MAX_URL_BYTES = 300;
export const MAX_SEQ = Number.MAX_SAFE_INTEGER; // 2^53 - 1, the contract's limit too
export const EVENT_PREFIX = 'EVENT_JSON:';

const HEAD_RE = /^[0-9a-f]{64}$/;
const CAIP10_RE = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$/;
const URL_RE = /^https?:\/\/(?!\/)[\x21\x23-\x5b\x5d-\x7e]+$/; // then printable ASCII except space, " and \
const ACCOUNT_RE = /^(?=.{2,64}$)[a-z0-9]+(?:[-_.][a-z0-9]+)*$/;
const DECIMAL_RE = /^(0|[1-9][0-9]*)$/;

function fail(msg) { throw new Error(`registry: ${msg}`); }

function checkSeq(seq) {
  if (!Number.isSafeInteger(seq) || seq < 0) fail(`seq must be an integer in 0..2^53-1, got ${seq}`);
  return seq;
}

function checkIndex(n, what) {
  if (!Number.isSafeInteger(n) || n < 0) fail(`${what} must be a non-negative integer, got ${n}`);
  return n;
}

export function checkAccount(account) {
  if (typeof account !== 'string' || !ACCOUNT_RE.test(account)) fail(`not a NEAR account id: ${JSON.stringify(account)}`);
  return account;
}

// register({ agent_id }): agent_id is the CAIP-10 id of the wallet whose decisions the agent records.
export function registerArgs(agentId) {
  if (typeof agentId !== 'string' || !CAIP10_RE.test(agentId)) fail(`agent_id must be CAIP-10 (namespace:reference:address), got ${JSON.stringify(agentId)}`);
  return { agent_id: agentId };
}

// anchor({ seq, head, records_url }): the same checks the contract makes, so a bad call fails before it costs gas.
export function anchorArgs({ seq, head, recordsUrl }) {
  checkSeq(seq);
  if (typeof head !== 'string' || !HEAD_RE.test(head)) fail('head must be 64 lowercase hex characters');
  if (typeof recordsUrl !== 'string' || !URL_RE.test(recordsUrl) || recordsUrl.length > MAX_URL_BYTES) {
    fail(`records_url must be an http(s) URL of at most ${MAX_URL_BYTES} printable ASCII bytes`);
  }
  return { seq, head, records_url: recordsUrl };
}

export function getAgentArgs(account) {
  return { account: checkAccount(account) };
}

export function getAnchorsArgs(account, fromIndex = 0, limit = MAX_LIMIT) {
  checkIndex(fromIndex, 'from_index');
  checkIndex(limit, 'limit');
  return { account: checkAccount(account), from_index: fromIndex, limit: Math.min(limit, MAX_LIMIT) };
}

export function getAgentsArgs(fromIndex = 0, limit = MAX_LIMIT) {
  checkIndex(fromIndex, 'from_index');
  checkIndex(limit, 'limit');
  return { from_index: fromIndex, limit: Math.min(limit, MAX_LIMIT) };
}

// FunctionCall args bytes (what a transaction carries; RPC call_function takes them base64-encoded).
export function encodeArgs(args) {
  return new TextEncoder().encode(JSON.stringify(args));
}

// A view result: the parsed JSON value (what rpc.callFunction returns as `value`), its JSON text, or the raw
// result bytes as a Uint8Array (for a raw RPC `call_function` result: Uint8Array.from(r.result)).
function asValue(result) {
  if (result instanceof Uint8Array) return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result));
  if (typeof result === 'string') return JSON.parse(result);
  return result;
}

function decimal(s, what) {
  if (typeof s !== 'string' || !DECIMAL_RE.test(s)) fail(`${what} must be a decimal string, got ${JSON.stringify(s)}`);
  return BigInt(s);
}

function exactKeys(o, keys, what) {
  if (o === null || typeof o !== 'object' || Array.isArray(o)) fail(`${what} is not an object`);
  const got = Object.keys(o).sort().join(',');
  if (got !== [...keys].sort().join(',')) fail(`${what} has fields ${got}, expected ${keys.join(',')}`);
}

// One stored anchor → { seq, head, recordsUrl, blockHeight, timestampNs (BigInt), time (ISO, ms precision) }.
// { seq, head } is what verifySparse (src/chain.mjs) takes as a claim.
export function parseAnchor(a) {
  exactKeys(a, ['seq', 'head', 'records_url', 'block_height', 'timestamp_ns'], 'anchor');
  checkSeq(a.seq);
  if (typeof a.head !== 'string' || !HEAD_RE.test(a.head)) fail('anchor head is not 64 lowercase hex');
  if (typeof a.records_url !== 'string') fail('anchor records_url is not a string');
  if (!Number.isSafeInteger(a.block_height) || a.block_height < 0) fail('anchor block_height is not a safe integer');
  const timestampNs = decimal(a.timestamp_ns, 'timestamp_ns');
  if (timestampNs >= 2n ** 64n) fail('timestamp_ns exceeds u64');
  return {
    seq: a.seq,
    head: a.head,
    recordsUrl: a.records_url,
    blockHeight: a.block_height,
    timestampNs,
    time: new Date(Number(timestampNs / 1_000_000n)).toISOString(), // u64 ns always fits a Date
  };
}

// get_anchors result → anchors, checking that seq strictly increases (the contract guarantees it).
export function parseAnchors(result) {
  const v = asValue(result);
  if (!Array.isArray(v)) fail('get_anchors did not return an array');
  if (v.length > MAX_LIMIT) fail(`get_anchors returned ${v.length} entries (max ${MAX_LIMIT})`);
  const out = v.map(parseAnchor);
  for (let i = 1; i < out.length; i++) if (out[i].seq <= out[i - 1].seq) fail(`seq not increasing at entry ${i}`);
  return out;
}

// get_agent result → null, or { agentId, count, storageBalance (BigInt yocto), last: anchor | null }.
export function parseAgent(result) {
  const v = asValue(result);
  if (v === null) return null;
  exactKeys(v, ['agent_id', 'count', 'storage_balance', 'last'], 'agent');
  if (typeof v.agent_id !== 'string') fail('agent_id is not a string');
  if (!Number.isSafeInteger(v.count) || v.count < 0) fail('count is not a safe integer');
  const last = v.last === null ? null : parseAnchor(v.last);
  if ((v.count === 0) !== (last === null)) fail('count and last disagree');
  return { agentId: v.agent_id, count: v.count, storageBalance: decimal(v.storage_balance, 'storage_balance'), last };
}

// get_agents result → account ids.
export function parseAgents(result) {
  const v = asValue(result);
  if (!Array.isArray(v) || v.length > MAX_LIMIT) fail('get_agents did not return an array of at most 100');
  return v.map(checkAccount);
}

// A receipt log line → { account, seq, head } for the registry's anchor event, or null for any other log.
export function parseAnchorEvent(log) {
  if (typeof log !== 'string' || !log.startsWith(EVENT_PREFIX)) return null;
  let e;
  try { e = JSON.parse(log.slice(EVENT_PREFIX.length)); } catch { return null; }
  if (e?.standard !== 'blackbox' || e.event !== 'anchor') return null;
  if (e.version !== '1.0.0' || !Array.isArray(e.data) || e.data.length !== 1) fail('unexpected anchor event shape');
  const d = e.data[0];
  exactKeys(d, ['account', 'seq', 'head'], 'anchor event');
  if (typeof d.head !== 'string' || !HEAD_RE.test(d.head)) fail('anchor event head is not 64 lowercase hex');
  return { account: checkAccount(d.account), seq: checkSeq(d.seq), head: d.head };
}

// Reads every anchor of `account` through `view(method, args)` (e.g. (m, a) => rpc.callFunction(url, registry, m, a)
// returning { value }), 100 per page, until a short page.
export async function readAllAnchors(view, account) {
  const all = [];
  for (;;) {
    const r = await view('get_anchors', getAnchorsArgs(account, all.length, MAX_LIMIT));
    const page = parseAnchors(r?.value !== undefined ? r.value : r);
    if (all.length && page.length && page[0].seq <= all[all.length - 1].seq) fail('seq not increasing across pages');
    all.push(...page);
    if (page.length < MAX_LIMIT) return all;
  }
}
