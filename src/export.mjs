// Exporter: the agent's raw ledger -> data/records.jsonl (decision records only).
//
//   node src/export.mjs [--ledger /root/claude-10x/ledger.jsonl] [--upto N] [--out data]
//
// Operator-only step: it needs the private ledger (BLACKBOX_LEDGER or --ledger).
// Judges start from the committed data/records.jsonl.
//
// The output is deterministic: the same ledger lines and the same FILTER_VERSION
// always give byte-identical records.jsonl and manifest.json (no clocks, no
// randomness). Only complete lines (ending in "\n") are read, so a ledger that is
// being appended to is safe to export. If FILTER_VERSION changes, seq numbers can
// change, and heads anchored before the change no longer match: re-anchor.
//
// Each source line goes through these steps, in this order:
//
//   1. PARSE      a line that is not JSON is dropped ("unparseable").
//   2. PRIVACY    rows with engine "kleos-side" are dropped (operator side-wallet
//                 activity, not the agent). Every 0x-address (0x + 40 hex, not part
//                 of a longer hex string) in the raw line is lowercased and hashed
//                 with sha256; if any hash is in data/excluded-address-hashes.json
//                 the row is dropped. That list holds the operator's personal
//                 wallets, which are not the agent's; it stores hashes only, so the
//                 addresses themselves are not published.
//   3. DECISION   rows whose type is in TELEMETRY_TYPES are dropped: they are market
//                 observations, heartbeats or transport noise, not decisions. Every
//                 other type is kept. Known types get a category (CATEGORY_OF);
//                 unknown types are kept as "unclassified" and listed in the
//                 manifest, so a new decision type is never lost silently.
//   4. REDACT     engine "apply" rows (whitelist applications) are reduced to
//                 {t, engine, type, action}. In every kept row, at any depth, a field
//                 is removed when its name matches SENSITIVE_NAME, except the exact
//                 names in PUBLIC_CHAIN_NAMES (token, tokenId, tokenIds, tokens) when
//                 the value is an address or an integer id (public chain data).
//                 Fields in BULKY_NAMES are removed. Tx hashes and contract
//                 addresses are kept on purpose: they are public chain data and
//                 they are what lets anyone check the record against the chain.
//   5. WRAP       the record is
//                   { seq, line, src, cat, txs, stripped, row }
//                 seq      1-based position among kept records (the chain index)
//                 line     1-based line number in the source ledger
//                 src      sha256 of the raw source line (UTF-8, no newline): the
//                          operator can reveal the line later and anyone can check
//                          it was filtered, not invented
//                 cat      category from step 3
//                 txs      tx hashes found in row.tx / row.hash / row.txs, lowercased
//                 stripped paths of the fields removed in step 4 (names only)
//                 row      the source row minus the removed fields
//                 and is written as one canonical JSON line (src/canon.mjs).

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canon } from './canon.mjs';

export const FILTER_VERSION = 'blackbox-filter-v1';

// Observation and transport rows: dropped (step 3).
export const TELEMETRY_TYPES = {
  beat: 'heartbeat',
  liq_beat: 'heartbeat',
  mm_snap: 'market snapshot',
  mm_true: 'market snapshot',
  seen: 'market observation',
  opp: 'market observation (spread seen, nothing done)',
  opp_end: 'market observation (spread gone)',
  candidate: 'mint scanner observation',
  followup: 'mint scanner observation',
  drop: 'drop calendar observation',
  drop_recheck: 'drop calendar observation',
  dexgap: 'DEX price-gap observation',
  stream_open: 'websocket transport',
  stream_close: 'websocket transport',
  stream_stats: 'websocket transport',
  poll_err: 'RPC transport error (not a decision)',
  liq_near: 'third-party position near liquidation (observation; alerts are kept)',
  kleos_paper: 'aggregate paper-trading statistics (no individual trade)',
  noctrive_post: 'copy of a third-party X post',
  vanta_post: 'copy of a third-party X post',
};

// Kept rows: category by type (step 3).
export const CATEGORY_OF = {
  live: 'money', tx: 'money', lp_mint: 'money', lp_exit: 'money', lp_recenter: 'money',
  free_mint: 'money', fill: 'money', stub_offer: 'money',
  skip: 'refusal', fire_refused: 'refusal', flock_skip: 'refusal', mintarm_skip: 'refusal',
  stub_pause: 'refusal', arm_gave_up: 'refusal', qcwatch_end: 'refusal',
  alert: 'alert',
  flock_sim: 'sim', poke_dry_done: 'sim', crank_dry_done: 'sim', mintarm_dry_done: 'sim',
  crank_rehearsal_done: 'sim',
  paper: 'paper', ladder: 'paper', metaculus_forecast: 'paper',
  armed: 'arming', arm_wait: 'arming', mintarm_armed: 'arming', mintarm_signed: 'arming',
  mintarm_moved: 'arming', mintarm_t60: 'arming', mintarm_build: 'arming', mint_sell_wait: 'arming',
  crank_armed: 'arming', crank_signed: 'arming', crank_remote: 'arming', poke_armed: 'arming',
  start: 'lifecycle', metaculus_watch_start: 'lifecycle', merkl_radar_start: 'lifecycle',
  wl: 'application', wl_apply: 'application',
};

export const PRIVACY_ENGINES = new Set(['kleos-side']);
// 0x + 40 hex, not inside a longer hex/word token (so a 64-hex tx hash never matches).
export const ADDRESS_IN_TEXT = /(?<![0-9A-Za-z])0[xX][0-9a-fA-F]{40}(?![0-9A-Za-z])/g;
export const EXCLUDED_HASHES_FILE = new URL('../data/excluded-address-hashes.json', import.meta.url);

// sha256 hex of the lowercased 0x-address string (UTF-8).
export function addressHash(address) {
  return createHash('sha256').update(address.toLowerCase(), 'utf8').digest('hex');
}

// Loads the exclusion list; a missing or malformed list is an error, never "no exclusions".
export function loadExcludedHashes(file = EXCLUDED_HASHES_FILE) {
  const j = JSON.parse(readFileSync(file, 'utf8'));
  const list = j.sha256;
  if (!Array.isArray(list) || !list.every((h) => /^[0-9a-f]{64}$/.test(h))) throw new Error('excluded-address-hashes.json: "sha256" must be a list of 64-hex strings');
  return new Set(list);
}

let cachedExcluded = null;
export function defaultExcluded() {
  return (cachedExcluded ??= loadExcludedHashes());
}

export function mentionsExcludedAddress(rawLine, excluded) {
  for (const m of rawLine.matchAll(ADDRESS_IN_TEXT)) if (excluded.has(addressHash(m[0]))) return true;
  return false;
}
export const SENSITIVE_NAME = /token|key|secret|email|cookie|auth|password|session/i;
export const PUBLIC_CHAIN_NAMES = new Set(['token', 'tokenId', 'tokenIds', 'tokens']);
// snap/book/listings/offers: order-book dumps. tail: process output (paths, traces).
// resp: raw API responses. text: verbatim third-party posts (the url is kept).
// host: the operator's server address.
export const BULKY_NAMES = new Set(['snap', 'book', 'listings', 'offers', 'tail', 'resp', 'text', 'host']);
const APPLY_KEEP = ['t', 'engine', 'type', 'action'];

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const INTEGER = /^[0-9]{1,78}$/;
const TX_HASH = /^0x[0-9a-fA-F]{64}$/;

function isPublicChainValue(v) {
  if (Array.isArray(v)) return v.every(isPublicChainValue);
  if (typeof v === 'number') return Number.isInteger(v) && v >= 0;
  return typeof v === 'string' && (ADDRESS.test(v) || INTEGER.test(v));
}

// Remove sensitive and bulky fields at every depth. Returns [clean, strippedPaths].
export function redact(value, path = '', stripped = []) {
  if (Array.isArray(value)) {
    return [value.map((v, i) => redact(v, `${path}[${i}]`, stripped)[0]), stripped];
  }
  if (value === null || typeof value !== 'object') return [value, stripped];
  const out = {};
  for (const k of Object.keys(value)) {
    const p = path ? `${path}.${k}` : k;
    const v = value[k];
    if (BULKY_NAMES.has(k)) { stripped.push(p); continue; }
    if (SENSITIVE_NAME.test(k) && !(PUBLIC_CHAIN_NAMES.has(k) && isPublicChainValue(v))) { stripped.push(p); continue; }
    out[k] = redact(v, p, stripped)[0];
  }
  return [out, stripped];
}

export function txHashesOf(row) {
  const found = [];
  const add = (h) => { if (typeof h === 'string' && TX_HASH.test(h)) found.push(h.toLowerCase()); };
  add(row.tx);
  add(row.hash);
  if (Array.isArray(row.txs)) row.txs.forEach(add);
  return [...new Set(found)];
}

// Decide what happens to one source line. Pure; used by the tests.
export function classify(rawLine, excluded = defaultExcluded()) {
  let row;
  try {
    row = JSON.parse(rawLine);
  } catch {
    return { keep: false, reason: 'unparseable' };
  }
  if (row === null || typeof row !== 'object' || Array.isArray(row)) return { keep: false, reason: 'unparseable' };
  if (PRIVACY_ENGINES.has(row.engine)) return { keep: false, reason: 'privacy:engine-kleos-side', row };
  if (mentionsExcludedAddress(rawLine, excluded)) return { keep: false, reason: 'privacy:operator-wallet', row };
  if (Object.prototype.hasOwnProperty.call(TELEMETRY_TYPES, row.type)) return { keep: false, reason: `telemetry:${row.type}`, row };
  const cat = CATEGORY_OF[row.type] || 'unclassified';
  let base = row;
  const stripped = [];
  if (row.engine === 'apply') {
    base = {};
    for (const k of Object.keys(row)) {
      if (APPLY_KEEP.includes(k)) base[k] = row[k];
      else stripped.push(k);
    }
  }
  const [clean] = redact(base, '', stripped);
  return { keep: true, cat, row: clean, stripped, txs: txHashesOf(clean) };
}

const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const keyOf = (row) => `${row?.engine ?? '(none)'}|${row?.type ?? '(none)'}`;
const bump = (obj, k, n = 1) => { obj[k] = (obj[k] || 0) + n; };
const sortObj = (o) => Object.fromEntries(Object.entries(o).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)));

// Export a ledger text. Returns { lines: [canonical record lines], manifest }.
export function exportText(text, { upto = Infinity, sourceName = 'ledger.jsonl', excluded = defaultExcluded() } = {}) {
  const end = text.lastIndexOf('\n') + 1; // complete lines only
  const body = text.slice(0, end);
  const raw = body.split('\n');
  raw.pop();
  const take = Math.min(raw.length, upto);
  const out = [];
  const kept = {}, dropped = {}, cats = {}, strippedNames = {}, unclassified = {};
  const reasons = { 'privacy:engine-kleos-side': 0, 'privacy:operator-wallet': 0 }; // always listed, even at 0
  let firstT = null, lastT = null, txRecords = 0;
  for (let i = 0; i < take; i++) {
    const rawLine = raw[i];
    if (rawLine.trim() === '') { bump(reasons, 'blank'); continue; }
    const d = classify(rawLine, excluded);
    if (!d.keep) {
      bump(reasons, d.reason.startsWith('telemetry:') ? 'telemetry' : d.reason);
      bump(dropped, `${keyOf(d.row)}  [${d.reason.split(':')[0]}]`);
      continue;
    }
    const rec = { seq: out.length + 1, line: i + 1, src: sha256hex(rawLine), cat: d.cat, txs: d.txs, stripped: d.stripped, row: d.row };
    out.push(canon(rec));
    bump(kept, keyOf(d.row));
    bump(cats, d.cat);
    if (d.cat === 'unclassified') bump(unclassified, d.row.type ?? '(none)');
    for (const p of d.stripped) bump(strippedNames, p.replace(/\[\d+\]/g, '[]'));
    if (d.txs.length) txRecords++;
    const t = d.row.t ?? null;
    if (t && firstT === null) firstT = t;
    if (t) lastT = t;
  }
  const consumed = raw.slice(0, take).map((l) => l + '\n').join('');
  const manifest = {
    filterVersion: FILTER_VERSION,
    source: {
      name: sourceName,
      linesRead: take,
      bytesRead: Buffer.byteLength(consumed, 'utf8'),
      sha256: sha256hex(consumed),
      note: 'sha256 of the first linesRead complete lines of the source ledger, newlines included',
    },
    records: out.length,
    firstT,
    lastT,
    txRecords,
    dropped: Object.values(reasons).reduce((a, b) => a + b, 0),
    droppedByReason: sortObj(reasons),
    keptByCategory: sortObj(cats),
    keptByEngineType: sortObj(kept),
    droppedByEngineType: sortObj(dropped),
    strippedFields: sortObj(strippedNames),
    unclassifiedTypes: sortObj(unclassified),
    rules: {
      privacyEngines: [...PRIVACY_ENGINES],
      excludedAddresses: `rows that contain a 0x-address whose sha256(lowercase address) is listed in data/excluded-address-hashes.json (${excluded.size} hashes)`,
      telemetryTypes: TELEMETRY_TYPES,
      sensitiveFieldName: String(SENSITIVE_NAME),
      publicChainFieldNames: [...PUBLIC_CHAIN_NAMES],
      bulkyFieldNames: [...BULKY_NAMES],
      applyRowsKeep: APPLY_KEEP,
    },
  };
  return { lines: out, manifest };
}

// ---------------------------------------------------------------- CLI
const { pathToFileURL } = await import('node:url');
const pathMod = await import('node:path');
if (process.argv[1] && import.meta.url === pathToFileURL(pathMod.resolve(process.argv[1])).href) {
  const fs = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const argv = process.argv.slice(2);
  const arg = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : d; };
  const root = pathMod.resolve(pathMod.dirname(fileURLToPath(import.meta.url)), '..');
  const ledger = arg('ledger', process.env.BLACKBOX_LEDGER || '/root/claude-10x/ledger.jsonl');
  const outDir = pathMod.resolve(arg('out', pathMod.join(root, 'data')));
  const upto = arg('upto') ? Number(arg('upto')) : Infinity;
  if (!fs.existsSync(ledger)) {
    console.error(`ledger not found: ${ledger}\nThis step needs the agent's private ledger. Judges: skip it and use the committed data/records.jsonl.`);
    process.exit(2);
  }
  const { lines, manifest } = exportText(fs.readFileSync(ledger, 'utf8'), { upto, sourceName: pathMod.basename(ledger) });
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(pathMod.join(outDir, 'records.jsonl'), lines.join('\n') + (lines.length ? '\n' : ''));
  fs.writeFileSync(pathMod.join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 1) + '\n');

  const pad = (s, n) => String(s).padStart(n);
  console.log(`source: ${ledger}  lines read: ${manifest.source.linesRead}  sha256: ${manifest.source.sha256}`);
  console.log(`\nKEPT ${manifest.records} records (${manifest.txRecords} carry a tx hash), by category:`);
  for (const [k, v] of Object.entries(manifest.keptByCategory)) console.log(`${pad(v, 7)}  ${k}`);
  console.log('\nkept by engine|type:');
  for (const [k, v] of Object.entries(manifest.keptByEngineType)) console.log(`${pad(v, 7)}  ${k}`);
  console.log(`\nDROPPED ${manifest.dropped} lines, by reason:`);
  for (const [k, v] of Object.entries(manifest.droppedByReason)) console.log(`${pad(v, 7)}  ${k}`);
  console.log('\ndropped by engine|type [reason]:');
  for (const [k, v] of Object.entries(manifest.droppedByEngineType)) console.log(`${pad(v, 7)}  ${k}`);
  console.log('\nfields stripped (count of records):');
  for (const [k, v] of Object.entries(manifest.strippedFields)) console.log(`${pad(v, 7)}  ${k}`);
  if (Object.keys(manifest.unclassifiedTypes).length) {
    console.log('\nWARNING unclassified types kept (add them to CATEGORY_OF or TELEMETRY_TYPES):');
    for (const [k, v] of Object.entries(manifest.unclassifiedTypes)) console.log(`${pad(v, 7)}  ${k}`);
  }
  console.log(`\nwrote ${pathMod.relative(process.cwd(), pathMod.join(outDir, 'records.jsonl'))} and manifest.json`);
  console.log('next: node src/chain.mjs build');
}
