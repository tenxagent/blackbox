// Exporter: an agent's raw JSONL ledger -> records.jsonl (decision records only) + manifest.json.
//
//   node src/export.mjs [--config blackbox.config.json] [--ledger <ledger.jsonl>] [--upto N] [--out data]
//
// Operator-only step: it needs the private ledger (--ledger or BLACKBOX_LEDGER).
// Judges start from the committed data/records.jsonl.
//
// The code here is generic. Every rule that belongs to one agent (which types are telemetry, which category a
// type gets, which engines and addresses are private, which field names are sensitive or bulky, where tx hashes
// are) comes from a JSON config file. The default, blackbox.config.json at the repository root, holds the rules
// of claude-10x; examples/minimal-agent/ has a small config for a made-up agent. loadConfig() lists every field.
//
// The output is deterministic: the same ledger lines and the same config always give byte-identical
// records.jsonl and manifest.json (no clocks, no randomness). Only complete lines (ending in "\n") are read, so a
// ledger that is being appended to is safe to export. The config's filterVersion is written into the manifest:
// change it whenever a rule (or this code) changes the output. Then seq numbers can change, and heads anchored
// before the change no longer match: re-anchor.
//
// Each source line goes through these steps, in this order:
//
//   1. PARSE      a line that is not a JSON object is dropped ("unparseable").
//   2. PRIVACY    rows whose engine is in config.privacyEngines are dropped ("privacy:engine-<engine>"). Every
//                 0x-address (0x + 40 hex, not part of a longer hex string) in the raw line is lowercased and
//                 hashed with sha256; if any hash is in the config's excludedAddressHashesFile the row is
//                 dropped ("privacy:operator-wallet"). That list holds the operator's personal wallets, which are
//                 not the agent's; it stores hashes only, so the addresses themselves are not published.
//   3. DECISION   rows whose type matches config.telemetryTypes are dropped: they are observations, heartbeats
//                 or transport noise, not decisions. Every other row is kept. config.categories gives it a
//                 category: exact type names first, then patterns ("*" globs, or {type, action, engine}
//                 objects) in file order. A row that matches nothing is kept as "unclassified" and its type is
//                 listed in the manifest, so a new decision type is never lost silently.
//   4. REDACT     rows of an engine in config.reduceEngines are reduced to that engine's field list. In every
//                 kept row, at any depth, a field is removed when its name matches config.sensitiveFieldName,
//                 except the exact names in config.publicChainFieldNames when the value is an address or an
//                 integer id (public chain data). Fields named in config.bulkyFieldNames are removed. With
//                 config.redactLocalPaths, a local path inside a string (an absolute path or file:// URL whose
//                 first segment is in config.localPathRoots) becomes "<path>" and the field is kept. Tx hashes and
//                 contract addresses are kept on purpose: they are public chain data and they are what lets
//                 anyone check the record against the chain.
//   5. WRAP       the record is
//                   { seq, line, src, cat, txs, stripped, row }
//                 seq      1-based position among kept records (the chain index)
//                 line     1-based line number in the source ledger
//                 src      sha256 of the raw source line (UTF-8, no newline): the
//                          operator can reveal the line later and anyone can check
//                          it was filtered, not invented
//                 cat      category from step 3
//                 txs      tx hashes found in config.txHashFields (one hash each) and config.txHashListFields
//                          (lists of hashes), lowercased
//                 stripped paths of the fields removed in step 4 (names only)
//                 row      the source row minus the removed fields
//                 and is written as one canonical JSON line (src/canon.mjs).

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canon } from './canon.mjs';

// Default filterVersion when a config does not name one. v2 = v1 + local paths inside strings redacted.
export const FILTER_VERSION = 'blackbox-filter-v2';
export const DEFAULT_CONFIG_FILE = fileURLToPath(new URL('../blackbox.config.json', import.meta.url));

// 0x + 40 hex, not inside a longer hex/word token (so a 64-hex tx hash never matches).
export const ADDRESS_IN_TEXT = /(?<![0-9A-Za-z])0[xX][0-9a-fA-F]{40}(?![0-9A-Za-z])/g;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const INTEGER = /^[0-9]{1,78}$/;
const TX_HASH = /^0x[0-9a-fA-F]{64}$/;
const CAIP10 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$/;

// ---------------------------------------------------------------- config
//
// Fields (only agentId is required):
//   agentId                    CAIP-10 id of the wallet whose decisions are recorded (src/chain.mjs build uses it
//                              for h_0), e.g. "eip155:4663:0x0073…be04"
//   filterVersion              label written into the manifest (default FILTER_VERSION)
//   telemetryTypes             { "<type or *-glob>": "why it is not a decision" }: rows dropped in step 3
//   observedTxTypes            { "<type>": "why" }: rows KEPT, but their tx hashes are someone else's (a watcher saw them),
//                              so they are not listed in rec.txs and rh-proof does not claim them for the agent (default {})
//   categories                 { "<category>": [ "<type>" | "<*-glob on type>" | {type?, action?, engine?} ] }
//   privacyEngines             [ "<engine>" ] or { "<engine>": "why" }: rows dropped in step 2
//   excludedAddressHashesFile  path (relative to the config file) of {"sha256": [64-hex, ...]}, or null (default)
//   reduceEngines              { "<engine>": [ "<field kept>", ... ] }
//   sensitiveFieldName         "/regex/flags" matched against field names
//                              (default "/token|key|secret|email|cookie|auth|password|session/i")
//   publicChainFieldNames      [ names ] or { name: why }: sensitive-looking names kept for address/integer values
//                              (default token, tokenId, tokenIds, tokens)
//   bulkyFieldNames            [ names ] or { name: why }: always removed (default none)
//   txHashFields               fields holding one tx hash (default ["tx", "hash"])
//   txHashListFields           fields holding a list of tx hashes (default ["txs"])
//   redactLocalPaths           true (default) or false
//   localPathRoots             first path segments treated as local (default root home tmp var etc usr opt run)
//   comment                    free text, ignored
// Any other field is an error, so a misspelt rule can never be skipped silently.

const CONFIG_FIELDS = new Set(['comment', 'agentId', 'filterVersion', 'telemetryTypes', 'observedTxTypes', 'categories', 'privacyEngines',
  'excludedAddressHashesFile', 'reduceEngines', 'sensitiveFieldName', 'publicChainFieldNames', 'bulkyFieldNames',
  'txHashFields', 'txHashListFields', 'redactLocalPaths', 'localPathRoots']);
const RULE_FIELDS = ['type', 'action', 'engine'];
const DEFAULTS = {
  sensitiveFieldName: '/token|key|secret|email|cookie|auth|password|session/i',
  publicChainFieldNames: ['token', 'tokenId', 'tokenIds', 'tokens'],
  txHashFields: ['tx', 'hash'],
  txHashListFields: ['txs'],
  localPathRoots: ['root', 'home', 'tmp', 'var', 'etc', 'usr', 'opt', 'run'],
};

const isPlain = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&');
const globRe = (g) => new RegExp('^' + g.split('*').map(escapeRe).join('.*') + '$', 's');

function names(v, field, where) {
  if (v === undefined) return undefined;
  const list = Array.isArray(v) ? v : isPlain(v) ? Object.keys(v) : null;
  if (!list || !list.every((x) => typeof x === 'string' && x !== '')) throw new Error(`${where}: "${field}" must be a list of names or an object keyed by name`);
  return list;
}

function regexOf(s, where) {
  const m = typeof s === 'string' && /^\/(.+)\/([a-z]*)$/s.exec(s);
  if (!m) throw new Error(`${where}: "sensitiveFieldName" must look like "/regex/flags"`);
  if (/[gy]/.test(m[2])) throw new Error(`${where}: "sensitiveFieldName" must not use the g or y flag (stateful .test)`);
  return new RegExp(m[1], m[2]);
}

// Validate a parsed config object and turn it into the rules the exporter applies.
// baseDir resolves excludedAddressHashesFile; name is used in error messages.
export function compileConfig(json, { baseDir = process.cwd(), name = 'config' } = {}) {
  if (!isPlain(json)) throw new Error(`${name}: must be a JSON object`);
  for (const k of Object.keys(json)) if (!CONFIG_FIELDS.has(k)) throw new Error(`${name}: unknown field "${k}"`);
  const { agentId } = json;
  if (typeof agentId !== 'string' || !CAIP10.test(agentId)) throw new Error(`${name}: "agentId" must be a CAIP-10 account id like "eip155:1:0x…"`);
  const filterVersion = json.filterVersion ?? FILTER_VERSION;
  if (typeof filterVersion !== 'string' || !filterVersion) throw new Error(`${name}: "filterVersion" must be a non-empty string`);

  const telemetryTypes = json.telemetryTypes ?? {};
  if (!isPlain(telemetryTypes) || !Object.entries(telemetryTypes).every(([k, v]) => k !== '' && typeof v === 'string')) {
    throw new Error(`${name}: "telemetryTypes" must be an object {"<type>": "<why it is not a decision>"}`);
  }
  const telemetryGlobs = Object.keys(telemetryTypes).filter((k) => k.includes('*')).map(globRe);
  const observedTxTypes = json.observedTxTypes ?? {};
  if (!isPlain(observedTxTypes) || !Object.entries(observedTxTypes).every(([k, v]) => k !== '' && !k.includes('*') && typeof v === 'string')) {
    throw new Error(`${name}: "observedTxTypes" must be an object {"<exact type>": "<why the tx is not the agent's>"}`);
  }

  const categories = json.categories ?? {};
  if (!isPlain(categories)) throw new Error(`${name}: "categories" must be an object {"<category>": [rules]}`);
  const catExact = Object.create(null);
  const catPatterns = [];
  for (const [cat, rules] of Object.entries(categories)) {
    if (cat === '' || cat === 'unclassified') throw new Error(`${name}: category name ${JSON.stringify(cat)} is reserved`);
    if (!Array.isArray(rules)) throw new Error(`${name}: categories.${cat} must be a list`);
    for (const r of rules) {
      if (typeof r === 'string' && r !== '' && !r.includes('*')) {
        if (r in catExact) throw new Error(`${name}: type "${r}" is in two categories (${catExact[r]}, ${cat})`);
        if (Object.hasOwn(telemetryTypes, r)) throw new Error(`${name}: type "${r}" is both telemetry and category ${cat}`);
        catExact[r] = cat;
      } else if (typeof r === 'string' && r !== '') {
        catPatterns.push({ cat, fields: [['type', globRe(r)]] });
      } else if (isPlain(r) && Object.keys(r).length && Object.entries(r).every(([k, v]) => RULE_FIELDS.includes(k) && typeof v === 'string' && v !== '')) {
        catPatterns.push({ cat, fields: Object.entries(r).map(([k, v]) => [k, globRe(v)]) });
      } else {
        throw new Error(`${name}: categories.${cat}: a rule is a type name, a "*" glob, or an object with type/action/engine strings; got ${JSON.stringify(r)}`);
      }
    }
  }

  const reduceEngines = json.reduceEngines ?? {};
  if (!isPlain(reduceEngines) || !Object.values(reduceEngines).every((l) => Array.isArray(l) && l.every((x) => typeof x === 'string' && x !== ''))) {
    throw new Error(`${name}: "reduceEngines" must be an object {"<engine>": ["<field kept>", ...]}`);
  }

  let excludedFile = null, excludedLabel = null;
  if (json.excludedAddressHashesFile != null) {
    if (typeof json.excludedAddressHashesFile !== 'string' || !json.excludedAddressHashesFile) throw new Error(`${name}: "excludedAddressHashesFile" must be a path or null`);
    excludedLabel = json.excludedAddressHashesFile;
    excludedFile = path.resolve(baseDir, excludedLabel);
  }

  const redactLocalPaths = json.redactLocalPaths ?? true;
  if (typeof redactLocalPaths !== 'boolean') throw new Error(`${name}: "redactLocalPaths" must be true or false`);
  const roots = names(json.localPathRoots, 'localPathRoots', name) ?? DEFAULTS.localPathRoots;
  if (!roots.every((r) => /^[A-Za-z0-9_.-]+$/.test(r))) throw new Error(`${name}: "localPathRoots" entries are single path segments`);
  if (redactLocalPaths && !roots.length) throw new Error(`${name}: "localPathRoots" is empty but redactLocalPaths is on`);

  return {
    name,
    agentId,
    filterVersion,
    telemetryTypes,
    telemetryGlobs,
    observedTxTypes,
    catExact,
    catPatterns,
    privacyEngines: new Set(names(json.privacyEngines, 'privacyEngines', name) ?? []),
    excludedFile,
    excludedLabel,
    reduceEngines,
    sensitiveName: regexOf(json.sensitiveFieldName ?? DEFAULTS.sensitiveFieldName, name),
    publicChainNames: new Set(names(json.publicChainFieldNames, 'publicChainFieldNames', name) ?? DEFAULTS.publicChainFieldNames),
    bulkyNames: new Set(names(json.bulkyFieldNames, 'bulkyFieldNames', name) ?? []),
    txHashFields: names(json.txHashFields, 'txHashFields', name) ?? DEFAULTS.txHashFields,
    txHashListFields: names(json.txHashListFields, 'txHashListFields', name) ?? DEFAULTS.txHashListFields,
    // not inside a URL or word
    localPath: redactLocalPaths
      ? new RegExp(String.raw`(?<![\w.:\/-])(?:file:\/\/)?\/(?:` + roots.map(escapeRe).join('|') + String.raw`)\/[^\s"'),:]*`, 'g')
      : null,
  };
}

export function loadConfig(file = DEFAULT_CONFIG_FILE) {
  const abs = path.resolve(file);
  let json;
  try {
    json = JSON.parse(readFileSync(abs, 'utf8'));
  } catch (e) {
    throw new Error(`cannot read config ${abs}: ${e.message}`);
  }
  return compileConfig(json, { baseDir: path.dirname(abs), name: path.basename(abs) });
}

// The default config is loaded once at import (if the file is there); everything below falls back to it.
const DEFAULT = existsSync(DEFAULT_CONFIG_FILE) ? loadConfig(DEFAULT_CONFIG_FILE) : null;
export function defaultConfig() {
  if (!DEFAULT) throw new Error(`no ${DEFAULT_CONFIG_FILE}; pass a config (--config <file>)`);
  return DEFAULT;
}
// The default config's rules, for callers that imported these names before the rules moved into the config.
export const SENSITIVE_NAME = DEFAULT?.sensitiveName;
export const PUBLIC_CHAIN_NAMES = DEFAULT?.publicChainNames;
export const BULKY_NAMES = DEFAULT?.bulkyNames;
export const EXCLUDED_HASHES_FILE = DEFAULT?.excludedFile ?? null;

// ---------------------------------------------------------------- privacy: excluded addresses

// sha256 hex of the lowercased 0x-address string (UTF-8).
export function addressHash(address) {
  return createHash('sha256').update(address.toLowerCase(), 'utf8').digest('hex');
}

// Loads an exclusion list; a missing or malformed list is an error, never "no exclusions".
export function loadExcludedHashes(file = EXCLUDED_HASHES_FILE) {
  if (!file) throw new Error('no excluded-address-hashes file given');
  const j = JSON.parse(readFileSync(file, 'utf8'));
  const list = j.sha256;
  if (!Array.isArray(list) || !list.every((h) => /^[0-9a-f]{64}$/.test(h))) throw new Error(`${path.basename(String(file))}: "sha256" must be a list of 64-hex strings`);
  return new Set(list);
}

// The exclusion set of a config (empty when the config names no file). Loaded once per config.
const excludedCache = new WeakMap();
export function excludedOf(config) {
  if (!excludedCache.has(config)) excludedCache.set(config, config.excludedFile ? loadExcludedHashes(config.excludedFile) : new Set());
  return excludedCache.get(config);
}
export const defaultExcluded = () => excludedOf(defaultConfig());

export function mentionsExcludedAddress(rawLine, excluded) {
  for (const m of rawLine.matchAll(ADDRESS_IN_TEXT)) if (excluded.has(addressHash(m[0]))) return true;
  return false;
}

// ---------------------------------------------------------------- rules

function isPublicChainValue(v) {
  if (Array.isArray(v)) return v.every(isPublicChainValue);
  if (typeof v === 'number') return Number.isInteger(v) && v >= 0;
  return typeof v === 'string' && (ADDRESS.test(v) || INTEGER.test(v));
}

function isTelemetry(row, cfg) {
  if (Object.hasOwn(cfg.telemetryTypes, row.type)) return true;
  return typeof row.type === 'string' && cfg.telemetryGlobs.some((re) => re.test(row.type));
}

export function categoryOf(row, cfg = defaultConfig()) {
  if (Object.hasOwn(cfg.catExact, row.type)) return cfg.catExact[row.type];
  for (const p of cfg.catPatterns) {
    if (p.fields.every(([k, re]) => typeof row[k] === 'string' && re.test(row[k]))) return p.cat;
  }
  return 'unclassified';
}

function redactInto(value, p, stripped, cfg) {
  if (Array.isArray(value)) return value.map((v, i) => redactInto(v, `${p}[${i}]`, stripped, cfg));
  // v2 (2026-10-31): a local path inside a string (e.g. a stack trace in an error row) becomes "<path>"; the field is kept
  if (typeof value === 'string') {
    if (!cfg.localPath) return value;
    const r = value.replace(cfg.localPath, '<path>');
    if (r !== value) stripped.push(p + '~path');
    return r;
  }
  if (value === null || typeof value !== 'object') return value;
  const out = {};
  for (const k of Object.keys(value)) {
    const q = p ? `${p}.${k}` : k;
    const v = value[k];
    if (cfg.bulkyNames.has(k)) { stripped.push(q); continue; }
    if (cfg.sensitiveName.test(k) && !(cfg.publicChainNames.has(k) && isPublicChainValue(v))) { stripped.push(q); continue; }
    out[k] = redactInto(v, q, stripped, cfg);
  }
  return out;
}

// Remove sensitive and bulky fields at every depth. Returns [clean, strippedPaths].
export function redact(value, cfg = defaultConfig()) {
  const stripped = [];
  return [redactInto(value, '', stripped, cfg), stripped];
}

export function txHashesOf(row, cfg = defaultConfig()) {
  const found = [];
  const add = (h) => { if (typeof h === 'string' && TX_HASH.test(h)) found.push(h.toLowerCase()); };
  for (const f of cfg.txHashFields) add(row[f]);
  for (const f of cfg.txHashListFields) if (Array.isArray(row[f])) row[f].forEach(add);
  return [...new Set(found)];
}

// Decide what happens to one source line. Pure; used by the tests.
export function classify(rawLine, excluded, cfg = defaultConfig()) {
  excluded ??= excludedOf(cfg);
  let row;
  try {
    row = JSON.parse(rawLine);
  } catch {
    return { keep: false, reason: 'unparseable' };
  }
  if (row === null || typeof row !== 'object' || Array.isArray(row)) return { keep: false, reason: 'unparseable' };
  if (cfg.privacyEngines.has(row.engine)) return { keep: false, reason: `privacy:engine-${row.engine}`, row };
  if (mentionsExcludedAddress(rawLine, excluded)) return { keep: false, reason: 'privacy:operator-wallet', row };
  if (isTelemetry(row, cfg)) return { keep: false, reason: `telemetry:${row.type}`, row };
  const cat = categoryOf(row, cfg);
  let base = row;
  const stripped = [];
  if (typeof row.engine === 'string' && Object.hasOwn(cfg.reduceEngines, row.engine)) {
    const keep = cfg.reduceEngines[row.engine];
    base = {};
    for (const k of Object.keys(row)) {
      if (keep.includes(k)) base[k] = row[k];
      else stripped.push(k);
    }
  }
  const clean = redactInto(base, '', stripped, cfg);
  const txs = Object.hasOwn(cfg.observedTxTypes, row.type) ? [] : txHashesOf(clean, cfg);
  return { keep: true, cat, row: clean, stripped, txs };
}

const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const keyOf = (row) => `${row?.engine ?? '(none)'}|${row?.type ?? '(none)'}`;
const bump = (obj, k, n = 1) => { obj[k] = (obj[k] || 0) + n; };
const sortObj = (o) => Object.fromEntries(Object.entries(o).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)));

// Export a ledger text. Returns { lines: [canonical record lines], manifest }.
export function exportText(text, { upto = Infinity, sourceName = 'ledger.jsonl', config = defaultConfig(), excluded = excludedOf(config) } = {}) {
  const cfg = config;
  const end = text.lastIndexOf('\n') + 1; // complete lines only
  const body = text.slice(0, end);
  const raw = body.split('\n');
  raw.pop();
  const take = Math.min(raw.length, upto);
  const out = [];
  const kept = {}, dropped = {}, cats = {}, strippedNames = {}, unclassified = {};
  const reasons = {}; // privacy reasons are always listed, even at 0
  for (const e of cfg.privacyEngines) reasons[`privacy:engine-${e}`] = 0;
  reasons['privacy:operator-wallet'] = 0;
  let firstT = null, lastT = null, txRecords = 0;
  for (let i = 0; i < take; i++) {
    const rawLine = raw[i];
    if (rawLine.trim() === '') { bump(reasons, 'blank'); continue; }
    const d = classify(rawLine, excluded, cfg);
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
  // The rules block keeps the shape of filter v2 (byte-identical manifests for the existing agent). The config
  // file is the full statement of the rules; categories, tx-hash fields and path roots are not repeated here.
  const rules = {
    privacyEngines: [...cfg.privacyEngines],
    excludedAddresses: cfg.excludedLabel === null && excluded.size === 0
      ? 'none (the config names no excludedAddressHashesFile)'
      : `rows that contain a 0x-address whose sha256(lowercase address) is listed in ${cfg.excludedLabel ?? 'the given set'} (${excluded.size} hashes)`,
    telemetryTypes: cfg.telemetryTypes,
    sensitiveFieldName: String(cfg.sensitiveName),
    publicChainFieldNames: [...cfg.publicChainNames],
    bulkyFieldNames: [...cfg.bulkyNames],
  };
  if (Object.keys(cfg.observedTxTypes).length) rules.observedTxTypes = cfg.observedTxTypes;   // only when used: v2 manifests stay byte-identical
  for (const [engine, keep] of Object.entries(cfg.reduceEngines)) rules[`${engine}RowsKeep`] = keep;
  const manifest = {
    filterVersion: cfg.filterVersion,
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
    rules,
  };
  return { lines: out, manifest };
}

// ---------------------------------------------------------------- CLI
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const fs = await import('node:fs');
  const argv = process.argv.slice(2);
  const arg = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : d; };
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const configFile = arg('config') ? path.resolve(arg('config')) : DEFAULT_CONFIG_FILE;
  let config;
  try {
    config = loadConfig(configFile);
  } catch (e) {
    console.error(e.message);
    process.exit(2);
  }
  const ledger = arg('ledger', process.env.BLACKBOX_LEDGER || 'ledger.jsonl');
  const outDir = path.resolve(arg('out', path.join(root, 'data')));
  const upto = arg('upto') ? Number(arg('upto')) : Infinity;
  if (!fs.existsSync(ledger)) {
    console.error(`ledger not found: ${ledger}\nThis step needs the agent's private ledger. Judges: skip it and use the committed data/records.jsonl.`);
    process.exit(2);
  }
  const { lines, manifest } = exportText(fs.readFileSync(ledger, 'utf8'), { upto, sourceName: path.basename(ledger), config });
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'records.jsonl'), lines.join('\n') + (lines.length ? '\n' : ''));
  fs.writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 1) + '\n');

  const pad = (s, n) => String(s).padStart(n);
  console.log(`config: ${path.relative(process.cwd(), configFile) || configFile}  agent: ${config.agentId}  filter: ${config.filterVersion}  sha256: ${sha256hex(fs.readFileSync(configFile, 'utf8'))}`);
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
    console.log(`\nWARNING unclassified types kept (add them to "categories" or "telemetryTypes" in ${config.name}):`);
    for (const [k, v] of Object.entries(manifest.unclassifiedTypes)) console.log(`${pad(v, 7)}  ${k}`);
  }
  console.log(`\nwrote ${path.relative(process.cwd(), path.join(outDir, 'records.jsonl'))} and manifest.json`);
  console.log('next: node src/chain.mjs build' + (arg('config') ? ` --config ${arg('config')}` : '') + (arg('out') ? ` --dir ${arg('out')}` : ''));
}
