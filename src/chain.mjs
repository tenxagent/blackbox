// Hash chain over the exported decision records, Black box v1.
//
//   leaf_i = sha256( utf8( canon(record_i) ) )
//            Each line of data/records.jsonl is already canon(record_i), so a
//            verifier hashes the line bytes as they are.
//   h_0    = sha256( utf8( "blackbox:v1:" + AGENT_ID ) )
//   h_i    = sha256( h_{i-1} || leaf_i )
//            "||" joins the two raw 32-byte digests (64 bytes in), not hex text.
//
// Record i has seq = i (1-based); heads[k] is h_k, so heads[0] is h_0 and
// heads[n] is the final head. A change to any byte of record i changes h_i
// and every later head. Dropping, inserting or reordering records changes the
// head at the first affected position.
//
// Checkpoints mark heads that can be anchored on NEAR. A checkpoint is taken
// after record i (i < n) when i is a multiple of `every`, or when record i+1
// falls in a later UTC hour than record i (by its `row.t`). The last record
// is never a closed checkpoint; it is `final` (the tip).
//
// SHA-256 comes from WebCrypto (globalThis.crypto.subtle), which Node 22 and
// browsers both provide, so web/index.html imports this same file.

import { canon, isCanonicalLine } from './canon.mjs';

export const VERSION = 'blackbox:v1:';
// CAIP-10 account id of the agent wallet on Robinhood Chain (chain id 4663),
// lowercased so the string has one spelling. The fallback when no config is given: `build` takes the agentId from
// blackbox.config.json (or --config), and every reader takes it from checkpoints.json.
export const AGENT_ID = 'eip155:4663:0x00731cd9e0bc7cad1b54f85187b09b942cd3be04';
export const DEFAULT_EVERY = 256;

const enc = new TextEncoder();

export async function sha256(bytes) {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
}

export function toHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function fromHex(hex) {
  if (!/^([0-9a-f]{2})*$/i.test(hex)) throw new Error('bad hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export async function genesis(agentId = AGENT_ID) {
  return sha256(enc.encode(VERSION + agentId));
}

export async function leafOfLine(line) {
  return sha256(enc.encode(line));
}

export async function step(prev, leaf) {
  const buf = new Uint8Array(64);
  buf.set(prev, 0);
  buf.set(leaf, 32);
  return sha256(buf);
}

// Split a records.jsonl text into lines (drops one trailing empty line).
export function splitLines(text) {
  const lines = text.split('\n');
  if (lines.length && lines[lines.length - 1] === '') lines.pop();
  return lines;
}

function hourOf(line) {
  try {
    const t = JSON.parse(line)?.row?.t;
    const ms = Date.parse(t);
    return Number.isFinite(ms) ? Math.floor(ms / 3_600_000) : null;
  } catch {
    return null;
  }
}

function tOf(line) {
  try {
    return JSON.parse(line)?.row?.t ?? null;
  } catch {
    return null;
  }
}

// Build the chain over canonical lines.
export async function buildLines(lines, { agentId = AGENT_ID, every = DEFAULT_EVERY } = {}) {
  const h0 = await genesis(agentId);
  const heads = [toHex(h0)];
  const checkpoints = [];
  let h = h0;
  for (let i = 1; i <= lines.length; i++) {
    h = await step(h, await leafOfLine(lines[i - 1]));
    heads.push(toHex(h));
  }
  const hours = lines.map(hourOf);
  for (let i = 1; i < lines.length; i++) {
    const why = [];
    if (every > 0 && i % every === 0) why.push('count');
    const a = hours[i - 1], b = hours[i];
    if (a !== null && b !== null && b > a) why.push('hour');
    if (why.length) checkpoints.push({ seq: i, t: tOf(lines[i - 1]), head: heads[i], why: why.join('+') });
  }
  const n = lines.length;
  return {
    agentId,
    genesis: heads[0],
    heads,
    checkpoints,
    final: { seq: n, t: n ? tOf(lines[n - 1]) : null, head: heads[n] },
  };
}

// Build from record objects: leaf = sha256(canon(record)).
export async function build(records, opts) {
  return buildLines(records.map((r) => canon(r)), opts);
}

// Compare recomputed heads with claimed heads (claimedHeads[k] = h_k as hex).
// Returns { ok, index, reason }. index is the seq of the first record whose
// head differs (0 means the genesis differs, i.e. another agentId), or -1
// when everything matches.
export async function verifyLines(lines, claimedHeads, { agentId = AGENT_ID } = {}) {
  let h = await genesis(agentId);
  if (toHex(h) !== claimedHeads[0]) return { ok: false, index: 0, reason: 'genesis differs (other agentId or version)' };
  const n = Math.min(lines.length, claimedHeads.length - 1);
  for (let i = 1; i <= n; i++) {
    const line = lines[i - 1];
    h = await step(h, await leafOfLine(line));
    if (toHex(h) !== claimedHeads[i]) {
      let reason = 'head differs: record changed, dropped, inserted or reordered';
      try {
        const seq = JSON.parse(line).seq;
        if (seq !== i) reason = `head differs; line ${i} carries seq ${seq} (record dropped, inserted or reordered)`;
        else if (!isCanonicalLine(line)) reason = 'head differs; line is not canonical JSON (edited by hand?)';
        else reason = 'head differs; record content changed';
      } catch {
        reason = 'head differs; line is not valid JSON';
      }
      return { ok: false, index: i, reason };
    }
  }
  if (lines.length < claimedHeads.length - 1) {
    return { ok: false, index: lines.length + 1, reason: `records end at seq ${lines.length}; claimed heads go to ${claimedHeads.length - 1} (records missing at the end)` };
  }
  if (lines.length > claimedHeads.length - 1) {
    return { ok: false, index: claimedHeads.length, reason: `records after seq ${claimedHeads.length - 1} have no claimed head` };
  }
  return { ok: true, index: -1, reason: 'all heads match' };
}

export async function verify(records, claimedHeads, opts) {
  return verifyLines(records.map((r) => canon(r)), claimedHeads, opts);
}

// Verify against sparse claims: [{seq, head}, ...] (checkpoints, the final
// head, or a head read back from NEAR). Records after the last claim are
// reported as an unclaimed tail, which is normal for a ledger that grows.
// Returns { ok, okThrough, firstBad, reason, claimsChecked }.
export async function verifySparse(lines, claims, { agentId = AGENT_ID } = {}) {
  const sorted = [...claims].sort((a, b) => a.seq - b.seq);
  let h = await genesis(agentId);
  let ci = 0, okThrough = 0, checked = 0;
  while (ci < sorted.length && sorted[ci].seq === 0) {
    if (sorted[ci].head !== toHex(h)) return { ok: false, okThrough: 0, firstBad: { after: 0, upTo: 0 }, reason: 'genesis differs', claimsChecked: checked };
    ci++; checked++;
  }
  for (let i = 1; i <= lines.length && ci < sorted.length; i++) {
    h = await step(h, await leafOfLine(lines[i - 1]));
    while (ci < sorted.length && sorted[ci].seq === i) {
      checked++;
      if (sorted[ci].head !== toHex(h)) {
        return { ok: false, okThrough, firstBad: { after: okThrough, upTo: i }, reason: `head at seq ${i} differs from the claim: something in seq ${okThrough + 1}..${i} changed`, claimsChecked: checked };
      }
      okThrough = i;
      ci++;
    }
  }
  if (ci < sorted.length) {
    // every claim inside the records matched; the rest are heads anchored AHEAD of these records (11-06: the agent anchors a gate
    // decision before it signs, and the records follow at the next publish). Not ok — nothing past the records is checked — but
    // `ahead` lets a reader say so instead of "mismatch"; once the records reach those seqs, a wrong head fails like any other.
    const seqs = [...new Set(sorted.slice(ci).map((c) => c.seq))];
    return { ok: false, okThrough, firstBad: { after: okThrough, upTo: sorted[ci].seq }, ahead: { seqs, recordsEnd: lines.length }, reason: `claim at seq ${sorted[ci].seq} but records end at seq ${lines.length}`, claimsChecked: checked };
  }
  return { ok: true, okThrough, firstBad: null, reason: lines.length > okThrough ? `records ${okThrough + 1}..${lines.length} are after the last claim` : 'all claims match', claimsChecked: checked };
}

// ---------------------------------------------------------------- CLI (Node)
const isMain =
  typeof process !== 'undefined' &&
  process.argv?.[1] &&
  import.meta.url === (await import('node:url')).pathToFileURL((await import('node:path')).resolve(process.argv[1])).href;

if (isMain) await cli(process.argv.slice(2));

async function cli(argv) {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const arg = (name, dflt) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 ? argv[i + 1] : dflt;
  };
  const cmd = argv[0];
  // --dir <data dir> holds records.jsonl, checkpoints.json and heads.txt (default data/); --records etc. override one file
  const dir = path.resolve(arg('dir', path.join(root, 'data')));
  const recordsPath = path.resolve(arg('records', path.join(dir, 'records.jsonl')));
  const cpPath = path.resolve(arg('checkpoints', path.join(dir, 'checkpoints.json')));
  const headsPath = path.resolve(arg('heads', path.join(dir, 'heads.txt')));
  // agentId for h_0: --config <file> (default blackbox.config.json at the repo root), else the AGENT_ID constant
  const agentIdOf = () => {
    const file = arg('config') ? path.resolve(arg('config')) : path.join(root, 'blackbox.config.json');
    if (!fs.existsSync(file)) {
      if (arg('config')) throw new Error(`config not found: ${file}`);
      return AGENT_ID;
    }
    const id = JSON.parse(fs.readFileSync(file, 'utf8')).agentId;
    if (typeof id !== 'string' || !id) throw new Error(`${file}: "agentId" is missing`);
    return id;
  };

  if (cmd === 'build') {
    const text = fs.readFileSync(recordsPath, 'utf8');
    const lines = splitLines(text);
    const every = Number(arg('every', DEFAULT_EVERY));
    const nonCanon = lines.findIndex((l) => !isCanonicalLine(l));
    if (nonCanon >= 0) throw new Error(`line ${nonCanon + 1} of ${recordsPath} is not canonical JSON; re-run src/export.mjs`);
    const res = await buildLines(lines, { every, agentId: agentIdOf() });
    const doc = {
      version: 1,
      scheme: 'leaf=sha256(line); h0=sha256("blackbox:v1:"+agentId); h_i=sha256(h_{i-1}||leaf_i)',
      agentId: res.agentId,
      genesis: res.genesis,
      rule: { every, hourly: true },
      records: lines.length,
      recordsSha256: toHex(await sha256(new TextEncoder().encode(text))),
      final: res.final,
      checkpoints: res.checkpoints,
    };
    fs.writeFileSync(cpPath, JSON.stringify(doc, null, 1) + '\n');
    fs.writeFileSync(headsPath, res.heads.join('\n') + '\n');
    console.log(`agent:       ${res.agentId}`);
    console.log(`records:     ${lines.length}`);
    console.log(`genesis h_0: ${res.genesis}`);
    console.log(`final head:  h_${res.final.seq} = ${res.final.head}  (t ${res.final.t})`);
    console.log(`checkpoints: ${res.checkpoints.length} (every ${every} records or at each UTC hour change)`);
    console.log(`wrote ${path.relative(process.cwd(), cpPath)} and ${path.relative(process.cwd(), headsPath)}`);
    return;
  }

  if (cmd === 'verify') {
    const lines = splitLines(fs.readFileSync(recordsPath, 'utf8'));
    const cp = JSON.parse(fs.readFileSync(cpPath, 'utf8'));
    let failed = false;
    console.log(`agent:            ${cp.agentId}`);
    if (fs.existsSync(headsPath)) {
      const heads = splitLines(fs.readFileSync(headsPath, 'utf8'));
      const r = await verifyLines(lines, heads, { agentId: cp.agentId });
      if (r.ok) console.log(`heads.txt:        OK, all ${lines.length} heads match`);
      else { console.log(`heads.txt:        FIRST MISMATCH at seq ${r.index}: ${r.reason}`); failed = true; }
    }
    const claims = [{ seq: 0, head: cp.genesis }, ...cp.checkpoints, cp.final];
    const s = await verifySparse(lines, claims, { agentId: cp.agentId });
    if (s.ok) console.log(`checkpoints.json: OK through seq ${s.okThrough} (${s.claimsChecked} claims)`);
    else { console.log(`checkpoints.json: chain OK up to seq ${s.okThrough}; ${s.reason}`); failed = true; }
    process.exit(failed ? 1 : 0);
  }

  if (cmd === 'tamper') {
    // Demo helper: copy records.jsonl with ONE character changed in one record.
    const seq = Number(arg('seq', '1'));
    const out = path.resolve(arg('out', '/tmp/blackbox-tampered.jsonl'));
    const lines = splitLines(fs.readFileSync(recordsPath, 'utf8'));
    if (!(seq >= 1 && seq <= lines.length)) throw new Error(`--seq must be 1..${lines.length}`);
    const rec = JSON.parse(lines[seq - 1]);
    const c = rec.src[0];
    rec.src = (c === '0' ? '1' : '0') + rec.src.slice(1); // one hex digit of the source-line hash
    lines[seq - 1] = canon(rec);
    fs.writeFileSync(out, lines.join('\n') + '\n');
    console.log(`wrote ${out}: seq ${seq} has one changed character in "src"`);
    console.log(`now run: node src/chain.mjs verify --records ${out}`);
    return;
  }

  console.log('usage: node src/chain.mjs build [--dir data] [--config blackbox.config.json] [--every 256]');
  console.log('       node src/chain.mjs verify [--dir data] [--records data/records.jsonl]');
  console.log('       node src/chain.mjs tamper --seq N [--out /tmp/blackbox-tampered.jsonl]');
  process.exit(cmd ? 1 : 0);
}
