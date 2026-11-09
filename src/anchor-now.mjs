// Anchor BEFORE a send (2026-11-06; asked publicly: "can the action happen before the log is committed?").
// The cycle (src/cycle.mjs) anchors a few times a day, so on its own a payment could be signed hours before its decision is on NEAR.
// For a gated money send the operator's wrapper runs this between the gate's allow and the signature:
//   1. export the ledger to a TEMP dir (no git, no commit), build + verify the chain there;
//   2. check that the published records are a byte-for-byte prefix of that export (so the next cycle's records hash to the same head);
//   3. find the decision record by --include-src (sha256 of its raw ledger line, the record's `src` field);
//   4. anchor the head on SocialDB AND on the locked registry; records_url = main (not a commit: these records are not published yet;
//      the next cycle publishes them, and the page shows "anchored ahead of the published records" until it does);
//   5. read both back. Any failure ⇒ exit 1 and the wrapper must not sign.
// It prints one JSON line {ok, action:"anchor_before_send", seq, head, decision_seq, socialdb_tx, registry_tx, registry_time}.
//
//   BLACKBOX_LEDGER=<ledger.jsonl> node src/anchor-now.mjs --include-src <64 hex>                       dry: export + checks, no network writes
//   <SocialDB key json on stdin> | BLACKBOX_LEDGER=… BLACKBOX_REGISTRY_KEY_FILE=<file|/dev/fd/N> \
//     node src/anchor-now.mjs --include-src <64 hex> --send --i-understand-mainnet                        anchor for real (mainnet)
//
// The operator runs it under the same lock as the cycle (two anchoring jobs at once would race the key nonce and the registry's
// strictly increasing seq), with a bounded wait; a lock timeout is a refusal too.
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO_RAW_MAIN = 'https://raw.githubusercontent.com/tenxagent/blackbox/main/data/records.jsonl';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** The published records must be a byte prefix of the fresh export (whole lines), else the anchor would not match what the next
 *  cycle publishes. Pure; unit-tested. Returns null when it extends, else the reason. */
export function prefixProblem(publishedText, freshText) {
  if (!freshText.startsWith(publishedText)) {
    const a = publishedText.split('\n'), b = freshText.split('\n');
    let i = 0; while (i < a.length && a[i] === b[i]) i++;
    return `the fresh export differs from the published records at line ${i + 1}: the next cycle would not match this anchor`;
  }
  if (publishedText.length && !publishedText.endsWith('\n')) return 'published records do not end with a newline';
  return null;
}

/** The record whose `src` (sha256 of its raw ledger line) is `src`. Pure; unit-tested. */
export function findBySrc(lines, src) {
  if (!/^[0-9a-f]{64}$/.test(String(src))) throw new Error('--include-src must be 64 lowercase hex (sha256 of the raw ledger line)');
  for (const l of lines) { const r = JSON.parse(l); if (r.src === src) return r; }
  return null;
}

/** What the registry already holds decides whether to write: same seq + head = already anchored; a higher seq = refuse
 *  (the registry only takes a strictly increasing seq). Pure; unit-tested. */
export function registryPlan(newest, seq, head) {
  if (!newest || newest.seq < seq) return 'write';
  if (newest.seq === seq && newest.head === head) return 'already';
  return `registry already holds seq ${newest.seq}${newest.seq === seq ? ' with another head' : ''} ≥ ${seq}`;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const argv = process.argv.slice(2);
  const has = (f) => argv.includes(`--${f}`);
  const opt = (k, d) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : d; };
  const out = (o) => { console.log(JSON.stringify({ action: 'anchor_before_send', ...o })); process.exit(o.ok ? 0 : 1); };
  const refuse = (why, extra = {}) => out({ ok: false, why, ...extra });
  const SEND = has('send');
  const CONFIG = path.resolve(opt('config', path.join(ROOT, 'blackbox.config.json')));
  const LEDGER = process.env.BLACKBOX_LEDGER;
  if (!LEDGER) refuse('set BLACKBOX_LEDGER to the ledger file');
  if (SEND && !has('i-understand-mainnet')) refuse('refusing to send on mainnet without --i-understand-mainnet');
  if (SEND && !process.env.BLACKBOX_REGISTRY_KEY_FILE) refuse('set BLACKBOX_REGISTRY_KEY_FILE (the registry anchor key): both anchors are required');
  const key = SEND ? fs.readFileSync(0, 'utf8') : null;
  const account = key ? JSON.parse(key).account_id : opt('account');
  const node = (args, o = {}) => execFileSync(process.execPath, args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 << 20, timeout: 120_000, ...o });

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-now-'));
  process.on('exit', () => fs.rmSync(tmp, { recursive: true, force: true }));   // process.exit skips finally blocks; exit handlers run
  {
    try {
      node(['src/export.mjs', '--config', CONFIG, '--ledger', LEDGER, '--out', tmp]);
      node(['src/chain.mjs', 'build', '--dir', tmp, '--config', CONFIG]);
      node(['src/chain.mjs', 'verify', '--dir', tmp]);
    } catch (e) { refuse(`export/build/verify failed: ${String(e.stderr || e.message).trim().split('\n').pop().slice(0, 200)}`); }
    const fresh = fs.readFileSync(path.join(tmp, 'records.jsonl'), 'utf8');
    const pp = prefixProblem(fs.readFileSync(path.join(ROOT, 'data', 'records.jsonl'), 'utf8'), fresh);
    if (pp) refuse(pp);
    const lines = fresh.split('\n').filter(Boolean);
    let dec;
    try { dec = findBySrc(lines, opt('include-src')); } catch (e) { refuse(e.message); }
    if (!dec) refuse('the decision is not in the export (its ledger line was not written, or the filter drops it)');
    const fin = JSON.parse(fs.readFileSync(path.join(tmp, 'checkpoints.json'), 'utf8')).final;
    const base = { seq: fin.seq, head: fin.head, decision_seq: dec.seq, decision: dec.row?.action ?? dec.cat, records_url: REPO_RAW_MAIN };
    if (!SEND) out({ ok: true, dry: true, ...base });

    // registry state first: a head it already holds at a higher seq would make the write fail after the SocialDB one
    const rpc = await import('./near/rpc.mjs');
    const { REGISTRY } = await import('./registry-cli.mjs');
    const { readAllAnchors } = await import('./registry.mjs');
    const url = rpc.rpcUrl('mainnet');
    const view = (m, a) => rpc.callFunction(url, REGISTRY, m, a);
    const before = (await readAllAnchors(view, account)).at(-1) ?? null;
    const plan = registryPlan(before, fin.seq, fin.head);
    if (plan !== 'write' && plan !== 'already') refuse(plan, base);
    // 11-09: NEAR charges a tx's prepaid gas up front at a pessimistic price, so the SocialDB set (40 Tgas) and the registry anchor
    // (30 Tgas) sent back to back need about 0.07 NEAR liquid at once, although each burns far less. Below that the registry send is
    // rejected (NotEnoughBalance) after SocialDB was already written; refuse first, with the reason.
    const acct = await rpc.viewAccount(url, account), liquid = Number(BigInt(acct.amount) - BigInt(acct.storage_usage) * 10n ** 19n) / 1e24;
    if (liquid < 0.075) refuse(`NEAR balance too low to prepay the anchor gas: ${liquid.toFixed(4)} NEAR liquid, about 0.075 needed (top up the account, or withdraw unused SocialDB storage)`, base);

    const s = spawnSync(process.execPath, ['src/anchor.mjs', '--dir', tmp, '--network', 'mainnet', '--send', '--i-understand-mainnet', '--records-url', REPO_RAW_MAIN],
      { cwd: ROOT, encoding: 'utf8', input: key, env: { ...process.env, BLACKBOX_NEAR_KEY_FILE: '-' }, timeout: 180_000 });
    const sent = s.stdout.match(/^SENT (\w+): (.*)$/m) ?? [];
    if (sent[2] !== 'success') refuse(`SocialDB anchor not confirmed: ${(sent[2] ?? String(s.stderr || s.stdout).trim().split('\n').pop() ?? '').slice(0, 200)}`, base);
    let regTx = null;
    if (plan === 'write') {
      // 11-09: one retry, as in cycle.mjs. A send that throws (RPC transport/timeout, 03:19Z) may still land, so the registry is
      // read back first; only if this seq is not there is the anchor sent again.
      const once = () => spawnSync(process.execPath, ['src/registry-cli.mjs', 'anchor', '--dir', tmp, '--records-url', REPO_RAW_MAIN, '--send', '--i-understand-mainnet'],
        { cwd: ROOT, encoding: 'utf8', input: fs.readFileSync(process.env.BLACKBOX_REGISTRY_KEY_FILE, 'utf8'), env: { ...process.env, BLACKBOX_NEAR_KEY_FILE: '-' }, timeout: 120_000 });
      const okOf = (r) => { const line = (r.stdout || '').split('\n').reverse().find((l) => l.includes('"action":"registry_anchor"')); return line ? JSON.parse(line) : null; };
      // keep the thrown error's line, not node's trailing "Node.js vX" line (a crash printed only that, 03:19Z)
      const errLine = (r) => { const t = String(r.stderr || r.stdout || r.error || '').trim().split('\n').filter((l) => l.trim() && !/^Node\.js v\d/.test(l.trim())); return (t.find((l) => /^\s*\w*Error:/.test(l)) ?? t.find((l) => /refus|fail|panic|Exceeded|NotEnough/i.test(l)) ?? t.pop() ?? '').trim(); };
      let r = once(), res = okOf(r);
      if (!res?.ok) {
        const first = res?.err ?? errLine(r);
        await new Promise((ok) => setTimeout(ok, 15_000));
        const top = (await readAllAnchors(view, account)).at(-1);
        if (top && top.seq === fin.seq && top.head === fin.head) res = { ok: true, near_tx: null, note: `attempt 1 landed (${first.slice(0, 120)})` };
        else { r = once(); res = okOf(r); if (!res?.ok) refuse(`registry anchor failed twice: ${first.slice(0, 150)} | ${(res?.err ?? errLine(r)).slice(0, 150)}`, { ...base, socialdb_tx: sent[1] }); }
      }
      regTx = res.near_tx;
    }
    // read both back: the registry is what a later check (flows: not_anchored_before_send) compares with the send's block time
    const { readAnchor } = await import('./anchor.mjs');
    const sd = await readAnchor(url, 'social.near', account);
    const reg = (await readAllAnchors(view, account)).at(-1);
    if (!sd || sd.seq !== fin.seq || sd.head !== fin.head) refuse(`SocialDB read-back shows seq ${sd?.seq}, not ${fin.seq}`, { ...base, socialdb_tx: sent[1], registry_tx: regTx });
    if (!reg || reg.seq !== fin.seq || reg.head !== fin.head) refuse(`registry read-back shows seq ${reg?.seq}, not ${fin.seq}`, { ...base, socialdb_tx: sent[1], registry_tx: regTx });
    out({ ok: true, ...base, socialdb_tx: sent[1], registry_tx: regTx, registry_block: reg.blockHeight, registry_time: reg.time });
  }
}
