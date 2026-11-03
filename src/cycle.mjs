// Operator cycle, run a few times a day: re-export the ledger, rebuild and verify the chain, refresh the Robinhood Chain proof,
// run every test, commit the data, then anchor the new head on NEAR mainnet with records_url pinned to that exact commit (so the
// anchored URL always serves the records that hash to the anchored head). Nothing new in the ledger ⇒ nothing is committed or sent.
//
//   node src/cycle.mjs                         dry: exports to a temp dir and reports what an anchor would cover
//   <key json on stdin> | node src/cycle.mjs --send     commit + anchor (mainnet)
//
// The NEAR key ({"account_id","private_key"}) is read from stdin and handed to anchor.mjs on its stdin (key file "-"): never on disk.
// It anchors whenever the seq anchored on chain is behind the committed head, so a failed anchor is retried on the next run.
// The ledger path comes from BLACKBOX_LEDGER (operator-only, like src/export.mjs). Refuses on a dirty working tree.
// --config <file> (default blackbox.config.json) is passed to export.mjs and chain.mjs build: the filter rules and the agentId.
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SEND = process.argv.includes('--send');
const CONFIG = path.resolve(process.argv.includes('--config') ? process.argv[process.argv.indexOf('--config') + 1] : path.join(ROOT, 'blackbox.config.json'));
const LEDGER = process.env.BLACKBOX_LEDGER || 'ledger.jsonl'   // the operator sets BLACKBOX_LEDGER; no server path in the public code;
const REPO_RAW = 'https://raw.githubusercontent.com/tenxagent/blackbox';
const DATA = ['data/records.jsonl', 'data/manifest.json', 'data/checkpoints.json', 'data/heads.txt', 'data/rh-proof.json', 'data/coverage.json'];
const run = (args, opts = {}) => execFileSync('node', args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 << 20, ...opts });
const git = (...args) => execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' }).trim();
const fail = (m) => { console.error('cycle: ' + m); process.exit(1); };
const records = (dir) => JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8')).records;

if (git('status', '--porcelain')) fail('working tree is not clean');
const key = SEND ? fs.readFileSync(0, 'utf8') : null;
const account = key ? JSON.parse(key).account_id : null;
if (SEND && !/^[0-9a-f]{64}$|\.near$/.test(account ?? '')) fail('stdin is not a NEAR key file');

const before = records(path.join(ROOT, 'data'));
if (!SEND) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-cycle-'));
  run(['src/export.mjs', '--config', CONFIG, '--ledger', LEDGER, '--out', tmp]);
  const after = records(tmp); fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`dry: ${after - before} new records (${before} → ${after}); --send would commit them and anchor the new head`);
  process.exit(0);
}

// 11-01: any step failing after the export used to leave data/ half-written (next cycle: "working tree is not clean")
const step = (name, args) => { try { run(args); } catch (e) {
  try { git('checkout', '--', ...DATA); } catch {}
  const why = String(e.stdout || '').trim().split('\n').filter((l) => /mismatch|error|fail/i.test(l)).slice(-2).join(' | ') || String(e.stderr || e.message).trim().split('\n').filter((l) => !/^\s+at /.test(l)).pop();
  fail(`${name} failed, data reverted: ${why}`); } };
step('export', ['src/export.mjs', '--config', CONFIG, '--ledger', LEDGER]);
const after = records(path.join(ROOT, 'data'));
if (git('status', '--porcelain')) {
  step('chain build', ['src/chain.mjs', 'build', '--config', CONFIG]);
  step('chain verify', ['src/chain.mjs', 'verify']);
  step('rh-proof', ['src/rh-proof.mjs', '--all']);
  const t = spawnSync('node', ['test/run.mjs'], { cwd: ROOT, encoding: 'utf8' });
  const tl = (t.stdout + t.stderr).trim().split('\n').pop();
  if (t.status !== 0 || !/ 0 failed/.test(tl)) { git('checkout', '--', ...DATA); fail('tests failed after export, data reverted: ' + tl); }
  // 11-03 (screening): measured coverage + README numbers regenerated from this data, committed with it. Neither may block the anchor.
  try { run(['src/coverage.mjs']); } catch (e) { console.log('coverage skipped:', String(e.message).slice(0, 120)); }
  try { run(['src/readme-numbers.mjs', '--tests', tl]); } catch (e) { console.log('readme numbers skipped:', String(e.message).slice(0, 120)); }
  const f = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/checkpoints.json'), 'utf8')).final;
  git('add', ...DATA.filter((p) => fs.existsSync(path.join(ROOT, p))), 'README.md');
  git('commit', '-q', '-m', `data: re-export through ${f.t} (${f.seq} records, head h_${f.seq} = ${f.head.slice(0, 8)}…${f.head.slice(-4)})`);
  console.log(`committed ${git('rev-parse', '--short', 'HEAD')}: ${before} → ${after} records`);
}
// anchor whenever the chain's anchored seq is behind the committed head (also catches a commit whose anchor failed last time)
const fin = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/checkpoints.json'), 'utf8')).final;
const rd = spawnSync('node', ['src/anchor.mjs', '--read', '--network', 'mainnet', '--account', account], { cwd: ROOT, encoding: 'utf8', timeout: 60_000 });
const anchoredSeq = Number((rd.stdout.match(/^anchored on mainnet .*?: seq (\d+) /m) ?? [])[1] ?? 0);
if (anchoredSeq >= fin.seq) { console.log(`already anchored through seq ${anchoredSeq}; nothing to send`); process.exit(0); }
const sha = git('log', '-1', '--format=%H', '--', 'data/records.jsonl');   // the commit that holds exactly these records

const a = spawnSync('node', ['src/anchor.mjs', '--network', 'mainnet', '--send', '--i-understand-mainnet', '--records-url', `${REPO_RAW}/${sha}/data/records.jsonl`],
  { cwd: ROOT, encoding: 'utf8', input: key, env: { ...process.env, BLACKBOX_NEAR_KEY_FILE: '-' }, timeout: 180_000 });
const sent = (a.stdout.match(/^SENT (\w+): (.*)$/m) ?? []);
if (sent[2] !== 'success') fail(`anchor not confirmed (${sent[1] ?? 'no tx'}): ${(sent[2] ?? a.stderr ?? '').slice(0, 300)}`);
console.log(`anchored seq ${fin.seq} on mainnet (was ${anchoredSeq}): tx ${sent[1]} (records_url pinned to ${sha.slice(0, 7)})`);
console.log(JSON.stringify({ ok: true, seq: fin.seq, head: fin.head, commit: sha, near_tx: sent[1], account }));
