// Operator cycle, run a few times a day: re-export the ledger, rebuild and verify the chain, refresh the Robinhood Chain proof,
// run every test, commit the data, then anchor the new head on NEAR mainnet with records_url pinned to that exact commit (so the
// anchored URL always serves the records that hash to the anchored head). Nothing new in the ledger ⇒ nothing is committed or sent.
//
//   node src/cycle.mjs                         dry: exports to a temp dir and reports what an anchor would cover
//   <key json on stdin> | node src/cycle.mjs --send     commit + anchor (mainnet)
//
// The NEAR key ({"account_id","private_key"}) is read from stdin and handed to anchor.mjs on its stdin: it never touches disk.
// The ledger path comes from BLACKBOX_LEDGER (operator-only, like src/export.mjs). Refuses on a dirty working tree.
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SEND = process.argv.includes('--send');
const LEDGER = process.env.BLACKBOX_LEDGER || '/root/claude-10x/ledger.jsonl';
const REPO_RAW = 'https://raw.githubusercontent.com/tenxagent/blackbox';
const DATA = ['data/records.jsonl', 'data/manifest.json', 'data/checkpoints.json', 'data/heads.txt', 'data/rh-proof.json'];
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
  run(['src/export.mjs', '--ledger', LEDGER, '--out', tmp]);
  const after = records(tmp); fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`dry: ${after - before} new records (${before} → ${after}); --send would commit them and anchor the new head`);
  process.exit(0);
}

run(['src/export.mjs', '--ledger', LEDGER]);
const after = records(path.join(ROOT, 'data'));
if (after === before && !git('status', '--porcelain')) { console.log(`no new records (${after}); nothing to anchor`); process.exit(0); }
run(['src/chain.mjs', 'build']);
run(['src/chain.mjs', 'verify']);
run(['src/rh-proof.mjs', '--all']);
const t = spawnSync('node', ['test/run.mjs'], { cwd: ROOT, encoding: 'utf8' });
const tl = (t.stdout + t.stderr).trim().split('\n').pop();
if (t.status !== 0 || !/ 0 failed/.test(tl)) { git('checkout', '--', ...DATA); fail('tests failed after export, data reverted: ' + tl); }

const fin = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/checkpoints.json'), 'utf8')).final;
git('add', ...DATA);
git('commit', '-q', '-m', `data: re-export through ${fin.t} (${fin.seq} records, head h_${fin.seq} = ${fin.head.slice(0, 8)}…${fin.head.slice(-4)})`);
const sha = git('rev-parse', 'HEAD');
console.log(`committed ${sha.slice(0, 7)}: ${before} → ${after} records, head ${fin.head}`);

const a = spawnSync('node', ['src/anchor.mjs', '--network', 'mainnet', '--send', '--i-understand-mainnet', '--records-url', `${REPO_RAW}/${sha}/data/records.jsonl`],
  { cwd: ROOT, encoding: 'utf8', input: key, env: { ...process.env, BLACKBOX_NEAR_KEY_FILE: '/dev/stdin' }, timeout: 180_000 });
const sent = (a.stdout.match(/^SENT (\w+): (.*)$/m) ?? []);
if (sent[2] !== 'success') fail(`anchor not confirmed (${sent[1] ?? 'no tx'}): ${(sent[2] ?? a.stderr ?? '').slice(0, 300)}`);
console.log(`anchored seq ${fin.seq} on mainnet: tx ${sent[1]} (records_url pinned to ${sha.slice(0, 7)})`);
console.log(JSON.stringify({ ok: true, seq: fin.seq, head: fin.head, commit: sha, near_tx: sent[1], account }));
