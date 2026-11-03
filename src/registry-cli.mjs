// The append-only anchor registry from the command line: READ it and check it against the local records, and
// WRITE to it (anchor a head, or register a new agent). This is the code the operator's anchoring job runs
// (it used to live only in the operator's private folder; screening 11-03).
//
//   node src/registry-cli.mjs read --account ID [--network mainnet] [--dir data]
//       the registry's code hash and keys (locked = no access keys), the agent entry, every anchor; checks that seq
//       strictly increases and that each anchored head equals the local head at that seq (data/heads.txt).
//       Exit 1 on any mismatch.
//   node src/registry-cli.mjs anchor --records-url URL [--seq N] [--dir data] [--send --i-understand-mainnet]
//       anchor(seq, head, records_url) for the head at seq N (default: the final head in checkpoints.json)
//   node src/registry-cli.mjs register --agent-id CAIP10 [--deposit 0.08] [--send --i-understand-mainnet]
//
// Writes are dry runs unless --send (and --i-understand-mainnet on mainnet). The key comes from
// BLACKBOX_NEAR_KEY_FILE (a file, or "-" for stdin) as {"account_id","private_key"}; it is never written anywhere.
// The anchoring key only needs a FUNCTION-CALL permission on the registry's `anchor` method.

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as rpc from './near/rpc.mjs';
import { signTransaction, txContext, TGAS, YOCTO_PER_NEAR } from './near/tx.mjs';
import { loadKeyFile } from './anchor.mjs';
import { anchorArgs, registerArgs, encodeArgs, getAgentArgs, parseAgent, readAllAnchors, checkAccount } from './registry.mjs';

export const REGISTRY = '08035588c459e514c632061fb4862fde62297571f1e44716e01bcc9913986e8a';   // mainnet, deployed + locked 2026-10-31
export const REGISTRY_CODE_HASH = 'HHWM5HdMW4A513pxMmXGRt168Uh4PeDiBcCps8DG34Vk';              // = contract/res/blackbox_registry.wasm

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2), cmd = argv[0];
const opt = (k, d) => { const i = argv.indexOf('--' + k); return i >= 0 ? argv[i + 1] : d; };
const has = (k) => argv.includes('--' + k);
const near = (s) => { const [i, f = ''] = String(s).split('.'); return BigInt(i) * YOCTO_PER_NEAR + BigInt((f + '0'.repeat(24)).slice(0, 24)); };

/** Pure check (unit-tested): anchors [{seq, head}] vs local heads (array, index = seq). */
export function checkAnchors(anchors, heads) {
  const out = { ok: true, checked: 0, missingLocally: 0, problems: [] };
  for (let i = 0; i < anchors.length; i++) {
    const a = anchors[i];
    if (i > 0 && !(a.seq > anchors[i - 1].seq)) { out.ok = false; out.problems.push(`seq ${a.seq} does not increase after ${anchors[i - 1].seq}`); }
    if (a.seq >= heads.length) { out.missingLocally++; continue; }
    out.checked++;
    if (heads[a.seq] !== a.head) { out.ok = false; out.problems.push(`seq ${a.seq}: registry head ${a.head.slice(0, 12)}… ≠ local ${String(heads[a.seq]).slice(0, 12)}…`); }
  }
  return out;
}

async function read() {
  const account = checkAccount(opt('account'));
  const network = opt('network', 'mainnet'), url = rpc.rpcUrl(network), dir = path.resolve(opt('dir', path.join(ROOT, 'data')));
  const acc = await rpc.viewAccount(url, REGISTRY);
  const keys = (await rpc.call(url, 'query', { request_type: 'view_access_key_list', finality: 'final', account_id: REGISTRY })).keys;
  console.log(`registry     ${REGISTRY.slice(0, 8)}…${REGISTRY.slice(-4)} on ${network}: code hash ${acc.code_hash} ${acc.code_hash === REGISTRY_CODE_HASH ? '(= contract/res wasm)' : '(≠ the committed wasm!)'}, access keys ${keys.length} ${keys.length === 0 ? '(locked)' : '(NOT locked)'}`);
  const view = (m, a) => rpc.callFunction(url, REGISTRY, m, a);
  const agent = parseAgent((await view('get_agent', getAgentArgs(account))).value);
  if (!agent) { console.log(`agent        ${account}: not registered`); process.exit(1); }
  const anchors = await readAllAnchors(view, account);
  const heads = readFileSync(path.join(dir, 'heads.txt'), 'utf8').trim().split('\n');
  const r = checkAnchors(anchors, heads);
  const last = anchors[anchors.length - 1];
  console.log(`agent        ${account}: ${agent.agent_id ?? agent.agentId ?? ''} · ${anchors.length} anchors, newest seq ${last?.seq} head ${last?.head.slice(0, 8)}…${last?.head.slice(-4)}`);
  console.log(`local check  ${r.checked} anchored heads compared with ${path.relative(ROOT, dir) || '.'}/heads.txt (${r.missingLocally} beyond the local records): ${r.ok ? 'ALL MATCH' : 'MISMATCH'}`);
  for (const p of r.problems) console.log('  ' + p);
  const locked = keys.length === 0 && acc.code_hash === REGISTRY_CODE_HASH;
  process.exit(r.ok && locked ? 0 : 1);
}

async function write(methodName, args, deposit) {
  const network = opt('network', 'mainnet'), url = rpc.rpcUrl(network), send = has('send');
  if (send && network === 'mainnet' && !has('i-understand-mainnet')) { console.error('refusing to send on mainnet without --i-understand-mainnet (this spends real NEAR)'); process.exit(2); }
  const kf = process.env.BLACKBOX_NEAR_KEY_FILE;
  if (!kf) { console.error('set BLACKBOX_NEAR_KEY_FILE to a key file {"account_id","private_key"} or "-" for stdin'); process.exit(2); }
  const { account, keyPair } = loadKeyFile(kf);
  const ctx = await txContext(url, account, keyPair);
  const actions = [{ functionCall: { methodName, args: encodeArgs(args), gas: 30n * TGAS, deposit } }];
  const signed = signTransaction({ signerId: account, publicKey: keyPair.publicKey, nonce: ctx.nonce, receiverId: REGISTRY, blockHash: ctx.blockHash, actions }, keyPair);
  console.log(`${methodName}    ${JSON.stringify(args)} · signer ${account} (${typeof ctx.permission === 'string' ? ctx.permission : 'FunctionCall'}) · tx ${signed.hashBase58}`);
  if (!send) { console.log('DRY RUN: nothing was sent (add --send)'); return; }
  const res = await rpc.sendTx(url, signed.signedBase64, 'FINAL');
  const ok = res?.status?.SuccessValue !== undefined;
  console.log(JSON.stringify({ type: ok ? 'live' : 'alert', action: `registry_${methodName}`, near_tx: signed.hashBase58, ok, err: ok ? undefined : JSON.stringify(res?.status ?? res).slice(0, 300) }));
  if (!ok) process.exit(1);
}

async function main() {
  if (cmd === 'read') return read();
  if (cmd === 'anchor') {
    const dir = path.resolve(opt('dir', path.join(ROOT, 'data')));
    const cp = JSON.parse(readFileSync(path.join(dir, 'checkpoints.json'), 'utf8'));
    const seq = opt('seq') !== undefined ? Number(opt('seq')) : cp.final.seq;
    const hit = [...cp.checkpoints, cp.final].find((c) => c.seq === seq);
    if (!hit) { console.error(`seq ${seq} is not a checkpoint or the final head in checkpoints.json`); process.exit(2); }
    return write('anchor', anchorArgs({ seq, head: hit.head, recordsUrl: opt('records-url') }), 0n);
  }
  if (cmd === 'register') return write('register', registerArgs(opt('agent-id')), near(opt('deposit', '0.08')));
  console.error('usage: read --account ID | anchor --records-url URL [--seq N] | register --agent-id CAIP10  (writes: --send --i-understand-mainnet)');
  process.exit(2);
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
