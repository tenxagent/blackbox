// A SHARED blocklist that agents report to, with evidence (the security track's example prompt, added 2026-11-07).
// Any NEAR account can report: it writes, under its OWN SocialDB key,
//   <reporter>/blocklist/<chain>/<address> = '{"evidence":"…","reportedAt":"…"}'
// SocialDB only lets an account write under its own name, so every entry says who reported it, and nobody can edit or
// remove another reporter's entries. A gate counts the reports of the accounts its PUBLISHED policy lists in
// `trustedReporters` (gate.policy.json) and ignores everyone else's, so a stranger cannot get a good payee refused.
// A trusted report makes that payee a block, with the reporter and the evidence in the reason (src/gate.mjs).
//
//   node src/blocklist.mjs read [--policy gate.policy.json] [--network mainnet]      the entries the policy trusts
//   BLACKBOX_NEAR_KEY_FILE=<key file> node src/blocklist.mjs report --chain robinhood --address 0x… --evidence "…" [--send --i-understand-mainnet]
//     (dry by default: builds and signs the set() call locally and prints it; a function-call key for social.near `set` is enough
//      while the reporter's SocialDB storage covers the entry)
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { setAction, loadKeyFile } from './anchor.mjs';
import { signTransaction, txContext, formatNear } from './near/tx.mjs';
import * as rpc from './near/rpc.mjs';
import { reportData, parseShared } from './blocklist-core.mjs';
export { reportData, parseShared };

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
/** Network: read every trusted reporter's blocklist from SocialDB. → {entries, skipped} | {error} (the gate then fails closed). */
export async function readShared(trustedReporters, network = 'mainnet') {
  const reporters = (trustedReporters ?? []).map((r) => r.account ?? r).filter(Boolean);
  if (!reporters.length) return { entries: [], skipped: 0 };
  try {
    const { value } = await rpc.callFunction(rpc.rpcUrl(network), rpc.NETWORKS[network].socialDb, 'get', { keys: reporters.map((r) => `${r}/blocklist/**`) });
    return parseShared(value, trustedReporters);
  } catch (e) { return { error: String(e.message ?? e).slice(0, 120) }; }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const argv = process.argv.slice(2), opt = (k, d) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : d; };
  const network = opt('network', 'mainnet'), policy = JSON.parse(readFileSync(opt('policy', path.join(ROOT, 'gate.policy.json')), 'utf8'));
  if (argv[0] === 'read') {
    const r = await readShared(policy.trustedReporters, network);
    if (r.error) { console.error(`shared blocklist unreadable: ${r.error}`); process.exit(2); }
    console.log(`trusted reporters: ${(policy.trustedReporters ?? []).map((x) => x.account).join(', ') || 'none'} · entries ${r.entries.length} · skipped ${r.skipped}`);
    for (const e of r.entries) console.log(`BLOCK ${e.chain}:${e.address} (reported by ${e.reporter}, ${e.reportedAt}): ${e.evidence}`);
  } else if (argv[0] === 'report') {
    const send = argv.includes('--send');
    if (send && (network === 'mainnet') && !argv.includes('--i-understand-mainnet')) { console.error('refusing: add --i-understand-mainnet to write on mainnet'); process.exit(2); }
    const kf = process.env.BLACKBOX_NEAR_KEY_FILE;
    if (!kf) { console.error('set BLACKBOX_NEAR_KEY_FILE to the reporter key file {"account_id","private_key"}'); process.exit(2); }
    const { account, keyPair } = loadKeyFile(kf), urls = rpc.rpcUrl(network), net = rpc.NETWORKS[network];
    const data = reportData({ reporter: account, chain: opt('chain'), address: opt('address'), evidence: opt('evidence'), reportedAt: new Date().toISOString() });
    const ctx = await txContext(urls, account, keyPair);
    const tx = { signerId: account, publicKey: keyPair.publicKey, nonce: ctx.nonce, receiverId: net.socialDb, blockHash: ctx.blockHash, actions: [setAction(data, 0n)] };
    const signed = signTransaction(tx, keyPair);
    console.log(`reporter ${account} · ${net.socialDb}.set · deposit ${formatNear(0n)} NEAR · args ${JSON.stringify({ data })}`);
    if (!send) { console.log(`DRY RUN: signed ${signed.hashBase58}, nothing sent. Add --send --i-understand-mainnet.`); process.exit(0); }
    const res = await rpc.sendTx(urls, signed.signedBase64, 'EXECUTED_OPTIMISTIC');
    const ok = res?.status?.SuccessValue !== undefined;
    console.log(`${ok ? 'REPORTED' : 'FAILED'} ${signed.hashBase58}: ${ok ? 'success' : JSON.stringify(res?.status ?? res).slice(0, 300)}`);
    process.exit(ok ? 0 : 1);
  } else { console.error('usage: node src/blocklist.mjs read | report --chain C --address A --evidence "…" [--send --i-understand-mainnet]'); process.exit(2); }
}
