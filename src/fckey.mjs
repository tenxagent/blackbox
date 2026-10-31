// Give the anchoring cycle a key that can do one thing: call social.near `set` (SocialDB writes), burning at most --allowance NEAR
// of gas. A NEAR function-call access key cannot transfer NEAR, attach a deposit, add keys or call any other contract, so a leaked
// anchoring key can rewrite the agent's own SocialDB anchor at worst — never move its money. The full-access key that signs this
// AddKey stays offline (the operator's vault) and is only needed again to top up SocialDB storage or rotate keys.
//
//   <full-access key json> | BLACKBOX_NEAR_KEY_FILE=- node src/fckey.mjs --public-key ed25519:<new key> [--allowance 0.25]
//       [--network mainnet] [--send --i-understand-mainnet]          (dry by default: builds, signs and prints the AddKey tx)
//   node src/fckey.mjs --list --account <id> [--network mainnet]     (the account's access keys and their permissions)
import { readFileSync } from 'node:fs';
import { loadKeyFile } from './anchor.mjs';
import { publicKeyFromString } from './near/keys.mjs';
import { signTransaction, txContext, formatNear, YOCTO_PER_NEAR } from './near/tx.mjs';
import * as rpc from './near/rpc.mjs';

export const SOCIAL_METHODS = ['set'];

// The AddKey action for a function-call key limited to <receiver>.<methods> with a gas allowance in yoctoNEAR.
export function addFunctionCallKeyAction(publicKey, receiverId, methodNames, allowanceYocto) {
  return { addKey: { publicKey, accessKey: { nonce: 0n, permission: { functionCall: { allowance: allowanceYocto, receiverId, methodNames } } } } };
}

export function nearToYocto(s) {
  const [i, f = ''] = String(s).split('.');
  if (!/^\d+$/.test(i) || !/^\d*$/.test(f) || f.length > 24) throw new Error(`bad NEAR amount: ${s}`);
  return BigInt(i) * YOCTO_PER_NEAR + BigInt((f + '0'.repeat(24)).slice(0, 24));
}

async function main() {
  const argv = process.argv.slice(2);
  const has = (f) => argv.includes(`--${f}`);
  const arg = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : d; };
  const network = arg('network', 'mainnet');
  const net = rpc.NETWORKS[network];
  if (!net) { console.error(`unknown network ${network}`); process.exit(2); }
  const urls = rpc.rpcUrl(network);

  if (has('list')) {
    const r = await rpc.call(urls, 'query', { request_type: 'view_access_key_list', finality: 'final', account_id: arg('account') });
    for (const k of r.keys) console.log(k.public_key, JSON.stringify(k.access_key.permission));
    return;
  }

  const send = has('send');
  if (send && network === 'mainnet' && !has('i-understand-mainnet')) { console.error('refusing: mainnet needs --i-understand-mainnet'); process.exit(3); }
  const kf = process.env.BLACKBOX_NEAR_KEY_FILE;
  if (!kf) { console.error('set BLACKBOX_NEAR_KEY_FILE to the FULL-ACCESS key file ("-" = stdin)'); process.exit(3); }
  const { account, keyPair } = loadKeyFile(kf);
  const newKey = arg('public-key');
  if (!/^ed25519:/.test(newKey ?? '')) { console.error('pass --public-key ed25519:<base58> (the new function-call key)'); process.exit(2); }
  const allowance = nearToYocto(arg('allowance', '0.25'));

  const ctx = await txContext(urls, account, keyPair);
  if (ctx.permission !== 'FullAccess') { console.error('refusing: the signing key is not a full-access key'); process.exit(3); }
  const action = addFunctionCallKeyAction(publicKeyFromString(newKey), net.socialDb, SOCIAL_METHODS, allowance);
  const tx = { signerId: account, publicKey: keyPair.publicKey, nonce: ctx.nonce, receiverId: account, blockHash: ctx.blockHash, actions: [action] };
  const signed = signTransaction(tx, keyPair);
  console.log(`network      ${network}`);
  console.log(`account      ${account} (signed by its full-access key ${keyPair.publicKeyString})`);
  console.log(`add key      ${newKey}`);
  console.log(`permission   FunctionCall: ${net.socialDb}.${SOCIAL_METHODS.join(',')} only, gas allowance ${formatNear(allowance)} NEAR, no deposits`);
  console.log(`signed tx    ${signed.signedBytes.length} bytes, tx hash ${signed.hashBase58}`);
  if (!send) { console.log('\nDRY RUN: nothing was sent. Add --send --i-understand-mainnet to add the key.'); return; }
  const res = await rpc.sendTx(urls, signed.signedBase64, 'EXECUTED_OPTIMISTIC');
  const ok = res?.status?.SuccessValue !== undefined;
  console.log(`\nSENT ${signed.hashBase58}: ${ok ? 'success' : JSON.stringify(res?.status ?? res).slice(0, 300)}`);
  console.log(`explorer     ${net.explorerTx}${signed.hashBase58}`);
  if (!ok) process.exit(1);
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) await main();
