// Anchor the chain head on NEAR through SocialDB.
//
//   node src/anchor.mjs                         dry run on testnet: build + sign, send nothing
//   node src/anchor.mjs --read --account ID     read the anchored head and check it locally
//   BLACKBOX_NEAR_KEY_FILE=keys/x.json \
//     node src/anchor.mjs --send --records-url URL    send for real (testnet)
//   add --network mainnet --i-understand-mainnet       for social.near on mainnet
//
// SocialDB contract API (github.com/NearSocial/social-db, commit b4a023d,
// README "Storing data" and contract/src/api.rs + account.rs):
//   set(data: Value, options?: { refund_unused_deposit?: bool })   #[payable]
//     - top-level keys of `data` are account ids; the predecessor may write
//       under its own account id
//     - leaf values must be strings or null (api.rs panics: "The JSON value is
//       not a string, a null or an object"), so seq is written as a string
//     - keys may use a-z A-Z 0-9 _ . - and be at most 256 bytes (MAX_KEY_LENGTH)
//     - the attached deposit goes to the first key's storage balance; if that
//       account is not registered yet it is created, and the deposit must be at
//       least storage_balance_bounds().min = MIN_STORAGE_BYTES (2000) x 10^19
//       yoctoNEAR per byte = 0.02 NEAR (read live by the tests)
//   get(keys: string[], options?) -> the stored JSON tree
//   storage_balance_of(account_id) -> { total, available } | null   (NEP-145)
// Deployed at social.near (mainnet) and v1.social08.testnet (testnet).
//
// What gets written (one small fixed-shape object, overwritten on each anchor):
//   { "<account>": { "blackbox": { "head": "<64 hex>", "seq": "<n>", "t": "<ISO time>",
//                                  "agent": "<CAIP-10 agent id>", "records_url": "<url>" } } }

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { AGENT_ID, splitLines, verifySparse } from './chain.mjs';
import { generateKeyPair, keyPairFromString, base58Decode } from './near/keys.mjs';
import { signTransaction, txContext, TGAS, formatNear } from './near/tx.mjs';
import * as rpc from './near/rpc.mjs';

export const GAS = 100n * TGAS;
const KEY_RE = /^[a-zA-Z0-9_.-]{1,256}$/;

// anchors = { <seq>: <head> } written under blackbox/anchors/<seq>. SocialDB `set` merges keys, so earlier anchors stay readable
// next to the latest one and a verifier checks every one of them (2026-10-31: before this, each anchor overwrote the last).
export function anchorData({ account, head, seq, t, recordsUrl, agent = AGENT_ID, anchors = {} }) {
  if (!/^[0-9a-f]{64}$/.test(head)) throw new Error('head must be 64 lowercase hex characters');
  if (!Number.isInteger(seq) || seq < 0) throw new Error('seq must be a non-negative integer');
  const node = { head, seq: String(seq), t: String(t ?? ''), agent, records_url: String(recordsUrl ?? '') };
  for (const [s, h] of Object.entries(anchors)) {
    if (!/^[0-9a-f]{64}$/.test(h) || !/^\d+$/.test(String(s))) throw new Error(`bad anchor ${s}: ${h}`);
    (node.anchors ??= {})[String(s)] = h;
  }
  const data = { [account]: { blackbox: node } };
  checkSocialData(data);
  return data;
}

// Apply the contract's rules locally before spending gas.
export function checkSocialData(data, depth = 0) {
  if (data === null || typeof data !== 'object' || Array.isArray(data)) throw new Error('SocialDB data must be an object');
  for (const [k, v] of Object.entries(data)) {
    if (depth > 0 && !KEY_RE.test(k)) throw new Error(`SocialDB key not allowed: ${JSON.stringify(k)}`);
    if (v === null || typeof v === 'string') continue;
    if (typeof v === 'object' && !Array.isArray(v)) checkSocialData(v, depth + 1);
    else throw new Error(`SocialDB leaf ${JSON.stringify(k)} must be a string or null, got ${Array.isArray(v) ? 'array' : typeof v}`);
  }
}

export function setAction(data, deposit = 0n, gas = GAS) {
  return { functionCall: { methodName: 'set', args: new TextEncoder().encode(JSON.stringify({ data })), gas, deposit } };
}

// Deposit needed for this write. A new account pays the minimum storage balance
// AND the data: the minimum is used up by the registration itself (mainnet
// 2026-10-31, tx D76hGzr2…: a first set with only the minimum panicked "Not
// enough storage balance"). A registered account pays 0 while enough is available.
export function depositFor(storageBalance, minBalance, dataBytes) {
  const need = BigInt(dataBytes) * 3n * 10n ** 19n; // rough upper bound: 3x the JSON size at 10^19 yocto/byte
  if (!storageBalance) return BigInt(minBalance) + need;
  return BigInt(storageBalance.available) >= need ? 0n : need;
}

export function loadKeyFile(file) {
  // "-" = read the key from stdin (fd 0): a child's stdin from Node is a socket, which open('/dev/stdin') refuses (ENXIO)
  const j = JSON.parse(readFileSync(file === '-' ? 0 : file, 'utf8'));
  const secret = j.private_key || j.secret_key;
  if (!secret) throw new Error('key file needs "private_key" (or "secret_key")');
  const kp = keyPairFromString(secret);
  const account = j.account_id || kp.implicitAccountId;
  if (j.public_key && j.public_key !== kp.publicKeyString) throw new Error('key file public_key does not match its private_key');
  return { account, keyPair: kp };
}

function loadHead(root, seqArg) {
  const cp = JSON.parse(readFileSync(path.join(root, 'data/checkpoints.json'), 'utf8'));
  if (seqArg === undefined) return cp.final;
  const seq = Number(seqArg);
  const hit = [...cp.checkpoints, cp.final].find((c) => c.seq === seq);
  if (!hit) throw new Error(`no checkpoint at seq ${seq}`);
  return hit;
}

// Read the anchored head of an account and check it against local records.
export async function readAnchor(urls, socialDb, account) {
  const { value, blockHeight } = await rpc.callFunction(urls, socialDb, 'get', { keys: [`${account}/blackbox/**`], options: { with_block_height: true } });
  const node = value?.[account]?.blackbox;
  if (!node) return null;
  const leaf = (x) => (x && typeof x === 'object' ? x[''] : x);
  const anchors = Object.entries(node.anchors && typeof node.anchors === 'object' ? node.anchors : {})
    .filter(([k]) => /^\d+$/.test(k)).map(([k, v]) => ({ seq: Number(k), head: leaf(v), block: v?.[':block'] ?? null }))
    .filter(a => typeof a.head === 'string').sort((x, y) => x.seq - y.seq);
  return {
    head: leaf(node.head), seq: Number(leaf(node.seq)), t: leaf(node.t), agent: leaf(node.agent),
    records_url: leaf(node.records_url), block: node.head?.[':block'] ?? node[':block'] ?? null, readAtBlock: blockHeight, anchors,
  };
}

// The chain's own time for a block height (the "anchored at" a reader can trust; the t field is only what the agent claims).
export async function blockTime(urls, height) {
  const b = await rpc.block(urls, { block_id: Number(height) });
  return new Date(Number(BigInt(b.header.timestamp) / 1000000n)).toISOString();
}

// ---------------------------------------------------------------- CLI
if (process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1])}`).href) {
  const argv = process.argv.slice(2);
  const has = (f) => argv.includes(`--${f}`);
  const arg = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : d; };
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const network = arg('network', 'testnet');
  const net = rpc.NETWORKS[network];
  if (!net) { console.error(`unknown network ${network}`); process.exit(2); }
  const urls = rpc.rpcUrl(network);
  const send = has('send');

  // Refuse before touching the network or any key.
  if (send) {
    const kf = process.env.BLACKBOX_NEAR_KEY_FILE;
    if (!kf) {
      console.error('refusing to send: set BLACKBOX_NEAR_KEY_FILE to a key file {"account_id","private_key"} (keep it outside git; keys/ is ignored)');
      process.exit(3);
    }
    if (!(kf === "-" || existsSync(kf))) { console.error(`refusing to send: key file ${kf} not found`); process.exit(3); }
    if (network === 'mainnet' && !has('i-understand-mainnet')) {
      console.error('refusing to send on mainnet without --i-understand-mainnet (this spends real NEAR)');
      process.exit(3);
    }
    if (!arg('records-url', process.env.BLACKBOX_RECORDS_URL)) {
      console.error('refusing to send: pass --records-url <public URL of data/records.jsonl> (or BLACKBOX_RECORDS_URL)');
      process.exit(3);
    }
  }

  if (has('read')) {
    const account = arg('account', process.env.BLACKBOX_NEAR_ACCOUNT);
    if (!account) { console.error('--read needs --account <near account id>'); process.exit(2); }
    const a = await readAnchor(urls, net.socialDb, account);
    if (!a) { console.log(`no blackbox anchor under ${account} in ${net.socialDb}`); process.exit(1); }
    const written = a.block ? ` (written in block ${a.block} at ${await blockTime(urls, a.block)} by the chain's clock)` : '';
    console.log(`anchored on ${network} (${net.socialDb}) by ${account}: seq ${a.seq} head ${a.head} t ${a.t}${written}`);
    const lines = splitLines(readFileSync(path.join(root, 'data/records.jsonl'), 'utf8'));
    const claims = [{ seq: a.seq, head: a.head }, ...a.anchors.map(x => ({ seq: x.seq, head: x.head }))];
    if (a.anchors.length) console.log(`anchor history: ${a.anchors.map(x => `seq ${x.seq}${x.block ? ` @${x.block}` : ''}`).join(', ')}`);
    const s = await verifySparse(lines, claims, { agentId: a.agent || AGENT_ID });
    console.log(s.ok ? `local records match the anchor through seq ${s.okThrough} (${claims.length} anchored heads checked); ${s.reason}` : `MISMATCH: ${s.reason}`);
    process.exit(s.ok ? 0 : 1);
  }

  let account, keyPair, keyNote;
  if (send || process.env.BLACKBOX_NEAR_KEY_FILE) {
    ({ account, keyPair } = loadKeyFile(process.env.BLACKBOX_NEAR_KEY_FILE));
    keyNote = `key file (public key ${keyPair.publicKeyString})`;
  } else {
    keyPair = generateKeyPair();
    account = arg('account', keyPair.implicitAccountId);
    keyNote = 'EPHEMERAL demo key generated for this dry run (not funded, not saved)';
  }
  if (arg('account') && arg('account') !== account && send) {
    console.error(`refusing: --account ${arg('account')} differs from the key file account ${account}`);
    process.exit(3);
  }

  const cp = loadHead(root, arg('seq'));
  const recordsUrl = arg('records-url', process.env.BLACKBOX_RECORDS_URL || '');
  // history kept under anchors/<seq>: this head, the current latest anchor if it has no per-seq key yet, and --also seq:head,...
  // (a one-time backfill of anchors written before per-seq keys existed). Every one must verify against the local records first.
  const history = { [cp.seq]: cp.head };
  const prev = await readAnchor(urls, net.socialDb, account).catch(() => null);
  if (prev?.head && !prev.anchors.some(x => x.seq === prev.seq)) history[prev.seq] = prev.head;
  for (const pair of String(arg('also', '')).split(',').filter(Boolean)) { const [sq, hd] = pair.split(':'); history[Number(sq)] = hd; }
  const recLines = splitLines(readFileSync(path.join(root, 'data/records.jsonl'), 'utf8'));
  const hv = await verifySparse(recLines, Object.entries(history).map(([sq, hd]) => ({ seq: Number(sq), head: hd })), { agentId: AGENT_ID });
  if (!hv.ok) { console.error(`refusing: an anchor in the history does not match the local records: ${hv.reason}`); process.exit(6); }
  const data = anchorData({ account, head: cp.head, seq: cp.seq, t: cp.t, recordsUrl, anchors: history });
  const argsJson = JSON.stringify({ data });

  // Read-only lookups: storage registration, minimum balance, nonce, block hash.
  const { value: bounds } = await rpc.callFunction(urls, net.socialDb, 'storage_balance_bounds', {});
  const { value: bal } = await rpc.callFunction(urls, net.socialDb, 'storage_balance_of', { account_id: account });
  let deposit = depositFor(bal, bounds.min, Buffer.byteLength(argsJson));
  let nonce, blockHash, ctxNote;
  try {
    const ctx = await txContext(urls, account, keyPair);
    ({ nonce, blockHash } = ctx);
    ctxNote = `live nonce ${nonce} from view_access_key; permission ${JSON.stringify(ctx.permission)}`;
  } catch (e) {
    if (send) { console.error(`cannot send: access key lookup failed: ${e.message}`); process.exit(4); }
    const b = await rpc.block(urls);
    blockHash = base58Decode(b.header.hash);
    nonce = 1n;
    ctxNote = `no access key on chain for ${account} (expected for a dry run); nonce 1, live block ${b.header.height}`;
  }

  // A function-call key (src/fckey.mjs) cannot attach a deposit: write with 0 while the storage balance covers the data,
  // else refuse and say how to top up with the full-access key.
  if (send && ctxNote.includes('FunctionCall')) {
    const bytesCost = BigInt(Buffer.byteLength(argsJson)) * 10n ** 19n;
    if (!bal || BigInt(bal.available) < bytesCost) {
      console.error(`refusing: signing with a function-call key, which cannot attach a deposit, and SocialDB storage available ${bal ? formatNear(bal.available) : 0} NEAR < ${formatNear(bytesCost)} NEAR needed. Top up once with the full-access key (any anchor with it attaches the deposit).`);
      process.exit(5);
    }
    deposit = 0n;
  }
  const tx = { signerId: account, publicKey: keyPair.publicKey, nonce, receiverId: net.socialDb, blockHash, actions: [setAction(data, deposit)] };
  const signed = signTransaction(tx, keyPair);

  console.log(`network      ${network} (${urls[0]})`);
  console.log(`signer       ${account}  [${keyNote}]`);
  console.log(`contract     ${net.socialDb}.set  gas ${GAS / TGAS} Tgas  deposit ${formatNear(deposit)} NEAR`);
  console.log(`storage      ${bal ? `registered, available ${formatNear(bal.available)} NEAR` : `not registered: first write must attach the minimum ${formatNear(bounds.min)} NEAR`}`);
  console.log(`anchoring    seq ${cp.seq}  head ${cp.head}  t ${cp.t}`);
  console.log(`args         ${argsJson}`);
  console.log(`tx context   ${ctxNote}`);
  console.log(`signed tx    ${signed.signedBytes.length} bytes, tx hash ${signed.hashBase58}`);

  if (!send) {
    console.log('\nDRY RUN: nothing was sent. To send: BLACKBOX_NEAR_KEY_FILE=<key file> node src/anchor.mjs --send --records-url <url>');
    process.exit(0);
  }
  const res = await rpc.sendTx(urls, signed.signedBase64, 'EXECUTED_OPTIMISTIC');
  const outcome = res?.status?.SuccessValue !== undefined ? 'success' : JSON.stringify(res?.status ?? res).slice(0, 300);
  console.log(`\nSENT ${signed.hashBase58}: ${outcome}`);
  console.log(`explorer     ${net.explorerTx}${signed.hashBase58}`);
  const back = await readAnchor(urls, net.socialDb, account);
  console.log(`read back    ${back ? `seq ${back.seq} head ${back.head}` : 'not visible yet (try --read in a few seconds)'}`);
}
