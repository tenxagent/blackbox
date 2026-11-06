// NEAR JSON-RPC client over global fetch (no near-api-js).
// Methods: https://docs.near.org/api/rpc/introduction
// Providers: https://docs.near.org/api/rpc/providers (read 2026-10-31). Testnet
// endpoints listed there include https://test.rpc.fastnear.com,
// https://near-testnet.drpc.org, https://testnet-rpc.intea.rs; mainnet ones
// include https://free.rpc.fastnear.com and https://near.drpc.org. On 2026-10-31
// rpc.testnet.near.org and rpc.mainnet.near.org answered with -429 rate-limit
// warnings, so they are last in the fallback list. NEAR_RPC overrides the list.

import { base58Encode } from './keys.mjs';

export const NETWORKS = {
  testnet: {
    rpcs: ['https://test.rpc.fastnear.com', 'https://near-testnet.drpc.org', 'https://rpc.testnet.near.org'],
    socialDb: 'v1.social08.testnet',
    explorerTx: 'https://testnet.nearblocks.io/txns/',
  },
  mainnet: {
    rpcs: ['https://free.rpc.fastnear.com', 'https://near.drpc.org', 'https://rpc.mainnet.near.org'],
    socialDb: 'social.near',
    explorerTx: 'https://nearblocks.io/txns/',
  },
};

// A list of endpoints; call() tries them in order on transport errors and 429s.
export function rpcUrl(network) {
  if (process.env.NEAR_RPC) return [process.env.NEAR_RPC];
  const n = NETWORKS[network];
  if (!n) throw new Error(`unknown network ${network}`);
  return n.rpcs;
}

export class NearRpcError extends Error {}

export async function call(urls, method, params, opts = {}) {
  const list = Array.isArray(urls) ? urls : [urls];
  let last;
  for (const url of list) {
    try {
      return await callOne(url, method, params, opts);
    } catch (e) {
      if (e instanceof NearRpcError) throw e; // a real answer: do not ask the next node
      last = e;
    }
  }
  throw last;
}

async function callOne(url, method, params, { timeoutMs = 20000 } = {}) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 'blackbox', method, params }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status} from ${url}`);
  const j = await res.json();
  if (j.error && (j.error.code === -429 || /rate.?limit|too many/i.test(String(j.error.message)))) throw new Error(`HTTP 429 (rate limited) from ${url}`);
  if (j.error) {
    const cause = j.error.cause?.name ? `${j.error.cause.name}: ` : '';
    throw new NearRpcError(`${cause}${JSON.stringify(j.error.data ?? j.error.message).slice(0, 600)}`);
  }
  // query errors come back as a result with an "error" string
  if (j.result && typeof j.result.error === 'string') throw new NearRpcError(j.result.error.slice(0, 300));
  return j.result;
}

export const status = (url) => call(url, 'status', []);

export const block = (url, ref = { finality: 'final' }) => call(url, 'block', ref);

export const viewAccount = (url, accountId) =>
  call(url, 'query', { request_type: 'view_account', finality: 'final', account_id: accountId });

export const viewAccessKey = (url, accountId, publicKeyString) =>
  call(url, 'query', { request_type: 'view_access_key', finality: 'final', account_id: accountId, public_key: publicKeyString });

// call_function: args as an object, result decoded from bytes as JSON.
export async function callFunction(url, contractId, methodName, args = {}) {
  const r = await call(url, 'query', {
    request_type: 'call_function',
    finality: 'final',
    account_id: contractId,
    method_name: methodName,
    args_base64: Buffer.from(JSON.stringify(args)).toString('base64'),
  });
  const text = Buffer.from(r.result).toString('utf8');
  return { value: text ? JSON.parse(text) : null, blockHeight: r.block_height, blockHash: r.block_hash };
}

// send_tx (current) with wait_until; broadcast_tx_commit is the older equivalent.
export const sendTx = (url, signedTxBase64, waitUntil = 'EXECUTED_OPTIMISTIC') =>
  call(url, 'send_tx', { signed_tx_base64: signedTxBase64, wait_until: waitUntil }, { timeoutMs: 60000 });

export const broadcastTxCommit = (url, signedTxBase64) =>
  call(url, 'broadcast_tx_commit', [signedTxBase64], { timeoutMs: 60000 });

export const txStatus = (url, txHashBase58, senderId) =>
  call(url, 'tx', { tx_hash: txHashBase58, sender_account_id: senderId, wait_until: 'NONE' });

export { base58Encode };
