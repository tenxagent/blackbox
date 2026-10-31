// Build and sign NEAR transactions locally.
//
//   signTransaction(tx, keyPair) -> { txBytes, hash, hashBase58, signature, signedBytes, signedBase64 }
//
// hash = sha256(borsh(Transaction)); the ed25519 signature is over that hash;
// the base58 of the hash is the transaction id that explorers show.

import { createHash } from 'node:crypto';
import { serializeTransaction, serializeSignedTransaction } from './borsh.mjs';
import { base58Decode, base58Encode } from './keys.mjs';
import { viewAccessKey, block } from './rpc.mjs';

export function signTransaction(tx, keyPair) {
  if (Buffer.compare(Buffer.from(tx.publicKey), Buffer.from(keyPair.publicKey)) !== 0) {
    throw new Error('transaction public_key is not the signing key');
  }
  const txBytes = serializeTransaction(tx);
  const hash = new Uint8Array(createHash('sha256').update(txBytes).digest());
  const signature = keyPair.sign(hash);
  const signedBytes = serializeSignedTransaction(txBytes, signature);
  return {
    txBytes,
    hash,
    hashBase58: base58Encode(hash),
    signature,
    signedBytes,
    signedBase64: Buffer.from(signedBytes).toString('base64'),
  };
}

// Live nonce and recent block hash for an access key (read-only RPC calls).
export async function txContext(url, accountId, keyPair) {
  const ak = await viewAccessKey(url, accountId, keyPair.publicKeyString);
  const b = await block(url, { finality: 'final' });
  return {
    nonce: BigInt(ak.nonce) + 1n,
    blockHash: base58Decode(b.header.hash),
    blockHeight: b.header.height,
    permission: ak.permission,
  };
}

export const TGAS = 10n ** 12n;
export const YOCTO_PER_NEAR = 10n ** 24n;

export function formatNear(yocto) {
  const y = BigInt(yocto);
  const whole = y / YOCTO_PER_NEAR;
  const frac = (y % YOCTO_PER_NEAR).toString().padStart(24, '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : `${whole}`;
}
