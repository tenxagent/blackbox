// NEAR serializer, keys and RPC tests.
//
// Vectors come from near-api-js, commit 08d29f447abcb8b8c9bec35645638fbf3d979257
// (2026-10-23), https://github.com/near/near-api-js :
//   test/unit/transactions/serialize.test.ts   'serialize transfer tx',
//                                              'serialize multi-action tx'
//   test/unit/transactions/data/transaction1.json        (FunctionCall tx)
//   test/unit/transactions/data/signed_transaction1.json (signed transfer tx)
// The hex strings below are copied from those files.
import { assert, netOrSkip } from './lib.mjs';
import { createHash } from 'node:crypto';
import { base58Encode, base58Decode, keyPairFromString, keyPairFromSeed, generateKeyPair, publicKeyFromString, verifySignature, toHex } from '../src/near/keys.mjs';
import { serializeTransaction, decodeTransaction, decodeSignedTransaction, serializeSignedTransaction } from '../src/near/borsh.mjs';
import { signTransaction } from '../src/near/tx.mjs';
import * as rpc from '../src/near/rpc.mjs';
import { addFunctionCallKeyAction, nearToYocto, SOCIAL_METHODS } from '../src/fckey.mjs';

const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (s) => new Uint8Array(Buffer.from(s, 'hex'));
const BLOCK_HASH_B58 = '244ZQ9cgj3CQ6bWBdytfrJMuMQ1jdXLFGnr4HhvtCTnM';
const TRANSFER_PK_B58 = 'Anu7LYDfpLtkP7E16LT9imXF694BdQaa9ufVkQiwTQxC';
const TRANSFER_HEX = '09000000746573742e6e65617200917b3d268d4b58f7fec1b150bd68d69be3ee5d4cc39855e341538465bb77860d01000000000000000d00000077686174657665722e6e6561720fa473fd26901df296be6adc4cc4df34d040efa2435224b6986910e630c2fef6010000000301000000000000000000000000000000';
const SIGNED_TRANSFER_HEX = TRANSFER_HEX + '00969a83332186ee9755e4839325525806e189a3d2d2bb4b4760e94443e97e1c4f22deeef0059a8e9713100eda6e19144da7e8a0ef7e539b20708ba1d8d021bd01';
const FUNCTION_CALL_HEX = '0000000000795cb7b5f57222e742d1759092f0e20071a0cd2bf30e1f681d800e67935e168801000000000000001000000073747564696f2d76776375396534316d4def837b838543990f3380af8e2a3817ddf70fe9960135b2add25a679b2a01ed01000000020a0000006164644d6573736167650b0000007b2274657874223a22227d80841e000000000000000000000000000000000000000000';
const MULTI_SECRET = 'ed25519:2wyRcSwSuHtRVmkMCGjPwnzZmQLeXLzLLyED1NDMt4BjnKgQL6tF85yBx6Jr26D2dUNeC716RBoTxntVHsegogYw';
const MULTI_HEX = '09000000746573742e6e656172000f56a5f028dfc089ec7c39c1183b321b4d8f89ba5bec9e1762803cc2491f6ef80100000000000000030000003132330fa473fd26901df296be6adc4cc4df34d040efa2435224b6986910e630c2fef608000000000103000000010203020300000071717103000000010203e80300000000000040420f00000000000000000000000000037b0000000000000000000000000000000440420f00000000000000000000000000000f56a5f028dfc089ec7c39c1183b321b4d8f89ba5bec9e1762803cc2491f6ef805000f56a5f028dfc089ec7c39c1183b321b4d8f89ba5bec9e1762803cc2491f6ef800000000000000000000030000007a7a7a010000000300000077777706000f56a5f028dfc089ec7c39c1183b321b4d8f89ba5bec9e1762803cc2491f6ef80703000000313233';

const NET = 'testnet';
const url = () => rpc.rpcUrl(NET);

export const tests = [
  {
    name: 'fckey: function-call AddKey (social.near set only, 0.25 NEAR gas allowance) round-trips through borsh',
    fn() {
      const kp = keyPairFromSeed(new Uint8Array(32).fill(7)), nk = keyPairFromSeed(new Uint8Array(32).fill(9));
      assert.equal(nearToYocto('0.25'), 250000000000000000000000n);
      assert.equal(nearToYocto('1'), 10n ** 24n);
      assert.throws(() => nearToYocto('1e3'));
      const action = addFunctionCallKeyAction(nk.publicKey, 'social.near', SOCIAL_METHODS, nearToYocto('0.25'));
      const tx = { signerId: kp.implicitAccountId, publicKey: kp.publicKey, nonce: 5n, receiverId: kp.implicitAccountId, blockHash: base58Decode(BLOCK_HASH_B58), actions: [action] };
      const { tx: back, rest } = decodeTransaction(serializeTransaction(tx));
      assert.equal(rest.length, 0);
      const ak = back.actions[0].addKey.accessKey;
      assert.equal(hex(back.actions[0].addKey.publicKey), hex(nk.publicKey));
      assert.equal(ak.nonce, 0n);
      assert.deepEqual(ak.permission, { functionCall: { allowance: 250000000000000000000000n, receiverId: 'social.near', methodNames: ['set'] } });
    },
  },
  {
    name: 'base58: vector strings decode to the bytes inside the near-api-js tx hex',
    fn() {
      assert.equal(hex(base58Decode(TRANSFER_PK_B58)), '917b3d268d4b58f7fec1b150bd68d69be3ee5d4cc39855e341538465bb77860d');
      assert.equal(hex(base58Decode(BLOCK_HASH_B58)), '0fa473fd26901df296be6adc4cc4df34d040efa2435224b6986910e630c2fef6');
      assert.equal(base58Encode(base58Decode(BLOCK_HASH_B58)), BLOCK_HASH_B58);
    },
  },
  {
    name: 'base58: leading zeros, empty input, invalid characters, random round trips',
    fn() {
      assert.equal(base58Encode(new Uint8Array([])), '');
      assert.equal(base58Encode(new Uint8Array([0, 0, 1])), '112');
      assert.deepEqual([...base58Decode('112')], [0, 0, 1]);
      assert.equal(base58Encode(Buffer.from('hello world')), 'StV1DL6CwTryKyV'); // Bitcoin base58 of "hello world"
      assert.throws(() => base58Decode('0OIl'));
      for (let i = 0; i < 200; i++) {
        const b = new Uint8Array(1 + (i % 70)).map(() => (Math.random() < 0.1 ? 0 : (Math.random() * 256) | 0));
        assert.deepEqual([...base58Decode(base58Encode(b))], [...b]);
      }
    },
  },
  {
    name: "borsh: 'serialize transfer tx' vector, byte for byte",
    fn() {
      const tx = {
        signerId: 'test.near',
        publicKey: publicKeyFromString(TRANSFER_PK_B58),
        nonce: 1n,
        receiverId: 'whatever.near',
        blockHash: base58Decode(BLOCK_HASH_B58),
        actions: [{ transfer: { deposit: 1n } }],
      };
      assert.equal(hex(serializeTransaction(tx)), TRANSFER_HEX);
    },
  },
  {
    name: 'borsh: transaction1.json (FunctionCall addMessage) decodes and re-encodes byte for byte',
    fn() {
      const { tx, rest } = decodeTransaction(unhex(FUNCTION_CALL_HEX));
      assert.equal(rest.length, 0);
      assert.equal(tx.signerId, '');
      assert.equal(tx.receiverId, 'studio-vwcu9e41m');
      assert.equal(tx.nonce, 1n);
      const fc = tx.actions[0].functionCall;
      assert.equal(fc.methodName, 'addMessage');
      assert.equal(Buffer.from(fc.args).toString(), '{"text":""}');
      assert.equal(fc.gas, 2_000_000n);
      assert.equal(fc.deposit, 0n);
      // rebuild from plain values, not from the decoded object
      const rebuilt = serializeTransaction({
        signerId: '', publicKey: unhex('795cb7b5f57222e742d1759092f0e20071a0cd2bf30e1f681d800e67935e1688'), nonce: 1n,
        receiverId: 'studio-vwcu9e41m', blockHash: unhex('4def837b838543990f3380af8e2a3817ddf70fe9960135b2add25a679b2a01ed'),
        actions: [{ functionCall: { methodName: 'addMessage', args: Buffer.from('{"text":""}'), gas: 2000000n, deposit: 0n } }],
      });
      assert.equal(hex(rebuilt), FUNCTION_CALL_HEX);
    },
  },
  {
    name: "borsh + keys: 'serialize multi-action tx' vector (FunctionCall with deposit, AddKey, ...) from its secret key",
    fn() {
      const kp = keyPairFromString(MULTI_SECRET);
      assert.equal(kp.implicitAccountId, '0f56a5f028dfc089ec7c39c1183b321b4d8f89ba5bec9e1762803cc2491f6ef8');
      const pk = kp.publicKey;
      const tx = {
        signerId: 'test.near', publicKey: pk, nonce: 1n, receiverId: '123', blockHash: base58Decode(BLOCK_HASH_B58),
        actions: [
          { createAccount: {} },
          { deployContract: { code: [1, 2, 3] } },
          { functionCall: { methodName: 'qqq', args: [1, 2, 3], gas: 1000n, deposit: 1000000n } },
          { transfer: { deposit: 123n } },
          { stake: { stake: 1000000n, publicKey: pk } },
          { addKey: { publicKey: pk, accessKey: { nonce: 0n, permission: { functionCall: { allowance: null, receiverId: 'zzz', methodNames: ['www'] } } } } },
          { deleteKey: { publicKey: pk } },
          { deleteAccount: { beneficiaryId: '123' } },
        ],
      };
      assert.equal(hex(serializeTransaction(tx)), MULTI_HEX);
    },
  },
  {
    name: 'signature: signed_transaction1.json verifies with ed25519 over sha256(borsh(tx))',
    fn() {
      const { tx, signature, txBytes } = decodeSignedTransaction(unhex(SIGNED_TRANSFER_HEX));
      assert.equal(hex(txBytes), TRANSFER_HEX);
      const digest = createHash('sha256').update(txBytes).digest();
      assert.equal(verifySignature(digest, signature, tx.publicKey), true);
      // signing the raw bytes instead of the hash would not verify
      assert.equal(verifySignature(txBytes, signature, tx.publicKey), false);
      assert.equal(hex(serializeSignedTransaction(txBytes, signature)), SIGNED_TRANSFER_HEX);
    },
  },
  {
    name: 'keys: generate, sign, verify; implicit account = hex(pubkey); secret string round trip',
    fn() {
      const kp = generateKeyPair();
      assert.match(kp.implicitAccountId, /^[0-9a-f]{64}$/);
      assert.equal(kp.implicitAccountId, toHex(publicKeyFromString(kp.publicKeyString)));
      const again = keyPairFromString(kp.secretKeyString());
      assert.equal(again.publicKeyString, kp.publicKeyString);
      const msg = new TextEncoder().encode('blackbox');
      assert.equal(verifySignature(msg, kp.sign(msg), kp.publicKey), true);
      assert.ok(!JSON.stringify(kp).includes(kp.secretKeyString().slice(8)), 'secret must not serialise');
      // RFC 8032 test 1: seed 9d61..7f60 -> public key d75a..511a
      const rfc = keyPairFromSeed(unhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'));
      assert.equal(hex(rfc.publicKey), 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
    },
  },
  {
    name: 'tx: build + sign locally; hash = base58(sha256(tx)); signature checks out',
    fn() {
      const kp = generateKeyPair();
      const tx = {
        signerId: kp.implicitAccountId, publicKey: kp.publicKey, nonce: 7n, receiverId: 'v1.social08.testnet',
        blockHash: base58Decode(BLOCK_HASH_B58),
        actions: [{ functionCall: { methodName: 'set', args: Buffer.from('{"data":{}}'), gas: 100n * 10n ** 12n, deposit: 0n } }],
      };
      const s = signTransaction(tx, kp);
      assert.equal(s.hashBase58, base58Encode(createHash('sha256').update(s.txBytes).digest()));
      assert.equal(verifySignature(s.hash, s.signature, kp.publicKey), true);
      const back = decodeSignedTransaction(s.signedBytes);
      assert.equal(back.tx.actions[0].functionCall.methodName, 'set');
    },
  },
  {
    name: 'testnet RPC (read only): status, final block, view_account v1.social08.testnet',
    network: true,
    async fn() {
      return netOrSkip(async () => {
        const st = await rpc.status(url());
        assert.equal(st.chain_id, 'testnet');
        const b = await rpc.block(url());
        assert.equal(base58Decode(b.header.hash).length, 32);
        const acc = await rpc.viewAccount(url(), 'v1.social08.testnet');
        assert.ok(acc.code_hash && acc.code_hash !== '11111111111111111111111111111111', 'contract deployed');
        return `${url()[0]} block ${b.header.height}`;
      });
    },
  },
  {
    name: 'testnet RPC (read only): view_access_key of a key that does not exist => clear error',
    network: true,
    async fn() {
      return netOrSkip(async () => {
        const kp = generateKeyPair();
        await assert.rejects(rpc.viewAccessKey(url(), kp.implicitAccountId, kp.publicKeyString), rpc.NearRpcError);
      });
    },
  },
  {
    name: 'testnet SocialDB (read only): storage_balance_bounds and get on v1.social08.testnet',
    network: true,
    async fn() {
      return netOrSkip(async () => {
        const { value: bounds } = await rpc.callFunction(url(), 'v1.social08.testnet', 'storage_balance_bounds', {});
        // social-db contract/src/account.rs: MIN_STORAGE_BYTES = 2000 bytes x 10^19 yocto/byte
        assert.equal(bounds.min, '20000000000000000000000');
        const kp = generateKeyPair();
        const { value } = await rpc.callFunction(url(), 'v1.social08.testnet', 'get', { keys: [`${kp.implicitAccountId}/blackbox/**`] });
        assert.deepEqual(value, {});
        return `min storage balance ${bounds.min} yocto = 0.02 NEAR`;
      });
    },
  },
];
