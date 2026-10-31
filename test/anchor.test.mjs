import { assert, netOrSkip } from './lib.mjs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { anchorData, checkSocialData, setAction, depositFor, readAnchor } from '../src/anchor.mjs';
import { decodeSignedTransaction } from '../src/near/borsh.mjs';
import { generateKeyPair, base58Decode, verifySignature } from '../src/near/keys.mjs';
import { signTransaction } from '../src/near/tx.mjs';
import * as rpc from '../src/near/rpc.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const HEAD = 'ab'.repeat(32);
const run = (args, env = {}) => spawnSync(process.execPath, ['src/anchor.mjs', ...args], { cwd: root, encoding: 'utf8', env: { PATH: process.env.PATH, ...env }, timeout: 60000 });

export const tests = [
  {
    name: 'SocialDB data: leaves are strings (seq as a string), keys use allowed characters',
    fn() {
      const d = anchorData({ account: 'agent.testnet', head: HEAD, seq: 1183, t: '2026-10-31T12:47:06.282Z', recordsUrl: 'https://example.org/r.jsonl' });
      assert.deepEqual(d, { 'agent.testnet': { blackbox: { head: HEAD, seq: '1183', t: '2026-10-31T12:47:06.282Z', agent: 'eip155:4663:0x00731cd9e0bc7cad1b54f85187b09b942cd3be04', records_url: 'https://example.org/r.jsonl' } } });
      assert.throws(() => checkSocialData({ a: { b: 1 } }), /string or null/);
      assert.throws(() => checkSocialData({ a: { 'b c': 'x' } }), /key not allowed/);
      assert.throws(() => anchorData({ account: 'a', head: 'XYZ', seq: 1 }), /64 lowercase hex/);
    },
  },
  {
    name: 'deposit: minimum storage balance on first write, 0 once registered with room',
    fn() {
      assert.equal(depositFor(null, '20000000000000000000000', 300), 20000000000000000000000n + 300n * 3n * 10n ** 19n);
      assert.equal(depositFor({ total: '2e22', available: '19000000000000000000000' }, '20000000000000000000000', 300), 0n);
      assert.equal(depositFor({ total: '1', available: '0' }, '20000000000000000000000', 300), 300n * 3n * 10n ** 19n);
    },
  },
  {
    name: 'set FunctionCall: signed locally, decodes back to social set with the same JSON args',
    fn() {
      const kp = generateKeyPair();
      const data = anchorData({ account: kp.implicitAccountId, head: HEAD, seq: 5, t: 't', recordsUrl: '' });
      const tx = { signerId: kp.implicitAccountId, publicKey: kp.publicKey, nonce: 1n, receiverId: 'v1.social08.testnet', blockHash: base58Decode('244ZQ9cgj3CQ6bWBdytfrJMuMQ1jdXLFGnr4HhvtCTnM'), actions: [setAction(data, 20000000000000000000000n)] };
      const s = signTransaction(tx, kp);
      const back = decodeSignedTransaction(s.signedBytes);
      const fc = back.tx.actions[0].functionCall;
      assert.equal(back.tx.receiverId, 'v1.social08.testnet');
      assert.equal(fc.methodName, 'set');
      assert.equal(fc.deposit, 20000000000000000000000n);
      assert.equal(fc.gas, 100n * 10n ** 12n);
      assert.deepEqual(JSON.parse(Buffer.from(fc.args).toString()), { data });
      assert.equal(verifySignature(s.hash, back.signature, kp.publicKey), true);
    },
  },
  {
    name: '--send refuses without BLACKBOX_NEAR_KEY_FILE (and before any network call)',
    fn() {
      const r = run(['--send'], { NEAR_RPC: 'http://127.0.0.1:9' });
      assert.equal(r.status, 3);
      assert.match(r.stderr, /refusing to send: set BLACKBOX_NEAR_KEY_FILE/);
      const m = run(['--send', '--network', 'mainnet', '--records-url', 'x'], { NEAR_RPC: 'http://127.0.0.1:9', BLACKBOX_NEAR_KEY_FILE: 'package.json' });
      assert.equal(m.status, 3);
      assert.match(m.stderr, /--i-understand-mainnet/);
    },
  },
  {
    name: 'dry run against testnet: builds and signs the anchor tx, sends nothing',
    network: true,
    async fn() {
      return netOrSkip(async () => {
        const r = run([]);
        if (r.status !== 0 && /fetch failed|429|timeout/i.test(r.stderr)) throw new Error(`fetch failed: ${r.stderr.slice(0, 200)}`);
        assert.equal(r.status, 0, r.stderr);
        assert.match(r.stdout, /DRY RUN: nothing was sent/);
        assert.match(r.stdout, /contract {5}v1\.social08\.testnet\.set/);
        assert.match(r.stdout, /tx hash [1-9A-HJ-NP-Za-km-z]{43,44}/);
        return r.stdout.match(/signed tx .*/)[0];
      });
    },
  },
  {
    name: 'readAnchor parses SocialDB get with block heights (known testnet profile as a stand-in)',
    network: true,
    async fn() {
      return netOrSkip(async () => {
        // eugenethedream is the example account in the social-db README; we only check the parser on a real reply.
        const { value } = await rpc.callFunction(rpc.rpcUrl('testnet'), 'v1.social08.testnet', 'get', { keys: ['eugenethedream/profile/name'], options: { with_block_height: true } });
        assert.equal(typeof value.eugenethedream.profile.name[''], 'string');
        assert.equal(typeof value.eugenethedream.profile.name[':block'], 'number');
        assert.equal(await readAnchor(rpc.rpcUrl('testnet'), 'v1.social08.testnet', generateKeyPair().implicitAccountId), null);
      });
    },
  },
];
