import { assert } from './lib.mjs';
import {
  registerArgs, anchorArgs, getAgentArgs, getAnchorsArgs, getAgentsArgs, encodeArgs, parseAnchors, parseAgent, parseAgents,
  parseAnchorEvent, readAllAnchors, MAX_SEQ,
} from '../src/registry.mjs';
import { buildLines, verifySparse, AGENT_ID } from '../src/chain.mjs';

const H = (n) => n.toString(16).padStart(64, '0');
const AB = 'ab'.repeat(32);
const URL = 'https://example.org/blackbox/records.jsonl';
// Exactly the shape the contract's get_anchors writes (see contract/src/tests.rs).
const anchorJson = (seq, head, url = URL, height = 123456789, ts = '1761930000000000007') =>
  `{"seq":${seq},"head":"${head}","records_url":"${url}","block_height":${height},"timestamp_ns":"${ts}"}`;

export const tests = [
  {
    name: 'registry args: register / anchor / views build the exact JSON the contract reads',
    fn() {
      assert.deepEqual(registerArgs(AGENT_ID), { agent_id: AGENT_ID });
      assert.equal(new TextDecoder().decode(encodeArgs(anchorArgs({ seq: 1183, head: AB, recordsUrl: URL }))),
        `{"seq":1183,"head":"${AB}","records_url":"${URL}"}`);
      assert.deepEqual(getAgentArgs('agent.near'), { account: 'agent.near' });
      assert.deepEqual(getAnchorsArgs('agent.near'), { account: 'agent.near', from_index: 0, limit: 100 });
      assert.deepEqual(getAnchorsArgs('agent.near', 200, 1000), { account: 'agent.near', from_index: 200, limit: 100 }, 'limit capped at 100');
      assert.deepEqual(getAgentsArgs(5, 3), { from_index: 5, limit: 3 });
      assert.throws(() => getAnchorsArgs('Agent.near'), /account id/);
      assert.throws(() => getAnchorsArgs('agent.near', -1), /from_index/);
    },
  },
  {
    name: 'registry args: refuse what the contract refuses (head, records_url, seq, agent_id)',
    fn() {
      const ok = { seq: 1, head: AB, recordsUrl: URL };
      for (const head of [AB.toUpperCase(), 'A' + AB.slice(1), AB.slice(1), AB + '0', 'g'.repeat(64), '0x' + AB.slice(2), ''])
        assert.throws(() => anchorArgs({ ...ok, head }), /head/, head);
      const atLimit = 'https://x.org/' + 'a'.repeat(286);
      for (const recordsUrl of ['', 'ftp://x.org/r', 'example.org/r', 'https://', 'http://', 'HTTPS://x.org/r', 'https:///x', 'https://x.org/a b',
        'https://x.org/"', 'https://x.org/\\', 'https://x.org/é', 'javascript:alert(1)', atLimit + 'a'])
        assert.throws(() => anchorArgs({ ...ok, recordsUrl }), /records_url/, recordsUrl);
      assert.equal(anchorArgs({ ...ok, recordsUrl: atLimit }).records_url.length, 300);
      for (const seq of [-1, 1.5, MAX_SEQ + 1, '5', 5n, NaN]) assert.throws(() => anchorArgs({ ...ok, seq }), /seq/, String(seq));
      assert.equal(anchorArgs({ ...ok, seq: MAX_SEQ }).seq, 9007199254740991);
      for (const id of ['', 'eip155:1', 'EIP155:1:0xab', 'ei:1:0xab', 'eip155:1:0x ab', 'eip155:1:0xab:x', 'eip155:1:a_b', `eip155:1:${'a'.repeat(129)}`])
        assert.throws(() => registerArgs(id), /agent_id/, id);
      registerArgs('cosmos:cosmoshub-3:cosmos1t2uflqwqe0fsj0shcfkrvpukewcw40yjj6hdc0');
    },
  },
  {
    name: 'parseAnchors: contract output → claims, timestamp_ns exact as BigInt, strict about the shape',
    fn() {
      const text = `[${anchorJson(1, H(1))},${anchorJson(7, AB, URL, 170000001, '18446744073709551615')}]`;
      for (const input of [text, JSON.parse(text), new TextEncoder().encode(text)]) {
        const [a, b] = parseAnchors(input);
        assert.deepEqual(a, { seq: 1, head: H(1), recordsUrl: URL, blockHeight: 123456789, timestampNs: 1761930000000000007n, time: '2025-10-31T17:00:00.000Z' });
        assert.equal(b.timestampNs, 18446744073709551615n);
      }
      assert.deepEqual(parseAnchors('[]'), []);
      const bad = [
        `[{"seq":1,"head":"${H(1)}","records_url":"${URL}","block_height":1,"timestamp_ns":1761930000000000000}]`, // number: precision lost
        `[{"seq":1,"head":"${H(1)}","records_url":"${URL}","block_height":1}]`,
        `[{"seq":1,"head":"${H(1)}","records_url":"${URL}","block_height":1,"timestamp_ns":"1","extra":1}]`,
        `[${anchorJson(1, AB.toUpperCase())}]`,
        `[${anchorJson(2, H(2))},${anchorJson(2, H(3))}]`,
        `[${anchorJson(1, H(1), URL, 1, '01')}]`,
        `{"seq":1}`,
        `[${Array.from({ length: 101 }, (_, i) => anchorJson(i, H(i))).join(',')}]`,
      ];
      for (const b of bad) assert.throws(() => parseAnchors(b), /registry:/, b.slice(0, 80));
    },
  },
  {
    name: 'parseAgent / parseAgents / parseAnchorEvent: the other view and the NEP-297 log',
    fn() {
      assert.equal(parseAgent('null'), null);
      const fresh = parseAgent(`{"agent_id":"${AGENT_ID}","count":0,"storage_balance":"5000000000000000000000","last":null}`);
      assert.deepEqual(fresh, { agentId: AGENT_ID, count: 0, storageBalance: 5000000000000000000000n, last: null });
      const two = parseAgent(`{"agent_id":"${AGENT_ID}","count":2,"storage_balance":"0","last":${anchorJson(9, H(9))}}`);
      assert.equal(two.last.seq, 9);
      assert.throws(() => parseAgent(`{"agent_id":"${AGENT_ID}","count":2,"storage_balance":"0","last":null}`), /disagree/);
      assert.throws(() => parseAgent(`{"agent_id":"${AGENT_ID}","count":0,"storage_balance":0,"last":null}`), /storage_balance/);
      assert.deepEqual(parseAgents('["a0.near","agent.testnet"]'), ['a0.near', 'agent.testnet']);
      assert.throws(() => parseAgents('["A.near"]'), /account id/);
      const log = `EVENT_JSON:{"standard":"blackbox","version":"1.0.0","event":"anchor","data":[{"account":"alice.near","seq":7,"head":"${AB}"}]}`;
      assert.deepEqual(parseAnchorEvent(log), { account: 'alice.near', seq: 7, head: AB });
      assert.equal(parseAnchorEvent('EVENT_JSON:{"standard":"nep171","version":"1.0.0","event":"nft_mint","data":[]}'), null);
      assert.equal(parseAnchorEvent('hello'), null);
      assert.throws(() => parseAnchorEvent('EVENT_JSON:{"standard":"blackbox","version":"2.0.0","event":"anchor","data":[]}'), /shape/);
    },
  },
  {
    name: 'readAllAnchors pages through get_anchors 100 at a time and the claims verify with verifySparse',
    async fn() {
      const lines = Array.from({ length: 250 }, (_, i) => JSON.stringify({ seq: i + 1, t: '2026-10-31T00:00:00Z', why: `r${i}` }));
      const { heads } = await buildLines(lines, { agentId: AGENT_ID, every: 0 });
      const stored = Array.from({ length: 220 }, (_, i) => anchorJson(i + 1, heads[i + 1]));
      const calls = [];
      const view = async (method, args) => {
        calls.push([method, args]);
        return { value: JSON.parse(`[${stored.slice(args.from_index, args.from_index + args.limit).join(',')}]`) };
      };
      const all = await readAllAnchors(view, 'agent.near');
      assert.equal(all.length, 220);
      assert.deepEqual(calls.map(([m, a]) => `${m}:${a.from_index}:${a.limit}`), ['get_anchors:0:100', 'get_anchors:100:100', 'get_anchors:200:100']);
      const ok = await verifySparse(lines, all, { agentId: AGENT_ID });
      assert.equal(ok.ok, true, ok.reason);
      assert.equal(ok.claimsChecked, 220);
      const tampered = [...lines];
      tampered[49] = JSON.stringify({ seq: 50, t: '2026-10-31T00:00:00Z', why: 'edited' });
      const bad = await verifySparse(tampered, all, { agentId: AGENT_ID });
      assert.equal(bad.ok, false);
      assert.equal(bad.firstBad.upTo, 50);
    },
  },
];
