// src/flows.mjs: where the money of each gated send went (first hop), checked against the policy, the gate decision and 1Click.
// Offline: the receipts below are the real ones of seq 3395 (relay_swap) and 3399 (near_fund_deposit), cut to the fields used.
import { assert } from './lib.mjs';
import { judgeFlows, outflows, judgeOneClick, historyPairs } from '../src/flows.mjs';
import { readPolicy, txDigest } from '../src/gate.mjs';

const W = '0x00731cd9e0bc7cad1b54f85187b09b942cd3be04', USDG = '0x5fc5360d0400a0fd4f2af552add042d716f1d168';
const PROXY = '0x5567954cd026cebfe486062cb75848e0f1c12e58', ROUTER = '0x0729e2a4716d9f7dd17858d5d504426d228697f7';
const DEP = '0x767c4923b2f39e4a6640344945b11ce739540653', ATTACKER = '0x000000000000000000000000000000000000dead';
const NEAR_SELF = '00537bf24e164c18f3512de1040d34c88a11f37976a3ef6d4de673dc9cef6590';
const T = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef', A = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
const top = (a) => '0x' + a.slice(2).padStart(64, '0');
const amt = (n) => '0x' + BigInt(n).toString(16).padStart(64, '0');
const log = (kind, token, from, to, n) => ({ address: token, topics: [kind, top(from), top(to)], data: amt(n) });
const H1 = '0x23a36974169a577942f79fbf5741040b8f4cc01a9bfc1d5f77a2853b867cdc03', H2 = '0x7db041e956ab27afe695b1acdc0fb9fc2b34906b8bc5397375348982be939080';
const H3 = '0x3a10124c0d4c99781c07a7390bf1e2a01a4de50e6f846ba5948f7e257386c32d';
const REAL = {
  [`robinhood:${H1}`]: { tx: { from: W, to: USDG, value: '0x0' }, receipt: { status: '0x1', logs: [log(A, USDG, W, PROXY, 1000000)] } },
  [`robinhood:${H2}`]: { tx: { from: W, to: PROXY, value: '0x0' }, receipt: { status: '0x1', logs: [
    log(T, USDG, W, ROUTER, 1000000), log(A, USDG, ROUTER, '0x603206d6105217dd972e4ab30676a220ca393346', 1000000),
    log(T, USDG, ROUTER, '0xe6eeda550918638529c6cf2ea14f9ea0572d6f88', 999400)] } },
  [`robinhood:${H3}`]: { tx: { from: W, to: USDG, value: '0x0' }, receipt: { status: '0x1', logs: [log(T, USDG, W, DEP, 1000000)] } },
};
const ONECLICK = { [DEP]: { status: 'SUCCESS', quoteResponse: { quoteRequest: { recipient: NEAR_SELF, refundTo: '0x00731cd9e0BC7CAD1b54f85187B09B942cD3be04', appFees: [{ fee: 20 }] } },
  swapDetails: { originChainTxHashes: [{ hash: H3 }], destinationChainTxHashes: [{ hash: '6yXYjudpsSrNHxPLx1PFN6AHUB7oz7ssWHSTmUYqY7AC' }] } } };
const gate = (seq, t, what, usd) => ({ seq, row: { t, engine: 'gate', type: 'gate', action: 'gate_allow', what, pendingUsd: usd } });
const RECORDS = [
  gate(3394, '2026-11-05T18:12:53.902Z', 'relay swap 1 USDG -> ETH', 0.999715),
  { seq: 3395, row: { t: '2026-11-05T18:13:15.293Z', engine: 'swap', action: 'relay_swap', chain: 'robinhood', type: 'live' }, txs: [H1, H2] },
  gate(3397, '2026-11-05T18:16:51.211Z', 'near fund 1 USDG -> NEAR', 1),
  { seq: 3399, row: { t: '2026-11-05T18:16:57.059Z', engine: 'nearfund', action: 'near_fund_deposit', type: 'live', depositAddress: '0x767C4923B2F39e4A6640344945B11ce739540653' }, txs: [H3] },
];
const policy = readPolicy();
const run = (o = {}) => judgeFlows({ records: RECORDS, policy, read: REAL, oneClick: ONECLICK, wallet: W, ...o });
const kinds = (r) => r.findings.map((f) => f.kind).sort();

export const tests = [
  { name: 'the real relay swap and NEAR funding: every first hop goes to a listed contract or the 1Click deposit address that pays the agent',
    fn() {
      const r = run();
      assert.deepEqual([r.sends, r.txs, r.findings.length], [2, 3, 0], JSON.stringify(r.findings));
      assert.deepEqual(r.results.map((s) => s.usdOut), [1, 1]);
      const near = r.results[1].txs[0].flows[0];
      assert.equal(near.oneClick.recipient, NEAR_SELF); assert.equal(near.oneClick.appFeeBps, 20);
      // only value leaving the wallet counts: the router's own transfers and approvals in the same tx are not first hops
      assert.equal(r.results[0].txs[1].flows.length, 1);
    } },
  { name: 'without Relay\'s erc20Router on the allow-list the swap is a finding (what the first run found, 2026-11-06)',
    fn() {
      const r = run({ policy: { ...policy, allow: policy.allow.filter((e) => e.address !== ROUTER) } });
      assert.deepEqual(kinds(r), ['unlisted_destination']); assert.equal(r.findings[0].seq, 3395);
    } },
  { name: 'escape 16: the gate was told Relay, the tx paid the attacker directly ⇒ unlisted_destination',
    fn() {
      const read = { ...REAL, [`robinhood:${H2}`]: { tx: { from: W, to: USDG, value: '0x0' }, receipt: { status: '0x1', logs: [log(T, USDG, W, ATTACKER, 1000000)] } } };
      const r = run({ read });
      assert.deepEqual(kinds(r), ['unlisted_destination']); assert.match(r.findings[0].why, /0x0+dead/);
    } },
  { name: 'escape 27: $0.01 claimed, 22.16 USDG moved ⇒ amount_over_gate; an approval above the amount or unlimited ⇒ approval_over_gate',
    fn() {
      const records = RECORDS.map((x) => (x.seq === 3394 ? gate(3394, x.row.t, x.row.what, 0.01) : x));
      const big = { ...REAL, [`robinhood:${H2}`]: { tx: REAL[`robinhood:${H2}`].tx, receipt: { status: '0x1', logs: [log(T, USDG, W, ROUTER, 22155330)] } } };
      assert.deepEqual(kinds(run({ records, read: big })), ['amount_over_gate', 'approval_over_gate']);   // 22.16 moved, $1 approval vs $0.01
      const moved = (n) => ({ ...REAL, [`robinhood:${H2}`]: { tx: REAL[`robinhood:${H2}`].tx, receipt: { status: '0x1', logs: [log(T, USDG, W, ROUTER, n)] } } });
      assert.deepEqual(kinds(run({ read: moved(1_025_000) })), []);                    // told $0.999715, moved $1.025: inside 2 % + 1 cent ($1.0297)
      assert.deepEqual(kinds(run({ read: moved(1_050_000) })), ['amount_over_gate']);  // $1.05: over
      const unlimited = { ...REAL, [`robinhood:${H1}`]: { tx: REAL[`robinhood:${H1}`].tx, receipt: { status: '0x1', logs: [log(A, USDG, W, PROXY, (1n << 256n) - 1n)] } } };
      const u = run({ read: unlimited });
      assert.deepEqual(kinds(u), ['approval_over_gate']); assert.match(u.findings[0].why, /unlimited/);
    } },
  { name: 'escape 26: 1Click\'s own record decides: another recipient, other refunds, a tx it does not list, or no record ⇒ oneclick_mismatch',
    fn() {
      const q = ONECLICK[DEP].quoteResponse.quoteRequest;
      const variant = (quoteRequest, swapDetails = ONECLICK[DEP].swapDetails) => ({ [DEP]: { ...ONECLICK[DEP], quoteResponse: { quoteRequest }, swapDetails } });
      for (const oneClick of [variant({ ...q, recipient: 'attacker.near' }), variant({ ...q, refundTo: ATTACKER }),
        variant(q, { originChainTxHashes: [{ hash: '0x' + '11'.repeat(32) }] }), { [DEP]: { error: 'HTTP 404' } }, {}])
        assert.deepEqual(kinds(run({ oneClick })), ['oneclick_mismatch'], JSON.stringify(oneClick).slice(0, 80));
      assert.equal(judgeOneClick(ONECLICK[DEP], { policy, tx: H3 }).ok, true);
    } },
  { name: 'per chain, and no silent passes: an Elysium allow entry does not clear a Robinhood address; an unread tx is a finding',
    fn() {
      const moved = { ...policy, allow: policy.allow.map((e) => (e.address === ROUTER ? { ...e, chain: 'elysium' } : e)) };
      assert.deepEqual(kinds(run({ policy: moved })), ['unlisted_destination']);
      const read = { ...REAL }; delete read[`robinhood:${H3}`];
      assert.deepEqual(kinds(run({ read })), ['not_read']);
    } },
  { name: '--history: every send of the gated tools, also before the gate; its gate decision where it has one, else no amount check',
    fn() {
      const SB = '0x50025f4847000000000000000000000000000000000000000000000000000001', ELYSPUMP = '0x751cefb96ac88db5327d39e0fbdd5d882d80b430';
      const old = { seq: 2701, row: { t: '2026-11-03T19:38:33.569Z', engine: 'sleeve', action: 'sleeve_buy', type: 'live' }, txs: [SB] };
      const fund = { seq: 2696, row: { t: '2026-11-03T19:30:00Z', engine: 'sleeve', action: 'sleeve_fund_relay_deposit', type: 'live' }, txs: ['0x' + '22'.repeat(32)] };
      const records = [fund, old, ...RECORDS], pairs = historyPairs(records);
      assert.deepEqual(pairs, [{ seq: 2701, gateSeq: null }, { seq: 3395, gateSeq: 3394 }, { seq: 3399, gateSeq: 3397 }]);   // not the ungated funding hop
      const read = { ...REAL, [`elysium:${SB}`]: { tx: { from: W, to: ELYSPUMP, value: '0x' + (35178240000000000n).toString(16) }, receipt: { status: '0x1', logs: [] } } };
      const r = judgeFlows({ records, policy, read, oneClick: ONECLICK, wallet: W, pairs });
      assert.deepEqual([r.sends, r.findings.length], [3, 0], JSON.stringify(r.findings));
      assert.equal(r.results[0].txs[0].flows[0].label, 'ElysPump v2 router on Elysium');
      const bad = { ...read, [`elysium:${SB}`]: { tx: { from: W, to: ATTACKER, value: '0x1' }, receipt: { status: '0x1', logs: [] } } };
      assert.deepEqual(kinds(judgeFlows({ records, policy, read: bad, oneClick: ONECLICK, wallet: W, pairs })), ['unlisted_destination']);
    } },
  { name: 'outflows: native value counts, value coming IN does not',
    fn() {
      assert.deepEqual(outflows({ from: W, to: PROXY, value: '0x10' }, { logs: [log(T, USDG, ROUTER, W, 5)] }, W), [{ kind: 'native', to: PROXY, amount: '16' }]);
    } },
  { name: 'tx-bound (2026-11-06): after the cutover the tx on chain must be one the gate decision was shown (digest); another tx, or none shown ⇒ tx_not_shown_to_gate',
    fn() {
      const input = '0xa9059cbb' + DEP.slice(2).padStart(64, '0') + (1000000).toString(16).padStart(64, '0');
      const signed = { chain: 'robinhood', to: USDG, data: input, value: '0x0' };
      const read = { ...REAL, [`robinhood:${H3}`]: { ...REAL[`robinhood:${H3}`], tx: { ...REAL[`robinhood:${H3}`].tx, input } } };
      const after = (shownTxs) => [gate(3397, '2026-11-07T10:00:00.000Z', 'near fund 1 USDG -> NEAR', 1), { ...RECORDS[3], row: { ...RECORDS[3].row, t: '2026-11-07T10:00:05.000Z' } }]
        .map((x, i) => (i === 0 ? { ...x, row: { ...x.row, ...(shownTxs ? { shownTxs } : {}) } } : x));
      const go = (shownTxs) => judgeFlows({ records: after(shownTxs), policy, read, oneClick: ONECLICK, wallet: W, anchorSince: '2099-01-01T00:00:00Z' });   // anchor check: next test
      const ok = go([{ ...signed, digest: txDigest(signed) }]);
      assert.deepEqual(ok.findings, []); assert.equal(ok.results[0].txs[0].shownToGate, true);
      const other = { ...signed, data: input.slice(0, -2) + '01' };   // the gate saw a different amount
      assert.deepEqual(kinds(go([{ ...other, digest: txDigest(other) }])), ['tx_not_shown_to_gate']);
      const none = go(null);
      assert.deepEqual(kinds(none), ['tx_not_shown_to_gate']); assert.match(none.findings[0].why, /lists no transactions/);
      assert.equal(run().results[1].txs[0].shownToGate, undefined);   // the 11-05 sends predate the cutover: not checked
    } },
  { name: 'anchor-before-send (2026-11-06): a registry head at seq ≥ the decision, matching the records, written before the tx block; else not_anchored_before_send',
    fn() {
      const input = '0xa9059cbb' + DEP.slice(2).padStart(64, '0') + (1000000).toString(16).padStart(64, '0');
      const signed = { chain: 'robinhood', to: USDG, data: input, value: '0x0' };
      const blockAt = '2026-11-07T10:00:05.000Z';
      const read = { ...REAL, [`robinhood:${H3}`]: { ...REAL[`robinhood:${H3}`], tx: { ...REAL[`robinhood:${H3}`].tx, input }, blockTime: Date.parse(blockAt) / 1000 } };
      const records = [{ ...gate(3397, '2026-11-07T10:00:00.000Z', 'near fund 1 USDG -> NEAR', 1), row: { ...gate(3397, '2026-11-07T10:00:00.000Z', 'near fund 1 USDG -> NEAR', 1).row, shownTxs: [{ ...signed, digest: txDigest(signed) }] } },
        { ...RECORDS[3], row: { ...RECORDS[3].row, t: '2026-11-07T10:00:06.000Z' } }];
      const heads = Array.from({ length: 3400 }, (_, i) => (i % 2 ? 'aa' : 'bb').repeat(32));
      const anc = (seq, at, head = heads[seq]) => ({ seq, head, timestampNs: BigInt(Date.parse(at)) * 1_000_000n, time: at });
      const go = (anchors, r = read) => judgeFlows({ records, policy, read: r, oneClick: ONECLICK, wallet: W, anchors, heads });
      const ok = go([anc(3300, '2026-11-07T06:31:40.000Z'), anc(3398, '2026-11-07T10:00:02.500Z')]);
      assert.deepEqual(ok.findings, []);
      assert.deepEqual(ok.results[0].txs[0].anchoredBefore, { seq: 3398, time: '2026-11-07T10:00:02.500Z' });
      assert.deepEqual(kinds(go([anc(3398, '2026-11-07T10:00:05.000Z')])), ['not_anchored_before_send']);    // same instant as the block: not before
      assert.deepEqual(kinds(go([anc(3396, '2026-11-07T09:59:59.000Z')])), ['not_anchored_before_send']);    // older than the decision itself
      assert.deepEqual(kinds(go([anc(3398, '2026-11-07T10:00:02.000Z', 'cc'.repeat(32))])), ['not_anchored_before_send']);   // a head these records do not have
      assert.deepEqual(kinds(go([anc(3500, '2026-11-07T10:00:02.000Z', 'cc'.repeat(32))])), ['not_anchored_before_send']);   // beyond the records: cannot be checked
      const unread = go(null);
      assert.deepEqual(kinds(unread), ['not_anchored_before_send']); assert.match(unread.findings[0].why, /registry could not be read/);
      const { blockTime, ...noTime } = read[`robinhood:${H3}`];
      assert.match(go([anc(3398, '2026-11-07T10:00:02.000Z')], { ...read, [`robinhood:${H3}`]: noTime }).findings[0].why, /block time/);
      assert.equal(run({ anchors: [], heads }).results[1].txs[0].anchoredBefore, undefined);   // the 11-05 sends predate it: not checked
    } },
];
