// The browser verifier's logic, run in Node (same module the page loads).
import { assert, netOrSkip } from './lib.mjs';
import { readFileSync } from 'node:fs';
import { checkRecords, describe, readNearAnchor, coverageSummary, flowsSummary, nearRpc, anchorState, AHEAD_MAX_H, PINNED_GRACE_H, pinnedUrl, gateDemo, GATE_EXAMPLES, GATE_STATE } from '../web/verify.js';
import { verifySparse, splitLines } from '../src/chain.mjs';
import { canon } from '../src/canon.mjs';

const text = readFileSync(new URL('../data/records.jsonl', import.meta.url), 'utf8');
const cp = JSON.parse(readFileSync(new URL('../data/checkpoints.json', import.meta.url), 'utf8'));

export const tests = [
  {
    name: 'NEAR panels (screen 5 Z-2): a pre-send head beyond the records is amber ≤ 9 h; a head pinned to a published commit is red after 1 h (a dropped tail); unknown age red',
    async fn() {
      const lines = splitLines(text);
      const n = lines.length, now = Date.parse('2026-11-06T15:00:00Z'), ago = (h) => new Date(now - h * 3.6e6).toISOString();
      const MAIN = 'https://raw.githubusercontent.com/tenxagent/blackbox/main/data/records.jsonl';
      const PIN = 'https://raw.githubusercontent.com/tenxagent/blackbox/722dc32ef3f22222fe585e27231ecf11d3eaa3e4/data/records.jsonl';
      assert.equal(pinnedUrl(PIN), true); assert.equal(pinnedUrl(MAIN), false);
      const ahead = await verifySparse(lines, [cp.final, { seq: n + 7, head: 'ab'.repeat(32) }], { agentId: cp.agentId });
      assert.deepEqual(ahead.ahead, { seqs: [n + 7], recordsEnd: n });
      const pre = anchorState(ahead, [{ seq: n + 7, time: ago(40 / 60), pinned: false }], now);   // a pre-send anchor, 40 min old
      assert.equal(pre.state, 'ahead');
      assert.ok(pre.text.includes(`seq ${n + 7} was anchored 40 min ago, beyond these records (they end at seq ${n})`), pre.text);
      assert.ok(!/gate decision before it signs/.test(pre.text));                                   // no unchecked cause asserted
      assert.equal(anchorState(ahead, [{ seq: n + 7, time: ago(AHEAD_MAX_H + 0.5), pinned: false }], now).state, 'bad');
      // the dropped tail: the head is pinned to a commit that WAS published, the records here stop short of it
      assert.equal(anchorState(ahead, [{ seq: n + 7, time: ago(0.2), pinned: true }], now).state, 'ahead');   // deploy lag: minutes
      const dropped = anchorState(ahead, [{ seq: n + 7, time: ago(PINNED_GRACE_H + 0.1), pinned: true }], now);
      assert.equal(dropped.state, 'bad'); assert.match(dropped.text, /published records are missing/);
      assert.equal(anchorState(ahead, [{ seq: n + 7, time: ago(0.2), pinned: null }], now).state, 'ahead');
      assert.equal(anchorState(ahead, [{ seq: n + 7, time: ago(PINNED_GRACE_H + 1), pinned: null }], now).state, 'ahead');   // unknown target: amber past the 1 h pinned grace
      assert.equal(anchorState(ahead, [{ seq: n + 7, time: ago(AHEAD_MAX_H + 0.5), pinned: null }], now).state, 'bad');      // … and red after the 9 h rule
      assert.equal(anchorState(ahead, [], now).state, 'bad');                                              // age unknown: red
      const wrong = await verifySparse(lines, [{ seq: n, head: 'cd'.repeat(32) }], { agentId: cp.agentId });
      assert.deepEqual(anchorState(wrong, [], now), { state: 'bad' });                                       // differs inside the records: red
      const fine = await verifySparse(lines, [cp.final], { agentId: cp.agentId });
      assert.deepEqual(anchorState(fine), { state: 'ok' });
    },
  },
  {
    name: 'decision list: gate rows read as allowed / REFUSED / bypassed',
    fn() {
      const g = (row) => describe({ row: { type: 'gate', ...row } });
      assert.ok(g({ action: 'gate_allow', pendingUsd: 3, what: 'relay swap', anchorAgeH: 3.4, spent24h: 0 }).startsWith('Pre-sign gate allowed $3.00 (relay swap)'));
      assert.ok(g({ action: 'gate_refuse', pendingUsd: 3, reasons: ['newest anchor is 21.0 h old'] }).includes('REFUSED $3.00: newest anchor is 21.0 h old.'));
      assert.ok(g({ action: 'gate_bypass', pendingUsd: 1 }).includes('bypassed by hand'));
      assert.ok(g({ action: 'gate_allow', pendingUsd: 1, anchorAgeH: 3.7, spent24h: 0 }).endsWith('$0 already allowed in 24 h.'));   // was "$0."
    },
  },
  {
    name: 'coverage panel: committed numbers in the text, never green with unaccounted txs, live nonce delta',
    fn() {
      const cov = JSON.parse(readFileSync(new URL('../data/coverage.json', import.meta.url), 'utf8'));
      const s = coverageSummary(cov);
      assert.ok(s.text.includes(`Of the ${cov.total} transactions`) && s.text.includes(`${cov.unexplained} (`));
      assert.equal(s.state, cov.unexplained === 0 ? 'ok' : 'idle');
      assert.equal(coverageSummary({ ...cov, unexplained: 0 }).state, 'ok');
      assert.ok(coverageSummary(cov, cov.total + 3).text.includes('has sent 3 more since'));
      assert.ok(coverageSummary(cov, cov.total).text.includes(`Live nonce ${cov.total}: current.`));
      assert.ok(coverageSummary(cov, false).text.includes('could not be read'));
    },
  },
  {
    name: 'where-the-money-went panel: the committed data/flows.json; red on any finding, an unread tx or a send without a gate decision',
    fn() {
      const fl = JSON.parse(readFileSync(new URL('../data/flows.json', import.meta.url), 'utf8'));
      const s = flowsSummary(fl), clean = fl.findings.length === 0 && fl.missingGate.length === 0;
      assert.equal(s.state, clean ? 'ok' : 'bad');
      assert.ok(s.text.startsWith(`${fl.sends} gated send`) && s.text.includes(`${fl.txs} transaction`) && s.text.includes('First hop only') === clean, s.text);
      assert.equal(s.sends.length, fl.results.length);
      if (clean) assert.ok(s.sends.every((x) => x.txs.every((t) => t.ok && t.text.startsWith('✓'))));
      const near = fl.results.find((r) => r.action === 'near_fund_deposit');
      if (near) assert.match(s.sends[fl.results.indexOf(near)].txs[0].text, /1Click SUCCESS: pays the agent's NEAR account, refunds to its wallet/);
      // synthetic: an unlisted payee, an unread tx, a send with no gate decision, nothing at all
      const r0 = fl.results[0], f0 = r0.txs[0].flows[0];
      const bad = { ...fl, findings: [{ seq: r0.seq, tx: r0.txs[0].tx, kind: 'unlisted_destination', why: 'transfer to 0x…dead: not on the allow-list' }],
        results: [{ ...r0, txs: [{ ...r0.txs[0], flows: [{ ...f0, ok: false, label: 'not on the allow-list' }] }] }] };
      const b = flowsSummary(bad);
      assert.equal(b.state, 'bad'); assert.ok(b.text.includes(`#${r0.seq} unlisted destination`) && !b.text.includes('First hop only'), b.text);
      assert.ok(b.sends[0].txs[0].text.startsWith('✗') && !b.sends[0].txs[0].ok);
      const unread = flowsSummary({ ...fl, findings: [{ seq: r0.seq, tx: r0.txs[0].tx, kind: 'not_read', why: 'HTTP 429' }], results: [{ ...r0, txs: [{ tx: r0.txs[0].tx, result: 'not_read', error: 'HTTP 429' }] }] });
      assert.equal(unread.state, 'bad'); assert.equal(unread.sends[0].txs[0].text, '✗ not read: HTTP 429');
      const nogate = flowsSummary({ ...fl, findings: [], missingGate: [3500] });
      assert.equal(nogate.state, 'bad'); assert.ok(nogate.text.includes('No gate decision before #3500'));
      assert.equal(flowsSummary({ since: fl.since, sends: 0, txs: 0, findings: [], missingGate: [], results: [] }).state, 'idle');
    },
  },
  {
    name: 'page check: committed records => chain OK up to the last seq',
    async fn() {
      const r = await checkRecords(text, cp);
      assert.equal(r.structural, null);
      assert.equal(r.sparse.ok, true);
      assert.equal(r.sparse.okThrough, cp.final.seq);
    },
  },
  {
    name: 'page check: one changed record => exact seq from the structural check or the checkpoint interval',
    async fn() {
      const lines = text.split('\n').filter(Boolean);
      const rec = JSON.parse(lines[499]);
      rec.row.t = '2020-01-01T00:00:00.000Z'; // still canonical, content changed
      const bad = [...lines];
      bad[499] = canon(rec);
      const r = await checkRecords(bad.join('\n') + '\n', cp);
      assert.equal(r.sparse.ok, false);
      assert.ok(r.sparse.firstBad.after < 500 && r.sparse.firstBad.upTo >= 500);
      const dropped = await checkRecords(lines.filter((_, i) => i !== 99).join('\n') + '\n', cp);
      assert.deepEqual(dropped.structural?.seq, 100);
      const hand = [...lines];
      hand[9] = hand[9].replace('{', '{ ');
      assert.equal((await checkRecords(hand.join('\n') + '\n', cp)).structural.seq, 10);
    },
  },
  {
    name: 'plain-word descriptions exist for every committed record (no undefined/NaN, no empty slot)',
    fn() {
      for (const l of text.split('\n').filter(Boolean)) {
        const d = describe(JSON.parse(l));
        // an empty slot shows up as "()", a double space, " ." or a bare "$" (e.g. "bounty  vs gas  → wait", "$0.")
        assert.ok(d.length > 5 && !/undefined|NaN|null|\(\s*\)|\s\.$|(^|\s)\$[ .]|  /.test(d), d);
      }
    },
  },
  {
    name: 'decision list: money and NEAR rows say what moved, not just the action name',
    fn() {
      const live = (row) => describe({ row: { type: 'live', ...row } });
      assert.equal(live({ action: 'relay_swap', chain: 'robinhood', from: 'USDG', to: 'ETH', amount: '1', received: '0.000444044331860622' }),
        'Swapped 1 USDG for 0.000444 ETH through Relay on Robinhood Chain.');
      assert.equal(live({ action: 'near_fund_done', status: 'SUCCESS', details: { amountInFormatted: '1.0', amountOutFormatted: '0.271814462645214675369177' } }),
        'NEAR Intents finished the swap (SUCCESS): 1.0 USDG in, 0.2718 NEAR out.');
      assert.ok(live({ action: 'registry_storage_deposit', near: 0.04, anchorsLeft: 41 }).startsWith('Prepaid 0.04 NEAR of registry storage (room for about 41 anchors)'));
      assert.equal(describe({ row: { type: 'flock_sim', ok: false, err: '{"message":"execution reverted: FMG: SLIPPAGE","code":3}' } }),
        'Simulated a reinvest: the call would fail (reverted: FMG: SLIPPAGE) → wait.');
      assert.ok(describe({ row: { type: 'live_intent', action: 'near_fund', usdg: '1', downside: '-$1' } }).startsWith('About to send (written before signing): near fund, 1 USDG; worst case -$1'));
      assert.ok(describe({ row: { type: 'vanta_err', engine: 'vanta', err: 'fetch failed' } }).includes('not a decision'));
    },
  },
  {
    name: 'page NEAR read: SocialDB get through fastnear (no anchor under a fresh account)',
    network: true,
    async fn() {
      return netOrSkip(async () => {
        assert.equal(await readNearAnchor('testnet', 'a'.repeat(64)), null);
      });
    },
  },
  {
    name: 'page NEAR reads: a rate limit or a dead endpoint moves on to the next RPC; a contract error does not',
    async fn() {
      const net = { rpcs: ['https://a.example', 'https://b.example', 'https://c.example'] }, seen = [];
      const fake = (replies) => async (url) => { seen.push(new URL(url).host); const r = replies[new URL(url).host]; if (r === 'down') throw new Error('fetch failed');
        return { status: r.status ?? 200, json: async () => r.body }; };
      const ok = await nearRpc(net, 'block', {}, fake({ 'a.example': { status: 429, body: {} }, 'b.example': { body: { error: { code: -429, message: 'Rate limits exceeded' } } }, 'c.example': { body: { result: { x: 1 } } } }));
      assert.deepEqual(ok, { x: 1 }); assert.deepEqual(seen, ['a.example', 'b.example', 'c.example']);
      seen.length = 0;
      await assert.rejects(nearRpc(net, 'query', {}, fake({ 'a.example': { body: { result: { error: 'wasm execution failed' } } } })), /wasm execution failed/);
      assert.deepEqual(seen, ['a.example']);
      await assert.rejects(nearRpc(net, 'block', {}, fake({ 'a.example': 'down', 'b.example': 'down', 'c.example': 'down' })), /every endpoint/);
    },
  },
  {
    name: 'page section 7 (try the gate): the five one-tap examples give the verdicts the README promises, on the real policy and records',
    fn() {
      const policy = JSON.parse(readFileSync(new URL('../gate.policy.json', import.meta.url), 'utf8')), lines = splitLines(text);
      const ME = policy.trustedReporters[0].account, BAD = '0x000000000000000000000000000000000000dead';
      const nowMs = Date.parse('2026-11-07T12:00:00Z');
      const anchors = [{ seq: 3915, timestampNs: BigInt(nowMs - 3 * 3.6e6) * 1_000_000n, recordsUrl: 'https://raw.githubusercontent.com/tenxagent/blackbox/a0b752c644e35058dbfbaa67fc46856acc171992/data/records.jsonl' }];
      const sharedValue = { [ME]: { blocklist: { robinhood: { [BAD]: JSON.stringify({ evidence: 'phishing payee from the attack demo (record 3463)', reportedAt: '2026-11-07T10:25:52Z' }) } } } };
      const RELAY = '0x5567954cd026cebfe486062cb75848e0f1c12e58', relayFacts = { [`robinhood:${RELAY}`]: { codeHash: policy.allow.find((x) => x.address === RELAY).codeHash, nonce: 1 } };
      const run = (e, extra = {}) => gateDemo({ policy, recordLines: lines, anchors, sharedValue, facts: relayFacts, input: e, nowMs, ...extra });
      const [phish, relaySelf, relayOther, overCap, fresh] = GATE_EXAMPLES;
      const r1 = run(phish); assert.equal(r1.action, 'gate_refuse'); assert.match(r1.reasons.join(), /blocklisted by .* \(shared list/);
      const r2 = run(relaySelf); assert.equal(r2.action, 'gate_allow', r2.reasons.join('; '));
      const r3 = run(relayOther); assert.equal(r3.action, 'gate_warn'); assert.match(r3.reasons.join(), /not one of the agent's own addresses/);
      const r4 = run(overCap); assert.equal(r4.action, 'gate_refuse'); assert.match(r4.reasons.join(), /cap/);
      const addr = '0x' + '7'.repeat(40);
      const r5 = run({ ...fresh, address: addr }, { facts: { [`robinhood:${addr}`]: { codeHash: null, nonce: 0 } } });
      assert.equal(r5.action, 'gate_warn'); assert.match(r5.reasons.join(), /fresh address \(0 txs, no code\)/);
      assert.equal(run(relaySelf, { sharedValue: null }).action, 'gate_refuse');   // shared blocklist unread ⇒ fail closed
      assert.equal(run(relaySelf, { anchorError: 'registry unreadable' }).action, 'gate_refuse');
      assert.deepEqual(Object.keys(GATE_STATE), ['gate_allow', 'gate_warn', 'gate_refuse']);
    },
  },
];
