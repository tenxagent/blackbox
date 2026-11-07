// src/blocklist.mjs + the gate's use of it (2026-11-07): the shared blocklist other agents report to, with evidence.
import { assert } from './lib.mjs';
import { reportData, parseShared } from '../src/blocklist.mjs';
import { evaluate, judgeCounterparty, readPolicy } from '../src/gate.mjs';

const ME = '00537bf24e164c18f3512de1040d34c88a11f37976a3ef6d4de673dc9cef6590', STRANGER = 'stranger.near';
const BAD = '0x000000000000000000000000000000000000dead', RELAY = '0x' + '1'.repeat(40), HASH = '0x' + 'ab'.repeat(32);
const T = '2026-11-07T11:40:00.000Z', NOW = Date.parse('2026-11-07T12:00:00Z');
const entry = (ev = 'phishing payee from the attack demo; live refusal = record 3463') => JSON.stringify({ evidence: ev, reportedAt: T });

export const tests = [
  { name: 'blocklist: a report is written under the reporter\'s own key; bad chain, address or evidence are refused',
    fn() {
      const d = reportData({ reporter: ME, chain: 'Robinhood', address: BAD.toUpperCase().replace('0X', '0x'), evidence: 'phishing payee from the attack demo', reportedAt: T });
      assert.deepEqual(Object.keys(d), [ME]);
      assert.equal(JSON.parse(d[ME].blocklist.robinhood[BAD]).evidence, 'phishing payee from the attack demo');   // chain and address lowercased
      assert.throws(() => reportData({ reporter: ME, chain: 'robin hood', address: BAD, evidence: 'long enough text', reportedAt: T }));
      assert.throws(() => reportData({ reporter: ME, chain: 'robinhood', address: '0x123', evidence: 'long enough text', reportedAt: T }));
      assert.throws(() => reportData({ reporter: ME, chain: 'robinhood', address: BAD, evidence: 'short', reportedAt: T }));
    } },
  { name: 'blocklist: only the reporters the policy trusts count; malformed entries are skipped, not trusted',
    fn() {
      const value = { [ME]: { blocklist: { robinhood: { [BAD]: entry(), ['0x' + '2'.repeat(40)]: 'not json' } } },
        [STRANGER]: { blocklist: { robinhood: { [RELAY]: entry('Relay is a scam (a stranger says so)') } } } };
      const r = parseShared(value, [{ account: ME }]);
      assert.deepEqual(r.entries.map((e) => [e.reporter, e.chain, e.address]), [[ME, 'robinhood', BAD]]);
      assert.equal(r.skipped, 2);   // the stranger's report and the malformed entry
      assert.equal(parseShared(value, []).entries.length, 0);
    } },
  { name: 'gate: a trusted report blocks with reporter and evidence; an untrusted one cannot get a good payee refused; unreadable ⇒ refuse',
    fn() {
      const P = { self: [{ chain: 'robinhood', address: '0x' + '5'.repeat(40) }], allow: [{ chain: 'robinhood', address: RELAY, label: 'Relay proxy', codeHash: HASH }],
        trustedReporters: [{ account: ME }] };
      const shared = parseShared({ [ME]: { blocklist: { robinhood: { [BAD]: entry() } } }, [STRANGER]: { blocklist: { robinhood: { [RELAY]: entry('Relay is a scam') } } } }, P.trustedReporters);
      const go = (to, sh) => evaluate({ rows: [], anchor: { timeMs: NOW - 3.6e6 }, policy: P, pendingUsd: 1, nowMs: NOW, to, facts: { [`robinhood:${RELAY}`]: { codeHash: HASH, nonce: 1 } }, shared: sh });
      const bad = go([{ address: BAD, chain: 'robinhood', role: 'recipient' }], shared);
      assert.equal(bad.action, 'gate_refuse'); assert.match(bad.reasons.join(), new RegExp(`blocklisted by ${ME} \\(shared list, reported 2026-11-07\\): phishing payee`));
      assert.deepEqual(bad.sharedBlocklist, { reporters: 1, entries: 1 });
      assert.equal(bad.policy.trustedReporters, undefined);   // the decision records limits, not the reporter list
      const relay = go([{ address: RELAY, chain: 'robinhood', role: 'spender' }], shared);
      assert.equal(relay.action, 'gate_allow', relay.reasons.join('; '));   // the stranger's report is ignored
      const blind = go([{ address: RELAY, chain: 'robinhood', role: 'spender' }], { error: 'timeout' });
      assert.equal(blind.action, 'gate_refuse'); assert.match(blind.reasons[0], /shared blocklist not read \(timeout\): refusing \(fail closed\)/);
      assert.equal(go([{ address: RELAY, chain: 'robinhood', role: 'spender' }], undefined).action, 'gate_refuse');   // not read at all
      assert.equal(evaluate({ rows: [], anchor: { timeMs: NOW - 3.6e6 }, policy: { ...P, trustedReporters: [] }, pendingUsd: 1, nowMs: NOW,
        to: [{ address: RELAY, chain: 'robinhood' }], facts: { [`robinhood:${RELAY}`]: { codeHash: HASH, nonce: 1 } } }).action, 'gate_allow');   // no reporters ⇒ nothing to read
    } },
  { name: 'gate: the published policy trusts exactly one reporter today, the agent itself',
    fn() {
      const p = readPolicy();
      assert.deepEqual((p.trustedReporters ?? []).map((r) => r.account), [ME]);
      assert.equal(judgeCounterparty({ address: BAD, chain: 'robinhood' }, { ...p, block: [{ address: BAD, chain: 'robinhood', evidence: 'x', reporter: ME, reportedAt: T }] }, new Map()).verdict, 'block');
    } },
];
