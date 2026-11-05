// src/gate.mjs evaluate(): the pre-sign gate's three rules on hand-built inputs (no network).
import { assert } from './lib.mjs';
import { evaluate, spentLast24h, priorApproved, readPolicy, gateCoverage } from '../src/gate.mjs';
import { readFileSync } from 'node:fs';

// rule 3 fixtures: made-up addresses (0x1…, 0x2…), a code hash, and one blocklisted 0xbad… address
const RELAY = '0x' + '1'.repeat(40), HUMAN = '0x' + '2'.repeat(40), BAD = '0x' + 'bad'.repeat(13) + 'b', NEW = '0x' + '3'.repeat(40), HASH = '0x' + 'ab'.repeat(32);
const P = { allow: [{ chain: 'robinhood', address: RELAY, label: 'Relay proxy', codeHash: HASH }], trustedApis: [{ api: '1click.chaindefuser.com', label: '1Click' }],
  humanApproved: [{ address: HUMAN, by: 'operator', at: '2026-11-06' }], block: [{ address: BAD, evidence: 'drainer (test)' }] };
const OK = [{ address: RELAY, chain: 'robinhood', role: 'spender' }];

const NOW = Date.parse('2026-11-05T12:00:00Z'), H = 3.6e6;
const allow = (t, usd) => ({ t, engine: 'gate', type: 'gate', action: 'gate_allow', pendingUsd: usd });
const fresh = { timeMs: NOW - 3 * H };

export const tests = [
  { name: 'allow: fresh anchor, nothing spent, small send',
    fn() { const r = evaluate({ rows: [], anchor: fresh, pendingUsd: 3, nowMs: NOW, policy: P, to: OK }); assert.equal(r.allow, true); assert.equal(r.reasons.length, 0); } },
  { name: 'refuse: newest anchor older than maxAnchorAgeH (no anchoring => no spending)',
    fn() { const r = evaluate({ rows: [], anchor: { timeMs: NOW - 21 * H }, pendingUsd: 1, nowMs: NOW, policy: P, to: OK });
      assert.equal(r.allow, false); assert.ok(/21\.0 h old/.test(r.reasons[0])); } },
  { name: 'refuse: registry unreadable => fail closed; --fail-open skips only that rule',
    fn() {
      const closed = evaluate({ rows: [], anchor: { error: 'timeout' }, pendingUsd: 1, nowMs: NOW, policy: P, to: OK });
      assert.equal(closed.allow, false); assert.ok(/fail closed/.test(closed.reasons[0]));
      const open = evaluate({ rows: [], anchor: { error: 'timeout' }, pendingUsd: 1, nowMs: NOW, failOpen: true, policy: P, to: OK });
      assert.equal(open.allow, true); assert.equal(open.notes.length, 1);
      const openButOver = evaluate({ rows: [allow('2026-11-05T11:00:00Z', 29.5)], anchor: { error: 'timeout' }, pendingUsd: 1, nowMs: NOW, failOpen: true, policy: P, to: OK });
      assert.equal(openButOver.allow, false);   // the spend cap still applies
    } },
  { name: 'refuse: allowed sends in the last 24 h + this one exceed the cap; older ones and refusals do not count',
    fn() {
      const rows = [allow('2026-11-05T02:00:00Z', 20), { row: allow('2026-11-05T10:00:00Z', 8) },   // raw row and record shapes
        allow('2026-11-04T11:59:00Z', 100),                                                         // 24 h + 1 min ago: out
        { t: '2026-11-05T11:00:00Z', engine: 'gate', action: 'gate_refuse', pendingUsd: 50 }];       // a refusal is not spend
      assert.equal(spentLast24h(rows, NOW), 28);
      assert.equal(evaluate({ rows, anchor: fresh, pendingUsd: 2, nowMs: NOW, policy: P, to: OK }).allow, true);       // 30 = cap: allowed
      const r = evaluate({ rows, anchor: fresh, pendingUsd: 2.01, nowMs: NOW, policy: P, to: OK });
      assert.equal(r.allow, false); assert.ok(/\$30\.01 in 24 h would exceed the \$30 cap/.test(r.reasons[0]));
    } },
  { name: 'policy overrides and bad input',
    fn() {
      assert.equal(evaluate({ rows: [], anchor: { timeMs: NOW - 30 * H }, policy: { ...P, maxAnchorAgeH: 48 }, pendingUsd: 1, nowMs: NOW, to: OK }).allow, true);
      assert.equal(evaluate({ rows: [], anchor: fresh, policy: { ...P, maxDailyUsd: 5 }, pendingUsd: 6, nowMs: NOW, to: OK }).allow, false);
      assert.equal(evaluate({ rows: [], anchor: fresh, pendingUsd: NaN, nowMs: NOW, policy: P, to: OK }).allow, false);
      assert.equal(evaluate({ rows: [], anchor: fresh, pendingUsd: -1, nowMs: NOW, policy: P, to: OK }).allow, false);
    } },
  { name: 'rule 3: blocklisted => block (gate_refuse); allow-listed => allow; changed code hash => warn (gate_warn)',
    fn() {
      const g = (to, facts) => evaluate({ rows: [], anchor: fresh, pendingUsd: 1, nowMs: NOW, policy: P, to, facts });
      const b = g([{ address: BAD.toUpperCase().replace('0X', '0x') }]);
      assert.equal(b.allow, false); assert.equal(b.action, 'gate_refuse'); assert.ok(/^BLOCK .*blocklisted: drainer \(test\)/.test(b.reasons[0]));
      const a = g(OK, { [RELAY]: { codeHash: HASH } });
      assert.equal(a.allow, true); assert.equal(a.action, 'gate_allow'); assert.equal(a.counterparties[0].why, 'allow-listed: Relay proxy');
      const changed = g(OK, { [RELAY]: { codeHash: '0x' + 'cd'.repeat(32) } });
      assert.equal(changed.allow, false); assert.equal(changed.action, 'gate_warn'); assert.ok(/code hash changed/.test(changed.reasons[0]));
      assert.equal(g([{ address: RELAY, chain: 'elysium' }]).allow, false);   // an allow entry is per chain
      assert.ok(/could not be read/.test(g(OK, { [RELAY]: { error: 'rpc timeout' } }).reasons[0]));   // unreadable code => warn, not a silent pass
      assert.equal(g(OK, { [RELAY]: { codeHash: null } }).action, 'gate_warn');                        // code removed => warn
    } },
  { name: 'rule 3: trusted-API provenance, a committed human approval, or a prior approved send => allow',
    fn() {
      const g = (to, rows = []) => evaluate({ rows, anchor: fresh, pendingUsd: 1, nowMs: NOW, policy: P, to });
      const api = g([{ address: NEW, provenance: { api: '1click.chaindefuser.com', path: '/v0/quote' } }]);
      assert.equal(api.allow, true); assert.deepEqual(api.counterparties[0].provenance, { api: '1click.chaindefuser.com', path: '/v0/quote' });
      assert.equal(g([{ address: NEW, provenance: { api: 'evil.example' } }]).action, 'gate_warn');   // provenance from an API the policy does not name
      assert.equal(g([{ address: HUMAN }]).counterparties[0].why, 'approved by a human: operator, 2026-11-06');
      const before = { t: '2026-11-05T09:00:00Z', engine: 'gate', type: 'gate', action: 'gate_allow', pendingUsd: 1, to: [NEW] };
      assert.equal(g([{ address: NEW }], [before]).counterparties[0].why, 'prior interaction: 1 earlier approved send');
      const refusedBefore = { ...before, action: 'gate_refuse' }, later = { ...before, t: '2026-11-05T13:00:00Z' };
      assert.equal(priorApproved([refusedBefore, { row: later }], NOW).size, 0);   // a refusal or a future row is no interaction
    } },
  { name: 'rule 3: unknown address => warn (refused, waiting for a human); none given => refuse; warn + over cap => gate_refuse',
    fn() {
      const w = evaluate({ rows: [], anchor: fresh, pendingUsd: 1, nowMs: NOW, policy: P, to: [...OK, { address: NEW, role: 'recipient' }], facts: { [NEW]: { nonce: 0, codeHash: null } } });
      assert.equal(w.allow, false); assert.equal(w.action, 'gate_warn'); assert.equal(w.reasons.length, 1);
      assert.ok(w.reasons[0].startsWith(`WARN ${NEW} (recipient): unknown counterparty`) && /fresh address \(0 txs, no code\)/.test(w.reasons[0]) && /ask a human/.test(w.reasons[0]));
      const none = evaluate({ rows: [], anchor: fresh, pendingUsd: 1, nowMs: NOW, policy: P });
      assert.equal(none.allow, false); assert.ok(/no counterparty given/.test(none.reasons[0]));
      const over = evaluate({ rows: [], anchor: fresh, pendingUsd: 31, nowMs: NOW, policy: P, to: [{ address: NEW }] });
      assert.equal(over.action, 'gate_refuse');
    } },
  { name: 'gate.policy.json: every allow entry has chain, lowercase address, label, source and code hash; no duplicates',
    fn() {
      const pol = readPolicy(), seen = new Set();
      assert.ok(pol.maxAnchorAgeH > 0 && pol.maxDailyUsd > 0);
      for (const e of pol.allow) {
        assert.ok(/^0x[0-9a-f]{40}$/.test(e.address) && e.chain && e.label && e.source && /^0x[0-9a-f]{64}$/.test(e.codeHash), JSON.stringify(e));
        assert.ok(!seen.has(e.chain + e.address)); seen.add(e.chain + e.address);
      }
      for (const k of ['trustedApis', 'humanApproved', 'block']) assert.ok(Array.isArray(pol[k]), k);
    } },
  { name: 'gate coverage: every gated send needs its own gate decision shortly before it; the committed log has none missing',
    fn() {
      const g = (t, what, action = 'gate_allow') => ({ t, engine: 'gate', type: 'gate', action, what });
      const swap = (t) => ({ t, engine: 'swap', type: 'live', action: 'relay_swap' });
      const since = '2026-11-06T00:00:00Z';
      const ok = gateCoverage([g('2026-11-06T01:00:00Z', 'relay swap 1 USDG -> ETH'), swap('2026-11-06T01:00:20Z')], { since });
      assert.deepEqual([ok.sends, ok.covered, ok.missing.length], [1, 1, 0]);
      const twice = gateCoverage([g('2026-11-06T01:00:00Z', 'relay swap 1'), swap('2026-11-06T01:00:20Z'), swap('2026-11-06T01:01:00Z')], { since });
      assert.equal(twice.missing.length, 1);                                    // one decision covers one send
      assert.equal(gateCoverage([g('2026-11-06T01:00:00Z', 'relay swap 1'), swap('2026-11-06T01:20:00Z')], { since }).missing.length, 1);   // > 15 min
      assert.equal(gateCoverage([g('2026-11-06T01:00:00Z', 'near fund 1 USDG'), swap('2026-11-06T01:00:20Z')], { since }).missing.length, 1); // other kind
      assert.equal(gateCoverage([g('2026-11-06T01:00:00Z', 'relay swap 1', 'gate_bypass'), swap('2026-11-06T01:00:20Z')], { since }).bypassed, 1);
      assert.equal(gateCoverage([swap('2026-11-05T23:00:00Z')], { since }).sends, 0);   // before the gate went live
      const rows = readFileSync(new URL('../data/records.jsonl', import.meta.url), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
      const c = gateCoverage(rows);
      assert.ok(c.sends >= 2); assert.equal(c.missing.length, 0, JSON.stringify(c.missing));
    } },
];
