// src/gate.mjs evaluate(): the pre-sign gate's two rules on hand-built inputs (no network).
import { assert } from './lib.mjs';
import { evaluate, spentLast24h } from '../src/gate.mjs';

const NOW = Date.parse('2026-11-05T12:00:00Z'), H = 3.6e6;
const allow = (t, usd) => ({ t, engine: 'gate', type: 'gate', action: 'gate_allow', pendingUsd: usd });
const fresh = { timeMs: NOW - 3 * H };

export const tests = [
  { name: 'allow: fresh anchor, nothing spent, small send',
    fn() { const r = evaluate({ rows: [], anchor: fresh, pendingUsd: 3, nowMs: NOW }); assert.equal(r.allow, true); assert.equal(r.reasons.length, 0); } },
  { name: 'refuse: newest anchor older than maxAnchorAgeH (no anchoring => no spending)',
    fn() { const r = evaluate({ rows: [], anchor: { timeMs: NOW - 21 * H }, pendingUsd: 1, nowMs: NOW });
      assert.equal(r.allow, false); assert.ok(/21\.0 h old/.test(r.reasons[0])); } },
  { name: 'refuse: registry unreadable => fail closed; --fail-open skips only that rule',
    fn() {
      const closed = evaluate({ rows: [], anchor: { error: 'timeout' }, pendingUsd: 1, nowMs: NOW });
      assert.equal(closed.allow, false); assert.ok(/fail closed/.test(closed.reasons[0]));
      const open = evaluate({ rows: [], anchor: { error: 'timeout' }, pendingUsd: 1, nowMs: NOW, failOpen: true });
      assert.equal(open.allow, true); assert.equal(open.notes.length, 1);
      const openButOver = evaluate({ rows: [allow('2026-11-05T11:00:00Z', 29.5)], anchor: { error: 'timeout' }, pendingUsd: 1, nowMs: NOW, failOpen: true });
      assert.equal(openButOver.allow, false);   // the spend cap still applies
    } },
  { name: 'refuse: allowed sends in the last 24 h + this one exceed the cap; older ones and refusals do not count',
    fn() {
      const rows = [allow('2026-11-05T02:00:00Z', 20), { row: allow('2026-11-05T10:00:00Z', 8) },   // raw row and record shapes
        allow('2026-11-04T11:59:00Z', 100),                                                         // 24 h + 1 min ago: out
        { t: '2026-11-05T11:00:00Z', engine: 'gate', action: 'gate_refuse', pendingUsd: 50 }];       // a refusal is not spend
      assert.equal(spentLast24h(rows, NOW), 28);
      assert.equal(evaluate({ rows, anchor: fresh, pendingUsd: 2, nowMs: NOW }).allow, true);       // 30 = cap: allowed
      const r = evaluate({ rows, anchor: fresh, pendingUsd: 2.01, nowMs: NOW });
      assert.equal(r.allow, false); assert.ok(/\$30\.01 in 24 h would exceed the \$30 cap/.test(r.reasons[0]));
    } },
  { name: 'policy overrides and bad input',
    fn() {
      assert.equal(evaluate({ rows: [], anchor: { timeMs: NOW - 30 * H }, policy: { maxAnchorAgeH: 48 }, pendingUsd: 1, nowMs: NOW }).allow, true);
      assert.equal(evaluate({ rows: [], anchor: fresh, policy: { maxDailyUsd: 5 }, pendingUsd: 6, nowMs: NOW }).allow, false);
      assert.equal(evaluate({ rows: [], anchor: fresh, pendingUsd: NaN, nowMs: NOW }).allow, false);
      assert.equal(evaluate({ rows: [], anchor: fresh, pendingUsd: -1, nowMs: NOW }).allow, false);
    } },
];
