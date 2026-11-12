// src/gate.mjs evaluate(): the pre-sign gate's three rules on hand-built inputs (no network).
import { assert } from './lib.mjs';
import { evaluate, spentLast24h, priorApproved, readPolicy, gateCoverage, judgeCounterparty, decodeTxs, txDigest, newestPublished, isPinned } from '../src/gate.mjs';
import { readFileSync } from 'node:fs';

// rule 3 fixtures: made-up addresses (0x1…, 0x2…), a code hash, and one blocklisted 0xbad… address
const RELAY = '0x' + '1'.repeat(40), HUMAN = '0x' + '2'.repeat(40), BAD = '0x' + 'bad'.repeat(13) + 'b', NEW = '0x' + '3'.repeat(40), HASH = '0x' + 'ab'.repeat(32);
const SELF = '0x' + '5'.repeat(40), ROUTER = '0x' + '6'.repeat(40);
const P = { self: [{ chain: 'robinhood', address: SELF }],
  allow: [{ chain: 'robinhood', address: RELAY, label: 'Relay proxy', codeHash: HASH }, { chain: 'robinhood', address: ROUTER, label: 'Router', codeHash: HASH, forwards: true }],
  trustedApis: [{ api: '1click.chaindefuser.com', label: '1Click', forwards: true }],
  humanApproved: [{ chain: 'robinhood', address: HUMAN, by: 'operator', at: '2026-11-06' }], block: [{ address: BAD, evidence: 'drainer (test)' }] };
const OK = [{ address: RELAY, chain: 'robinhood', role: 'spender' }];
const F = { [`robinhood:${RELAY}`]: { codeHash: HASH, nonce: 1 }, [`robinhood:${ROUTER}`]: { codeHash: HASH, nonce: 1 } };   // what readFacts() returns for them

const NOW = Date.parse('2026-11-05T12:00:00Z'), H = 3.6e6;
// tx fixtures: USDG on Robinhood Chain (priced), another token (not priced), transfer/approve calldata built by hand
const USDG = '0x5fc5360d0400a0fd4f2af552add042d716f1d168', OTHER_TOKEN = '0x' + '7'.repeat(40), MAX = (1n << 256n) - 1n;
const word = (x) => BigInt(x).toString(16).padStart(64, '0');
const tUSDG = (to, n) => ({ chain: 'robinhood', to: USDG, data: '0xa9059cbb' + word(to) + word(n), value: '0x0' });
const aUSDG = (sp, n) => ({ chain: 'robinhood', to: USDG, data: '0x095ea7b3' + word(sp) + word(n), value: '0x0' });
const DECL = [{ address: HUMAN, chain: 'robinhood', role: 'recipient' }];   // a human-approved payee
const allow = (t, usd) => ({ t, engine: 'gate', type: 'gate', action: 'gate_allow', pendingUsd: usd });
const fresh = { timeMs: NOW - 3 * H };

export const tests = [
  { name: 'rule 3 lookalike (2026-11-12): same first and last 4 hex as a known address but different ⇒ block, even when human-approved; exact known addresses and other payees are untouched',
    fn() {
      const look = (a) => '0x' + a.slice(2, 6) + '9'.repeat(32) + a.slice(-4);           // starts and ends like a, a different address
      const L_SELF = look(SELF), L_RELAY = look(RELAY), L_HUMAN = look(HUMAN), PRIOR = '0x' + 'c0de' + 'e'.repeat(32) + 'f00d';
      const j = (a, pol = P, prior = new Map()) => judgeCounterparty({ address: a, chain: 'robinhood', role: 'recipient' }, pol, prior, {});
      const self = j(L_SELF);
      assert.equal(self.verdict, 'block'); assert.equal(self.lookalikeOf, SELF);
      assert.match(self.why, /^address-poisoning lookalike of the agent's own address 0x5{40}: the same first 4 and last 4 hex characters/);
      assert.equal(j(L_RELAY).verdict, 'block'); assert.match(j(L_RELAY).why, /lookalike of the allow-listed Relay proxy/);
      assert.equal(j(L_HUMAN).verdict, 'block'); assert.match(j(L_HUMAN).why, /lookalike of a human-approved payee/);
      // a human approval of the lookalike itself does not clear it
      const approved = { ...P, humanApproved: [...P.humanApproved, { chain: 'robinhood', address: L_SELF, by: 'operator', at: '2026-11-12' }] };
      assert.equal(j(L_SELF, approved).verdict, 'block');
      // an earlier approved payee counts too (any chain key in the prior map)
      assert.equal(j(look(PRIOR), P, new Map([[`robinhood:${PRIOR}`, 1]])).verdict, 'block');
      assert.equal(j(look(PRIOR), P, new Map([[`elysium:${PRIOR}`, 2]])).verdict, 'block');
      // exact known addresses are never lookalikes: the allow-listed one still allows, the human-approved one still allows
      assert.equal(judgeCounterparty({ address: RELAY, chain: 'robinhood', role: 'spender' }, P, new Map(), F[`robinhood:${RELAY}`]).verdict, 'allow');
      assert.equal(j(HUMAN).verdict, 'allow');
      // only the first 4 or only the last 4 equal: not a lookalike (an ordinary unknown payee, warn)
      assert.equal(j('0x5555' + '9'.repeat(36)).verdict, 'warn');
      assert.equal(j('0x' + '9'.repeat(36) + '5555').verdict, 'warn');
      assert.equal(j(NEW).verdict, 'warn');
      // an allow-listed address that happens to look like another known one is still allowed (exact entries win)
      const both = { ...P, allow: [...P.allow, { chain: 'robinhood', address: L_SELF, label: 'deliberately listed' }] };
      assert.equal(j(L_SELF, both).verdict, 'allow');
      // NEAR account ids are not compared
      assert.equal(judgeCounterparty({ address: 'x.near', chain: 'near' }, P, new Map([['near:y.near', 1]]), {}).verdict, 'warn');
    } },
  { name: 'allow: fresh anchor, nothing spent, small send',
    fn() { const r = evaluate({ rows: [], anchor: fresh, pendingUsd: 3, nowMs: NOW, policy: P, to: OK, facts: F }); assert.equal(r.allow, true); assert.equal(r.reasons.length, 0); } },
  { name: 'refuse: newest anchor older than maxAnchorAgeH (no anchoring => no spending)',
    fn() { const r = evaluate({ rows: [], anchor: { timeMs: NOW - 21 * H }, pendingUsd: 1, nowMs: NOW, policy: P, to: OK, facts: F });
      assert.equal(r.allow, false); assert.ok(/21\.0 h old/.test(r.reasons[0])); } },
  { name: 'refuse: registry unreadable => fail closed; --fail-open skips only that rule',
    fn() {
      const closed = evaluate({ rows: [], anchor: { error: 'timeout' }, pendingUsd: 1, nowMs: NOW, policy: P, to: OK, facts: F });
      assert.equal(closed.allow, false); assert.ok(/fail closed/.test(closed.reasons[0]));
      const open = evaluate({ rows: [], anchor: { error: 'timeout' }, pendingUsd: 1, nowMs: NOW, failOpen: true, policy: P, to: OK, facts: F });
      assert.equal(open.allow, true); assert.equal(open.notes.length, 1);
      const openButOver = evaluate({ rows: [allow('2026-11-05T11:00:00Z', 29.5)], anchor: { error: 'timeout' }, pendingUsd: 1, nowMs: NOW, failOpen: true, policy: P, to: OK, facts: F });
      assert.equal(openButOver.allow, false);   // the spend cap still applies
    } },
  { name: 'refuse: allowed sends in the last 24 h + this one exceed the cap; older ones and refusals do not count',
    fn() {
      const rows = [allow('2026-11-05T02:00:00Z', 20), { row: allow('2026-11-05T10:00:00Z', 8) },   // raw row and record shapes
        allow('2026-11-04T11:59:00Z', 100),                                                         // 24 h + 1 min ago: out
        { t: '2026-11-05T11:00:00Z', engine: 'gate', action: 'gate_refuse', pendingUsd: 50 }];       // a refusal is not spend
      assert.equal(spentLast24h(rows, NOW), 28);
      assert.equal(evaluate({ rows, anchor: fresh, pendingUsd: 2, nowMs: NOW, policy: P, to: OK, facts: F }).allow, true);       // 30 = cap: allowed
      const r = evaluate({ rows, anchor: fresh, pendingUsd: 2.01, nowMs: NOW, policy: P, to: OK, facts: F });
      assert.equal(r.allow, false); assert.ok(/\$30\.01 in 24 h would exceed the \$30 cap/.test(r.reasons[0]));
    } },
  { name: 'policy overrides and bad input',
    fn() {
      assert.equal(evaluate({ rows: [], anchor: { timeMs: NOW - 30 * H }, policy: { ...P, maxAnchorAgeH: 48 }, pendingUsd: 1, nowMs: NOW, to: OK, facts: F }).allow, true);
      assert.equal(evaluate({ rows: [], anchor: fresh, policy: { ...P, maxDailyUsd: 5 }, pendingUsd: 6, nowMs: NOW, to: OK, facts: F }).allow, false);
      assert.equal(evaluate({ rows: [], anchor: fresh, pendingUsd: NaN, nowMs: NOW, policy: P, to: OK, facts: F }).allow, false);
      assert.equal(evaluate({ rows: [], anchor: fresh, pendingUsd: -1, nowMs: NOW, policy: P, to: OK, facts: F }).allow, false);
    } },
  { name: 'rule 3: blocklisted => block (gate_refuse); allow-listed => allow; changed code hash => warn (gate_warn)',
    fn() {
      const g = (to, facts) => evaluate({ rows: [], anchor: fresh, pendingUsd: 1, nowMs: NOW, policy: P, to, facts });
      const b = g([{ address: BAD.toUpperCase().replace('0X', '0x') }]);   // a chainless block entry blocks with or without a chain
      assert.equal(b.allow, false); assert.equal(b.action, 'gate_refuse'); assert.ok(/^BLOCK .*blocklisted: drainer \(test\)/.test(b.reasons[0]));
      const a = g(OK, F);
      assert.equal(a.allow, true); assert.equal(a.action, 'gate_allow'); assert.equal(a.counterparties[0].why, 'allow-listed: Relay proxy');
      const changed = g(OK, { [`robinhood:${RELAY}`]: { codeHash: '0x' + 'cd'.repeat(32) } });
      assert.equal(changed.allow, false); assert.equal(changed.action, 'gate_warn'); assert.ok(/code hash changed/.test(changed.reasons[0]));
      assert.equal(g([{ address: RELAY, chain: 'elysium' }], F).allow, false);   // an allow entry is per chain
      assert.ok(/unknown counterparty/.test(g([{ address: RELAY, chain: 'elysium' }], { [`elysium:${RELAY}`]: { codeHash: HASH, nonce: 1 } }).reasons[0]));   // same code there, still not listed there
      assert.ok(/could not be read/.test(g(OK, { [`robinhood:${RELAY}`]: { error: 'rpc timeout' } }).reasons[0]));   // unreadable code => warn, not a silent pass
      assert.equal(g(OK, { [`robinhood:${RELAY}`]: { codeHash: null } }).action, 'gate_warn');
      assert.ok(/code hash not checked/.test(g(OK).reasons[0]));                                      // no on-chain read => warn                        // code removed => warn
    } },
  { name: 'rule 3: trusted-API provenance or a committed human approval => allow; a prior approved send alone => warn (history is a signal since 2026-11-08)',
    fn() {
      const g = (to, rows = []) => evaluate({ rows, anchor: fresh, pendingUsd: 1, nowMs: NOW, policy: P, to });
      const api = g([{ address: NEW, chain: 'robinhood', provenance: { api: '1click.chaindefuser.com', path: '/v0/quote', recipient: SELF } }]);
      assert.equal(api.allow, true); assert.equal(api.counterparties[0].provenance.path, '/v0/quote');
      assert.equal(g([{ address: NEW, chain: 'robinhood', provenance: { api: 'evil.example' } }]).action, 'gate_warn');   // provenance from an API the policy does not name
      assert.ok(g([{ address: HUMAN, chain: 'robinhood' }]).counterparties[0].why.startsWith('approved by a human: operator, 2026-11-06'));
      const before = { t: '2026-11-05T09:00:00Z', engine: 'gate', type: 'gate', action: 'gate_allow', pendingUsd: 1, to: [NEW], counterparties: [{ address: NEW, chain: 'robinhood' }] };
      const again = g([{ address: NEW, chain: 'robinhood' }], [before]);
      assert.equal(again.action, 'gate_warn'); assert.match(again.counterparties[0].why, /1 earlier approved send on this chain, but history alone never clears a payee/); assert.equal(again.counterparties[0].priorSends, 1);
      // revocation (screen 6 B-1): an allow-listed router removed from the policy is not cleared by its earlier sends, even with a self recipient
      const delisted = evaluate({ rows: [{ ...before, to: [RELAY], counterparties: [{ address: RELAY, chain: 'robinhood', verdict: 'allow', why: 'allow-listed: Relay proxy' }] }], anchor: fresh, pendingUsd: 1, nowMs: NOW,
        policy: { ...P, allow: P.allow.filter((e) => e.address !== RELAY) }, to: [{ address: RELAY, chain: 'robinhood', role: 'spender', recipient: SELF }], facts: F });
      assert.equal(delisted.action, 'gate_warn');
      assert.equal(g([{ address: NEW, chain: 'elysium' }], [before]).action, 'gate_warn');                 // a prior send on another chain does not count
      assert.equal(priorApproved([{ ...before, counterparties: undefined }], NOW).size, 0);                // a bare `to` list (no chain) counts for nothing
      const refusedBefore = { ...before, action: 'gate_refuse' }, later = { ...before, t: '2026-11-05T13:00:00Z' };
      assert.equal(priorApproved([refusedBefore, { row: later }], NOW).size, 0);   // a refusal or a future row is no interaction
    } },
  { name: 'rule 3: unknown address => warn (refused, waiting for a human); none given => refuse; warn + over cap => gate_refuse',
    fn() {
      const w = evaluate({ rows: [], anchor: fresh, pendingUsd: 1, nowMs: NOW, policy: P, to: [...OK, { address: NEW, chain: 'robinhood', role: 'recipient' }], facts: { ...F, [`robinhood:${NEW}`]: { nonce: 0, codeHash: null } } });
      assert.equal(w.allow, false); assert.equal(w.action, 'gate_warn'); assert.equal(w.reasons.length, 1);
      assert.ok(w.reasons[0].startsWith(`WARN ${NEW} (recipient): unknown counterparty`) && /fresh address \(0 txs, no code\)/.test(w.reasons[0]) && /ask a human/.test(w.reasons[0]));
      const none = evaluate({ rows: [], anchor: fresh, pendingUsd: 1, nowMs: NOW, policy: P });
      assert.equal(none.allow, false); assert.ok(/no counterparty given/.test(none.reasons[0]));
      const over = evaluate({ rows: [], anchor: fresh, pendingUsd: 31, nowMs: NOW, policy: P, to: [{ address: NEW, chain: 'robinhood' }] });
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
      assert.ok(pol.self.some((x) => x.address === '0x00731cd9e0bc7cad1b54f85187b09b942cd3be04') && pol.self.every((x) => x.chain && x.label));
      for (const e of [...pol.allow, ...pol.trustedApis]) assert.equal(e.forwards, true, `${e.label} forwards value: it must say so`);
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
  { name: 'rule 3: no chain => warn; a forwarding entry needs the final recipient and it must be the agent itself; unpublished policy refuses',
    fn() {
      const P2 = { ...P }, j = (c, facts = F) => judgeCounterparty(c, P2, new Map(), facts[`${c.chain}:${c.address}`] ?? {});
      assert.ok(/no chain given/.test(j({ address: RELAY }).why));
      assert.ok(/no final recipient/.test(j({ address: ROUTER, chain: 'robinhood' }).why));
      assert.ok(/not one of the agent's own addresses/.test(j({ address: ROUTER, chain: 'robinhood', recipient: NEW }).why));
      assert.equal(j({ address: ROUTER, chain: 'robinhood', recipient: SELF.toUpperCase().replace('0X', '0x') }).verdict, 'allow');
      assert.ok(/no final recipient/.test(j({ address: NEW, chain: 'robinhood', provenance: { api: '1click.chaindefuser.com' } }).why));   // 1Click address, recipient not given
      assert.ok(/not one of the agent's own/.test(j({ address: NEW, chain: 'robinhood', provenance: { api: '1click.chaindefuser.com', recipient: 'attacker.near' } }).why));
      const r = evaluate({ rows: [], anchor: fresh, pendingUsd: 1, nowMs: NOW, policy: P, to: OK, facts: F, published: { ok: false, why: 'the policy file on disk differs from the published one' } });
      assert.equal(r.action, 'gate_refuse'); assert.ok(/policy not usable/.test(r.reasons[0]));
      assert.equal(evaluate({ rows: [], anchor: fresh, pendingUsd: 1, nowMs: NOW, policy: P, to: OK, facts: F, published: { ok: true } }).allow, true);
    } },
  // ---- the transactions themselves (2026-11-06): the gate decodes the unsigned txs instead of believing the description ----
  { name: 'txs: decodeTxs reads transfer / approve / native value / plain calls, prices only USDG, and flags unlimited approvals',
    fn() {
      const d = decodeTxs([tUSDG(SELF, 1_500_000), aUSDG(RELAY, 2_000_000), { chain: 'robinhood', to: ROUTER, data: '0x12345678', value: '0x0' },
        { chain: 'robinhood', to: NEW, data: '0x', value: '0x10' }, { chain: 'robinhood', to: OTHER_TOKEN, data: tUSDG(NEW, 7).data, value: 0 }, aUSDG(BAD, MAX)]);
      assert.deepEqual(d.counterparties.map((c) => [c.address, c.role]), [[SELF, 'transfer recipient'], [RELAY, 'approve spender'], [ROUTER, 'call target'],
        [NEW, 'native value'], [NEW, 'transfer recipient'], [BAD, 'approve spender']]);
      assert.equal(d.usd, 3.5);   // 1.5 USDG sent + 2 USDG approved; the other token and the native coin are not priced
      assert.equal(d.unpriced.length, 2); assert.deepEqual(d.unlimited.map((u) => u.spender), [BAD]); assert.equal(d.errors.length, 0);
      assert.equal(decodeTxs([{ chain: 'robinhood', to: USDG, data: tUSDG(SELF, 1).data.slice(0, 74), value: 0 }]).errors.length, 1);   // cut calldata
      assert.equal(decodeTxs([{ to: USDG, data: '0x' }]).errors.length, 1);   // no chain
    } },
  { name: 'txs: the digest is the same for the same tx however it is written (case, hex or decimal value), and differs when anything changes',
    fn() {
      const t = tUSDG(SELF, 1_000_000), dgt = txDigest(t);
      assert.equal(txDigest({ ...t, to: t.to.toUpperCase().replace('0X', '0x'), data: t.data.toUpperCase().replace('0X', '0x'), value: '0' }), dgt);
      assert.equal(txDigest({ ...t, value: 0n }), dgt);
      assert.notEqual(txDigest(tUSDG(SELF, 1_000_001)), dgt); assert.notEqual(txDigest({ ...t, chain: 'elysium' }), dgt);
    } },
  { name: 'txs: honest transfer allowed and its digest returned; an undeclared payee, an understated USDG amount, an unlimited approval or no tx at all are refused',
    fn() {
      const go = (txs, usd = 1, to = DECL) => evaluate({ rows: [], anchor: fresh, pendingUsd: usd, nowMs: NOW, policy: P, to, facts: F, txs });
      const ok = go([tUSDG(HUMAN, 1_000_000)]);
      assert.equal(ok.action, 'gate_allow', ok.reasons.join('; ')); assert.equal(ok.shownTxs[0].digest, txDigest(tUSDG(HUMAN, 1_000_000))); assert.equal(ok.shownUsd, 1);
      const pays = go([tUSDG(NEW, 1_000_000)]);   // escape 16 direct: the description names the agent, the bytes pay someone else
      assert.equal(pays.action, 'gate_refuse'); assert.match(pays.reasons.join(), /did not declare it/);
      const under = go([tUSDG(HUMAN, 22_155_330)], 0.01);   // escape 27 for USDG
      assert.equal(under.action, 'gate_refuse'); assert.match(under.reasons.join(), /\$22\.15533 of USDG; the caller declared \$0\.01/);
      assert.equal(go([tUSDG(HUMAN, 1_025_000)]).allow, true);   // inside 2 % + 1 cent of $1
      const unl = go([aUSDG(RELAY, MAX)], 1, [{ address: RELAY, chain: 'robinhood', role: 'spender' }]);
      assert.equal(unl.action, 'gate_refuse'); assert.match(unl.reasons.join(), /unlimited USDG approval/);
      assert.equal(go([]).action, 'gate_refuse');
      const cap = go([tUSDG(HUMAN, 31_000_000)], 31); assert.match(cap.reasons.join(), /exceed the \$30 cap/);
    } },
  { name: 'price ceilings (2026-11-07, escape 29): an amount the gate cannot price exactly is counted at the published ceiling, or refused without one',
    fn() {
      const CEIL = [{ chain: 'robinhood', token: 'native', symbol: 'ETH', decimals: 18, usd: 3000 }, { chain: 'robinhood', token: OTHER_TOKEN, symbol: 'OTH', decimals: 18, usd: 0.5 }];
      const PC = { ...P, priceCeilings: CEIL };
      const nat = (wei) => ({ chain: 'robinhood', to: RELAY, data: '0x12345678', value: '0x' + BigInt(wei).toString(16) });
      const aOTH = (n) => ({ chain: 'robinhood', to: OTHER_TOKEN, data: '0x095ea7b3' + word(RELAY) + word(n), value: '0x0' });
      // decodeTxs: native and the listed token are counted at their ceilings; without ceilings both are unpriced
      const d = decodeTxs([nat(10n ** 15n), aOTH(4n * 10n ** 18n), tUSDG(SELF, 1_000_000)], CEIL);
      assert.equal(d.usd, 1); assert.equal(d.ceilingUsd, 5);   // 0.001 ETH × $3,000 + 4 OTH × $0.5
      assert.equal(d.unpriced.length, 0); assert.equal(d.bounded.length, 2);
      assert.equal(decodeTxs([nat(10n ** 15n), aOTH(1n)]).unpriced.length, 2);
      assert.equal(decodeTxs([{ ...nat(10n ** 15n), chain: 'elysium' }], CEIL).unpriced.length, 1);   // ceilings are per chain
      const go = (txs, usd, rows = []) => evaluate({ rows, anchor: fresh, pendingUsd: usd, nowMs: NOW, policy: PC, to: OK, facts: F, txs });
      // an honest small native swap is allowed; the decision counts it at the ceiling and records that
      const ok = go([nat(10n ** 15n)], 2.24);
      assert.equal(ok.action, 'gate_allow', ok.reasons.join('; ')); assert.equal(ok.countedUsd, 3); assert.match(ok.notes.join(), /published price ceilings/);
      // escape 27 with the native coin: 0.012 ETH declared as $0.01 counts $36 > the $30 cap
      const under = go([nat(12n * 10n ** 15n)], 0.01);
      assert.equal(under.action, 'gate_refuse'); assert.match(under.reasons.join(), /\$36\.00 in 24 h would exceed the \$30 cap/);
      // escape 29: a token with no published ceiling cannot be bounded ⇒ refused
      const UNK = '0x' + '9'.repeat(40);
      const unk = go([{ chain: 'robinhood', to: UNK, data: '0x095ea7b3' + word(RELAY) + word(10n ** 24n), value: '0x0' }], 0.01);
      assert.equal(unk.action, 'gate_refuse'); assert.match(unk.reasons.join(), /cannot bound this spend/);
      // rule 2 history: an earlier decision's countedUsd counts, not only its declared figure
      const earlier = { ...allow('2026-11-05T11:00:00Z', 0.01), countedUsd: 28 };
      assert.equal(spentLast24h([earlier], NOW), 28);
      assert.equal(go([nat(10n ** 15n)], 2.24, [earlier]).action, 'gate_refuse');   // 28 + 3 > 30
    } },
  { name: "activity (2026-11-07, the prompt's age/activity signal): an unknown payee's warn names what the chain shows; unreadable facts are said, not guessed",
    fn() {
      const used = judgeCounterparty({ address: NEW, chain: 'robinhood' }, P, new Map(), { nonce: 1, codeHash: null, balanceWei: '2000000000000000' });
      assert.equal(used.verdict, 'warn'); assert.match(used.why, /on chain: 1 tx sent, no code, balance 0\.00200 native \(barely used\)/);
      assert.deepEqual(used.activity, { txsSent: 1, contract: false, balanceWei: '2000000000000000' });
      const busy = judgeCounterparty({ address: NEW, chain: 'robinhood' }, P, new Map(), { nonce: 812, codeHash: HASH });
      assert.match(busy.why, /on chain: a contract, nonce 812 \(for a contract the nonce counts the contracts it created/); assert.doesNotMatch(busy.why, /barely used/);
      const blind = judgeCounterparty({ address: NEW, chain: 'robinhood' }, P, new Map(), { error: 'timeout' });
      assert.equal(blind.verdict, 'warn'); assert.match(blind.why, /on-chain facts unreadable \(timeout\)/); assert.equal(blind.activity, undefined);
      // an allow-listed or prior-approved payee is not touched by these facts
      assert.equal(judgeCounterparty({ address: RELAY, chain: 'robinhood' }, P, new Map(), { codeHash: HASH, nonce: 1 }).verdict, 'allow');
    } },
  { name: 'txs: without txs the decision is exactly what it was before (the judge steps run that path)',
    fn() {
      const a = evaluate({ rows: [], anchor: fresh, pendingUsd: 3, nowMs: NOW, policy: P, to: OK, facts: F });
      assert.equal(a.shownTxs, undefined); assert.equal(a.allow, true); assert.deepEqual(a.notes, []);
    } },
  { name: "1Click's own record decides (2026-11-06): fresh record paying and refunding the agent ⇒ allow; another recipient, other refunds, a used record, no record, unread or unreadable ⇒ warn",
    fn() {
      const PS = { ...P, self: [...P.self, { chain: 'near', address: 'agent.near' }], trustedApis: [{ ...P.trustedApis[0], status: 'https://1click.example/v0/status?depositAddress=' }] };
      const DEP = '0x' + '8'.repeat(40), c = [{ address: DEP, chain: 'robinhood', role: 'deposit address', provenance: { api: '1click.chaindefuser.com', recipient: SELF } }];
      const rec = (o) => ({ [`robinhood:${DEP}`]: { api: { status: 'PENDING_DEPOSIT', recipient: 'agent.near', refundTo: SELF, appFeeBps: 20, ...o } } });
      const go = (facts) => evaluate({ rows: [], anchor: fresh, pendingUsd: 1, nowMs: NOW, policy: PS, to: c, facts });
      const ok = go(rec({}));
      assert.equal(ok.action, 'gate_allow', ok.reasons.join('; ')); assert.match(ok.counterparties[0].why, /its own record \(PENDING_DEPOSIT\) pays the agent/);
      for (const [facts, re] of [[rec({ recipient: 'attacker.near' }), /pays attacker\.near/], [rec({ refundTo: NEW }), /refunds to/], [rec({ status: 'SUCCESS' }), /says SUCCESS/],
        [{ [`robinhood:${DEP}`]: { api: { notFound: true, status: null } } }, /never issued it/], [{}, /was not read/], [{ [`robinhood:${DEP}`]: { apiError: 'timeout' } }, /could not be read \(timeout\)/]]) {
        const r = go(facts); assert.equal(r.action, 'gate_warn', JSON.stringify(facts)); assert.match(r.reasons[0], re);
      }
      // the caller's own label no longer counts: it says the agent, the record says attacker ⇒ warn
      assert.equal(go(rec({ recipient: 'attacker.near' })).allow, false);
      // an API entry without a status URL keeps the old rule (the caller's recipient)
      assert.equal(evaluate({ rows: [], anchor: fresh, pendingUsd: 1, nowMs: NOW, policy: P, to: c, facts: {} }).allow, true);
    } },
  { name: 'rule 1 (screen 5 Z-1): only anchors pinned to a published commit count; a pre-send anchor (records_url = main) does not refresh it',
    fn() {
      const at = (iso) => BigInt(Date.parse(iso)) * 1_000_000n;
      const pinned = { seq: 3686, recordsUrl: 'https://raw.githubusercontent.com/tenxagent/blackbox/761f0b3d29953a5bd23bdbb084497992d3d54d87/data/records.jsonl', timestampNs: at('2026-11-06T14:34:00Z') };
      const preSend = { seq: 3697, recordsUrl: 'https://raw.githubusercontent.com/tenxagent/blackbox/main/data/records.jsonl', timestampNs: at('2026-11-07T14:00:00Z') };
      assert.equal(isPinned(pinned.recordsUrl), true); assert.equal(isPinned(preSend.recordsUrl), false); assert.equal(isPinned(undefined), false);
      const r = newestPublished([pinned, preSend]);
      assert.deepEqual(r, { timeMs: Date.parse('2026-11-06T14:34:00Z'), seq: 3686 });
      // a day of pre-send anchors with no published cycle: rule 1 sees the 14:34 anchor (> 20 h) and refuses
      const e = evaluate({ rows: [], anchor: r, pendingUsd: 1, nowMs: Date.parse('2026-11-07T14:00:05Z'), policy: P, to: [{ address: RELAY, chain: 'robinhood', role: 'spender' }], facts: { [`robinhood:${RELAY}`]: { codeHash: HASH } } });
      assert.equal(e.allow, false); assert.match(e.reasons.join(' '), /newest published anchor is 23\.\d h old/);
      assert.match(newestPublished([preSend]).error, /no anchor pinned/);
    } },
  { name: 'rule 3 (screen 5 Z-3): an address allowed only because a trusted API issued it is never re-cleared by "prior interaction"',
    fn() {
      const DEP = '0x' + '9'.repeat(40);
      const earlier = { row: { t: new Date(NOW - 3.6e6).toISOString(), engine: 'gate', action: 'gate_allow', counterparties: [
        { address: DEP, chain: 'robinhood', verdict: 'allow', via: 'api', why: 'from a trusted API: 1Click; its own record …', provenance: { api: '1click.chaindefuser.com' } },
        { address: RELAY, chain: 'robinhood', verdict: 'allow', via: 'allowlist', why: 'allow-listed: Relay proxy' }] } };
      const legacy = { row: { ...earlier.row, counterparties: [{ address: DEP, chain: 'robinhood', why: 'from a trusted API: 1Click' }] } };   // rows before `via` existed
      assert.equal(priorApproved([earlier], NOW).has(`robinhood:${DEP}`), false);
      assert.equal(priorApproved([legacy], NOW).has(`robinhood:${DEP}`), false);
      assert.equal(priorApproved([earlier], NOW).get(`robinhood:${RELAY}`), 1);
      const again = judgeCounterparty({ address: DEP, chain: 'robinhood', role: 'deposit address', recipient: '0x' + 'dead'.padStart(40, '0') }, P, priorApproved([earlier], NOW));
      assert.equal(again.verdict, 'warn');
      assert.equal(judgeCounterparty({ address: HUMAN, chain: 'robinhood' }, P, new Map()).via, 'human');
    } },
];
