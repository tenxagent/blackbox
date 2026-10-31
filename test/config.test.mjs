// The config file that holds every agent-specific export rule (blackbox.config.json, examples/*/blackbox.config.json).
import { assert } from './lib.mjs';
import { readFileSync } from 'node:fs';
import { compileConfig, loadConfig, defaultConfig, classify, categoryOf, redact, exportText } from '../src/export.mjs';
import { AGENT_ID } from '../src/chain.mjs';

const root = new URL('..', import.meta.url);
const read = (p) => readFileSync(new URL(p, root), 'utf8');
const L = (o) => JSON.stringify(o);
const AG = 'eip155:1:0x' + '1'.repeat(40);
const cfg = (extra) => compileConfig({ agentId: AG, ...extra });

export const tests = [
  {
    name: 'default config: its rules are the ones the committed manifest lists; agentId = chain constant = checkpoints',
    fn() {
      const c = defaultConfig();
      const m = JSON.parse(read('data/manifest.json'));
      assert.equal(c.filterVersion, m.filterVersion);
      assert.deepEqual(c.telemetryTypes, m.rules.telemetryTypes);
      assert.deepEqual(Object.keys(c.telemetryTypes), Object.keys(m.rules.telemetryTypes));
      assert.deepEqual([...c.privacyEngines], m.rules.privacyEngines);
      assert.equal(String(c.sensitiveName), m.rules.sensitiveFieldName);
      assert.deepEqual([...c.publicChainNames], m.rules.publicChainFieldNames);
      assert.deepEqual([...c.bulkyNames], m.rules.bulkyFieldNames);
      assert.deepEqual(c.reduceEngines, { apply: m.rules.applyRowsKeep });
      assert.equal(c.agentId, AGENT_ID);
      assert.equal(c.agentId, JSON.parse(read('data/checkpoints.json')).agentId);
      return `${Object.keys(c.telemetryTypes).length} telemetry types, ${Object.keys(c.catExact).length} categorised types`;
    },
  },
  {
    name: 'config errors: unknown field, bad agentId, g flag, a type in two categories or in telemetry and a category',
    fn() {
      assert.throws(() => cfg({ privacyEngine: ['x'] }), /unknown field "privacyEngine"/);
      assert.throws(() => compileConfig({}), /agentId/);
      assert.throws(() => compileConfig({ agentId: 'my agent' }), /CAIP-10/);
      assert.throws(() => cfg({ sensitiveFieldName: '/key/gi' }), /g or y flag/);
      assert.throws(() => cfg({ sensitiveFieldName: 'key' }), /\/regex\/flags/);
      assert.throws(() => cfg({ categories: { money: ['swap'], sim: ['swap'] } }), /two categories/);
      assert.throws(() => cfg({ telemetryTypes: { beat: 'x' }, categories: { money: ['beat'] } }), /both telemetry/);
      assert.throws(() => cfg({ categories: { unclassified: ['x'] } }), /reserved/);
      assert.throws(() => cfg({ categories: { money: [{ type: 'x', amount: '1' }] } }), /type\/action\/engine/);
      assert.throws(() => cfg({ reduceEngines: { apply: 't' } }), /reduceEngines/);
      assert.throws(() => cfg({ localPathRoots: ['a/b'] }), /single path segments/);
      assert.throws(() => loadConfig(new URL('no-such-config.json', import.meta.url).pathname), /cannot read config/);
      assert.equal(cfg({}).agentId, AG);
    },
  },
  {
    name: 'categories: exact type names first, then globs and {type, action, engine} rules in file order; first match wins',
    fn() {
      const c = cfg({
        categories: {
          money: [{ type: 'decision', action: 'swap' }, 'transfer'],
          refusal: ['*_refused', { type: 'decision', action: 'hold' }],
          sim: [{ engine: 'sim*' }],
          other: [{ type: 'decision' }, 'decision_refused'],
        },
      });
      const cat = (row) => categoryOf(row, c);
      assert.equal(cat({ type: 'decision', action: 'swap' }), 'money');
      assert.equal(cat({ type: 'decision', action: 'hold' }), 'refusal');
      assert.equal(cat({ type: 'decision', action: 'other' }), 'other');
      assert.equal(cat({ type: 'transfer' }), 'money');
      assert.equal(cat({ type: 'mint_refused' }), 'refusal');
      assert.equal(cat({ type: 'decision_refused' }), 'other'); // exact name beats the earlier glob
      assert.equal(cat({ type: 'x', engine: 'simulator' }), 'sim');
      assert.equal(cat({ type: 'x', engine: 5 }), 'unclassified'); // patterns only match strings
      for (const t of ['constructor', 'toString', '__proto__', undefined]) assert.equal(cat({ type: t }), 'unclassified');
    },
  },
  {
    name: 'rules come from the config: telemetry globs, privacy engines, reduced engines, bulky names, tx fields, path roots',
    fn() {
      const c = cfg({
        telemetryTypes: { '*_tick': 'price', beat: 'heartbeat' },
        privacyEngines: { personal: 'operator' },
        reduceEngines: { forms: ['t', 'type'] },
        bulkyFieldNames: ['dump'],
        txHashFields: ['txHash'],
        txHashListFields: ['bundle'],
        localPathRoots: ['Users'],
      });
      const none = new Set();
      assert.equal(classify(L({ type: 'eth_tick' }), none, c).reason, 'telemetry:eth_tick');
      assert.equal(classify(L({ type: 'beat' }), none, c).reason, 'telemetry:beat');
      assert.equal(classify(L({ type: 'x', engine: 'personal' }), none, c).reason, 'privacy:engine-personal');
      const f = classify(L({ t: 'a', type: 'apply', engine: 'forms', email: 'e', body: 1 }), none, c);
      assert.deepEqual([f.row, f.stripped], [{ t: 'a', type: 'apply' }, ['engine', 'email', 'body']]);
      const A = '0x' + 'ab'.repeat(32), B = '0x' + 'CD'.repeat(32);
      const d = classify(L({ type: 'x', dump: [1], tx: A, txHash: A, bundle: [B], err: 'at /Users/user/a.js and /home/user/b.js' }), none, c);
      assert.deepEqual(d.txs, [A, B.toLowerCase()]);
      assert.equal('dump' in d.row, false);
      assert.equal(d.row.err, 'at <path> and /home/user/b.js');
      // redaction off: strings are left alone
      const off = cfg({ redactLocalPaths: false });
      assert.deepEqual(redact({ e: '/home/user/x' }, off), [{ e: '/home/user/x' }, []]);
      // the manifest names the reduced engine's field list and the privacy reasons (always listed, even at 0)
      const m = exportText(L({ t: 'a', type: 'beat' }) + '\n', { config: c }).manifest;
      assert.deepEqual(m.droppedByReason, { 'privacy:engine-personal': 0, 'privacy:operator-wallet': 0, telemetry: 1 });
      assert.deepEqual(m.rules.formsRowsKeep, ['t', 'type']);
      assert.match(m.rules.excludedAddresses, /^none/);
    },
  },
];
