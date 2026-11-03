import { assert, Skip } from './lib.mjs';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { classify, exportText, addressHash, loadExcludedHashes, redact, ADDRESS_IN_TEXT, SENSITIVE_NAME, PUBLIC_CHAIN_NAMES, BULKY_NAMES } from '../src/export.mjs';
import { isCanonicalLine } from '../src/canon.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const recordsText = () => readFileSync(root + 'data/records.jsonl', 'utf8');
const manifest = () => JSON.parse(readFileSync(root + 'data/manifest.json', 'utf8'));
const L = (o) => JSON.stringify(o);

function walkKeys(v, f, path = '') {
  if (Array.isArray(v)) v.forEach((x, i) => walkKeys(x, f, `${path}[${i}]`));
  else if (v && typeof v === 'object') for (const k of Object.keys(v)) { f(k, v[k], `${path}.${k}`); walkKeys(v[k], f, `${path}.${k}`); }
}

export const tests = [
  {
    name: 'privacy: local paths inside strings are redacted, URLs are kept (filter v2)',
    fn() {
      const [r, st] = redact({ err: 'at f (file:///root/x/a.mjs:7:2) wrote /tmp/b.json', url: 'https://site.com/home/page', n: 1 });
      assert.equal(r.err, 'at f (<path>:7:2) wrote <path>');
      assert.equal(r.url, 'https://site.com/home/page');
      assert.deepEqual(st, ['err~path']);
    },
  },
  {
    name: 'privacy: kleos-side rows are dropped',
    fn() {
      const d = classify(L({ t: 'x', engine: 'kleos-side', type: 'side', action: 'buy', tx: '0x' + 'a'.repeat(64) }));
      assert.equal(d.keep, false);
      assert.equal(d.reason, 'privacy:engine-kleos-side');
    },
  },
  {
    name: 'privacy: rows containing an excluded address (matched by sha256, any case, any field) are dropped',
    fn() {
      // Synthetic address, never a real one. Only its hash goes into the exclusion set.
      const fake = '0x' + 'ab12'.repeat(10);
      const excluded = new Set([addressHash(fake)]);
      assert.equal(addressHash(fake), createHash('sha256').update(fake).digest('hex'));
      for (const v of [fake, fake.toUpperCase().replace('0X', '0x'), `robinhood/${fake}/7`]) {
        const d = classify(L({ t: 'x', engine: 'offer', type: 'live', deep: { list: [{ to: v }] } }), excluded);
        assert.equal(d.keep, false, v);
        assert.equal(d.reason, 'privacy:operator-wallet');
      }
      // a 64-hex tx hash that starts with the same 40 hex digits is not an address: kept
      const tx = fake + 'cd'.repeat(12);
      assert.equal(classify(L({ t: 'x', type: 'live', tx }), excluded).keep, true);
      // another address is kept
      assert.equal(classify(L({ t: 'x', type: 'live', to: '0x' + 'cd34'.repeat(10) }), excluded).keep, true);
    },
  },
  {
    name: 'privacy: committed exclusion list holds only sha256 hashes and a comment',
    fn() {
      const j = JSON.parse(readFileSync(root + 'data/excluded-address-hashes.json', 'utf8'));
      assert.deepEqual(Object.keys(j).sort(), ['comment', 'sha256']);
      assert.equal(j.comment, "operator's personal wallets, not the agent's; addresses withheld");
      assert.ok(j.sha256.length >= 1 && j.sha256.every((h) => /^[0-9a-f]{64}$/.test(h)));
      assert.equal(loadExcludedHashes().size, j.sha256.length);
    },
  },
  {
    name: 'privacy: apply rows are reduced to {t, engine, type, action}',
    fn() {
      const d = classify(L({ t: 'x', engine: 'apply', type: 'wl', action: 'foo', postUrl: 'https://x.com/a', register: { body: { user: { id: 'u' } } }, wallet: '0xabc' }));
      assert.equal(d.keep, true);
      assert.deepEqual(d.row, { t: 'x', engine: 'apply', type: 'wl', action: 'foo' });
      assert.deepEqual(d.stripped.sort(), ['postUrl', 'register', 'wallet']);
    },
  },
  {
    name: 'privacy: sensitive field names stripped at every depth; token/tokenId kept only for chain-shaped values',
    fn() {
      const row = {
        t: 'x', engine: 'offer', type: 'live', action: 'approve_exact',
        token: '0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168', tokenId: '33', tokenIds: ['1', '2'],
        apiKey: 'k', os: { key: 'ACC5_4', calls: 3 }, list: [{ sessionId: 's', ok: 1 }], authHeader: 'Bearer z',
        cookie: 'c', userEmail: 'a@b.c', secretThing: 1, password: 'p', token2: 'x',
      };
      const d = classify(L(row));
      assert.equal(d.keep, true);
      assert.deepEqual(d.row, {
        t: 'x', engine: 'offer', type: 'live', action: 'approve_exact',
        token: '0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168', tokenId: '33', tokenIds: ['1', '2'],
        os: { calls: 3 }, list: [{ ok: 1 }],
      });
      // a "token" field holding something that is not an address or an integer id is stripped
      assert.equal('token' in classify(L({ t: 'x', type: 'live', token: 'eyJhbGciOi.secret' })).row, false);
    },
  },
  {
    name: 'bulky fields (snap, book, listings, offers, tail, resp, text, host) are stripped',
    fn() {
      const d = classify(L({ t: 'x', engine: 'crank', type: 'crank_remote', host: 'root@1.2.3.4', tail: '/root/x', resp: '{}', snap: 1, book: 1, listings: 1, offers: 1, text: 'tweet', exit: 0 }));
      assert.deepEqual(d.row, { t: 'x', engine: 'crank', type: 'crank_remote', exit: 0 });
    },
  },
  {
    name: 'decision filter: telemetry dropped, decisions kept, unknown types kept as unclassified',
    fn() {
      for (const type of ['beat', 'mm_snap', 'mm_true', 'opp', 'candidate', 'poll_err', 'liq_near', 'kleos_paper']) {
        assert.equal(classify(L({ t: 'x', type })).keep, false, type);
      }
      const want = { live: 'money', fire_refused: 'refusal', skip: 'refusal', alert: 'alert', flock_sim: 'sim', paper: 'paper', ladder: 'paper', start: 'lifecycle' };
      for (const [type, cat] of Object.entries(want)) assert.equal(classify(L({ t: 'x', type })).cat, cat, type);
      assert.equal(classify(L({ t: 'x', type: 'brand_new_type' })).cat, 'unclassified');
    },
  },
  {
    name: 'tx hashes collected from tx, hash and txs[], lowercased, deduplicated',
    fn() {
      const A = '0x' + 'A'.repeat(64), B = '0x' + 'b'.repeat(64);
      assert.deepEqual(classify(L({ t: 'x', type: 'live', tx: A, txs: [B, A.toLowerCase()] })).txs, [A.toLowerCase(), B]);
      assert.deepEqual(classify(L({ t: 'x', type: 'tx', hash: B })).txs, [B]);
      assert.deepEqual(classify(L({ t: 'x', type: 'live', tx: '0x1234' })).txs, []);
    },
  },
  {
    name: 'export: seq, source line, source-line hash; partial last line ignored; byte-identical on re-run',
    fn() {
      const lines = [L({ t: 'a', type: 'beat' }), L({ t: 'b', type: 'live', tx: '0x' + '1'.repeat(64) }), 'not json', L({ t: 'c', type: 'skip', why: 'name' })];
      const text = lines.join('\n') + '\n' + '{"t":"d","type":"live"'; // last line still being written
      const a = exportText(text), b = exportText(text);
      assert.deepEqual(a, b);
      assert.equal(a.lines.length, 2);
      const r1 = JSON.parse(a.lines[0]), r2 = JSON.parse(a.lines[1]);
      assert.deepEqual([r1.seq, r1.line, r2.seq, r2.line], [1, 2, 2, 4]);
      assert.equal(r1.src, createHash('sha256').update(lines[1]).digest('hex'));
      assert.equal(a.manifest.source.linesRead, 4);
      assert.deepEqual(a.manifest.droppedByReason, { 'privacy:engine-kleos-side': 0, 'privacy:operator-wallet': 0, telemetry: 1, unparseable: 1 });
      assert.ok(a.lines.every(isCanonicalLine));
    },
  },
  {
    name: 'committed data/records.jsonl: canonical, seq 1..n contiguous, source lines increasing',
    fn() {
      const lines = recordsText().split('\n').filter(Boolean);
      let lastLine = 0;
      lines.forEach((l, i) => {
        assert.ok(isCanonicalLine(l), `seq ${i + 1} not canonical`);
        const r = JSON.parse(l);
        assert.equal(r.seq, i + 1);
        assert.ok(r.line > lastLine);
        assert.match(r.src, /^[0-9a-f]{64}$/);
        lastLine = r.line;
      });
      assert.equal(lines.length, manifest().records);
      return `${lines.length} records`;
    },
  },
  {
    name: 'committed data/records.jsonl passes the privacy scan',
    fn() {
      const text = recordsText();
      for (const [label, re] of [
        ['kleos-side', /kleos-side/], ['local paths', /\/root\/|\/home\//],
        ['server address', /18\.221\.|root@/], ['email address', /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}/],
        ['bearer/api key', /bearer |api[_-]?key|x-api-key/i],
      ]) assert.equal(re.test(text), false, `found ${label}`);
      const excluded = loadExcludedHashes();
      for (const m of text.matchAll(ADDRESS_IN_TEXT)) assert.ok(!excluded.has(addressHash(m[0])), 'an excluded address is in the records');
      for (const l of text.split('\n').filter(Boolean)) {
        const r = JSON.parse(l);
        walkKeys(r.row, (k, v, p) => {
          assert.ok(!BULKY_NAMES.has(k), `bulky field ${p} in seq ${r.seq}`);
          if (SENSITIVE_NAME.test(k)) assert.ok(PUBLIC_CHAIN_NAMES.has(k), `sensitive field ${p} in seq ${r.seq}`);
        });
        if (r.row.engine === 'apply') assert.deepEqual(Object.keys(r.row).filter((k) => !['t', 'engine', 'type', 'action'].includes(k)), []);
      }
    },
  },
  {
    name: 'operator check: committed records rebuild byte-for-byte from the ledger',
    fn() {
      const ledger = process.env.BLACKBOX_LEDGER || 'ledger.jsonl';
      if (!existsSync(ledger)) throw new Skip('private ledger not on this machine (expected for judges)');
      const m = manifest();
      const { lines, manifest: m2 } = exportText(readFileSync(ledger, 'utf8'), { upto: m.source.linesRead, sourceName: m.source.name });
      if (m2.source.sha256 !== m.source.sha256) throw new Error('ledger prefix changed since export: history was rewritten');
      assert.equal(lines.join('\n') + '\n', recordsText());
      return `first ${m.source.linesRead} ledger lines unchanged`;
    },
  },
];
