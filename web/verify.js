// Browser verifier for Black box. Plain ES module, no libraries, no CDNs.
// It imports the same canon/chain code that Node uses (SHA-256 via WebCrypto),
// so the browser and `node src/chain.mjs verify` cannot disagree.
//
// Everything loaded here (records, checkpoints, RPC replies) is treated as
// data: it is written into the page with textContent, never as HTML.

import { splitLines, verifySparse, AGENT_ID } from '../src/chain.mjs';
import { isCanonicalLine } from '../src/canon.mjs';

// the agent's own NEAR account that anchors the head (live on mainnet since 2026-10-31)
const DEFAULT_ANCHOR_ACCOUNT = '00537bf24e164c18f3512de1040d34c88a11f37976a3ef6d4de673dc9cef6590';

export const RH_EXPLORER_TX = 'https://robinhoodchain.blockscout.com/tx/';
export const NEAR = {
  testnet: { rpc: 'https://test.rpc.fastnear.com', socialDb: 'v1.social08.testnet', explorer: 'https://testnet.nearblocks.io/address/' },
  mainnet: { rpc: 'https://free.rpc.fastnear.com', socialDb: 'social.near', explorer: 'https://nearblocks.io/address/' },
};

const short = (s, n = 6) => (typeof s === 'string' && s.length > 2 * n + 2 ? `${s.slice(0, n + 2)}…${s.slice(-n)}` : String(s ?? ''));
const usd = (x) => (typeof x === 'number' ? `$${x < 1 ? x.toFixed(4).replace(/0+$/, '') : x.toFixed(2)}` : '');

// One record -> one plain sentence.
export function describe(rec) {
  const r = rec.row || {};
  const a = r.action;
  const on = r.slug ? ` on ${r.slug}` : '';
  switch (r.type) {
    case 'live':
      switch (a) {
        case 'approve_exact': return `Approved exactly ${r.amount} units of token ${short(r.token)} for spender ${short(r.spender)} (no unlimited approval).`;
        case 'approve_nft_conduit': case 'approve_conduit': return `Approved the marketplace conduit ${short(r.conduit)} for collection ${short(r.collection)}.`;
        case 'place_collection_offer': return `Placed a collection offer${on}: ${usd(r.usd)} for ${r.hours} h.`;
        case 'list_nft': return `Listed ${r.slug} #${r.tokenId} for sale for ${r.hours} h.`;
        case 'flock_reinvest': return `Sent a reinvest call for its bounty (simulated bounty ${usd(r.bountyUsdSim)}).`;
        case 'mint_race_done': return `Mint race${on} finished: minted ${r.minted}${r.tokenIds?.length ? ` (#${r.tokenIds.join(', #')})` : ''}.`;
        case 'crank_race_done': return `Crank race finished: ${r.rungsLanded} txs landed, ETH change ${r.ethDelta}.`;
        case 'sell_to_bid': return `Sold ${r.slug} #${r.tokenId} into the best bid${r.sold ? '' : ' (not sold)'}.`;
        case 'mint_sell': return `Sold the minted ${r.slug} #${r.tokenId} at ${usd(r.bestUsd)}.`;
        case 'bridge_eth_to_bnb': return `Bridged ${r.eth} ETH to ${r.bnb} BNB (${usd(r.usdIn)} in, ${usd(r.usdOut)} out).`;
        case 'somi_bridge': return `Bridged ${r.eth} ETH to Somnia (${usd(r.usdIn)} in, ${usd(r.usdOut)} out).`;
        case 'free_mint': return `Minted a free NFT${on} (operator note: ${r.why ?? ''}).`;
        case 'unwrap_weth': return `Unwrapped ${r.amount} WETH (${r.why ?? ''}).`;
        case 'stub_filled_relist': return `Stub bid${on} was filled at ${usd(r.costUsd)}; relisted at ${usd(r.listUsd)}.`;
        default: return `Sent ${String(a || 'a transaction').replace(/_/g, ' ')}${on}${r.chain && r.chain !== 'robinhood' ? ` on ${r.chain}` : ''}.`;
      }
    case 'tx': return `Sent tx: ${r.label}.`;
    case 'lp_mint': return `Opened a liquidity position #${r.tokenId} (${r.eth} ETH + ${r.usdg} USDG).`;
    case 'lp_exit': return `Closed liquidity position #${r.tokenId}: got ${r.eth} ETH + ${r.usdg} USDG.`;
    case 'lp_recenter': return `Recentred the liquidity position (width ${r.width} ticks, ${r.usdg} USDG).`;
    case 'free_mint': return `Minted ${r.qty} free ${r.name || 'NFTs'}.`;
    case 'fill': return `Its ${r.kind} on ${r.slug} was filled at ${usd(r.usd)}.`;
    case 'stub_offer': return `Placed a low "stub" offer${on} at ${usd(r.stubUsd)} (floor ${usd(r.floorUsd)})${r.ok === false ? ' — it failed' : ''}.`;
    case 'stub_pause': return `Paused stub offers: ${r.why}.`;
    case 'skip': return `Skipped ${r.name || short(r.contract)} on ${r.chain}: ${r.why}.`;
    case 'fire_refused': return `REFUSED to mint ${short(r.nft)} on ${r.chain}: ${r.why}.`;
    case 'flock_skip': return `Did not reinvest: ${r.why}.`;
    case 'mintarm_skip': return `Gave up the mint${on}: ${r.why}.`;
    case 'arm_gave_up': return `Gave up "${r.label}" after ${r.tries} tries: ${r.lastWhy}.`;
    case 'qcwatch_end': return `Stopped watching: ${r.why}.`;
    case 'alert': {
      const detail = r.note || r.url || (Array.isArray(r.after) ? `now ${r.after.join(', ')}` : '');
      return `Alert from ${r.engine}${r.action ? ` (${r.action.replace(/_/g, ' ')})` : ''}${detail ? `: ${detail}` : ''}.`;
    }
    case 'flock_sim': return `Simulated a reinvest: bounty ${usd(r.bountyUsd)} vs gas ${usd(r.gasUsd)} → ${r.go ? 'go' : 'wait'}.`;
    case 'paper': return `Paper trade: ${[String(r.action || '').replace(/_/g, ' '), r.side, r.market, r.pct ? `${r.pct}%` : ''].filter(Boolean).join(' ')}${r.ok === false ? ' (failed)' : ''}.`;
    case 'ladder': {
      const step = String(r.action || '').replace(/^ladder_/, '').replace(/_/g, ' ');
      const what = r.market ? `: ${r.side ?? ''} ${r.market}`.replace(/\s+/g, ' ') : '';
      const roi = typeof r.roi === 'number' ? ` (paper ROI ${r.roi}%)` : '';
      return `Paper ladder ${step}${what}${roi}${r.dry ? ' (dry)' : ''}.`;
    }
    case 'metaculus_forecast': {
      // Market Pulse sub-questions (group posts) carry a label + phase instead of a title
      const what = r.title ?? (r.label ? `Market Pulse: ${r.label}${r.phase ? `, ${r.phase} forecast` : ''}` : `post ${r.postId}`);
      return `Forecast: "${what}" — ${r.summary}.`;
    }
    case 'start': return `Engine ${r.engine || 'scanner'} started.`;
    case 'wl': case 'wl_apply': return `Applied for an allowlist (${r.action || r.project || 'details redacted'}).`;
    default: {
      if (/_start$/.test(r.type || '')) return `Started ${r.engine || r.type.replace(/_start$/, '')}.`;
      if (/armed|signed|t60|build|moved|wait|remote/.test(r.type || '')) return `Preparing: ${r.type.replace(/_/g, ' ')}${on}${r.dry ? ' (dry)' : ''}.`;
      if (/dry_done|rehearsal/.test(r.type || '')) return `Dry run: ${r.type.replace(/_/g, ' ')}${on}.`;
      return `${r.engine || ''} ${r.type || ''} ${a || ''}`.trim() + '.';
    }
  }
}

// Recompute the chain over a records.jsonl text and check it.
export async function checkRecords(text, checkpoints) {
  const lines = splitLines(text);
  // structural checks localise problems to one exact record
  let structural = null;
  for (let i = 0; i < lines.length; i++) {
    let seq;
    try { seq = JSON.parse(lines[i]).seq; } catch { structural = { seq: i + 1, reason: 'line is not valid JSON' }; break; }
    if (seq !== i + 1) { structural = { seq: i + 1, reason: `line ${i + 1} carries seq ${seq}: a record was dropped, inserted or moved` }; break; }
    if (!isCanonicalLine(lines[i])) { structural = { seq: i + 1, reason: 'not canonical JSON: edited by hand' }; break; }
  }
  const claims = [{ seq: 0, head: checkpoints.genesis }, ...checkpoints.checkpoints, checkpoints.final];
  const sparse = await verifySparse(lines, claims, { agentId: checkpoints.agentId });
  return { lines, structural, sparse };
}

export async function readNearAnchor(network, account) {
  const net = NEAR[network];
  // with_block_height: every leaf comes back as { "": value, ":block": height of the block that wrote it } (chain time, not the
  // agent's claimed t). anchors/<seq> holds every anchored head, so all of them are checked, not just the latest.
  const args = btoa(JSON.stringify({ keys: [`${account}/blackbox/**`], options: { with_block_height: true } }));
  const rpcCall = async (method, params) => {
    const res = await fetch(net.rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 'bb', method, params }) });
    const j = await res.json();
    if (j.error || j.result?.error) throw new Error(JSON.stringify(j.error || j.result.error).slice(0, 200));
    return j.result;
  };
  const r = await rpcCall('query', { request_type: 'call_function', finality: 'final', account_id: net.socialDb, method_name: 'get', args_base64: args });
  const value = JSON.parse(new TextDecoder().decode(new Uint8Array(r.result)));
  const node = value?.[account]?.blackbox;
  if (!node) return null;
  const leaf = (x) => (x && typeof x === 'object' ? x[''] : x);
  const anchors = Object.entries(node.anchors && typeof node.anchors === 'object' ? node.anchors : {})
    .filter(([k]) => /^\d+$/.test(k)).map(([k, v]) => ({ seq: Number(k), head: String(leaf(v)), block: v?.[':block'] ?? null }))
    .sort((x, y) => x.seq - y.seq);
  const writeBlock = node.head?.[':block'] ?? null;
  let writtenAt = null;
  if (writeBlock) { const b = await rpcCall('block', { block_id: Number(writeBlock) }); writtenAt = new Date(Number(BigInt(b.header.timestamp) / 1000000n)).toISOString(); }
  return { head: String(leaf(node.head)), seq: Number(leaf(node.seq)), t: leaf(node.t), agent: leaf(node.agent), records_url: leaf(node.records_url), block: r.block_height, writeBlock, writtenAt, anchors };
}

// ---------------------------------------------------------------- page
if (typeof document !== 'undefined') main();

function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v;
    else if (k === 'href') e.href = v;
    else e.setAttribute(k, v);
  }
  for (const k of kids) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return e;
}

function setStatus(id, state, text) {
  const box = document.getElementById(id);
  box.dataset.state = state;
  box.querySelector('.msg').textContent = text;
}

async function main() {
  const params = new URLSearchParams(location.search);
  // defaults = the agent's live mainnet anchor (first anchored 2026-10-31), so the hosted page checks it with one click
  const network = NEAR[params.get('network')] ? params.get('network') : 'mainnet';
  const account = params.has('account') ? params.get('account') : DEFAULT_ANCHOR_ACCOUNT;
  document.getElementById('account').value = account;
  document.getElementById('network').value = network;

  let checkpoints, proof = null;
  try {
    checkpoints = await (await fetch('../data/checkpoints.json', { cache: 'no-store' })).json();
  } catch (e) {
    setStatus('chain-status', 'bad', `could not load ../data/checkpoints.json (${e.message}). Serve the repo root: python3 -m http.server 8000, then open http://localhost:8000/web/`);
    return;
  }
  try { proof = await (await fetch('../data/rh-proof.json', { cache: 'no-store' })).json(); } catch { /* optional */ }
  const proofByTx = new Map((proof?.results || []).map((p) => [p.tx, p]));

  // ?records=<path> loads another copy (same origin, relative path only), e.g. a tampered one.
  const recordsParam = params.get('records');
  const recordsPath = recordsParam && !/^[a-z]+:|^\/\//i.test(recordsParam) ? recordsParam : '../data/records.jsonl';
  const text = await (await fetch(recordsPath, { cache: 'no-store' })).text();
  const state = { lines: [], anchor: null };
  await runCheck(text, recordsPath.replace(/^\.\.\//, ''));

  document.getElementById('file').addEventListener('change', async (ev) => {
    const f = ev.target.files[0];
    if (f) await runCheck(await f.text(), f.name);
  });

  async function runCheck(t, label) {
    setStatus('chain-status', 'busy', `recomputing ${label} with WebCrypto SHA-256…`);
    const t0 = performance.now();
    const { lines, structural, sparse } = await checkRecords(t, checkpoints);
    state.lines = lines;
    const ms = Math.round(performance.now() - t0);
    if (sparse.ok && !structural) {
      setStatus('chain-status', 'ok', `chain OK up to seq ${sparse.okThrough} of ${lines.length} (${label}, ${sparse.claimsChecked} checkpoint heads match, ${ms} ms). ${sparse.reason}.`);
    } else {
      const where = structural ? `first mismatch at seq ${structural.seq}: ${structural.reason}` : `first mismatch in seq ${sparse.firstBad.after + 1}..${sparse.firstBad.upTo}: ${sparse.reason}`;
      setStatus('chain-status', 'bad', `chain OK up to seq ${sparse.okThrough} (${label}); ${where}.`);
    }
    document.getElementById('final-head').textContent = `h_${checkpoints.final.seq} = ${checkpoints.final.head}`;
    document.getElementById('agent-id').textContent = checkpoints.agentId;
    renderList(lines);
    if (account) await checkAnchor();
  }

  async function checkAnchor() {
    setStatus('near-status', 'busy', `reading ${account}/blackbox from ${NEAR[network].socialDb} (${network})…`);
    try {
      const a = await readNearAnchor(network, account);
      if (!a) { setStatus('near-status', 'bad', `no Black box anchor stored under ${account} on ${network}.`); return; }
      if (a.agent && a.agent !== AGENT_ID) { setStatus('near-status', 'bad', `anchor is for another agent: ${a.agent}`); return; }
      const claims = [{ seq: a.seq, head: a.head }, ...a.anchors.map((x) => ({ seq: x.seq, head: x.head }))];
      const s = await verifySparse(state.lines, claims, { agentId: checkpoints.agentId });
      const when = a.writtenAt ? `written on chain ${a.writtenAt} (block ${a.writeBlock})` : `agent-claimed time ${a.t}`;
      const hist = a.anchors.length ? ` ${a.anchors.length} anchored heads in its history (seq ${a.anchors.map((x) => x.seq).join(', ')}), all checked.` : '';
      if (s.ok) setStatus('near-status', 'ok', `NEAR anchor matches: seq ${a.seq} head ${short(a.head, 8)}, ${when}.${hist} Records 1..${a.seq} match what was anchored. ${s.reason}.`);
      else setStatus('near-status', 'bad', `NEAR anchors (latest seq ${a.seq}) do not match these records: ${s.reason}.`);
    } catch (e) {
      setStatus('near-status', 'bad', `NEAR read failed: ${e.message}`);
    }
  }

  document.getElementById('near-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const acc = document.getElementById('account').value.trim();
    const netw = document.getElementById('network').value;
    const keep = recordsParam ? `&records=${encodeURIComponent(recordsParam)}` : '';
    location.search = `?network=${encodeURIComponent(netw)}&account=${encodeURIComponent(acc)}${keep}`;
  });
  if (!account) setStatus('near-status', 'idle', 'No NEAR account set. Enter the account that anchors the head (or add ?network=mainnet&account=<id> to the URL).');

  function renderList(lines) {
    const list = document.getElementById('decisions');
    list.replaceChildren();
    const recs = [];
    for (let i = lines.length - 1; i >= 0 && recs.length < 50; i--) {
      try { recs.push(JSON.parse(lines[i])); } catch { /* reported above */ }
    }
    for (const rec of recs) {
      const li = el('li', { class: `cat-${rec.cat}` });
      li.append(el('span', { class: 'seq' }, `#${rec.seq}`), el('span', { class: 'when' }, String(rec.row?.t ?? '').replace('T', ' ').slice(0, 19)), el('span', { class: 'cat' }, rec.cat));
      const body = el('div', { class: 'what' }, describe(rec));
      for (const tx of rec.txs || []) {
        const p = proofByTx.get(tx);
        const offRh = p?.result === 'not_on_rh' || (rec.row?.chain && rec.row.chain !== 'robinhood');
        const tag = p ? (p.result === 'verified' ? ' ✓ receipt from agent wallet' : ` (${p.result.replace(/_/g, ' ')})`) : '';
        body.append(el('br'));
        if (offRh) body.append(el('span', { class: 'tx' }, `tx ${short(tx, 8)} on ${rec.row?.chain || 'another chain'}${tag}`));
        else body.append(el('a', { class: 'tx', href: RH_EXPLORER_TX + tx, target: '_blank', rel: 'noopener noreferrer' }, `tx ${short(tx, 8)}`), el('span', { class: 'ok' }, tag));
      }
      li.append(body);
      list.append(li);
    }
  }
}
