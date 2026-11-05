// Browser verifier for Black box. Plain ES module, no libraries, no CDNs.
// It imports the same canon/chain code that Node uses (SHA-256 via WebCrypto),
// so the browser and `node src/chain.mjs verify` cannot disagree.
//
// Everything loaded here (records, checkpoints, RPC replies) is treated as
// data: it is written into the page with textContent, never as HTML.

import { splitLines, verifySparse } from '../src/chain.mjs';
import { isCanonicalLine } from '../src/canon.mjs';
import { readAllAnchors } from '../src/registry.mjs';

// the append-only registry (contract/; deployed + locked on mainnet 2026-10-31: DeployContract + new() + DeleteKey in one tx)
const REGISTRY = '08035588c459e514c632061fb4862fde62297571f1e44716e01bcc9913986e8a';
export const REGISTRY_CODE_HASH = 'HHWM5HdMW4A513pxMmXGRt168Uh4PeDiBcCps8DG34Vk';   // = contract/res/blackbox_registry.wasm (test/contract.test.mjs checks it)

// the agent's own NEAR account that anchors the head (live on mainnet since 2026-10-31)
const DEFAULT_ANCHOR_ACCOUNT = '00537bf24e164c18f3512de1040d34c88a11f37976a3ef6d4de673dc9cef6590';

export const RH_EXPLORER_TX = 'https://robinhoodchain.blockscout.com/tx/';
export const RH_RPC = 'https://rpc.mainnet.chain.robinhood.com';   // public, CORS-enabled; the live nonce for the coverage panel

/** Coverage panel (pure; tested in test/web.test.mjs): data/coverage.json from src/coverage.mjs, plus the wallet's live nonce if
 *  the browser could read it. Never green while any transaction is unaccounted for: omissions are measured, not prevented. */
export function coverageSummary(cov, liveNonce = null) {
  const pct = cov.total ? ((100 * cov.unexplained) / cov.total).toFixed(1) : '0';
  let text = `Of the ${cov.total} transactions the agent wallet had sent when data/coverage.json was written (${String(cov.at).replace('T', ' ').slice(0, 16)}Z), `
    + `${cov.explainedTx} match a record's own tx hash and ${cov.explainedBatch} fall inside a recorded mint or crank batch; `
    + `${cov.unexplained} (${pct}%) are not accounted for. A decision that sent no transaction cannot show up here.`;
  if (Number.isSafeInteger(liveNonce)) text += liveNonce > cov.total ? ` Live: the wallet has sent ${liveNonce - cov.total} more since (nonce ${liveNonce}); node src/coverage.mjs re-counts.` : ` Live nonce ${liveNonce}: current.`;
  else if (liveNonce === false) text += ' (The live nonce could not be read from this browser.)';
  return { state: cov.unexplained === 0 ? 'ok' : 'idle', text };
}
export const NEAR = {
  testnet: { rpc: 'https://test.rpc.fastnear.com', socialDb: 'v1.social08.testnet', explorer: 'https://testnet.nearblocks.io/address/' },
  mainnet: { rpc: 'https://free.rpc.fastnear.com', socialDb: 'social.near', explorer: 'https://nearblocks.io/address/' },
};

const short = (s, n = 6) => (typeof s === 'string' && s.length > 2 * n + 2 ? `${s.slice(0, n + 2)}…${s.slice(-n)}` : String(s ?? ''));
export const usd = (x) => (typeof x === 'number' ? `$${x < 1 ? x.toFixed(4).replace(/\.?0+$/, '') : x.toFixed(2)}` : '');
// a token amount (number or decimal string) for reading: 2 decimals from 1 up, 4 significant digits below
const amt = (x) => { const v = Number(x); return x == null || x === '' || !Number.isFinite(v) ? String(x ?? '?') : String(v >= 1 ? +v.toFixed(2) : +v.toPrecision(4)); };
const words = (s) => String(s ?? '').replace(/_/g, ' ');
const CHAINS = { robinhood: 'Robinhood Chain', bsc: 'BNB Chain', hyperevm: 'HyperEVM', elysium: 'Elysium', base: 'Base', somnia: 'Somnia' };
const chainOn = (c) => (c ? ` on ${CHAINS[c] || c}` : '');
// the useful part of an RPC/HTTP error string: the revert reason if there is one, else the first 100 characters
const errText = (e) => { const s = typeof e === 'string' ? e : JSON.stringify(e ?? ''); const m = s.match(/execution reverted:? ?([^"\\]*)/); return m ? `reverted${m[1] ? `: ${m[1].trim()}` : ''}` : s.slice(0, 100); };
const why = (r) => (r.why ? `: ${r.why}` : '');

// One record -> one plain sentence.
export function describe(rec) {
  const r = rec.row || {};
  const a = r.action;
  const on = r.slug ? ` on ${r.slug}` : '';
  switch (r.type) {
    case 'gate': {   // src/gate.mjs decisions written by the agent before a deliberate send
      const what = r.what ? ` (${r.what})` : '';
      if (a === 'gate_allow') return `Pre-sign gate allowed ${usd(r.pendingUsd)}${what}: newest anchor ${r.anchorAgeH} h old, ${usd(r.spent24h)} already allowed in 24 h.`;
      if (a === 'gate_refuse') return `Pre-sign gate REFUSED ${usd(r.pendingUsd)}${what}: ${(r.reasons || []).join('; ')}.`;
      if (a === 'gate_bypass') return `Pre-sign gate bypassed by hand (--no-gate) for ${usd(r.pendingUsd)}${what}.`;
      return `Pre-sign gate: ${String(a).replace(/_/g, ' ')}.`;
    }
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
        case 'relay_swap': return `Swapped ${r.amount} ${r.from} for ${amt(r.received)} ${r.to} through Relay${chainOn(r.chain)}.`;
        case 'giga_sell': return `Sold ${r.giga} GIGA for ${amt(r.usdg)} USDG${r.via === 'relay' ? ' through Relay' : ''}${why(r)}.`;
        case 'mint_autolist': return `Listed the minted ${r.slug} #${r.tokenId} for sale at ${usd(r.usd)}.`;
        case 'mint_now_done': return `Minted ${r.minted} ${r.slug}${r.tokenIds?.length ? ` (#${r.tokenIds.join(', #')})` : ''}.`;
        case 'reprice_nft': return `Repriced its ${r.slug} #${r.tokenId} listing to ${usd(r.usd)} (from recent ${r.basis}).`;
        case 'sleeve_buy': return `Bought ${r.symbol} on Elysium for ${amt(r.hype)} HYPE (${usd(r.usd)})${why(r)}.`;
        case 'sleeve_fund_relay_approve': return 'Approved the exact USDG amount for the Relay bridge (Robinhood Chain → HyperEVM).';
        case 'sleeve_fund_relay_deposit': return 'Deposited USDG into the Relay bridge (Robinhood Chain → HyperEVM).';
        case 'sleeve_fund_relay': return `Relay filled the ${usd(r.usd)} bridge: HyperEVM balance now ${amt(r.hyperevmHype)} HYPE.`;
        case 'sleeve_fund_inbox': return `Deposited ${amt(r.hype)} HYPE into the Elysium bridge inbox on HyperEVM.`;
        case 'near_fund_deposit': return 'Sent USDG to a NEAR Intents deposit address, to fund its NEAR account.';
        case 'near_fund_done': { const d = r.details || {}; return `NEAR Intents finished the swap (${r.status}): ${d.amountInFormatted} USDG in, ${amt(d.amountOutFormatted)} NEAR out.`; }
        case 'near_hackathon_submitted': return `Submitted ${r.project} to the NEAR hackathon (${r.repo}).`;
        case 'blackbox_first_anchor': return `First anchor on NEAR: wrote the head after record ${r.seq} to SocialDB (read back: ${r.readback}).`;
        case 'blackbox_anchor': return `Anchored the head after record ${r.seq} on NEAR (SocialDB).`;
        case 'blackbox_anchor_failed': return `Anchoring on NEAR failed: ${r.status}.`;
        case 'social_set': return 'Wrote its anchor entry to NEAR SocialDB.';
        case 'socialdb_storage_deposit': return `Prepaid ${r.near} NEAR of SocialDB storage.`;
        case 'registry_fund': return "Funded the registry contract's NEAR account.";
        case 'registry_deploy_init_lock': return 'Deployed the registry contract, initialised it and deleted its access key in one transaction, so the code cannot change.';
        case 'registry_checks': return `Read back the deployed registry (code hash ${r.code_hash}): ${r.ok ? 'checks passed' : 'checks FAILED'}.`;
        case 'registry_register': return 'Registered its NEAR account in the registry.';
        case 'registry_addkey': return "Added the anchor key: a function-call key that can only call the registry's anchor method.";
        case 'registry_anchor': return 'Anchored the head in the NEAR registry contract.';
        case 'registry_storage_deposit': return `Prepaid ${r.near} NEAR of registry storage${r.anchorsLeft != null ? ` (room for about ${r.anchorsLeft} anchors)` : ''}${why(r)}.`;
        case 'termix_claim': return 'Claimed a Termix bounty slot in its escrow contract on BNB Chain.';
        case 'termix_submit': return 'Submitted the Termix bounty proof to the escrow contract on BNB Chain.';
        case 'termix_tx': return `Sent a Termix transaction${chainOn(r.chain)}.`;
        case 'termix_bounty_submitted': return `Termix accepted the bounty submission (${r.status}; review by ${String(r.reviewDeadline).slice(0, 10)}).`;
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
    case 'flock_sim': return typeof r.bountyUsd === 'number'
      ? `Simulated a reinvest: bounty ${usd(r.bountyUsd)} vs gas ${usd(r.gasUsd)} → ${r.go ? 'go' : 'wait'}.`
      : `Simulated a reinvest: the call would fail (${errText(r.err)}) → wait.`;
    case 'live_intent': {   // written BEFORE signing; the matching live row follows if the send happened
      const size = [r.usdg && `${r.usdg} USDG`, r.near && `${r.near} NEAR`].filter(Boolean).join(', ');
      return `About to send (written before signing): ${words(r.action)}${size ? `, ${size}` : ''}${r.downside ? `; worst case ${r.downside}` : ''}.`;
    }
    case 'decision': return `Decided: ${words(r.action)}${on}${why(r)}.`;
    case 'account': return `Registered an agent account on ${r.engine}${r.ok === false ? ' (failed)' : ''}.`;
    case 'publish': return `Made ${r.repo} public (operator approved; leak check ${String(r.leak_gate).split(' ')[0]}).`;
    case 'mint_autolist_skip': return `Did not list the minted ${r.slug}: no reference price.`;
    case 'mintarm_direct_skip': return `Skipped the direct mint${on}${why(r)}.`;
    case 'mintarm_fallback_local': return `Mint${on}: the remote sender did not confirm, so it fell back to sending from this server.`;
    case 'beefyclm_summary': return `Beefy keeper (paper) summary: ${r.ticks} checks, ${r.wouldSends} would-sends, ${r.won} won, ${r.taken} taken by other keepers.`;
    case 'beefyclm_would_send': return `Paper: would have harvested ${r.name} for ${usd(r.netUsd)} net (gas ${usd(r.gasUsd)}).`;
    case 'beefyclm_taken': return `Another keeper harvested ${r.name} (observed; the agent sent nothing; its paper net would have been ${usd(r.ourNetUsd)}).`;
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
      return `Forecast: "${what}" — ${String(r.summary ?? '').trim().replace(/\d+\.\d{5,}/g, (x) => String(+Number(x).toPrecision(4)))}.`;
    }
    case 'start': return `Engine ${r.engine || 'scanner'} started.`;
    case 'wl': case 'wl_apply': return `Applied for an allowlist (${r.action || r.project || 'details redacted'}).`;
    default: {
      if (/_start$/.test(r.type || '')) return `Started ${r.engine || r.type.replace(/_start$/, '')}.`;
      if (/_err$/.test(r.type || '')) return `Error in ${r.engine || r.type.replace(/_err$/, '')}${r.what ? ` (${r.what})` : ''}: ${errText(r.err)} (logged; not a decision).`;
      if (/armed|signed|t60|build|moved|wait|remote/.test(r.type || '')) return `Preparing: ${r.type.replace(/_/g, ' ')}${on}${r.dry ? ' (dry)' : ''}.`;
      if (/dry_done|rehearsal/.test(r.type || '')) return `Dry run: ${r.type.replace(/_/g, ' ')}${on}.`;
      return `${r.engine ? `${r.engine}: ` : ''}${words(r.type)}${a ? ` (${words(a)})` : ''}.`;
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

// Registry: is it locked (no access keys) and running the reviewed code? Then every head it holds for `account`.
export async function readRegistry(network, account) {
  const net = NEAR[network];
  const rpcCall = async (method, params) => {
    const res = await fetch(net.rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 'bb', method, params }) });
    const j = await res.json();
    if (j.error || j.result?.error) throw new Error(JSON.stringify(j.error || j.result.error).slice(0, 200));
    return j.result;
  };
  const acc = await rpcCall('query', { request_type: 'view_account', finality: 'final', account_id: REGISTRY });
  const keys = (await rpcCall('query', { request_type: 'view_access_key_list', finality: 'final', account_id: REGISTRY })).keys;
  const view = async (method, args) => {
    const r = await rpcCall('query', { request_type: 'call_function', finality: 'final', account_id: REGISTRY, method_name: method, args_base64: btoa(JSON.stringify(args)) });
    return JSON.parse(new TextDecoder().decode(new Uint8Array(r.result)));
  };
  const anchors = await readAllAnchors(view, account);
  return { codeHash: acc.code_hash, codeOk: acc.code_hash === REGISTRY_CODE_HASH, keyCount: keys.length, anchors };
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

  // ?records=<path> loads another copy of the records (e.g. a tampered one); ?checkpoints=<path> another agent's
  // checkpoints (e.g. ../examples/minimal-agent/expected/checkpoints.json). Same origin, relative paths only.
  const relative = (p) => (p && !/^[a-z]+:|^\/\//i.test(p) ? p : null);
  const recordsParam = params.get('records');
  const checkpointsParam = relative(params.get('checkpoints'));
  const checkpointsPath = checkpointsParam ?? '../data/checkpoints.json';
  let checkpoints, proof = null;
  try {
    checkpoints = await (await fetch(checkpointsPath, { cache: 'no-store' })).json();
  } catch (e) {
    setStatus('chain-status', 'bad', `could not load ${checkpointsPath} (${e.message}). Serve the repo root: python3 -m http.server 8000, then open http://localhost:8000/web/`);
    return;
  }
  try { proof = await (await fetch('../data/rh-proof.json', { cache: 'no-store' })).json(); } catch { /* optional */ }
  (async () => {   // coverage panel: the committed reconciliation + the live nonce (both optional; never blocks the chain check)
    let cov; try { cov = await (await fetch('../data/coverage.json', { cache: 'no-store' })).json(); } catch { setStatus('coverage-status', 'idle', 'data/coverage.json not found (run node src/coverage.mjs).'); return; }
    let live = false;
    try {
      const r = await (await fetch(RH_RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 'bb', method: 'eth_getTransactionCount', params: [cov.wallet, 'latest'] }) })).json();
      if (typeof r.result === 'string') live = Number(BigInt(r.result));
    } catch { /* stays false */ }
    const s = coverageSummary(cov, live); setStatus('coverage-status', s.state, s.text);
  })();
  const proofByTx = new Map((proof?.results || []).map((p) => [p.tx, p]));

  const recordsPath = relative(recordsParam) ?? '../data/records.jsonl';
  const text = await (await fetch(recordsPath, { cache: 'no-store' })).text();
  const state = { lines: [], anchor: null };
  await runCheck(text, recordsPath.replace(/^\.\.\//, ''));

  document.getElementById('file').addEventListener('change', async (ev) => {
    const f = ev.target.files[0];
    if (f) await runCheck(await f.text(), f.name);
  });

  async function runCheck(t, label) {
    const h = document.getElementById('chain-title'); if (h) h.textContent = `1. Chain over ${label}`;
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
    if (account && network === 'mainnet') await checkRegistry();
  }

  async function checkRegistry() {
    setStatus('registry-status', 'busy', `reading the registry ${short(REGISTRY, 8)} on mainnet…`);
    try {
      const r = await readRegistry(network, account);
      if (!r.codeOk || r.keyCount !== 0) { setStatus('registry-status', 'bad', `registry is not the locked reviewed contract: ${r.keyCount} access key(s), code hash ${r.codeHash}`); return; }
      if (!r.anchors.length) { setStatus('registry-status', 'bad', `the locked registry holds no heads for ${account}.`); return; }
      const s = await verifySparse(state.lines, r.anchors.map((x) => ({ seq: x.seq, head: x.head })), { agentId: checkpoints.agentId });
      const span = `${r.anchors.length} heads (seq ${r.anchors[0].seq} → ${r.anchors[r.anchors.length - 1].seq}), first written ${r.anchors[0].time}, last ${r.anchors[r.anchors.length - 1].time} by the contract's clock`;
      if (s.ok) setStatus('registry-status', 'ok', `Registry locked (0 access keys, code hash ${short(REGISTRY_CODE_HASH, 6)} = contract/ build) holds ${span}. All match these records. ${s.reason}.`);
      else setStatus('registry-status', 'bad', `Registry holds ${span}, but these records do not match: ${s.reason}.`);
    } catch (e) {
      setStatus('registry-status', 'bad', `registry read failed: ${e.message}`);
    }
  }

  async function checkAnchor() {
    setStatus('near-status', 'busy', `reading ${account}/blackbox from ${NEAR[network].socialDb} (${network})…`);
    try {
      const a = await readNearAnchor(network, account);
      if (!a) { setStatus('near-status', 'bad', `no Black box anchor stored under ${account} on ${network}.`); return; }
      if (a.agent && a.agent !== checkpoints.agentId) { setStatus('near-status', 'bad', `anchor is for another agent: ${a.agent} (these checkpoints are for ${checkpoints.agentId})`); return; }
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
    const keep = (recordsParam ? `&records=${encodeURIComponent(recordsParam)}` : '') + (checkpointsParam ? `&checkpoints=${encodeURIComponent(checkpointsParam)}` : '');
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
