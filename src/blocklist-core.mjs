// The pure half of the shared blocklist (split from src/blocklist.mjs on 2026-11-07 so the verifier page can parse it in a
// browser): building a report and parsing the reports of trusted reporters. No imports.
export const CHAIN_RE = /^[a-z0-9_-]{1,32}$/, EVM_RE = /^0x[0-9a-f]{40}$/, NEAR_RE = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;
const norm = (x) => String(x ?? '').trim().toLowerCase();

/** Pure: the SocialDB set() data for one report. Throws on a malformed chain, address or evidence. */
export function reportData({ reporter, chain, address, evidence, reportedAt }) {
  const c = norm(chain), a = norm(address);
  if (!CHAIN_RE.test(c)) throw new Error(`bad chain: ${chain}`);
  if (a.startsWith('0x') ? !EVM_RE.test(a) : !(a.length >= 2 && a.length <= 64 && NEAR_RE.test(a))) throw new Error(`bad address: ${address}`);
  const ev = String(evidence ?? '').trim();
  if (ev.length < 10 || ev.length > 500) throw new Error('evidence must be 10–500 characters (say what happened and where to check it)');
  if (!Number.isFinite(Date.parse(reportedAt))) throw new Error('reportedAt must be an ISO time');
  return { [reporter]: { blocklist: { [c]: { [a]: JSON.stringify({ evidence: ev, reportedAt }) } } } };
}

/** Pure: SocialDB get() value → the entries of the trusted reporters only (malformed ones are skipped and counted). */
export function parseShared(value, trustedReporters) {
  const trusted = new Set((trustedReporters ?? []).map((r) => norm(r.account ?? r)));
  const entries = [];
  let skipped = 0;
  for (const [reporter, node] of Object.entries(value ?? {})) {
    if (!trusted.has(norm(reporter))) { skipped++; continue; }
    for (const [chain, byAddr] of Object.entries(node?.blocklist ?? {})) {
      if (!CHAIN_RE.test(chain) || !byAddr || typeof byAddr !== 'object') { skipped++; continue; }
      for (const [address, raw] of Object.entries(byAddr)) {
        try {
          const j = JSON.parse(typeof raw === 'object' && raw !== null ? raw[''] : raw);
          if (!j?.evidence || !Number.isFinite(Date.parse(j.reportedAt))) throw new Error('fields');
          entries.push({ address: norm(address), chain, evidence: String(j.evidence).slice(0, 500), reporter, reportedAt: j.reportedAt });
        } catch { skipped++; }
      }
    }
  }
  return { entries, skipped };
}
