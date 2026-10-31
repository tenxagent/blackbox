// Tiny test harness helpers (Node stdlib only).
export { default as assert } from 'node:assert/strict';

export class Skip extends Error {
  constructor(reason) { super(reason); this.name = 'Skip'; }
}

// Network tests call this: a fetch failure means SKIP, not FAIL.
export async function netOrSkip(fn) {
  try {
    return await fn();
  } catch (e) {
    const msg = String(e?.cause?.code || e?.message || e);
    if (/fetch failed|ENOTFOUND|ECONNREFUSED|ECONNRESET|ETIMEDOUT|EAI_AGAIN|aborted|timeout|HTTP 5\d\d|HTTP 429/i.test(msg)) {
      throw new Skip(`network unavailable: ${msg}`);
    }
    throw e;
  }
}
