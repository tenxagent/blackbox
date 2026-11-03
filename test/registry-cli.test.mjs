// src/registry-cli.mjs checkAnchors(): registry anchors vs the local heads (index = seq).
import { assert } from './lib.mjs';
import { checkAnchors } from '../src/registry-cli.mjs';

const heads = ['h0', 'h1', 'h2', 'h3', 'h4'];
export const tests = [
  { name: 'matching anchors pass; anchors past the local records are counted, not failed',
    fn() { const r = checkAnchors([{ seq: 1, head: 'h1' }, { seq: 4, head: 'h4' }, { seq: 9, head: 'x' }], heads);
      assert.deepEqual([r.ok, r.checked, r.missingLocally, r.problems.length], [true, 2, 1, 0]); } },
  { name: 'a changed local record (head differs) is a mismatch',
    fn() { const r = checkAnchors([{ seq: 2, head: 'h2' }, { seq: 3, head: 'hX' }], heads); assert.equal(r.ok, false); assert.equal(r.problems.length, 1); } },
  { name: 'a non-increasing seq is reported',
    fn() { const r = checkAnchors([{ seq: 3, head: 'h3' }, { seq: 3, head: 'h3' }], heads); assert.equal(r.ok, false); } },
];
