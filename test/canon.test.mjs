import { assert } from './lib.mjs';
import { canon, isCanonicalLine } from '../src/canon.mjs';

export const tests = [
  {
    name: 'sorts keys at every depth, no whitespace',
    fn() {
      assert.equal(canon({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: null } }), '{"a":{"c":null,"d":[3,{"y":2,"z":1}]},"b":1}');
    },
  },
  {
    name: 'same value, different key order => same bytes',
    fn() {
      assert.equal(canon(JSON.parse('{"x":1,"y":[true,false]}')), canon(JSON.parse('{ "y" : [true, false], "x" : 1 }')));
    },
  },
  {
    name: 'numbers print as JSON.stringify prints them',
    fn() {
      assert.equal(canon([1, 0.1, 1e21, 1e-7, -0, 4.5, 100, 2 ** 53]), '[1,0.1,1e+21,1e-7,0,4.5,100,9007199254740992]');
    },
  },
  {
    name: 'RFC 8785 section 3.2.2 example',
    fn() {
      // Input and expected output copied from RFC 8785, section 3.2.2 / 3.2.3.
      const input = '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}';
      const want = '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}';
      assert.equal(canon(JSON.parse(input)), want);
    },
  },
  {
    name: 'keys sort by UTF-16 code units',
    fn() {
      // "€" (euro) sorts before "😀" (emoji, surrogate pair) by UTF-16 units.
      assert.equal(canon({ '😀': 1, '€': 2, a: 3, B: 4 }), '{"B":4,"a":3,"€":2,"😀":1}');
    },
  },
  {
    name: 'rejects non-JSON values',
    fn() {
      for (const bad of [NaN, Infinity, undefined, 1n, () => 1, new Date(0), new Map(), { a: undefined }, [1, , 2]]) {
        assert.throws(() => canon(bad), TypeError);
      }
    },
  },
  {
    name: 'isCanonicalLine accepts canonical and rejects spaced JSON',
    fn() {
      assert.equal(isCanonicalLine('{"a":1,"b":2}'), true);
      assert.equal(isCanonicalLine('{"b":2,"a":1}'), false);
      assert.equal(isCanonicalLine('{"a": 1}'), false);
      assert.equal(isCanonicalLine('not json'), false);
    },
  },
];
