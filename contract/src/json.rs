//! Just enough JSON for this contract, with no allocation.
//!
//! Reader: one flat object whose fields are known in advance, each a string or a non-negative integer.
//! It is strict on purpose and rejects anything else:
//! - empty input (or only whitespace) means "no arguments", the same as `{}`;
//! - keys in any order, separated by standard JSON whitespace; unknown or duplicate keys are refused;
//! - strings: printable ASCII (0x20..=0x7E) only, no escape sequences (no argument of this contract
//!   needs one, and refusing them means stored strings never need escaping on the way out);
//! - integers: `0` or `[1-9][0-9]*`, at most u64::MAX; no sign, fraction, exponent, quotes or null;
//! - nothing may follow the closing brace except whitespace.
//!
//! Writer: `Out` appends bytes, decimal integers, lowercase hex and already-validated strings to a
//! caller-provided buffer and stops the call (panic_utf8) rather than overflow it.

use crate::contract::fail;

#[derive(Clone, Copy)]
pub enum Kind {
    Str,
    U64,
}

#[derive(Clone, Copy, Debug)]
pub enum Val<'a> {
    Str(&'a [u8]),
    U64(u64),
}

pub struct Field {
    pub name: &'static [u8],
    pub kind: Kind,
    pub required: bool,
}

pub type Error = &'static str;

struct Cursor<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.peek() {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> bool {
        let hit = self.peek() == Some(c);
        if hit {
            self.i += 1;
        }
        hit
    }

    fn string(&mut self) -> Result<&'a [u8], Error> {
        if !self.eat(b'"') {
            return Err("expected a string");
        }
        let start = self.i;
        loop {
            match self.peek() {
                None => return Err("unterminated string"),
                Some(b'"') => break,
                Some(b'\\') => return Err("escape sequences are not accepted"),
                Some(0x20..=0x7e) => self.i += 1,
                Some(_) => return Err("strings must be printable ASCII"),
            }
        }
        let s = self.s.get(start..self.i).ok_or("expected a string")?;
        self.i += 1; // closing quote
        Ok(s)
    }

    fn number(&mut self) -> Result<u64, Error> {
        let start = self.i;
        let mut n: u64 = 0;
        while let Some(d @ b'0'..=b'9') = self.peek() {
            n = n.checked_mul(10).and_then(|n| n.checked_add((d - b'0') as u64)).ok_or("integer too large")?;
            self.i += 1;
        }
        match self.i - start {
            0 => Err("expected a non-negative integer"),
            1 => Ok(n),
            _ if self.s.get(start) == Some(&b'0') => Err("leading zeros are not accepted"),
            _ => Ok(n),
        }
    }
}

/// Parses `input` as one flat object with the given fields. `out[i]` is the value of `fields[i]`.
pub fn parse_object<'a, const N: usize>(input: &'a [u8], fields: &[Field; N]) -> Result<[Option<Val<'a>>; N], Error> {
    let mut out: [Option<Val<'a>>; N] = [None; N];
    parse_into(input, fields, &mut out)?;
    Ok(out)
}

// One non-generic copy of the parser, whatever the number of fields.
fn parse_into<'a>(input: &'a [u8], fields: &[Field], out: &mut [Option<Val<'a>>]) -> Result<(), Error> {
    let mut c = Cursor { s: input, i: 0 };
    c.ws();
    if c.peek().is_some() {
        if !c.eat(b'{') {
            return Err("expected an object");
        }
        c.ws();
        if !c.eat(b'}') {
            loop {
                c.ws();
                let key = c.string()?;
                c.ws();
                if !c.eat(b':') {
                    return Err("expected ':'");
                }
                c.ws();
                let mut hit = None;
                for (f, slot) in fields.iter().zip(out.iter_mut()) {
                    if f.name == key {
                        hit = Some((f.kind, slot));
                        break;
                    }
                }
                let Some((kind, slot)) = hit else { return Err("unknown field") };
                if slot.is_some() {
                    return Err("duplicate field");
                }
                *slot = Some(match kind {
                    Kind::Str => Val::Str(c.string()?),
                    Kind::U64 => Val::U64(c.number()?),
                });
                c.ws();
                if c.eat(b',') {
                    continue;
                }
                if c.eat(b'}') {
                    break;
                }
                return Err("expected ',' or '}'");
            }
        }
        c.ws();
        if c.peek().is_some() {
            return Err("unexpected characters after the object");
        }
    }
    for (f, v) in fields.iter().zip(out.iter()) {
        if f.required && v.is_none() {
            return Err("missing field");
        }
    }
    Ok(())
}

/// Append-only writer over a caller-provided buffer.
pub struct Out<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Out<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Out { buf, len: 0 }
    }

    pub fn bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    /// The written bytes, keeping the buffer's lifetime.
    pub fn done(self) -> &'a [u8] {
        let Out { buf, len } = self;
        match buf.get(..len) {
            Some(s) => s,
            None => &[],
        }
    }

    pub fn push(&mut self, s: &[u8]) -> &mut Self {
        let end = self.len + s.len();
        match self.buf.get_mut(self.len..end) {
            // same length by construction; zip instead of copy_from_slice keeps its formatting panic out
            Some(dst) => dst.iter_mut().zip(s).for_each(|(d, b)| *d = *b),
            None => fail(b"internal error: output buffer full"),
        }
        self.len = end;
        self
    }

    /// Decimal, without 128-bit division: four 32-bit limbs divided by 10 with u64 arithmetic.
    pub fn u128(&mut self, v: u128) -> &mut Self {
        let mut limbs = [(v >> 96) as u32, (v >> 64) as u32, (v >> 32) as u32, v as u32];
        let mut t = [0u8; 39];
        let mut i = t.len();
        loop {
            let mut rem = 0u64;
            for l in limbs.iter_mut() {
                let cur = rem << 32 | *l as u64;
                *l = (cur / 10) as u32;
                rem = cur % 10;
            }
            i -= 1;
            if let Some(d) = t.get_mut(i) {
                *d = b'0' + rem as u8;
            }
            if limbs == [0; 4] {
                break;
            }
        }
        self.push(t.get(i..).unwrap_or(&[]))
    }

    pub fn u64(&mut self, mut v: u64) -> &mut Self {
        let mut t = [0u8; 20];
        let mut i = t.len();
        loop {
            i -= 1;
            if let Some(d) = t.get_mut(i) {
                *d = b'0' + (v % 10) as u8;
            }
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.push(t.get(i..).unwrap_or(&[]))
    }

    pub fn hex(&mut self, bytes: &[u8]) -> &mut Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for b in bytes {
            self.push(&[HEX[(b >> 4) as usize], HEX[(b & 15) as usize]]);
        }
        self
    }

    /// A JSON string. Everything this contract stores was validated to safe printable ASCII on the way in,
    /// so nothing needs escaping; anything else here would mean corrupt state, and the call stops.
    pub fn str(&mut self, s: &[u8]) -> &mut Self {
        if s.iter().any(|&b| b == b'"' || b == b'\\' || !(0x20..=0x7e).contains(&b)) {
            fail(b"internal error: unsafe string in state");
        }
        self.push(b"\"").push(s).push(b"\"")
    }
}
