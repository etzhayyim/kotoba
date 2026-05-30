//! Hand-written recursive-descent EDN parser.
//!
//! Grammar (informal):
//! ```text
//! value     := nil | bool | number | char | string | keyword | symbol
//!            | list | vector | map | set | namespaced-map | tagged
//! list      := '(' value* ')'
//! vector    := '[' value* ']'
//! map       := '{' (value value)* '}'
//! set       := '#{' value* '}'
//! ns-map    := '#:' symbol map
//! tagged    := '#' symbol value
//! discard   := '#_' value
//! comment   := ';' .* '\n'
//! ```

use crate::value::{EdnValue, Keyword, Symbol};
use ordered_float::OrderedFloat;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("unexpected end of input at offset {0}")]
    UnexpectedEof(usize),
    #[error("unexpected character {ch:?} at offset {offset}")]
    UnexpectedChar { ch: char, offset: usize },
    #[error("invalid number {literal:?} at offset {offset}")]
    InvalidNumber { literal: String, offset: usize },
    #[error("invalid escape \\{ch} at offset {offset}")]
    InvalidEscape { ch: char, offset: usize },
    #[error("invalid character literal {literal:?} at offset {offset}")]
    InvalidChar { literal: String, offset: usize },
    #[error("unbalanced {kind} at offset {offset}")]
    Unbalanced { kind: &'static str, offset: usize },
    #[error("map has odd number of forms (expected key/value pairs) at offset {offset}")]
    OddMap { offset: usize },
    #[error("trailing data after value at offset {offset}")]
    TrailingData { offset: usize },
}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src: src.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }
    fn peek_at(&self, off: usize) -> Option<u8> {
        self.src.get(self.pos + off).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }
    fn eof(&self) -> bool {
        self.pos >= self.src.len()
    }

    fn skip_ws(&mut self) {
        loop {
            match self.peek() {
                Some(b) if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' || b == b',' => {
                    self.pos += 1;
                }
                Some(b';') => {
                    while let Some(b) = self.peek() {
                        self.pos += 1;
                        if b == b'\n' {
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
    }

    fn parse_value(&mut self) -> Result<EdnValue, ParseError> {
        loop {
            self.skip_ws();
            // Discard `#_ form` may appear before the value we want.
            if self.peek() == Some(b'#') && self.peek_at(1) == Some(b'_') {
                self.pos += 2;
                self.parse_value()?; // discard
                continue;
            }
            break;
        }
        let off = self.pos;
        let b = self.peek().ok_or(ParseError::UnexpectedEof(off))?;
        match b {
            b'(' => self.parse_list(),
            b'[' => self.parse_vector(),
            b'{' => self.parse_map(),
            b'#' => self.parse_dispatch(),
            b'"' => self.parse_string(),
            b'\\' => self.parse_char(),
            b':' => self.parse_keyword(),
            b'-' | b'+' | b'0'..=b'9' => self.parse_number_or_symbol(),
            _ if is_symbol_start(b) => self.parse_symbol_or_literal(),
            _ => Err(ParseError::UnexpectedChar {
                ch: b as char,
                offset: off,
            }),
        }
    }

    fn parse_list(&mut self) -> Result<EdnValue, ParseError> {
        let start = self.pos;
        self.pos += 1; // '('
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b'#') && self.peek_at(1) == Some(b'_') {
                self.pos += 2;
                self.parse_value()?;
                continue;
            }
            match self.peek() {
                None => {
                    return Err(ParseError::Unbalanced {
                        kind: "list",
                        offset: start,
                    })
                }
                Some(b')') => {
                    self.pos += 1;
                    return Ok(EdnValue::List(items));
                }
                _ => items.push(self.parse_value()?),
            }
        }
    }

    fn parse_vector(&mut self) -> Result<EdnValue, ParseError> {
        let start = self.pos;
        self.pos += 1; // '['
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b'#') && self.peek_at(1) == Some(b'_') {
                self.pos += 2;
                self.parse_value()?;
                continue;
            }
            match self.peek() {
                None => {
                    return Err(ParseError::Unbalanced {
                        kind: "vector",
                        offset: start,
                    })
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(EdnValue::Vector(items));
                }
                _ => items.push(self.parse_value()?),
            }
        }
    }

    fn parse_map(&mut self) -> Result<EdnValue, ParseError> {
        let start = self.pos;
        self.pos += 1; // '{'
        let mut items: Vec<EdnValue> = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b'#') && self.peek_at(1) == Some(b'_') {
                self.pos += 2;
                self.parse_value()?;
                continue;
            }
            match self.peek() {
                None => {
                    return Err(ParseError::Unbalanced {
                        kind: "map",
                        offset: start,
                    })
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => items.push(self.parse_value()?),
            }
        }
        if items.len() % 2 != 0 {
            return Err(ParseError::OddMap { offset: start });
        }
        let mut m = BTreeMap::new();
        let mut it = items.into_iter();
        while let (Some(k), Some(v)) = (it.next(), it.next()) {
            m.insert(k, v);
        }
        Ok(EdnValue::Map(m))
    }

    fn parse_set(&mut self) -> Result<EdnValue, ParseError> {
        let start = self.pos;
        self.pos += 1; // '{'  (caller already consumed '#')
        let mut items = BTreeSet::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b'#') && self.peek_at(1) == Some(b'_') {
                self.pos += 2;
                self.parse_value()?;
                continue;
            }
            match self.peek() {
                None => {
                    return Err(ParseError::Unbalanced {
                        kind: "set",
                        offset: start,
                    })
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(EdnValue::Set(items));
                }
                _ => {
                    items.insert(self.parse_value()?);
                }
            }
        }
    }

    fn parse_dispatch(&mut self) -> Result<EdnValue, ParseError> {
        let off = self.pos;
        self.pos += 1; // '#'
        match self.peek() {
            Some(b'{') => self.parse_set(),
            Some(b':') => self.parse_namespaced_map(),
            Some(b'#') => self.parse_symbolic_float(off),
            Some(b'_') => {
                self.pos += 1;
                self.parse_value()?; // discard
                self.parse_value() // continue with next form
            }
            Some(b) if is_symbol_start(b) => {
                let tag_off = self.pos;
                let tag_str = self.read_symbol_chars();
                if tag_str.is_empty() {
                    return Err(ParseError::UnexpectedChar {
                        ch: b as char,
                        offset: tag_off,
                    });
                }
                let tag = Symbol::parse(&tag_str);
                self.skip_ws();
                let value = self.parse_value()?;
                Ok(EdnValue::Tagged {
                    tag,
                    value: Box::new(value),
                })
            }
            Some(b) => Err(ParseError::UnexpectedChar {
                ch: b as char,
                offset: self.pos,
            }),
            None => Err(ParseError::UnexpectedEof(off)),
        }
    }

    fn parse_symbolic_float(&mut self, off: usize) -> Result<EdnValue, ParseError> {
        self.pos += 1; // second '#'
        let literal = self.read_symbol_chars();
        match literal.as_str() {
            "Inf" => Ok(EdnValue::float(f64::INFINITY)),
            "-Inf" => Ok(EdnValue::float(f64::NEG_INFINITY)),
            "NaN" => Ok(EdnValue::float(f64::NAN)),
            _ => Err(ParseError::InvalidNumber {
                literal: format!("##{literal}"),
                offset: off,
            }),
        }
    }

    fn parse_namespaced_map(&mut self) -> Result<EdnValue, ParseError> {
        let off = self.pos;
        self.pos += 1; // ':'
        let namespace = self.read_symbol_chars();
        if namespace.is_empty() {
            return Err(ParseError::UnexpectedChar {
                ch: ':',
                offset: off,
            });
        }
        self.skip_ws();
        if self.peek() != Some(b'{') {
            return Err(ParseError::UnexpectedChar {
                ch: self.peek().unwrap_or_default() as char,
                offset: self.pos,
            });
        }
        let EdnValue::Map(map) = self.parse_map()? else {
            unreachable!("parse_map always returns a map");
        };
        Ok(EdnValue::Map(
            map.into_iter()
                .map(|(k, v)| (qualify_namespaced_map_key(k, &namespace), v))
                .collect(),
        ))
    }

    fn parse_string(&mut self) -> Result<EdnValue, ParseError> {
        let start = self.pos;
        self.pos += 1; // '"'
        let mut s = String::new();
        loop {
            let b = self.peek().ok_or(ParseError::Unbalanced {
                kind: "string",
                offset: start,
            })?;
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(EdnValue::String(s));
                }
                b'\\' => {
                    self.pos += 1;
                    let esc_off = self.pos;
                    let esc = self.bump().ok_or(ParseError::UnexpectedEof(esc_off))?;
                    let ch = match esc {
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'\\' => '\\',
                        b'"' => '"',
                        b'/' => '/',
                        b'b' => '\u{08}',
                        b'f' => '\u{0C}',
                        b'u' => {
                            let mut code = 0u32;
                            for _ in 0..4 {
                                let h = self.bump().ok_or(ParseError::UnexpectedEof(self.pos))?;
                                let d =
                                    (h as char).to_digit(16).ok_or(ParseError::InvalidEscape {
                                        ch: h as char,
                                        offset: self.pos,
                                    })?;
                                code = code * 16 + d;
                            }
                            char::from_u32(code).ok_or(ParseError::InvalidEscape {
                                ch: 'u',
                                offset: esc_off,
                            })?
                        }
                        _ => {
                            return Err(ParseError::InvalidEscape {
                                ch: esc as char,
                                offset: esc_off,
                            })
                        }
                    };
                    s.push(ch);
                }
                _ => {
                    let tail = std::str::from_utf8(&self.src[self.pos..]).map_err(|_| {
                        ParseError::UnexpectedChar {
                            ch: b as char,
                            offset: self.pos,
                        }
                    })?;
                    let ch = tail.chars().next().ok_or(ParseError::Unbalanced {
                        kind: "string",
                        offset: start,
                    })?;
                    self.pos += ch.len_utf8();
                    s.push(ch);
                }
            }
        }
    }

    fn parse_char(&mut self) -> Result<EdnValue, ParseError> {
        let off = self.pos;
        self.pos += 1; // '\'
        let mut buf = String::new();
        while let Some(b) = self.peek() {
            if is_terminator(b) {
                break;
            }
            buf.push(b as char);
            self.pos += 1;
        }
        if buf.is_empty() {
            return Err(ParseError::InvalidChar {
                literal: buf,
                offset: off,
            });
        }
        let ch = match buf.as_str() {
            "newline" => '\n',
            "return" => '\r',
            "tab" => '\t',
            "space" => ' ',
            "formfeed" => '\u{0C}',
            "backspace" => '\u{08}',
            s if s.starts_with('u') && s.len() == 5 => {
                let code =
                    u32::from_str_radix(&s[1..], 16).map_err(|_| ParseError::InvalidChar {
                        literal: s.into(),
                        offset: off,
                    })?;
                char::from_u32(code).ok_or(ParseError::InvalidChar {
                    literal: s.into(),
                    offset: off,
                })?
            }
            s if s.chars().count() == 1 => s.chars().next().unwrap(),
            _ => {
                return Err(ParseError::InvalidChar {
                    literal: buf,
                    offset: off,
                })
            }
        };
        Ok(EdnValue::Char(ch))
    }

    fn parse_keyword(&mut self) -> Result<EdnValue, ParseError> {
        self.pos += 1; // ':'
        let s = self.read_symbol_chars();
        Ok(EdnValue::Keyword(Keyword::parse(&s)))
    }

    fn parse_number_or_symbol(&mut self) -> Result<EdnValue, ParseError> {
        // Distinguish `-` / `+` as start of symbol vs. signed number.
        let off = self.pos;
        let first = self.peek().unwrap();
        if (first == b'-' || first == b'+') && !matches!(self.peek_at(1), Some(b'0'..=b'9')) {
            return self.parse_symbol_or_literal();
        }
        let lit = self.read_symbol_chars();
        parse_number_literal(&lit, off)
    }

    fn parse_symbol_or_literal(&mut self) -> Result<EdnValue, ParseError> {
        let s = self.read_symbol_chars();
        Ok(match s.as_str() {
            "nil" => EdnValue::Nil,
            "true" => EdnValue::Bool(true),
            "false" => EdnValue::Bool(false),
            _ => EdnValue::Symbol(Symbol::parse(&s)),
        })
    }

    fn read_symbol_chars(&mut self) -> String {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if is_terminator(b) {
                break;
            }
            self.pos += 1;
        }
        std::str::from_utf8(&self.src[start..self.pos])
            .unwrap_or("")
            .to_string()
    }
}

fn parse_number_literal(lit: &str, off: usize) -> Result<EdnValue, ParseError> {
    if lit.is_empty() {
        return Err(ParseError::InvalidNumber {
            literal: lit.into(),
            offset: off,
        });
    }
    // BigDecimal: trailing M
    if let Some(stripped) = lit.strip_suffix('M') {
        // validate it's at least parseable as f64
        stripped
            .parse::<f64>()
            .map_err(|_| ParseError::InvalidNumber {
                literal: lit.into(),
                offset: off,
            })?;
        return Ok(EdnValue::BigDec(stripped.to_string()));
    }
    // BigInt: trailing N
    if let Some(stripped) = lit.strip_suffix('N') {
        stripped
            .parse::<i128>()
            .map_err(|_| ParseError::InvalidNumber {
                literal: lit.into(),
                offset: off,
            })?;
        return Ok(EdnValue::BigInt(stripped.to_string()));
    }
    // Float if contains '.', 'e', 'E'
    if lit.contains('.') || lit.contains('e') || lit.contains('E') {
        let f: f64 = lit.parse().map_err(|_| ParseError::InvalidNumber {
            literal: lit.into(),
            offset: off,
        })?;
        return Ok(EdnValue::Float(OrderedFloat(f)));
    }
    // Try i64; fall back to BigInt
    match lit.parse::<i64>() {
        Ok(i) => Ok(EdnValue::Integer(i)),
        Err(_) => {
            // Validate it's an integer-shaped string
            let body = lit
                .strip_prefix('-')
                .or_else(|| lit.strip_prefix('+'))
                .unwrap_or(lit);
            if !body.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ParseError::InvalidNumber {
                    literal: lit.into(),
                    offset: off,
                });
            }
            Ok(EdnValue::BigInt(lit.to_string()))
        }
    }
}

fn qualify_namespaced_map_key(key: EdnValue, namespace: &str) -> EdnValue {
    match key {
        EdnValue::Keyword(keyword) if keyword.namespace().is_none() => {
            EdnValue::Keyword(Keyword::namespaced(namespace, keyword.name()))
        }
        EdnValue::Symbol(symbol) if symbol.namespace.is_none() => {
            EdnValue::Symbol(Symbol::namespaced(namespace, symbol.name))
        }
        other => other,
    }
}

fn is_terminator(b: u8) -> bool {
    matches!(
        b,
        b' ' | b'\t' | b'\n' | b'\r' | b',' | b';' | b'(' | b')' | b'[' | b']' | b'{' | b'}' | b'"'
    )
}

fn is_symbol_start(b: u8) -> bool {
    matches!(b,
        b'a'..=b'z' | b'A'..=b'Z' |
        b'.' | b'*' | b'+' | b'!' | b'-' | b'_' | b'?' | b'$' | b'%' | b'&' | b'=' | b'<' | b'>' | b'/'
    )
}

/// Parse a single EDN value. Trailing content (after optional whitespace) is an error.
pub fn parse(src: &str) -> Result<EdnValue, ParseError> {
    let mut p = Parser::new(src);
    let v = p.parse_value()?;
    p.skip_ws();
    if !p.eof() {
        return Err(ParseError::TrailingData { offset: p.pos });
    }
    Ok(v)
}

/// Parse a stream of EDN values separated by whitespace.
pub fn parse_all(src: &str) -> Result<Vec<EdnValue>, ParseError> {
    let mut p = Parser::new(src);
    let mut out = Vec::new();
    loop {
        p.skip_ws();
        if p.eof() {
            break;
        }
        out.push(p.parse_value()?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars() {
        assert_eq!(parse("nil").unwrap(), EdnValue::Nil);
        assert_eq!(parse("true").unwrap(), EdnValue::Bool(true));
        assert_eq!(parse("false").unwrap(), EdnValue::Bool(false));
        assert_eq!(parse("42").unwrap(), EdnValue::Integer(42));
        assert_eq!(parse("-7").unwrap(), EdnValue::Integer(-7));
        assert_eq!(parse("3.14").unwrap(), EdnValue::float(3.14));
        assert_eq!(parse("\"hi\\n\"").unwrap(), EdnValue::String("hi\n".into()));
        assert_eq!(
            parse("\"テスト会社\"").unwrap(),
            EdnValue::String("テスト会社".into())
        );
        assert_eq!(parse(":foo").unwrap(), EdnValue::kw_bare("foo"));
        assert_eq!(parse(":db/id").unwrap(), EdnValue::kw("db", "id"));
        assert_eq!(parse("foo").unwrap(), EdnValue::sym("foo"));
        assert_eq!(parse("\\a").unwrap(), EdnValue::Char('a'));
        assert_eq!(parse("\\newline").unwrap(), EdnValue::Char('\n'));
    }

    #[test]
    fn collections() {
        let v = parse("[1 2 3]").unwrap();
        assert_eq!(
            v,
            EdnValue::vector([EdnValue::int(1), EdnValue::int(2), EdnValue::int(3)])
        );
        let l = parse("(a b)").unwrap();
        assert_eq!(l, EdnValue::list([EdnValue::sym("a"), EdnValue::sym("b")]));
        let m = parse("{:a 1 :b 2}").unwrap();
        if let EdnValue::Map(m) = m {
            assert_eq!(m.get(&EdnValue::kw_bare("a")), Some(&EdnValue::int(1)));
            assert_eq!(m.get(&EdnValue::kw_bare("b")), Some(&EdnValue::int(2)));
        } else {
            panic!()
        }
        let s = parse("#{1 2}").unwrap();
        assert!(matches!(s, EdnValue::Set(_)));
    }

    #[test]
    fn namespaced_map_qualifies_unqualified_keys() {
        let v = parse("#:person{:name \"Alice\" :age 30 :db/id \"alice\" plain true}").unwrap();
        let EdnValue::Map(m) = v else { panic!() };
        assert_eq!(
            m.get(&EdnValue::kw("person", "name")),
            Some(&EdnValue::String("Alice".into()))
        );
        assert_eq!(
            m.get(&EdnValue::kw("person", "age")),
            Some(&EdnValue::Integer(30))
        );
        assert_eq!(
            m.get(&EdnValue::kw("db", "id")),
            Some(&EdnValue::String("alice".into()))
        );
        assert_eq!(
            m.get(&EdnValue::Symbol(Symbol::namespaced("person", "plain"))),
            Some(&EdnValue::Bool(true))
        );
    }

    #[test]
    fn tagged_and_discard() {
        let v = parse("#inst \"2024-01-01\"").unwrap();
        if let EdnValue::Tagged { tag, value } = v {
            assert_eq!(tag.name, "inst");
            assert_eq!(*value, EdnValue::String("2024-01-01".into()));
        } else {
            panic!()
        }
        assert_eq!(parse("#_ ignored 42").unwrap(), EdnValue::Integer(42));
    }

    #[test]
    fn comments_and_commas() {
        assert_eq!(parse("; line comment\n42").unwrap(), EdnValue::Integer(42));
        assert_eq!(
            parse("[1, 2, 3]").unwrap(),
            EdnValue::vector([EdnValue::int(1), EdnValue::int(2), EdnValue::int(3)])
        );
    }

    #[test]
    fn datomic_tx() {
        let src = "[[:db/add -1 :person/name \"Alice\"]]";
        let v = parse(src).unwrap();
        if let EdnValue::Vector(outer) = v {
            assert_eq!(outer.len(), 1);
            if let EdnValue::Vector(inner) = &outer[0] {
                assert_eq!(inner[0], EdnValue::kw("db", "add"));
                assert_eq!(inner[1], EdnValue::Integer(-1));
                assert_eq!(inner[2], EdnValue::kw("person", "name"));
                assert_eq!(inner[3], EdnValue::String("Alice".into()));
            } else {
                panic!()
            }
        } else {
            panic!()
        }
    }

    #[test]
    fn parse_all_stream() {
        let xs = parse_all("1 2 3").unwrap();
        assert_eq!(
            xs,
            vec![EdnValue::int(1), EdnValue::int(2), EdnValue::int(3)]
        );
    }

    #[test]
    fn bigint_and_bigdec() {
        assert_eq!(parse("123N").unwrap(), EdnValue::BigInt("123".into()));
        assert_eq!(parse("3.14M").unwrap(), EdnValue::BigDec("3.14".into()));
    }

    #[test]
    fn symbolic_floats() {
        assert_eq!(parse("##Inf").unwrap(), EdnValue::float(f64::INFINITY));
        assert_eq!(parse("##-Inf").unwrap(), EdnValue::float(f64::NEG_INFINITY));
        let EdnValue::Float(nan) = parse("##NaN").unwrap() else {
            panic!()
        };
        assert!(nan.is_nan());
    }

    #[test]
    fn signed_symbol_vs_number() {
        assert_eq!(parse("-").unwrap(), EdnValue::sym("-"));
        assert_eq!(parse("+").unwrap(), EdnValue::sym("+"));
        assert_eq!(parse("-1").unwrap(), EdnValue::Integer(-1));
    }
}
