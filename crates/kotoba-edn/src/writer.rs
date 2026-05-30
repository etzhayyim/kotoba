use crate::value::EdnValue;
use std::fmt::Write;

/// Canonical EDN serialization (sorted maps/sets, no extra whitespace).
pub fn to_string(v: &EdnValue) -> String {
    let mut buf = String::new();
    write_value(&mut buf, v, None, 0);
    buf
}

/// Pretty-printed EDN with 2-space indentation.
pub fn to_string_pretty(v: &EdnValue) -> String {
    let mut buf = String::new();
    write_value(&mut buf, v, Some(2), 0);
    buf
}

fn write_value(out: &mut String, v: &EdnValue, indent: Option<usize>, depth: usize) {
    match v {
        EdnValue::Nil => out.push_str("nil"),
        EdnValue::Bool(true) => out.push_str("true"),
        EdnValue::Bool(false) => out.push_str("false"),
        EdnValue::Integer(i) => {
            let _ = write!(out, "{}", i);
        }
        EdnValue::BigInt(s) => {
            out.push_str(s);
            out.push('N');
        }
        EdnValue::Float(f) => {
            let f = f.0;
            if f.is_nan() {
                out.push_str("##NaN");
            } else if f.is_infinite() {
                out.push_str(if f > 0.0 { "##Inf" } else { "##-Inf" });
            } else {
                let s = format!("{}", f);
                if !s.contains('.') && !s.contains('e') && !s.contains('E') {
                    let _ = write!(out, "{}.0", s);
                } else {
                    out.push_str(&s);
                }
            }
        }
        EdnValue::BigDec(s) => {
            out.push_str(s);
            out.push('M');
        }
        EdnValue::Char(c) => {
            out.push('\\');
            match c {
                '\n' => out.push_str("newline"),
                '\r' => out.push_str("return"),
                '\t' => out.push_str("tab"),
                ' ' => out.push_str("space"),
                '\u{0C}' => out.push_str("formfeed"),
                '\u{08}' => out.push_str("backspace"),
                _ => out.push(*c),
            }
        }
        EdnValue::String(s) => write_string(out, s),
        EdnValue::Symbol(s) => out.push_str(&s.to_qualified()),
        EdnValue::Keyword(k) => {
            out.push(':');
            out.push_str(&k.to_qualified());
        }
        EdnValue::List(xs) => write_seq(out, "(", ")", xs.iter(), indent, depth),
        EdnValue::Vector(xs) => write_seq(out, "[", "]", xs.iter(), indent, depth),
        EdnValue::Set(xs) => write_seq(out, "#{", "}", xs.iter(), indent, depth),
        EdnValue::Map(m) => write_map(out, m.iter(), indent, depth),
        EdnValue::Tagged { tag, value } => {
            out.push('#');
            out.push_str(&tag.to_qualified());
            out.push(' ');
            write_value(out, value, indent, depth);
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
}

fn write_seq<'a, I: Iterator<Item = &'a EdnValue>>(
    out: &mut String,
    open: &str,
    close: &str,
    mut it: I,
    indent: Option<usize>,
    depth: usize,
) {
    out.push_str(open);
    let mut first = true;
    while let Some(v) = it.next() {
        if !first {
            match indent {
                Some(n) => {
                    out.push('\n');
                    pad(out, n * (depth + 1));
                }
                None => out.push(' '),
            }
        } else if let Some(n) = indent {
            out.push('\n');
            pad(out, n * (depth + 1));
        }
        first = false;
        write_value(out, v, indent, depth + 1);
    }
    if let (Some(n), false) = (indent, first) {
        out.push('\n');
        pad(out, n * depth);
    }
    out.push_str(close);
}

fn write_map<'a, I: Iterator<Item = (&'a EdnValue, &'a EdnValue)>>(
    out: &mut String,
    mut it: I,
    indent: Option<usize>,
    depth: usize,
) {
    out.push('{');
    let mut first = true;
    while let Some((k, v)) = it.next() {
        if !first {
            match indent {
                Some(n) => {
                    out.push('\n');
                    pad(out, n * (depth + 1));
                }
                None => out.push(' '),
            }
        } else if let Some(n) = indent {
            out.push('\n');
            pad(out, n * (depth + 1));
        }
        first = false;
        write_value(out, k, indent, depth + 1);
        out.push(' ');
        write_value(out, v, indent, depth + 1);
    }
    if let (Some(n), false) = (indent, first) {
        out.push('\n');
        pad(out, n * depth);
    }
    out.push('}');
}

fn pad(out: &mut String, n: usize) {
    for _ in 0..n {
        out.push(' ');
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    fn roundtrip(s: &str) {
        let v = parse(s).expect("parse");
        let out = to_string(&v);
        let v2 = parse(&out).expect("reparse");
        assert_eq!(v, v2, "roundtrip drift: {} -> {}", s, out);
    }

    #[test]
    fn rt_scalars() {
        for s in [
            "nil", "true", "false", "42", "-7", "3.14", "##Inf", "##-Inf", "##NaN", "\"hi\"",
            ":db/id", "foo", "\\a",
        ] {
            roundtrip(s);
        }
    }

    #[test]
    fn rt_collections() {
        for s in [
            "[1 2 3]",
            "(a b c)",
            "{:a 1 :b 2}",
            "#:person{:name \"Alice\" :age 30}",
            "#{1 2 3}",
            "#inst \"2024\"",
        ] {
            roundtrip(s);
        }
    }

    #[test]
    fn rt_datomic_tx() {
        roundtrip("[[:db/add -1 :person/name \"Alice\"] [:db/add -1 :person/age 30]]");
    }
}
