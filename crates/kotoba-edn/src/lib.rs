//! EDN (extensible data notation) reader/writer.
//!
//! EDN is the wire format used by Clojure/Datomic. This crate is the SSoT
//! for parsing and emitting Datomic-flavored data inside KOTOBA.
//!
//! Coverage:
//! - Scalars: nil, true/false, integers (i64 + arbitrary-precision string fallback),
//!   floats, big-decimals, characters, strings (with escape sequences), symbols,
//!   keywords (namespaced and bare).
//! - Collections: list `(...)`, vector `[...]`, map `{...}`, set `#{...}`.
//! - Tagged literals: `#tag value` (built-ins recognised: `#inst`, `#uuid`).
//! - Discard `#_form`, line comments `; ...`, `,` whitespace.
//!
//! Not covered (out of EDN spec): namespaced map syntax `#:ns{...}` is parsed
//! transparently (`:ns/k` keys are emitted), `#?` reader conditionals (Clojure-only).

mod parser;
pub mod value;
mod writer;

pub use parser::{parse, parse_all, ParseError};
pub use value::{EdnValue, Keyword, Symbol};
pub use writer::{to_string, to_string_pretty};
