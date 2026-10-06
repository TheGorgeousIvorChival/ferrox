//! A minimal `JSON` reader and writer, so the harness has no dependency whose
//! version could move a number.
//!
//! The benchmark's inputs and outputs are `JSON` documents, and the project
//! policy is that a measurement should not be attributable to a transitive
//! dependency that a lockfile bump could change
//! (`upstream/zeronet/docs/benchmarks/README.md:21`, "No dependencies. std only,
//! so CI builds it in seconds and nobody has to reason about whether a patched
//! transitive crate moved the number"). The same argument applies here: the
//! harness reads a request and writes a result, and nothing else it does needs a
//! serialisation library.
//!
//! It is deliberately small: objects, arrays, strings with the standard escapes,
//! numbers, `true`/`false`/`null`, nested 32 deep. Anything else is an error
//! rather than a guess, because a guess in a request parser is a request that
//! measures something other than what it says.

use std::fmt::Write as _;

/// One `JSON` value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Numbers are `f64`: every number in a request is a count or a port, and a
    /// count this harness accepts is below 2^32.
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    /// Insertion order is kept, so a written document is byte-stable and a diff
    /// between two runs shows the changed value rather than a reordered object.
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// An empty object.
    pub fn object() -> Self {
        Self::Obj(Vec::new())
    }

    /// Insert or replace a member. Insertion order is preserved on first insert.
    pub fn insert(&mut self, key: &str, value: Json) {
        if let Self::Obj(pairs) = self {
            match pairs.iter_mut().find(|(k, _)| k == key) {
                Some(slot) => slot.1 = value,
                None => pairs.push((key.to_owned(), value)),
            }
        }
    }

    /// Member lookup, `None` on a non-object or an absent key.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Self::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// String contents, `None` for every other shape.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Array items, `None` for every other shape.
    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Self::Arr(items) => Some(items),
            _ => None,
        }
    }

    /// Object members, `None` for every other shape.
    pub fn as_obj(&self) -> Option<&[(String, Json)]> {
        match self {
            Self::Obj(pairs) => Some(pairs),
            _ => None,
        }
    }

    /// A finite number, `None` for a non-number or a non-finite one.
    ///
    /// The finiteness check is load-bearing rather than defensive: `NaN` and the
    /// infinities have no `JSON` spelling, so a document containing one is a
    /// document this parser has misread.
    pub fn as_num(&self) -> Option<f64> {
        match self {
            Self::Num(n) if n.is_finite() => Some(*n),
            _ => None,
        }
    }

    /// A boolean, `None` for every other shape.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Serialise to compact `JSON`.
    ///
    /// Named `to_string` rather than implementing `Display` because it can fail:
    /// a `f64` that is not finite has no `JSON` spelling, so a document holding
    /// one has to be an error at the point it is written rather than a `NaN`
    /// appearing in a published result.
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> Result<String, String> {
        let mut out = String::new();
        self.write(&mut out)?;
        Ok(out)
    }

    /// Serialise into `out`, which is what [`Self::to_string`] wraps.
    ///
    /// A non-finite number is an error rather than a `NaN` in the output: a
    /// `result.json` is read by other tools, and a document they cannot parse is
    /// better than one they parse into a number that means nothing.
    fn write(&self, out: &mut String) -> Result<(), String> {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(true) => out.push_str("true"),
            Self::Bool(false) => out.push_str("false"),
            Self::Num(n) => {
                if !n.is_finite() {
                    return Err(format!("{n} has no json spelling"));
                }
                if n.fract() == 0.0 && n.abs() < 1e15 {
                    let _ = write!(out, "{}", *n as i64);
                } else {
                    let _ = write!(out, "{n}");
                }
            }
            Self::Str(s) => write_string(s, out),
            Self::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out)?;
                }
                out.push(']');
            }
            Self::Obj(pairs) => {
                out.push('{');
                for (i, (key, value)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(key, out);
                    out.push(':');
                    value.write(out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }
}

/// Write a `JSON` string literal, escaping what the grammar requires.
///
/// The two mandatory escapes, the five short forms, and every control character
/// below `0x20` as `\u00XX`. A lone surrogate cannot be produced by `escape_default`
/// for a `char`, and Rust strings cannot hold one, so the pair of cases above
/// `0x7f` needs nothing.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Parse a whole document, rejecting trailing bytes after the first value.
pub fn parse(text: &str) -> Result<Json, String> {
    let mut cursor = Cursor {
        bytes: text.as_bytes(),
        pos: 0,
    };
    let value = cursor.value(0)?;
    cursor.gap();
    if cursor.pos != cursor.bytes.len() {
        return Err(format!("trailing bytes at offset {}", cursor.pos));
    }
    Ok(value)
}

/// Deepest nesting accepted, matching the config reader in `ferrox-app`.
const MAX_DEPTH: usize = 32;

/// Byte cursor over the document.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    /// Skip whitespace between tokens.
    fn gap(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    /// The byte at the cursor, or `None` at the end.
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Expect one literal byte.
    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!(
                "expected `{}` at offset {}",
                byte as char, self.pos
            ))
        }
    }

    /// One complete value.
    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return Err(format!("nested deeper than {MAX_DEPTH}"));
        }
        self.gap();
        match self.peek() {
            None => Err("unexpected end of document".to_owned()),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Json::Str),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(_) => self.number(),
        }
    }

    /// A fixed literal.
    fn literal(&mut self, text: &str, value: Json) -> Result<Json, String> {
        if self.bytes[self.pos..].starts_with(text.as_bytes()) {
            self.pos += text.len();
            Ok(value)
        } else {
            Err(format!("expected `{text}` at offset {}", self.pos))
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut pairs = Vec::new();
        self.gap();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(pairs));
        }
        loop {
            self.gap();
            let key = self.string()?;
            self.gap();
            self.expect(b':')?;
            let value = self.value(depth + 1)?;
            pairs.push((key, value));
            self.gap();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(pairs));
                }
                _ => return Err(format!("expected `,` or `}}` at offset {}", self.pos)),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.gap();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.gap();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(format!("expected `,` or `]` at offset {}", self.pos)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err("unterminated string".to_owned());
            };
            self.pos += 1;
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let Some(esc) = self.peek() else {
                        return Err("unterminated escape".to_owned());
                    };
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        other => {
                            return Err(format!("unknown escape `\\{}`", other as char));
                        }
                    }
                }
                // Anything at or above 0x80 is copied through: the bytes are
                // passed on unchanged and validated as UTF-8 at the end.
                _ => {
                    let start = self.pos - 1;
                    while self.pos < self.bytes.len()
                        && self.bytes[self.pos] != b'"'
                        && self.bytes[self.pos] != b'\\'
                    {
                        self.pos += 1;
                    }
                    out.push_str(&String::from_utf8_lossy(&self.bytes[start..self.pos]));
                }
            }
        }
    }

    /// `\uXXXX`, with a surrogate pair joined when the next escape is the low half.
    fn unicode_escape(&mut self) -> Result<char, String> {
        let high = self.hex4()?;
        if (0xd800..0xdc00).contains(&high) {
            if self.peek() != Some(b'\\') {
                return Err("a high surrogate must be followed by its low half".to_owned());
            }
            self.pos += 1;
            self.expect(b'u')?;
            let low = self.hex4()?;
            if !(0xdc00..0xe000).contains(&low) {
                return Err("a high surrogate must be followed by a low surrogate".to_owned());
            }
            let combined = 0x1_0000 + ((high - 0xd800) << 10) + (low - 0xdc00);
            return char::from_u32(combined).ok_or_else(|| "invalid surrogate pair".to_owned());
        }
        char::from_u32(high).ok_or_else(|| format!("invalid code point {high:04x}"))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.bytes.len() {
            return Err("truncated \\u escape".to_owned());
        }
        let text = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
            .map_err(|_| "a \\u escape must be ascii".to_owned())?;
        let value = u32::from_str_radix(text, 16).map_err(|_| format!("bad \\u escape {text}"))?;
        self.pos += 4;
        Ok(value)
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(
            self.peek(),
            Some(b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
        ) {
            self.pos += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "a number must be ascii".to_owned())?;
        text.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| format!("`{text}` is not a number"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_nested_document() {
        let text = r#"{"a":1,"b":[true,null,-2.5],"c":{"d":"e"},"f":"x\ny"}"#;
        let parsed = parse(text).expect("parses");
        assert_eq!(parsed.get("a").and_then(Json::as_num), Some(1.0));
        assert_eq!(
            parsed.get("b").and_then(Json::as_arr).map(<[Json]>::len),
            Some(3)
        );
        assert_eq!(
            parsed
                .get("c")
                .and_then(|c| c.get("d"))
                .and_then(Json::as_str),
            Some("e")
        );
        let again = parse(&parsed.to_string().expect("serialises")).expect("reparses");
        assert_eq!(parsed, again, "a round trip must be lossless");
    }

    #[test]
    fn escapes_and_unescapes_everything_it_must() {
        let parsed = parse(r#""a\"b\\c\nd\teé""#).expect("parses");
        assert_eq!(parsed.as_str(), Some("a\"b\\c\nd\te\u{e9}"));
        assert_eq!(
            parse(&parsed.to_string().expect("serialises"))
                .expect("reparses")
                .as_str(),
            parsed.as_str()
        );
    }

    #[test]
    fn decodes_a_surrogate_pair() {
        let parsed = parse(r#""🎯""#).expect("parses");
        assert_eq!(parsed.as_str(), Some("\u{1f3af}"));
    }

    #[test]
    fn writes_control_characters_as_escapes() {
        let value = Json::Str("a\u{1}b".to_owned());
        let text = value.to_string().expect("serialises");
        assert_eq!(text, "\"a\\u0001b\"");
        assert_eq!(parse(&text).expect("reparses"), value);
    }

    #[test]
    fn whole_numbers_keep_their_integral_spelling() {
        let render = |n: f64| Json::Num(n).to_string().expect("finite");
        assert_eq!(render(4096.0), "4096");
        assert_eq!(render(-2.0), "-2");
        assert_eq!(render(1.5), "1.5");
    }

    /// A non-finite number has no `JSON` spelling, so writing one is an error at
    /// the point of writing rather than a `NaN` in a published result.
    #[test]
    fn a_non_finite_number_is_refused_rather_than_written() {
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(Json::Num(bad).to_string().is_err(), "{bad} must not write");
        }
    }

    #[test]
    fn rejects_malformed_documents() {
        for bad in [
            "{",
            "{}x",
            r#"{"a"}"#,
            r#"{"a":}"#,
            "[1,]",
            r#""unterminated"#,
            r#""\q""#,
            r#""\ud83c""#,
            // A lone low surrogate, and an escape that is not four hex digits.
            r#""\udf00""#,
            r#""\u00g0""#,
            // Trailing bytes after a complete value, including a second value.
            "{} {}",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn refuses_to_descend_past_the_depth_limit() {
        let deep = "[".repeat(40) + &"]".repeat(40);
        assert!(parse(&deep).is_err());
        let fine = "[".repeat(30) + &"]".repeat(30);
        assert!(parse(&fine).is_ok());
    }

    #[test]
    fn insertion_replaces_in_place() {
        let mut o = Json::object();
        o.insert("a", Json::Num(1.0));
        o.insert("b", Json::Num(2.0));
        o.insert("a", Json::Num(3.0));
        assert_eq!(o.to_string().expect("serialises"), r#"{"a":3,"b":2}"#);
    }
}
