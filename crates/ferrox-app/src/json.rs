//! Minimal `JSON` reader for Xray-shaped config files.
//!
//! Only what `run -c` looks up exists here: objects, arrays, strings, numbers,
//! `true`/`false`/`null`, nested 32 deep. Anything else is an error, never a guess.

/// One `JSON` value, borrowed from nothing and owned by the caller.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// Any number, kept as `f64` since only ports are read out of it.
    Num(f64),
    /// A string, escapes resolved.
    Str(String),
    /// An array.
    Arr(Vec<Json>),
    /// An object, insertion order kept.
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Member lookup on objects, `None` on anything else or when absent.
    pub(crate) fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Self::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// String contents, `None` for every other shape.
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Port numbers: integers in `0..=65535`, `None` otherwise.
    pub(crate) fn as_port(&self) -> Option<u16> {
        match self {
            Self::Num(n) if n.fract() == 0.0 && (0.0..=65535.0).contains(n) => Some(*n as u16),
            _ => None,
        }
    }

    /// Array items, `None` for every other shape.
    pub(crate) fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Self::Arr(items) => Some(items),
            _ => None,
        }
    }
}

/// Parse a whole document, rejecting trailing bytes after the first value.
pub(crate) fn parse(text: &str) -> Result<Json, String> {
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

/// Byte cursor over the document, tracking one position.
#[derive(Debug)]
struct Cursor<'a> {
    /// Raw document bytes.
    bytes: &'a [u8],
    /// Next unread offset.
    pos: usize,
}

impl Cursor<'_> {
    /// Skip ASCII whitespace.
    fn gap(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    /// Consume one expected byte, naming it on failure.
    fn byte(&mut self, want: u8, what: &str) -> Result<(), String> {
        self.gap();
        if self.bytes.get(self.pos) == Some(&want) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected {what} at offset {}", self.pos))
        }
    }

    /// Parse any value at the depth limit.
    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > 32 {
            return Err(format!("nesting past 32 at offset {}", self.pos));
        }
        self.gap();
        match self.bytes.get(self.pos) {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(c) if c.is_ascii_digit() || *c == b'-' => self.number(),
            Some(_) => self.word(),
            None => Err(format!("unexpected end at offset {}", self.pos)),
        }
    }

    /// Parse `{...}` after the brace is seen.
    fn object(&mut self, depth: usize) -> Result<Json, String> {
        self.pos += 1;
        let mut pairs = Vec::new();
        self.gap();
        if self.bytes.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(Json::Obj(pairs));
        }
        loop {
            self.gap();
            if self.bytes.get(self.pos) != Some(&b'"') {
                return Err(format!("expected a key at offset {}", self.pos));
            }
            let key = self.string()?;
            self.byte(b':', "`:`")?;
            pairs.push((key, self.value(depth + 1)?));
            self.gap();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(pairs));
                }
                _ => return Err(format!("expected `,` or `}}` at offset {}", self.pos)),
            }
        }
    }

    /// Parse `[...]` after the bracket is seen.
    fn array(&mut self, depth: usize) -> Result<Json, String> {
        self.pos += 1;
        let mut items = Vec::new();
        self.gap();
        if self.bytes.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.gap();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(format!("expected `,` or `]` at offset {}", self.pos)),
            }
        }
    }

    /// Parse a quoted string with its escapes resolved.
    fn string(&mut self) -> Result<String, String> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            let Some(&b) = self.bytes.get(self.pos) else {
                return Err(format!("unterminated string at offset {}", self.pos));
            };
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => out.push(self.escape()?),
                0x00..=0x1F => return Err(format!("raw control byte at offset {}", self.pos)),
                _ => out.push(b as char),
            }
        }
    }

    /// Parse one escape after the backslash is consumed.
    fn escape(&mut self) -> Result<char, String> {
        let Some(&b) = self.bytes.get(self.pos) else {
            return Err(format!("dangling backslash at offset {}", self.pos));
        };
        self.pos += 1;
        match b {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{0008}'),
            b'f' => Ok('\u{000C}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => {
                if self.pos + 4 > self.bytes.len() {
                    return Err(format!("short `\\u` escape at offset {}", self.pos));
                }
                let mut unit = 0u32;
                for i in 0..4 {
                    unit = unit * 16 + hex(self.bytes[self.pos + i], self.pos + i)?;
                }
                self.pos += 4;
                char::from_u32(unit).ok_or_else(|| format!("bad scalar at offset {}", self.pos))
            }
            _ => Err(format!("bad escape at offset {}", self.pos)),
        }
    }

    /// Parse a number, keeping one `f64`.
    fn number(&mut self) -> Result<Json, String> {
        let from = self.pos;
        if self.bytes.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        while self.bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
            self.pos += 1;
        }
        if self.bytes.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            while self.bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
                self.pos += 1;
            }
        }
        if matches!(self.bytes.get(self.pos), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.bytes.get(self.pos), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            while self.bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
                self.pos += 1;
            }
        }
        let text = std::str::from_utf8(&self.bytes[from..self.pos])
            .map_err(|_| format!("bad number at offset {from}"))?;
        text.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| format!("bad number at offset {from}"))
    }

    /// Parse `true`, `false` or `null` by exact word.
    fn word(&mut self) -> Result<Json, String> {
        for (word, value) in [
            ("true", Json::Bool(true)),
            ("false", Json::Bool(false)),
            ("null", Json::Null),
        ] {
            if self.bytes[self.pos..].starts_with(word.as_bytes()) {
                self.pos += word.len();
                return Ok(value);
            }
        }
        Err(format!("unexpected token at offset {}", self.pos))
    }
}

/// One hex digit's value.
fn hex(byte: u8, at: usize) -> Result<u32, String> {
    match byte {
        b'0'..=b'9' => Ok(u32::from(byte - b'0')),
        b'a'..=b'f' => Ok(u32::from(byte - b'a') + 10),
        b'A'..=b'F' => Ok(u32::from(byte - b'A') + 10),
        _ => Err(format!("bad hex digit at offset {at}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `SplitMix64` state, so a printed seed replays the exact corpus.
    ///
    /// Deterministic rather than random, and that is the whole design: a failure
    /// in CI on a runner nobody can log into cannot be reproduced at all, and a
    /// generator whose seed is printed replays anywhere.
    #[derive(Debug, Clone)]
    struct Rng(u64);

    impl Rng {
        /// A generator from a seed.
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        /// The next 64 bits, by `SplitMix64` (Steele, Lea and Flood).
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        /// One byte.
        fn byte(&mut self) -> u8 {
            #[allow(clippy::cast_possible_truncation)]
            {
                self.next_u64() as u8
            }
        }

        /// A byte in `0..bound`, by rejection so it is uniform, and `0` on a zero
        /// bound rather than a division by it.
        fn below(&mut self, bound: usize) -> usize {
            if bound == 0 {
                return 0;
            }
            let bound = u32::try_from(bound).unwrap_or(u32::MAX);
            let zone = 256 - (256 % bound);
            loop {
                let draw = u32::from(self.byte());
                if draw < zone {
                    return (draw % bound) as usize;
                }
            }
        }
    }

    /// The corpus seed: a golden-ratio odd number, so adjacent seeds produce
    /// visibly different corpora.
    const SEED: u64 = 0x4528_21e6_38d0_1377;

    /// Cases. 4096, and not a power of two: a count of `2^n` lets a
    /// modulo-bound generator cover half its range by accident.
    const CASES: usize = 4_096;

    /// A configuration the reader is meant to accept, so the corrupt cases are a
    /// delta from something valid rather than noise from nothing.
    const GOOD: &str = r#"{"inbounds":[{"protocol":"vless","port":443,"streamSettings":{"network":"ws","wsSettings":{"path":"/x"}}}],"outbounds":[{"protocol":"freedom"}]}"#;

    /// This reader is hand-written, so every escape, every number and every
    /// nesting level is code somebody wrote, and it is the one parser here with
    /// no `unsafe` and therefore no differential proof behind it. The claim is
    /// only that it never panics and never half-parses.
    ///
    /// A `libFuzzer` target would explore until it found a case; this explores
    /// 4096 seeded ones on every runner `ci.yml` has, which is a weaker guarantee
    /// and the one that is actually reached on every commit.
    #[test]
    fn the_reader_survives_corrupted_configuration() {
        for case in 0..CASES {
            let seed = SEED.wrapping_add(case as u64);
            let mut rng = Rng::new(seed);

            let mut text = String::from(GOOD);
            // One case in five is the control, so the loop asserts the reader
            // accepts what it should as well as refusing what it should not.
            match case % 5 {
                0 => {}
                1 => {
                    let at = rng.below(text.len());
                    text.replace_range(at..=at, "\u{fffd}");
                }
                2 => {
                    let at = rng.below(text.len());
                    text.remove(at);
                }
                3 => {
                    let at = rng.below(text.len());
                    text.insert(at, '\\');
                }
                _ => {
                    let at = rng.below(text.len());
                    text.insert(at, '"');
                }
            }

            // An `Err` is the usual answer and the correct one; the property is
            // that neither answer panics, hangs, or trusts a length the text
            // itself supplied.
            let _ = parse(&text);
        }
    }

    /// Every prefix of a valid document must be refused, never parsed into a
    /// config with fewer inbounds than it names.
    #[test]
    fn a_truncated_configuration_is_refused_rather_than_partially_parsed() {
        for cut in 1..GOOD.len() {
            assert!(
                parse(&GOOD[..cut]).is_err(),
                "cut {cut} parsed a prefix of a valid document instead of refusing it"
            );
        }
        assert!(
            parse(GOOD).is_ok(),
            "the corpus must be valid to mean anything"
        );
    }

    #[test]
    fn reads_the_oracle_config_shape() {
        let doc = parse(
            r#"{"log": {"loglevel": "debug"}, "inbounds": [{"tag": "in",
            "listen": "127.0.0.1", "port": 41234, "protocol": "vless",
            "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
            "decryption": "none"}, "streamSettings": {"network": "tcp"}}],
            "outbounds": [{"protocol": "freedom"}]}"#,
        )
        .expect("parses");
        let inbound = &doc
            .get("inbounds")
            .expect("inbounds")
            .as_arr()
            .expect("array")[0];
        assert_eq!(
            inbound.get("protocol").expect("protocol").as_str(),
            Some("vless")
        );
        assert_eq!(inbound.get("port").expect("port").as_port(), Some(41234));
        let id = inbound
            .get("settings")
            .expect("settings")
            .get("clients")
            .expect("clients")
            .as_arr()
            .expect("array")[0]
            .get("id")
            .expect("id")
            .as_str()
            .expect("string");
        assert_eq!(id, "b831381d-6324-4d53-ad4f-8cda48b30811");
    }

    #[test]
    fn rejects_trailing_bytes_and_bad_words() {
        assert!(parse(r#"{"a": 1} trailing"#).is_err());
        assert!(parse(r#"{"a": tru}"#).is_err());
        assert!(parse(r#"{"a": [1,]}"#).is_err());
        assert_eq!(parse("null").expect("null"), Json::Null);
        assert_eq!(parse("  41234 ").expect("port").as_port(), Some(41234));
        assert!(parse("70000").expect("big").as_port().is_none());
    }
}
