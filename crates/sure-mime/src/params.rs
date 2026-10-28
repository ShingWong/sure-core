//! MIME parameter parsing, including RFC 2231.
//!
//! v0.1 intentionally supports only `US-ASCII`, `UTF-8` and `ISO-8859-1`
//! charsets. An unknown charset is a typed error rather than a silent lossy
//! conversion. Hosts that need more charsets should decode at the edge with an
//! audited table and pass UTF-8 in.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::error::{Error, ParamError, Result};

const MAX_PARAMETERS: usize = 256;
const MAX_SECTION: u32 = 999;

/// One parsed MIME parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    /// Lowercase base name (continuation suffix removed).
    pub name: String,
    /// Decoded value.
    pub value: String,
    /// RFC 2231 charset, when one was declared.
    pub charset: Option<String>,
    /// RFC 2231 language, when one was declared.
    pub language: Option<String>,
}

impl Parameter {
    /// Case-insensitive name comparison.
    #[must_use]
    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

/// Parse a semicolon-separated parameter list.
///
/// # Errors
///
/// Returns a typed [`ParamError`] for malformed quoting, escapes, RFC 2231
/// continuations, duplicate names or unsupported charsets.
pub fn parse_parameters(input: &[u8]) -> Result<Vec<Parameter>> {
    let raw = parse_raw_parameters(input)?;
    let mut groups: Vec<Group> = Vec::new();

    for (order, item) in raw.into_iter().enumerate() {
        let parsed = parse_name(&item.name)?;
        let base = parsed.base;
        let position = match groups.iter().position(|group| group.base == base) {
            Some(position) => position,
            None => {
                groups.push(Group {
                    base: base.clone(),
                    order,
                    plain: None,
                    segments: Vec::new(),
                    charset: None,
                    language: None,
                });
                groups.len().saturating_sub(1)
            }
        };
        let group = groups
            .get_mut(position)
            .ok_or(Error::Param(ParamError::TooManyParameters))?;

        match parsed.section {
            None if parsed.extended => {
                if group.plain.is_some() || !group.segments.is_empty() {
                    return Err(Error::Param(ParamError::DuplicateParameter));
                }
                group.segments.push(Segment {
                    section: 0,
                    extended: true,
                    bytes: item.value,
                });
            }
            None => {
                if group.plain.is_some() || !group.segments.is_empty() {
                    return Err(Error::Param(ParamError::DuplicateParameter));
                }
                group.plain = Some(item.value);
            }
            Some(section) => {
                if group.plain.is_some() {
                    return Err(Error::Param(ParamError::DuplicateParameter));
                }
                group.segments.push(Segment {
                    section,
                    extended: parsed.extended,
                    bytes: item.value,
                });
            }
        }
    }

    groups.sort_by_key(|group| group.order);
    let mut result = Vec::with_capacity(groups.len());
    for group in groups {
        result.push(group.finish()?);
    }
    Ok(result)
}

struct RawParameter {
    name: Vec<u8>,
    value: Vec<u8>,
}

struct ParsedName {
    base: String,
    section: Option<u32>,
    extended: bool,
}

struct Segment {
    section: u32,
    extended: bool,
    bytes: Vec<u8>,
}

struct Group {
    base: String,
    order: usize,
    plain: Option<Vec<u8>>,
    segments: Vec<Segment>,
    charset: Option<String>,
    language: Option<String>,
}

impl Group {
    fn finish(mut self) -> Result<Parameter> {
        if let Some(plain) = self.plain {
            let value = decode_bytes(&plain, self.charset.as_deref())?;
            return Ok(Parameter {
                name: self.base,
                value,
                charset: self.charset,
                language: self.language,
            });
        }

        if self.segments.is_empty() {
            return Err(Error::Param(ParamError::NonContiguousSections));
        }
        self.segments.sort_by_key(|segment| segment.section);
        for (expected, segment) in self.segments.iter().enumerate() {
            let expected =
                u32::try_from(expected).map_err(|_| Error::Param(ParamError::InvalidSection))?;
            if segment.section != expected {
                return Err(Error::Param(if segment.section < expected {
                    ParamError::DuplicateSection
                } else {
                    ParamError::NonContiguousSections
                }));
            }
        }

        let mut decoded = Vec::new();
        for (index, segment) in self.segments.iter().enumerate() {
            let bytes = if segment.extended {
                if index == 0 {
                    let (charset, language, data) = split_charset_prefix(&segment.bytes)?;
                    self.charset = charset;
                    self.language = language;
                    percent_decode(data)?
                } else {
                    percent_decode(&segment.bytes)?
                }
            } else {
                segment.bytes.clone()
            };
            decoded.extend_from_slice(&bytes);
        }

        let value = decode_bytes(&decoded, self.charset.as_deref())?;
        Ok(Parameter {
            name: self.base,
            value,
            charset: self.charset,
            language: self.language,
        })
    }
}

fn parse_raw_parameters(input: &[u8]) -> Result<Vec<RawParameter>> {
    let mut result = Vec::new();
    let mut index = 0usize;
    let length = input.len();

    while index < length {
        while index < length && (input[index] == b';' || is_wsp(input[index])) {
            index = index.saturating_add(1);
        }
        if index >= length {
            break;
        }
        if result.len() >= MAX_PARAMETERS {
            return Err(Error::Param(ParamError::TooManyParameters));
        }

        let name_start = index;
        while index < length
            && input[index] != b'='
            && input[index] != b';'
            && !is_wsp(input[index])
        {
            index = index.saturating_add(1);
        }
        let name = trim_wsp(&input[name_start..index]);
        if name.is_empty() {
            return Err(Error::Param(ParamError::EmptyName));
        }
        if !name
            .iter()
            .all(|byte| (33..=126).contains(byte) && *byte != b'*' && *byte != b'"')
        {
            // Star is allowed in RFC 2231 names; the check is repeated below
            // with the star included. This branch only rejects control bytes,
            // separators and quotes.
            if !name
                .iter()
                .all(|byte| (33..=126).contains(byte) && *byte != b'=' && *byte != b'"')
            {
                return Err(Error::Param(ParamError::EmptyName));
            }
        }
        while index < length && is_wsp(input[index]) {
            index = index.saturating_add(1);
        }
        if index >= length || input[index] != b'=' {
            return Err(Error::Param(ParamError::MissingEquals));
        }
        index = index.saturating_add(1);
        while index < length && is_wsp(input[index]) {
            index = index.saturating_add(1);
        }

        let value = if index < length && input[index] == b'"' {
            parse_quoted(input, &mut index)?
        } else {
            let start = index;
            while index < length && input[index] != b';' {
                if input[index] == 0 || input[index] == b'\r' || input[index] == b'\n' {
                    return Err(Error::Param(ParamError::ControlInQuotedString));
                }
                index = index.saturating_add(1);
            }
            trim_wsp(&input[start..index]).to_vec()
        };

        while index < length && is_wsp(input[index]) {
            index = index.saturating_add(1);
        }
        if index < length && input[index] != b';' {
            return Err(Error::Param(ParamError::MissingEquals));
        }
        result.push(RawParameter {
            name: name.to_vec(),
            value,
        });
    }
    Ok(result)
}

fn parse_quoted(input: &[u8], index: &mut usize) -> Result<Vec<u8>> {
    if input.get(*index).copied() != Some(b'"') {
        return Err(Error::Param(ParamError::InvalidEscape));
    }
    *index = index.saturating_add(1);
    let mut out = Vec::new();
    while *index < input.len() {
        let byte = input[*index];
        *index = index.saturating_add(1);
        match byte {
            b'"' => return Ok(out),
            b'\\' => {
                let escaped = input
                    .get(*index)
                    .copied()
                    .ok_or(Error::Param(ParamError::InvalidEscape))?;
                *index = index.saturating_add(1);
                if escaped == 0 || escaped == b'\r' || escaped == b'\n' {
                    return Err(Error::Param(ParamError::ControlInQuotedString));
                }
                out.push(escaped);
            }
            0 | b'\r' | b'\n' => {
                return Err(Error::Param(ParamError::ControlInQuotedString));
            }
            _ => out.push(byte),
        }
    }
    Err(Error::Param(ParamError::UnterminatedQuotedString))
}

fn parse_name(name: &[u8]) -> Result<ParsedName> {
    let trailing_star = name.last().copied() == Some(b'*');
    let core = if trailing_star {
        &name[..name.len().saturating_sub(1)]
    } else {
        name
    };

    let star = core.iter().rposition(|byte| *byte == b'*');
    let (base_bytes, section, extended) = match star {
        Some(position) => {
            let suffix = &core[position.saturating_add(1)..];
            if suffix.is_empty() {
                // `base*` (only valid when the original name ended in `*`).
                if !trailing_star {
                    return Err(Error::Param(ParamError::InvalidSection));
                }
                (&core[..position], None, true)
            } else if suffix.iter().all(u8::is_ascii_digit) {
                (
                    &core[..position],
                    Some(parse_section(suffix)?),
                    trailing_star,
                )
            } else {
                return Err(Error::Param(ParamError::InvalidSection));
            }
        }
        None => (core, None, trailing_star),
    };

    if base_bytes.is_empty()
        || !base_bytes
            .iter()
            .all(|byte| (33..=126).contains(byte) && *byte != b'*')
    {
        return Err(Error::Param(ParamError::EmptyName));
    }
    let base = core::str::from_utf8(base_bytes)
        .map_err(|_| Error::Param(ParamError::EmptyName))?
        .to_ascii_lowercase();
    Ok(ParsedName {
        base,
        section,
        extended,
    })
}

fn parse_section(bytes: &[u8]) -> Result<u32> {
    if bytes.is_empty() {
        return Err(Error::Param(ParamError::InvalidSection));
    }
    let mut value = 0u32;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(Error::Param(ParamError::InvalidSection));
        }
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(byte.saturating_sub(b'0'))))
            .ok_or(Error::Param(ParamError::InvalidSection))?;
        if value > MAX_SECTION {
            return Err(Error::Param(ParamError::InvalidSection));
        }
    }
    Ok(value)
}

fn split_charset_prefix(input: &[u8]) -> Result<(Option<String>, Option<String>, &[u8])> {
    let first = input.iter().position(|byte| *byte == b'\'');
    let second = first.and_then(|first| {
        input
            .get(first.saturating_add(1)..)?
            .iter()
            .position(|byte| *byte == b'\'')
            .and_then(|offset| {
                first
                    .checked_add(1)
                    .and_then(|base| base.checked_add(offset))
            })
    });
    let (first, second) = match (first, second) {
        (Some(first), Some(second)) if second > first => (first, second),
        _ => return Err(Error::Param(ParamError::InvalidCharsetPrefix)),
    };
    let charset = &input[..first];
    let language = &input[first.saturating_add(1)..second];
    let data = &input[second.saturating_add(1)..];
    let charset = if charset.is_empty() {
        None
    } else {
        Some(
            core::str::from_utf8(charset)
                .map_err(|_| Error::Param(ParamError::InvalidCharsetPrefix))?
                .to_string(),
        )
    };
    let language = if language.is_empty() {
        None
    } else {
        Some(
            core::str::from_utf8(language)
                .map_err(|_| Error::Param(ParamError::InvalidCharsetPrefix))?
                .to_string(),
        )
    };
    Ok((charset, language, data))
}

fn percent_decode(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut index = 0usize;
    while index < input.len() {
        let byte = input[index];
        if byte == b'%' {
            let high = input
                .get(index.saturating_add(1))
                .copied()
                .and_then(hex_value)
                .ok_or(Error::Param(ParamError::InvalidPercent))?;
            let low = input
                .get(index.saturating_add(2))
                .copied()
                .and_then(hex_value)
                .ok_or(Error::Param(ParamError::InvalidPercent))?;
            out.push(high.saturating_mul(16).saturating_add(low));
            index = index.saturating_add(3);
        } else {
            out.push(byte);
            index = index.saturating_add(1);
        }
    }
    Ok(out)
}

fn decode_bytes(bytes: &[u8], charset: Option<&str>) -> Result<String> {
    match charset.map(str::to_ascii_lowercase).as_deref() {
        None | Some("utf-8" | "utf8") => {
            String::from_utf8(bytes.to_vec()).map_err(|_| Error::Param(ParamError::CharsetDecode))
        }
        Some("us-ascii" | "ascii") => {
            if bytes.iter().all(u8::is_ascii) {
                String::from_utf8(bytes.to_vec())
                    .map_err(|_| Error::Param(ParamError::CharsetDecode))
            } else {
                Err(Error::Param(ParamError::CharsetDecode))
            }
        }
        Some("iso-8859-1" | "latin1" | "latin-1") => {
            Ok(bytes.iter().map(|byte| char::from(*byte)).collect())
        }
        Some(_) => Err(Error::Param(ParamError::UnsupportedCharset)),
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.saturating_sub(b'0')),
        b'a'..=b'f' => Some(byte.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(byte.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

fn is_wsp(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

fn trim_wsp(mut bytes: &[u8]) -> &[u8] {
    while let Some(first) = bytes.first() {
        if is_wsp(*first) {
            bytes = &bytes[1..];
        } else {
            break;
        }
    }
    while let Some(last) = bytes.last() {
        if is_wsp(*last) {
            bytes = &bytes[..bytes.len().saturating_sub(1)];
        } else {
            break;
        }
    }
    bytes
}
