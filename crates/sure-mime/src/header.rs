//! RFC 5322 header blocks.
//!
//! Headers are kept in wire order. Each field retains a canonical `raw` form
//! (folded lines terminated with CRLF) for DKIM `simple` canonicalization and
//! an unfolded `value` for structured parsing.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    error::{Error, HeaderError, LimitKind, Result},
    limits::Limits,
};

/// One header field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Field name as received (case preserved).
    pub name: String,
    /// Unfolded field body (bytes after the colon, folding CRLF removed).
    pub value: Vec<u8>,
    /// Field name, colon, folded body and a normalised CRLF terminator.
    pub raw: Vec<u8>,
    /// Byte offset of the field within the message.
    pub offset: u64,
}

impl Header {
    /// Field name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Unfolded value bytes.
    #[must_use]
    pub fn value_bytes(&self) -> &[u8] {
        &self.value
    }

    /// Unfolded value with surrounding space/tab removed.
    #[must_use]
    pub fn value_trimmed(&self) -> &[u8] {
        trim_wsp(&self.value)
    }

    /// Unfolded value decoded as UTF-8 with replacement for invalid bytes.
    #[must_use]
    pub fn value_lossy(&self) -> String {
        String::from_utf8_lossy(&self.value).into_owned()
    }

    /// Case-insensitive field-name comparison.
    #[must_use]
    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

/// An ordered header block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderBlock {
    /// Headers in wire order, duplicates included.
    pub headers: Vec<Header>,
}

impl HeaderBlock {
    /// Number of fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Whether the block has no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// First field with this name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Header> {
        self.headers.iter().find(|header| header.is(name))
    }

    /// All fields with this name, in wire order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Header> + 'a {
        self.headers.iter().filter(move |header| header.is(name))
    }

    /// Last field with this name.
    #[must_use]
    pub fn get_last(&self, name: &str) -> Option<&Header> {
        self.headers.iter().rev().find(|header| header.is(name))
    }

    /// First trimmed value for this field.
    #[must_use]
    pub fn first_value(&self, name: &str) -> Option<&[u8]> {
        self.get(name).map(Header::value_trimmed)
    }
}

/// Parse one complete header block (without the terminating blank line).
///
/// # Errors
///
/// Returns a typed header error for malformed field names, continuations
/// without a field, NUL bytes, or a limit breach. The function never panics on
/// arbitrary bytes.
pub fn parse_header_block(input: &[u8], base_offset: u64, limits: &Limits) -> Result<HeaderBlock> {
    if input.len() > limits.max_header_bytes {
        return Err(LimitKind::HeaderBytes.exceeded(limits.max_header_bytes, input.len()));
    }

    let mut block = HeaderBlock::default();
    let mut current: Option<PartiallyParsed> = None;

    for (relative_offset, line, _terminator_len) in Lines::new(input) {
        if line.len() > limits.max_header_line_len {
            return Err(
                LimitKind::HeaderLineLength.exceeded(limits.max_header_line_len, line.len())
            );
        }
        if line.contains(&0) {
            return Err(Error::Header(HeaderError::NulByte));
        }
        if line.is_empty() {
            return Err(Error::Header(HeaderError::UnexpectedBlankLine));
        }

        if line[0] == b' ' || line[0] == b'\t' {
            let partial = current
                .as_mut()
                .ok_or(Error::Header(HeaderError::ContinuationWithoutField))?;
            partial.raw.extend_from_slice(line);
            partial.raw.extend_from_slice(b"\r\n");
            partial.value.extend_from_slice(line);
            continue;
        }

        if let Some(partial) = current.take() {
            block.headers.push(partial.finish()?);
        }

        if block.headers.len() >= limits.max_header_count {
            return Err(LimitKind::HeaderCount.exceeded(
                limits.max_header_count,
                block.headers.len().saturating_add(1),
            ));
        }

        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(Error::Header(HeaderError::MissingColon))?;
        let name_bytes = &line[..colon];
        if name_bytes.is_empty() {
            return Err(Error::Header(HeaderError::EmptyName));
        }
        for byte in name_bytes {
            // Printable US-ASCII except colon (the colon is the delimiter).
            if !(33..=126).contains(byte) || *byte == b':' {
                return Err(Error::Header(HeaderError::InvalidNameByte(*byte)));
            }
        }
        // Validation above guarantees ASCII.
        let name = core::str::from_utf8(name_bytes)
            .map_err(|_| Error::Header(HeaderError::InvalidNameByte(0)))?;
        let body = &line[colon.saturating_add(1)..];

        let mut raw = Vec::with_capacity(line.len().saturating_add(3));
        raw.extend_from_slice(name_bytes);
        raw.push(b':');
        raw.extend_from_slice(body);
        raw.extend_from_slice(b"\r\n");

        let offset = base_offset.saturating_add(relative_offset as u64);
        current = Some(PartiallyParsed {
            name: name.to_string(),
            value: body.to_vec(),
            raw,
            offset,
        });
    }

    if let Some(partial) = current.take() {
        block.headers.push(partial.finish()?);
    }
    if block.headers.len() > limits.max_header_count {
        return Err(LimitKind::HeaderCount.exceeded(limits.max_header_count, block.headers.len()));
    }
    Ok(block)
}

struct PartiallyParsed {
    name: String,
    value: Vec<u8>,
    raw: Vec<u8>,
    offset: u64,
}

impl PartiallyParsed {
    fn finish(self) -> Result<Header> {
        Ok(Header {
            name: self.name,
            value: self.value,
            raw: self.raw,
            offset: self.offset,
        })
    }
}

/// Iterate physical lines, accepting CRLF, LF and bare CR terminators.
struct Lines<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Lines<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }
}

impl<'a> Iterator for Lines<'a> {
    type Item = (usize, &'a [u8], usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.input.len() {
            return None;
        }
        let start = self.position;
        let mut end = start;
        while end < self.input.len() && self.input[end] != b'\r' && self.input[end] != b'\n' {
            end = end.saturating_add(1);
        }
        let mut terminator_len = 0;
        if end < self.input.len() {
            if self.input[end] == b'\r'
                && end.saturating_add(1) < self.input.len()
                && self.input[end.saturating_add(1)] == b'\n'
            {
                terminator_len = 2;
            } else {
                terminator_len = 1;
            }
        }
        self.position = end.saturating_add(terminator_len);
        Some((start, &self.input[start..end], terminator_len))
    }
}

fn trim_wsp(mut bytes: &[u8]) -> &[u8] {
    while let Some(first) = bytes.first() {
        if *first == b' ' || *first == b'\t' {
            bytes = &bytes[1..];
        } else {
            break;
        }
    }
    while let Some(last) = bytes.last() {
        if *last == b' ' || *last == b'\t' {
            bytes = &bytes[..bytes.len().saturating_sub(1)];
        } else {
            break;
        }
    }
    bytes
}
