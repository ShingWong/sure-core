//! RFC 2047 encoded-word decoding.
//!
//! Malformed encoded words are left byte-for-byte as they arrived. The decoder
//! never fails and never allocates beyond `max_output`; a host that needs a
//! diagnostic can compare the result with the input.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::decode::{Decoder, TransferEncoding};

/// Decode RFC 2047 encoded words in a header value.
///
/// Whitespace between adjacent encoded words is removed as RFC 2047 requires.
/// Unsupported charsets, malformed words and invalid base64/QP payloads are
/// preserved literally. Output is truncated at `max_output` bytes on a UTF-8
/// character boundary.
#[must_use]
pub fn decode_encoded_words(input: &[u8], max_output: usize) -> String {
    let mut out: Vec<u8> = Vec::new();
    let mut index = 0usize;
    let mut last_was_encoded = false;

    while index < input.len() {
        if input
            .get(index..)
            .is_some_and(|rest| rest.starts_with(b"=?"))
        {
            if let Some(word) = try_decode_word(input, index) {
                if out.len().saturating_add(word.bytes.len()) > max_output {
                    let remaining = max_output.saturating_sub(out.len());
                    let mut end = remaining.min(word.bytes.len());
                    while end > 0 && !word.bytes.is_char_boundary(end) {
                        end = end.saturating_sub(1);
                    }
                    out.extend_from_slice(&word.bytes.as_bytes()[..end]);
                    break;
                }
                out.extend_from_slice(word.bytes.as_bytes());
                index = word.end;
                last_was_encoded = true;
                continue;
            }

            // Malformed word: copy the shaped word (or the whole
            // whitespace-delimited token) literally. This keeps the scan
            // linear even for adversarial `=?` repetitions.
            let end =
                encoded_word_end(input, index).unwrap_or_else(|| next_token_end(input, index));
            let run = &input[index..end];
            if out.len().saturating_add(run.len()) > max_output {
                break;
            }
            out.extend_from_slice(run);
            index = end;
            last_was_encoded = false;
            continue;
        }

        if is_wsp(input[index]) {
            let start = index;
            while index < input.len() && is_wsp(input[index]) {
                index = index.saturating_add(1);
            }
            if last_was_encoded && encoded_word_end(input, index).is_some() {
                continue;
            }
            let run = &input[start..index];
            if out.len().saturating_add(run.len()) > max_output {
                break;
            }
            out.extend_from_slice(run);
            last_was_encoded = false;
            continue;
        }

        if out.len() >= max_output {
            break;
        }
        out.push(input[index]);
        index = index.saturating_add(1);
        last_was_encoded = false;
    }

    let mut result = String::from_utf8_lossy(&out).into_owned();
    if result.len() > max_output {
        let mut end = max_output;
        while end > 0 && !result.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        result.truncate(end);
    }
    result
}

struct DecodedWord {
    end: usize,
    bytes: String,
}

fn try_decode_word(input: &[u8], start: usize) -> Option<DecodedWord> {
    let end = encoded_word_end(input, start)?;
    let charset_start = start.checked_add(2)?;
    let first = find_byte(input, charset_start, b'?')?;
    let second = find_byte(input, first.checked_add(1)?, b'?')?;
    let text_end = end.checked_sub(2)?;
    if second >= text_end {
        return None;
    }
    let charset = &input[charset_start..first];
    let encoding = &input[first.checked_add(1)?..second];
    let text = &input[second.checked_add(1)?..text_end];
    if charset.is_empty() || encoding.len() != 1 {
        return None;
    }
    let decoded = match encoding[0].to_ascii_uppercase() {
        b'B' => decode_b(text)?,
        b'Q' => decode_q(text)?,
        _ => return None,
    };
    let bytes = decode_charset(charset, &decoded)?;
    Some(DecodedWord { end, bytes })
}

/// Return the index just past `?=` for a syntactically shaped encoded word.
fn encoded_word_end(input: &[u8], start: usize) -> Option<usize> {
    if !input.get(start..)?.starts_with(b"=?") {
        return None;
    }
    let charset_start = start.checked_add(2)?;
    let first = find_byte(input, charset_start, b'?')?;
    let second = find_byte(input, first.checked_add(1)?, b'?')?;
    let marker = find_pair(input, second.checked_add(1)?, b'?', b'=')?;
    if first == charset_start || second <= first.checked_add(1)? {
        return None;
    }
    marker.checked_add(2)
}

fn decode_b(text: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = Decoder::new(TransferEncoding::Base64);
    let mut out = Vec::new();
    decoder.push(text, &mut out).ok()?;
    decoder.finish(&mut out).ok()?;
    Some(out)
}

fn decode_q(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len());
    let mut index = 0usize;
    while index < text.len() {
        match text[index] {
            b'_' => {
                out.push(b' ');
                index = index.saturating_add(1);
            }
            b'=' => {
                let high = text
                    .get(index.saturating_add(1))
                    .copied()
                    .and_then(hex_value)?;
                let low = text
                    .get(index.saturating_add(2))
                    .copied()
                    .and_then(hex_value)?;
                out.push(high.saturating_mul(16).saturating_add(low));
                index = index.saturating_add(3);
            }
            byte => {
                out.push(byte);
                index = index.saturating_add(1);
            }
        }
    }
    Some(out)
}

fn decode_charset(charset: &[u8], bytes: &[u8]) -> Option<String> {
    let charset = core::str::from_utf8(charset).ok()?.to_ascii_lowercase();
    match charset.as_str() {
        "utf-8" | "utf8" => core::str::from_utf8(bytes).ok().map(ToString::to_string),
        "us-ascii" | "ascii" => {
            if bytes.iter().all(u8::is_ascii) {
                core::str::from_utf8(bytes).ok().map(ToString::to_string)
            } else {
                None
            }
        }
        "iso-8859-1" | "latin1" | "latin-1" => {
            Some(bytes.iter().map(|byte| char::from(*byte)).collect())
        }
        _ => None,
    }
}

fn next_token_end(input: &[u8], start: usize) -> usize {
    let mut index = start;
    while index < input.len() && !is_wsp(input[index]) {
        index = index.saturating_add(1);
    }
    index
}

fn find_byte(input: &[u8], start: usize, needle: u8) -> Option<usize> {
    input
        .get(start..)?
        .iter()
        .position(|byte| *byte == needle)
        .map(|offset| start.saturating_add(offset))
}

fn find_pair(input: &[u8], start: usize, first: u8, second: u8) -> Option<usize> {
    let slice = input.get(start..)?;
    let mut index = 0usize;
    while index.saturating_add(1) < slice.len() {
        if slice[index] == first && slice[index.saturating_add(1)] == second {
            return Some(start.saturating_add(index));
        }
        index = index.saturating_add(1);
    }
    None
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

const fn is_wsp(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}
