//! Streaming transfer decoders.
//!
//! The decoders carry state across arbitrary chunk boundaries. They never
//! allocate based on a declared length; output grows only with input actually
//! supplied (and is bounded by the caller's limits).

use alloc::vec::Vec;

use crate::error::{DecodeError, Error, Result};

/// Transfer encodings in the v0.1 subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferEncoding {
    /// No transformation (`identity`, `7bit`, `8bit`, `binary`).
    Identity,
    /// RFC 2045 `7bit`.
    SevenBit,
    /// RFC 2045 `8bit`.
    EightBit,
    /// RFC 2045 `binary`.
    Binary,
    /// RFC 2045 base64.
    Base64,
    /// RFC 2045 quoted-printable.
    QuotedPrintable,
}

impl TransferEncoding {
    /// Parse a `Content-Transfer-Encoding` value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedTransferEncoding`] outside the v0.1 subset.
    pub fn parse(value: &[u8]) -> Result<Self> {
        let trimmed = trim_wsp(value);
        let lower = core::str::from_utf8(trimmed)
            .map_err(|_| Error::UnsupportedTransferEncoding)?
            .to_ascii_lowercase();
        match lower.as_str() {
            "identity" | "" => Ok(Self::Identity),
            "7bit" => Ok(Self::SevenBit),
            "8bit" => Ok(Self::EightBit),
            "binary" => Ok(Self::Binary),
            "base64" => Ok(Self::Base64),
            "quoted-printable" => Ok(Self::QuotedPrintable),
            _ => Err(Error::UnsupportedTransferEncoding),
        }
    }

    /// Whether this encoding passes bytes through unchanged.
    #[must_use]
    pub const fn is_identity(self) -> bool {
        matches!(
            self,
            Self::Identity | Self::SevenBit | Self::EightBit | Self::Binary
        )
    }

    /// Canonical spelling for metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::SevenBit => "7bit",
            Self::EightBit => "8bit",
            Self::Binary => "binary",
            Self::Base64 => "base64",
            Self::QuotedPrintable => "quoted-printable",
        }
    }
}

/// A streaming decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoder {
    /// Identity / 7bit / 8bit / binary.
    Identity,
    /// Base64.
    Base64(Base64Decoder),
    /// Quoted-printable.
    QuotedPrintable(QuotedPrintableDecoder),
}

impl Decoder {
    /// Create a decoder for the encoding.
    #[must_use]
    pub fn new(encoding: TransferEncoding) -> Self {
        match encoding {
            TransferEncoding::Base64 => Self::Base64(Base64Decoder::new()),
            TransferEncoding::QuotedPrintable => {
                Self::QuotedPrintable(QuotedPrintableDecoder::new())
            }
            TransferEncoding::Identity
            | TransferEncoding::SevenBit
            | TransferEncoding::EightBit
            | TransferEncoding::Binary => Self::Identity,
        }
    }

    /// Feed a chunk, appending decoded bytes to `out`.
    ///
    /// # Errors
    ///
    /// Returns a typed decode error for malformed input.
    pub fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Identity => {
                out.extend_from_slice(input);
                Ok(())
            }
            Self::Base64(decoder) => decoder.push(input, out),
            Self::QuotedPrintable(decoder) => decoder.push(input, out),
        }
    }

    /// Finish the stream, flushing any carried bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed decode error for truncated or invalid trailing input.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Identity => Ok(()),
            Self::Base64(decoder) => decoder.finish(out),
            Self::QuotedPrintable(decoder) => decoder.finish(out),
        }
    }
}

/// One-shot helper for tests and hosts that already hold a bounded body.
///
/// # Errors
///
/// Returns a typed decode error.
pub fn decode_all(encoding: TransferEncoding, input: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let mut decoder = Decoder::new(encoding);
    decoder.push(input, out)?;
    decoder.finish(out)
}

/// Streaming base64 decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base64Decoder {
    quad: [u8; 4],
    qlen: u8,
    pad: u8,
    done: bool,
    finished: bool,
}

impl Base64Decoder {
    /// Create an empty decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            quad: [0; 4],
            qlen: 0,
            pad: 0,
            done: false,
            finished: false,
        }
    }

    fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if self.finished {
            return Err(Error::Decode(DecodeError::TrailingData));
        }
        for byte in input {
            let byte = *byte;
            if is_base64_whitespace(byte) {
                continue;
            }
            if byte == b'=' {
                if self.done {
                    return Err(Error::Decode(DecodeError::InvalidPadding));
                }
                if self.qlen < 2 {
                    return Err(Error::Decode(DecodeError::InvalidPadding));
                }
                self.pad = self.pad.saturating_add(1);
                if self.pad > 2 {
                    return Err(Error::Decode(DecodeError::InvalidPadding));
                }
                if self.pad == 2 || self.qlen == 3 {
                    self.emit_tail(out)?;
                    self.done = true;
                }
                continue;
            }
            if self.done || self.pad > 0 {
                return Err(Error::Decode(DecodeError::TrailingData));
            }
            let value = base64_value(byte).ok_or(Error::Decode(DecodeError::InvalidBase64))?;
            let index = usize::from(self.qlen);
            if let Some(slot) = self.quad.get_mut(index) {
                *slot = value;
            } else {
                return Err(Error::Decode(DecodeError::InvalidBase64));
            }
            self.qlen = self.qlen.saturating_add(1);
            if self.qlen == 4 {
                emit_quad(&self.quad, 3, out);
                self.qlen = 0;
            }
        }
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        if self.done {
            self.qlen = 0;
            self.pad = 0;
            return Ok(());
        }
        match (self.qlen, self.pad) {
            (0, 0 | 2) => {}
            (2, 0 | 1) => self.emit_tail(out)?,
            (3, 0) => self.emit_tail(out)?,
            (1, _) => return Err(Error::Decode(DecodeError::InvalidPadding)),
            _ => return Err(Error::Decode(DecodeError::InvalidPadding)),
        }
        self.qlen = 0;
        self.pad = 0;
        Ok(())
    }

    fn emit_tail(&mut self, out: &mut Vec<u8>) -> Result<()> {
        match self.qlen {
            2 => {
                emit_quad(&self.quad, 1, out);
                self.qlen = 0;
                self.pad = 0;
                Ok(())
            }
            3 => {
                emit_quad(&self.quad, 2, out);
                self.qlen = 0;
                self.pad = 0;
                Ok(())
            }
            _ => Err(Error::Decode(DecodeError::InvalidPadding)),
        }
    }
}

impl Default for Base64Decoder {
    fn default() -> Self {
        Self::new()
    }
}

fn emit_quad(quad: &[u8; 4], count: usize, out: &mut Vec<u8>) {
    let q0 = u32::from(quad[0]);
    let q1 = u32::from(quad[1]);
    let q2 = u32::from(quad[2]);
    let q3 = u32::from(quad[3]);
    let combined = q0.saturating_mul(4).saturating_add(q1 >> 4);
    if count >= 1 {
        out.push(combined as u8);
    }
    if count >= 2 {
        let second = (q1 & 0x0f).saturating_mul(16).saturating_add(q2 >> 2);
        out.push(second as u8);
    }
    if count >= 3 {
        let third = (q2 & 0x03).saturating_mul(64).saturating_add(q3);
        out.push(third as u8);
    }
}

const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

const fn is_base64_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QpState {
    Normal,
    AfterEquals,
    AfterEqualsHex,
    AfterEqualsCr,
}

/// Streaming quoted-printable decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotedPrintableDecoder {
    state: QpState,
    high: u8,
    finished: bool,
}

impl QuotedPrintableDecoder {
    /// Create an empty decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: QpState::Normal,
            high: 0,
            finished: false,
        }
    }

    fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if self.finished {
            return Err(Error::Decode(DecodeError::TruncatedQuotedPrintable));
        }
        for byte in input {
            let byte = *byte;
            match self.state {
                QpState::Normal => {
                    if byte == b'=' {
                        self.state = QpState::AfterEquals;
                    } else {
                        out.push(byte);
                    }
                }
                QpState::AfterEquals => match byte {
                    b'\r' => self.state = QpState::AfterEqualsCr,
                    b'\n' => self.state = QpState::Normal,
                    _ => {
                        self.high = hex_value(byte)
                            .ok_or(Error::Decode(DecodeError::InvalidQuotedPrintable))?;
                        self.state = QpState::AfterEqualsHex;
                    }
                },
                QpState::AfterEqualsHex => {
                    let low = hex_value(byte)
                        .ok_or(Error::Decode(DecodeError::InvalidQuotedPrintable))?;
                    out.push(self.high.saturating_mul(16).saturating_add(low));
                    self.state = QpState::Normal;
                }
                QpState::AfterEqualsCr => {
                    if byte == b'\n' {
                        self.state = QpState::Normal;
                    } else {
                        return Err(Error::Decode(DecodeError::InvalidQuotedPrintable));
                    }
                }
            }
        }
        Ok(())
    }

    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        if self.state == QpState::Normal {
            Ok(())
        } else {
            Err(Error::Decode(DecodeError::TruncatedQuotedPrintable))
        }
    }
}

impl Default for QuotedPrintableDecoder {
    fn default() -> Self {
        Self::new()
    }
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
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
