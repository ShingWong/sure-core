//! DKIM canonicalization (RFC 6376), formatting only.
//!
//! No cryptography lives here. A signer/verifier feeds these bytes to a
//! host-provided crypto provider. Header selection follows the `h=` rule:
//! names are processed in the order given, and each selects the last not-yet-
//! used header with that name.

use alloc::vec::Vec;

use crate::{
    error::{DkimError, Error, LimitKind, Result},
    header::Header,
    limits::Limits,
};

/// DKIM header or body canonicalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canonicalization {
    /// `simple`: bytes as-is (headers keep folding).
    Simple,
    /// `relaxed`: lowercase names, unfolded, whitespace collapsed.
    Relaxed,
}

/// Canonicalize one header field.
#[must_use]
pub fn canonicalize_header(header: &Header, canon: Canonicalization) -> Vec<u8> {
    match canon {
        Canonicalization::Simple => header.raw.clone(),
        Canonicalization::Relaxed => {
            let mut out = Vec::with_capacity(
                header
                    .name
                    .len()
                    .saturating_add(header.value.len())
                    .saturating_add(3),
            );
            for byte in header.name.bytes() {
                out.push(byte.to_ascii_lowercase());
            }
            out.push(b':');
            let mut pending_space = false;
            let mut started = false;
            for byte in &header.value {
                if *byte == b' ' || *byte == b'\t' {
                    if started {
                        pending_space = true;
                    }
                } else {
                    if pending_space {
                        out.push(b' ');
                        pending_space = false;
                    }
                    out.push(*byte);
                    started = true;
                }
            }
            out.extend_from_slice(b"\r\n");
            out
        }
    }
}

/// Canonicalize the headers selected by a DKIM `h=` list.
///
/// # Errors
///
/// Returns [`DkimError::MissingHeader`] if a listed header is absent.
pub fn canonicalize_headers(
    headers: &[Header],
    names: &[&str],
    canon: Canonicalization,
) -> Result<Vec<u8>> {
    let mut used = alloc::vec![false; headers.len()];
    let mut out = Vec::new();
    for name in names {
        let mut selected = None;
        for (index, header) in headers.iter().enumerate().rev() {
            if !used.get(index).copied().unwrap_or(true) && header.is(name) {
                selected = Some(index);
                break;
            }
        }
        let index = selected.ok_or(Error::Dkim(DkimError::MissingHeader))?;
        if let Some(slot) = used.get_mut(index) {
            *slot = true;
        }
        if let Some(header) = headers.get(index) {
            out.extend_from_slice(&canonicalize_header(header, canon));
        }
    }
    Ok(out)
}

/// Streaming DKIM body canonicalizer.
#[derive(Debug, Clone)]
pub struct DkimBodyCanonicalizer {
    canon: Canonicalization,
    out: Vec<u8>,
    pending_eol: usize,
    pending_wsp: bool,
    pending_cr: bool,
    input_len: usize,
    max_input: usize,
    max_output: usize,
    finished: bool,
}

impl DkimBodyCanonicalizer {
    /// Create a canonicalizer bounded by `limits`.
    #[must_use]
    pub fn new(canon: Canonicalization, limits: &Limits) -> Self {
        Self {
            canon,
            out: Vec::new(),
            pending_eol: 0,
            pending_wsp: false,
            pending_cr: false,
            input_len: 0,
            max_input: limits.max_body_bytes,
            // LF -> CRLF can double the body; allow the larger message bound.
            max_output: limits.max_message_bytes,
            finished: false,
        }
    }

    /// Feed body bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed limit or state error.
    pub fn push(&mut self, input: &[u8]) -> Result<()> {
        if self.finished {
            return Err(Error::Dkim(DkimError::Finished));
        }
        self.input_len = self.input_len.saturating_add(input.len());
        if self.input_len > self.max_input {
            return Err(LimitKind::BodyBytes.exceeded(self.max_input, self.input_len));
        }
        for byte in input {
            self.feed(*byte)?;
        }
        Ok(())
    }

    /// Finish and return the canonicalized body.
    ///
    /// # Errors
    ///
    /// Returns a typed limit or state error.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        if self.finished {
            return Err(Error::Dkim(DkimError::Finished));
        }
        if self.pending_cr {
            self.pending_cr = false;
            self.pending_eol = self.pending_eol.saturating_add(1);
        }
        self.pending_eol = 0;
        self.pending_wsp = false;
        self.push_eol()?;
        self.finished = true;
        Ok(core::mem::take(&mut self.out))
    }

    fn feed(&mut self, byte: u8) -> Result<()> {
        match byte {
            b'\r' => {
                if self.pending_cr {
                    self.eol();
                }
                self.pending_cr = true;
                Ok(())
            }
            b'\n' => {
                self.pending_cr = false;
                self.eol();
                Ok(())
            }
            _ => {
                if self.pending_cr {
                    self.pending_cr = false;
                    self.eol();
                }
                if self.canon == Canonicalization::Relaxed && (byte == b' ' || byte == b'\t') {
                    self.pending_wsp = true;
                    return Ok(());
                }
                self.content(byte)
            }
        }
    }

    fn eol(&mut self) {
        self.pending_wsp = false;
        self.pending_eol = self.pending_eol.saturating_add(1);
    }

    fn content(&mut self, byte: u8) -> Result<()> {
        if self.pending_wsp {
            self.push_byte(b' ')?;
            self.pending_wsp = false;
        }
        while self.pending_eol > 0 {
            self.push_eol()?;
            self.pending_eol = self.pending_eol.saturating_sub(1);
        }
        self.push_byte(byte)
    }

    fn push_eol(&mut self) -> Result<()> {
        self.push_byte(b'\r')?;
        self.push_byte(b'\n')
    }

    fn push_byte(&mut self, byte: u8) -> Result<()> {
        if self.out.len() >= self.max_output {
            return Err(Error::Dkim(DkimError::OutputLimit));
        }
        self.out.push(byte);
        Ok(())
    }
}

/// One-shot DKIM body canonicalization bounded by `limits`.
///
/// # Errors
///
/// Returns a typed limit error.
pub fn canonicalize_body(
    input: &[u8],
    canon: Canonicalization,
    limits: &Limits,
) -> Result<Vec<u8>> {
    let mut canonicalizer = DkimBodyCanonicalizer::new(canon, limits);
    canonicalizer.push(input)?;
    canonicalizer.finish()
}
