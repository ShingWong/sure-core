//! Fixed parser limits.

use crate::{
    error::{Error, LimitKind, Result},
    path::MAX_DEPTH,
};

/// Hard maximum boundary length from RFC 2046.
pub const MAX_BOUNDARY_LEN: usize = 70;

/// Hard maximum number of parts (index segment is `u16`).
pub const MAX_PARTS: usize = u16::MAX as usize;

/// Every bound applied to untrusted input.
///
/// All fields are byte or count limits. A host should lower these for its
/// environment; raising them is a deliberate capacity decision. The parser
/// rejects a limit set it cannot represent instead of clamping silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum bytes in one header block (per root/part).
    pub max_header_bytes: usize,
    /// Maximum header fields in one header block.
    pub max_header_count: usize,
    /// Maximum bytes in one physical header line, terminator excluded.
    pub max_header_line_len: usize,
    /// Maximum nested multipart depth. Root is depth 0.
    pub max_mime_depth: usize,
    /// Maximum total parts, including the root part.
    pub max_parts: usize,
    /// Maximum total input bytes accepted.
    pub max_message_bytes: usize,
    /// Maximum total decoded bytes across every part.
    pub max_decoded_bytes: usize,
    /// Maximum decoded bytes across non-attachment parts.
    pub max_body_bytes: usize,
    /// Maximum decoded bytes in one attachment part.
    pub max_attachment_bytes: usize,
    /// Maximum accepted multipart boundary length.
    pub max_boundary_len: usize,
    /// Maximum bytes in one emitted body/attachment chunk.
    pub max_chunk_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_header_bytes: 1_048_576,
            max_header_count: 1_000,
            max_header_line_len: 4_096,
            max_mime_depth: 32,
            max_parts: 1_000,
            max_message_bytes: 64 * 1024 * 1024,
            max_decoded_bytes: 64 * 1024 * 1024,
            max_body_bytes: 32 * 1024 * 1024,
            max_attachment_bytes: 32 * 1024 * 1024,
            max_boundary_len: MAX_BOUNDARY_LEN,
            max_chunk_bytes: 16 * 1024,
        }
    }
}

impl Limits {
    /// A conservative set for hostile-input gateways: smaller bodies and
    /// shallower nesting than the defaults.
    #[must_use]
    pub const fn hardened() -> Self {
        Self {
            max_header_bytes: 64 * 1024,
            max_header_count: 256,
            max_header_line_len: 2_048,
            max_mime_depth: 8,
            max_parts: 128,
            max_message_bytes: 8 * 1024 * 1024,
            max_decoded_bytes: 8 * 1024 * 1024,
            max_body_bytes: 4 * 1024 * 1024,
            max_attachment_bytes: 4 * 1024 * 1024,
            max_boundary_len: MAX_BOUNDARY_LEN,
            max_chunk_bytes: 8 * 1024,
        }
    }

    /// Validate the set before constructing a parser.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLimits`] for zero, inconsistent or
    /// unrepresentable values.
    pub fn validate(self) -> Result<()> {
        if self.max_header_bytes == 0 {
            return Err(Error::InvalidLimits("max_header_bytes must be > 0"));
        }
        if self.max_header_count == 0 {
            return Err(Error::InvalidLimits("max_header_count must be > 0"));
        }
        if self.max_header_line_len == 0 {
            return Err(Error::InvalidLimits("max_header_line_len must be > 0"));
        }
        if self.max_header_line_len > self.max_header_bytes {
            return Err(Error::InvalidLimits(
                "max_header_line_len must not exceed max_header_bytes",
            ));
        }
        if self.max_mime_depth == 0 || self.max_mime_depth > MAX_DEPTH {
            return Err(Error::InvalidLimits(
                "max_mime_depth must be in 1..=MAX_DEPTH",
            ));
        }
        if self.max_parts == 0 || self.max_parts > MAX_PARTS {
            return Err(Error::InvalidLimits("max_parts must be in 1..=MAX_PARTS"));
        }
        if self.max_message_bytes == 0 {
            return Err(Error::InvalidLimits("max_message_bytes must be > 0"));
        }
        if self.max_decoded_bytes == 0 {
            return Err(Error::InvalidLimits("max_decoded_bytes must be > 0"));
        }
        if self.max_body_bytes > self.max_decoded_bytes {
            return Err(Error::InvalidLimits(
                "max_body_bytes must not exceed max_decoded_bytes",
            ));
        }
        if self.max_attachment_bytes > self.max_decoded_bytes {
            return Err(Error::InvalidLimits(
                "max_attachment_bytes must not exceed max_decoded_bytes",
            ));
        }
        if self.max_boundary_len == 0 || self.max_boundary_len > MAX_BOUNDARY_LEN {
            return Err(Error::InvalidLimits(
                "max_boundary_len must be in 1..=MAX_BOUNDARY_LEN",
            ));
        }
        if self.max_chunk_bytes == 0 {
            return Err(Error::InvalidLimits("max_chunk_bytes must be > 0"));
        }
        Ok(())
    }
}

impl LimitKind {
    /// Convenience constructor for an exceeded-limit error.
    #[must_use]
    pub const fn exceeded(self, max: usize, observed: usize) -> Error {
        Error::LimitExceeded {
            limit: self,
            max,
            observed,
        }
    }
}
