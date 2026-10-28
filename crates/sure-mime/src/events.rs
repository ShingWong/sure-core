//! Structured parser events and part metadata.

use alloc::{string::String, vec::Vec};

use crate::{
    decode::TransferEncoding,
    header::HeaderBlock,
    media::{ContentDisposition, MediaType},
    path::PartPath,
};

/// Metadata for one part. Body bytes are never stored here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartMeta {
    /// Part path.
    pub path: PartPath,
    /// Parsed `Content-Type`, when present.
    pub content_type: Option<MediaType>,
    /// Parsed `Content-Disposition`, when present.
    pub disposition: Option<ContentDisposition>,
    /// Transfer encoding (identity when absent).
    pub transfer_encoding: TransferEncoding,
    /// Sanitized filename, when declared.
    pub filename: Option<String>,
    /// `Content-ID` value, when present.
    pub content_id: Option<String>,
    /// Whether this part is streamed as an attachment.
    pub is_attachment: bool,
    /// Whether this part is a multipart container.
    pub is_multipart: bool,
    /// Multipart boundary, when this is a container.
    pub boundary: Option<String>,
    /// Nesting depth; root is zero.
    pub depth: usize,
    /// Number of headers in this part's block.
    pub header_count: usize,
}

/// Attachment metadata (no attachment bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentMeta {
    /// Part metadata.
    pub meta: PartMeta,
    /// Decoded attachment size in bytes.
    pub decoded_bytes: u64,
}

/// Summary emitted at the end of a message.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MessageSummary {
    /// Total parts, including the root.
    pub parts: usize,
    /// Attachment parts.
    pub attachments: usize,
    /// Total decoded bytes across all parts.
    pub decoded_bytes: u64,
    /// Total encoded body bytes seen.
    pub encoded_bytes: u64,
    /// Maximum nesting depth observed.
    pub max_depth: usize,
}

/// A parser event.
///
/// `BodyChunk` and `AttachmentChunk` own a bounded byte chunk. The parser does
/// not retain attachment bytes after handing a chunk to the sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// First event from a parser.
    MessageStart,
    /// A header block was parsed for a part.
    Headers {
        /// Part path.
        path: PartPath,
        /// Parsed block.
        headers: HeaderBlock,
    },
    /// A part begins (after its headers).
    PartStart(PartMeta),
    /// Decoded non-attachment body bytes.
    BodyChunk {
        /// Part path.
        path: PartPath,
        /// Bounded decoded chunk.
        data: Vec<u8>,
    },
    /// Decoded attachment bytes. The host must write or discard these.
    AttachmentChunk {
        /// Part path.
        path: PartPath,
        /// Bounded decoded chunk.
        data: Vec<u8>,
    },
    /// Multipart preamble bytes (not part of any child).
    Preamble {
        /// Container path.
        path: PartPath,
        /// Bounded bytes.
        data: Vec<u8>,
    },
    /// Multipart epilogue bytes (not part of any child).
    Epilogue {
        /// Container path.
        path: PartPath,
        /// Bounded bytes.
        data: Vec<u8>,
    },
    /// A part ended.
    PartEnd {
        /// Part path.
        path: PartPath,
        /// Decoded bytes produced by this part.
        decoded_bytes: u64,
        /// Encoded body bytes consumed by this part.
        encoded_bytes: u64,
    },
    /// Message complete.
    MessageEnd(MessageSummary),
}
