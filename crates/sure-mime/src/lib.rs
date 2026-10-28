//! `sure-mime` — a pure, bounded, streaming MIME and RFC 5322 parser.
//!
//! # Scope (v0.1)
//!
//! * RFC 5322 header blocks with folding and duplicates, in original order.
//! * Basic mailbox / address-list parsing for `From`, `To`, `Cc`, `Reply-To`.
//! * MIME `Content-Type` / `Content-Disposition` parameters, quoted strings and
//!   RFC 2231 continuation / charset / language parameters.
//! * Multipart parsing with preamble, epilogue, nesting and line-start-only
//!   boundary matching.
//! * Streaming identity / 7bit / 8bit / binary / base64 / quoted-printable
//!   transfer decoding with carry state across chunk boundaries.
//! * RFC 2047 encoded-word decoding with a bounded fallback.
//! * DKIM `simple` / `relaxed` header and body canonicalization (formatting
//!   only; no cryptography).
//!
//! # Hard rules
//!
//! * No filesystem, network, process, clock or environment access.
//! * No `unsafe` code.
//! * No panics on untrusted input: every input path returns a typed error.
//! * Every allocation is bounded by [`Limits`].
//! * Attachment bytes are emitted as bounded chunks and never retained by the
//!   parser.
//!
//! This is deliberately a *subset* of MIME, not a claim of full RFC 5322 /
//! RFC 2045-2049 conformance. See `docs/security-validation.md` in the
//! repository for the exact threat model and residual risks.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(missing_docs)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod address;
pub mod decode;
pub mod dkim;
pub mod encoded_word;
pub mod error;
pub mod events;
pub mod header;
pub mod limits;
pub mod media;
pub mod params;
pub mod parser;
pub mod path;

pub use address::{parse_address_list, Address, AddressList, Mailbox};
pub use decode::{Decoder, TransferEncoding};
pub use dkim::{
    canonicalize_body, canonicalize_header, canonicalize_headers, Canonicalization,
    DkimBodyCanonicalizer,
};
pub use encoded_word::decode_encoded_words;
pub use error::{
    AddressError, DecodeError, DkimError, Error, HeaderError, LimitKind, MultipartError,
    ParamError, Result,
};
pub use events::{AttachmentMeta, Event, MessageSummary, PartMeta};
pub use header::{parse_header_block, Header, HeaderBlock};
pub use limits::Limits;
pub use media::{sanitize_filename, ContentDisposition, DispositionKind, MediaType};
pub use params::{parse_parameters, Parameter};
pub use parser::{parse_message, MessageParser, ParsedMessage};
pub use path::{PartPath, MAX_DEPTH};
