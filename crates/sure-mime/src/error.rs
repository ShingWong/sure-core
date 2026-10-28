//! Typed errors.
//!
//! Errors never contain caller-controlled text, so a host can log them without
//! reflecting hostile bytes into a terminal or a structured log field.

use core::fmt;

/// The fixed limit that was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    /// Total bytes in one header block.
    HeaderBytes,
    /// Number of header fields in one header block.
    HeaderCount,
    /// Bytes in one physical header line (terminator excluded).
    HeaderLineLength,
    /// Nested multipart depth.
    MimeDepth,
    /// Total number of parts, including the root part.
    PartCount,
    /// Total input bytes accepted by the parser.
    MessageBytes,
    /// Total decoded body bytes across every part.
    DecodedBytes,
    /// Decoded bytes across non-attachment parts.
    BodyBytes,
    /// Decoded bytes in one attachment part.
    AttachmentBytes,
    /// Multipart boundary length.
    BoundaryLength,
    /// Maximum event chunk size.
    ChunkBytes,
}

impl LimitKind {
    /// Stable, log-friendly name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HeaderBytes => "header_bytes",
            Self::HeaderCount => "header_count",
            Self::HeaderLineLength => "header_line_length",
            Self::MimeDepth => "mime_depth",
            Self::PartCount => "part_count",
            Self::MessageBytes => "message_bytes",
            Self::DecodedBytes => "decoded_bytes",
            Self::BodyBytes => "body_bytes",
            Self::AttachmentBytes => "attachment_bytes",
            Self::BoundaryLength => "boundary_length",
            Self::ChunkBytes => "chunk_bytes",
        }
    }
}

/// Header-block syntax failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// A non-continuation line had no `:`.
    MissingColon,
    /// A field name was empty.
    EmptyName,
    /// A field name contained a byte outside printable US-ASCII.
    InvalidNameByte(u8),
    /// A folded line appeared before any field.
    ContinuationWithoutField,
    /// A NUL byte appeared in a field name or value.
    NulByte,
    /// A line was empty in a header block that should not contain one.
    UnexpectedBlankLine,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingColon => f.write_str("header line has no colon"),
            Self::EmptyName => f.write_str("empty header field name"),
            Self::InvalidNameByte(_) => f.write_str("invalid byte in header field name"),
            Self::ContinuationWithoutField => {
                f.write_str("continuation line without a preceding field")
            }
            Self::NulByte => f.write_str("NUL byte in header field"),
            Self::UnexpectedBlankLine => f.write_str("unexpected blank line"),
        }
    }
}

/// Transfer-decoder failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// A non-base64 character appeared in base64 data.
    InvalidBase64,
    /// Base64 padding was inconsistent.
    InvalidPadding,
    /// Data followed a complete padded base64 quantum.
    TrailingData,
    /// Quoted-printable contained an invalid escape.
    InvalidQuotedPrintable,
    /// Quoted-printable ended in the middle of an escape or soft break.
    TruncatedQuotedPrintable,
    /// A quoted-printable escape contained a non-hex digit.
    InvalidHex,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidBase64 => "invalid base64 character",
            Self::InvalidPadding => "invalid base64 padding",
            Self::TrailingData => "trailing data after padded base64",
            Self::InvalidQuotedPrintable => "invalid quoted-printable escape",
            Self::TruncatedQuotedPrintable => "truncated quoted-printable escape",
            Self::InvalidHex => "invalid hexadecimal digit",
        })
    }
}

/// Parameter / RFC 2231 failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamError {
    /// A parameter had no `=`.
    MissingEquals,
    /// A parameter name was empty or non-ASCII.
    EmptyName,
    /// A quoted string was not terminated.
    UnterminatedQuotedString,
    /// A quoted string contained a forbidden control byte.
    ControlInQuotedString,
    /// A backslash escape was truncated.
    InvalidEscape,
    /// A percent escape was malformed.
    InvalidPercent,
    /// An RFC 2231 section number was malformed or too large.
    InvalidSection,
    /// Continuation sections were duplicated.
    DuplicateSection,
    /// Continuation sections were not contiguous from zero.
    NonContiguousSections,
    /// The same parameter name appeared more than once.
    DuplicateParameter,
    /// An RFC 2231 charset prefix was malformed.
    InvalidCharsetPrefix,
    /// The declared charset is not supported by v0.1.
    UnsupportedCharset,
    /// The decoded bytes were not valid in the declared charset.
    CharsetDecode,
    /// Too many parameters in one header value.
    TooManyParameters,
}

impl fmt::Display for ParamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingEquals => "parameter has no equals sign",
            Self::EmptyName => "empty or non-ASCII parameter name",
            Self::UnterminatedQuotedString => "unterminated quoted string",
            Self::ControlInQuotedString => "control byte in quoted string",
            Self::InvalidEscape => "invalid backslash escape",
            Self::InvalidPercent => "invalid percent escape",
            Self::InvalidSection => "invalid RFC 2231 section number",
            Self::DuplicateSection => "duplicate RFC 2231 section",
            Self::NonContiguousSections => "non-contiguous RFC 2231 sections",
            Self::DuplicateParameter => "duplicate parameter name",
            Self::InvalidCharsetPrefix => "invalid RFC 2231 charset prefix",
            Self::UnsupportedCharset => "unsupported RFC 2231 charset",
            Self::CharsetDecode => "parameter bytes are invalid for the declared charset",
            Self::TooManyParameters => "too many parameters",
        })
    }
}

/// Basic address parser failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    /// The list contained an empty address element.
    Empty,
    /// An addr-spec had no `@`.
    MissingAt,
    /// The local part was empty or invalid.
    InvalidLocalPart,
    /// The domain was empty or invalid.
    InvalidDomain,
    /// An angle address was not terminated.
    UnterminatedAngle,
    /// A quoted string was not terminated.
    UnterminatedQuotedString,
    /// A comment was not terminated.
    UnterminatedComment,
    /// A character was not valid in this position.
    UnexpectedCharacter,
    /// The address was longer than the v0.1 hard limit.
    TooLong,
    /// The list exceeded the v0.1 address-count bound.
    TooManyAddresses,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty address element",
            Self::MissingAt => "address has no at sign",
            Self::InvalidLocalPart => "invalid local part",
            Self::InvalidDomain => "invalid domain",
            Self::UnterminatedAngle => "unterminated angle address",
            Self::UnterminatedQuotedString => "unterminated quoted string",
            Self::UnterminatedComment => "unterminated comment",
            Self::UnexpectedCharacter => "unexpected character in address",
            Self::TooLong => "address exceeds v0.1 length limit",
            Self::TooManyAddresses => "address list exceeds v0.1 count limit",
        })
    }
}

/// Multipart state-machine failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultipartError {
    /// A multipart part had no boundary parameter.
    MissingBoundary,
    /// A boundary was empty, too long, or contained a non-printable byte.
    InvalidBoundary,
    /// Input ended before the closing delimiter.
    Unterminated,
    /// An opening delimiter appeared after the closing delimiter.
    BoundaryAfterClose,
    /// A multipart container declared a transfer encoding that would require
    /// decoding the boundaries.
    TransferEncoding,
    /// A part body appeared while no part was active.
    UnexpectedContent,
    /// A part header block ended without a blank line and without EOF.
    HeaderBlockUnterminated,
}

impl fmt::Display for MultipartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingBoundary => "multipart part has no boundary",
            Self::InvalidBoundary => "invalid multipart boundary",
            Self::Unterminated => "unterminated multipart body",
            Self::BoundaryAfterClose => "opening boundary after closing boundary",
            Self::TransferEncoding => "transfer encoding on a multipart container",
            Self::UnexpectedContent => "multipart content outside a part",
            Self::HeaderBlockUnterminated => "unterminated part header block",
        })
    }
}

/// DKIM formatting failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimError {
    /// A header named in the `h=` selection was absent.
    MissingHeader,
    /// Canonicalized output exceeded the configured bound.
    OutputLimit,
    /// The canonicalizer was used after `finish`.
    Finished,
}

impl fmt::Display for DkimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingHeader => "DKIM header selection names an absent header",
            Self::OutputLimit => "DKIM canonicalized output exceeds limit",
            Self::Finished => "DKIM canonicalizer already finished",
        })
    }
}

/// Every error returned by `sure-mime`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A configured [`crate::Limits`] value is out of range.
    InvalidLimits(&'static str),
    /// A hard limit was exceeded.
    LimitExceeded {
        /// Which limit.
        limit: LimitKind,
        /// Configured maximum.
        max: usize,
        /// Observed value.
        observed: usize,
    },
    /// Header syntax error.
    Header(HeaderError),
    /// Transfer-decoder error.
    Decode(DecodeError),
    /// Parameter error.
    Param(ParamError),
    /// Address error.
    Address(AddressError),
    /// Multipart error.
    Multipart(MultipartError),
    /// DKIM formatting error.
    Dkim(DkimError),
    /// A transfer encoding outside the v0.1 subset.
    UnsupportedTransferEncoding,
    /// A parser that previously returned an error may not be reused.
    AlreadyFailed,
    /// The parser was already finished.
    Finished,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(reason) => write!(f, "invalid limits: {reason}"),
            Self::LimitExceeded {
                limit,
                max,
                observed,
            } => write!(
                f,
                "limit exceeded: {} (max {max}, observed {observed})",
                limit.as_str()
            ),
            Self::Header(e) => write!(f, "malformed header: {e}"),
            Self::Decode(e) => write!(f, "transfer decoding failed: {e}"),
            Self::Param(e) => write!(f, "parameter parsing failed: {e}"),
            Self::Address(e) => write!(f, "address parsing failed: {e}"),
            Self::Multipart(e) => write!(f, "multipart parsing failed: {e}"),
            Self::Dkim(e) => write!(f, "DKIM formatting failed: {e}"),
            Self::UnsupportedTransferEncoding => {
                f.write_str("unsupported content-transfer-encoding")
            }
            Self::AlreadyFailed => f.write_str("parser is unusable after an earlier error"),
            Self::Finished => f.write_str("parser already finished"),
        }
    }
}

impl core::error::Error for Error {}

impl From<HeaderError> for Error {
    fn from(value: HeaderError) -> Self {
        Self::Header(value)
    }
}

impl From<DecodeError> for Error {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl From<ParamError> for Error {
    fn from(value: ParamError) -> Self {
        Self::Param(value)
    }
}

impl From<AddressError> for Error {
    fn from(value: AddressError) -> Self {
        Self::Address(value)
    }
}

impl From<MultipartError> for Error {
    fn from(value: MultipartError) -> Self {
        Self::Multipart(value)
    }
}

impl From<DkimError> for Error {
    fn from(value: DkimError) -> Self {
        Self::Dkim(value)
    }
}

/// Crate result alias.
pub type Result<T> = core::result::Result<T, Error>;
