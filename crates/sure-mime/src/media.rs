//! MIME media types and content dispositions.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    error::{Error, ParamError, Result},
    params::{parse_parameters, Parameter},
};

/// A parsed `Content-Type` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaType {
    /// Lowercase primary type.
    pub type_: String,
    /// Lowercase subtype.
    pub subtype: String,
    /// Parameters in declaration order.
    pub parameters: Vec<Parameter>,
}

impl MediaType {
    /// MIME default when `Content-Type` is absent: `text/plain`.
    #[must_use]
    pub fn default_text_plain() -> Self {
        Self {
            type_: "text".to_string(),
            subtype: "plain".to_string(),
            parameters: Vec::new(),
        }
    }

    /// Parse a `Content-Type` field body.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an invalid type/subtype token or malformed
    /// parameters.
    pub fn parse(input: &[u8]) -> Result<Self> {
        let semicolon = input
            .iter()
            .position(|byte| *byte == b';')
            .unwrap_or(input.len());
        let head = trim_wsp(&input[..semicolon]);
        let parameters = if semicolon < input.len() {
            parse_parameters(&input[semicolon.saturating_add(1)..])?
        } else {
            Vec::new()
        };

        let slash = head
            .iter()
            .position(|byte| *byte == b'/')
            .ok_or(Error::Param(ParamError::EmptyName))?;
        let type_bytes = trim_wsp(&head[..slash]);
        let subtype_bytes = trim_wsp(&head[slash.saturating_add(1)..]);
        if !is_token(type_bytes) || !is_token(subtype_bytes) {
            return Err(Error::Param(ParamError::EmptyName));
        }
        let type_ = core::str::from_utf8(type_bytes)
            .map_err(|_| Error::Param(ParamError::EmptyName))?
            .to_ascii_lowercase();
        let subtype = core::str::from_utf8(subtype_bytes)
            .map_err(|_| Error::Param(ParamError::EmptyName))?
            .to_ascii_lowercase();
        Ok(Self {
            type_,
            subtype,
            parameters,
        })
    }

    /// Whether this is a `multipart/*` type.
    #[must_use]
    pub fn is_multipart(&self) -> bool {
        self.type_.eq_ignore_ascii_case("multipart")
    }

    /// First parameter with this name.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&Parameter> {
        self.parameters.iter().find(|parameter| parameter.is(name))
    }

    /// Multipart boundary, if declared.
    #[must_use]
    pub fn boundary(&self) -> Option<&str> {
        self.param("boundary")
            .map(|parameter| parameter.value.as_str())
    }
}

/// `Content-Disposition` kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispositionKind {
    /// Inline presentation.
    Inline,
    /// Attachment presentation.
    Attachment,
    /// Any other token, lowercased.
    Other(String),
}

/// A parsed `Content-Disposition` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDisposition {
    /// Disposition kind.
    pub kind: DispositionKind,
    /// Parameters in declaration order.
    pub parameters: Vec<Parameter>,
}

impl ContentDisposition {
    /// Parse a `Content-Disposition` field body.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an invalid disposition token or malformed
    /// parameters.
    pub fn parse(input: &[u8]) -> Result<Self> {
        let semicolon = input
            .iter()
            .position(|byte| *byte == b';')
            .unwrap_or(input.len());
        let head = trim_wsp(&input[..semicolon]);
        if !is_token(head) {
            return Err(Error::Param(ParamError::EmptyName));
        }
        let token = core::str::from_utf8(head)
            .map_err(|_| Error::Param(ParamError::EmptyName))?
            .to_ascii_lowercase();
        let kind = match token.as_str() {
            "inline" => DispositionKind::Inline,
            "attachment" => DispositionKind::Attachment,
            _ => DispositionKind::Other(token),
        };
        let parameters = if semicolon < input.len() {
            parse_parameters(&input[semicolon.saturating_add(1)..])?
        } else {
            Vec::new()
        };
        Ok(Self { kind, parameters })
    }

    /// First parameter with this name.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&Parameter> {
        self.parameters.iter().find(|parameter| parameter.is(name))
    }

    /// Declared filename, if any.
    #[must_use]
    pub fn filename(&self) -> Option<&str> {
        self.param("filename")
            .map(|parameter| parameter.value.as_str())
            .filter(|value| !value.is_empty())
    }
}

/// Reduce an attacker-controlled filename to a single, bounded path component.
///
/// Removes directory separators, control bytes, leading/trailing dots and
/// spaces, rejects `.`/`..`, and truncates to 255 UTF-8 bytes on a character
/// boundary. The result is metadata only; the host must still choose its own
/// storage name and must not use this as a filesystem path.
#[must_use]
pub fn sanitize_filename(input: &str) -> String {
    let base = input
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or(input);
    let mut cleaned = String::with_capacity(base.len().min(255));
    for character in base.chars() {
        if character.is_control() || character == '\0' {
            cleaned.push('_');
        } else {
            cleaned.push(character);
        }
    }
    let cleaned = cleaned.trim_matches([' ', '.']).to_string();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return "attachment".to_string();
    }
    if cleaned.len() <= 255 {
        return cleaned;
    }
    let mut end = 255;
    while end > 0 && !cleaned.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    cleaned[..end].to_string()
}

fn is_token(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
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
