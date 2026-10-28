//! Basic mailbox and address-list parsing.
//!
//! This is deliberately *not* full RFC 5322 address grammar: obs-syntax,
//! source routes and encoded words inside quoted local parts are out of scope
//! for v0.1. The forms used by `From`, `To`, `Cc` and `Reply-To` in normal mail
//! are supported: `addr-spec`, `Display Name <addr-spec>`, quoted display
//! names, quoted local parts, domain literals, comments and simple groups.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    encoded_word::decode_encoded_words,
    error::{AddressError, Error, Result},
};

const MAX_LOCAL_PART: usize = 64;
const MAX_DOMAIN: usize = 255;
const MAX_DISPLAY_NAME: usize = 1_024;
const MAX_ADDRESSES: usize = 10_000;

/// One mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    /// Decoded display name, when present.
    pub display_name: Option<String>,
    /// Local part (quotes removed, escapes resolved).
    pub local: String,
    /// Domain (literal brackets retained).
    pub domain: String,
}

impl Mailbox {
    /// `local@domain` without a display name.
    ///
    /// A local part that is not a dot-atom is quoted and escaped.
    #[must_use]
    pub fn address(&self) -> String {
        let mut out = String::with_capacity(
            self.local
                .len()
                .saturating_add(self.domain.len())
                .saturating_add(3),
        );
        let needs_quotes = self.local.is_empty()
            || self.local.chars().any(|character| {
                !(character.is_ascii_alphanumeric() || ".!#$%&'*+-/=?^_`{|}~".contains(character))
            });
        if needs_quotes {
            out.push('"');
            for character in self.local.chars() {
                if character == '\\' || character == '"' {
                    out.push('\\');
                }
                out.push(character);
            }
            out.push('"');
        } else {
            out.push_str(&self.local);
        }
        out.push('@');
        out.push_str(&self.domain);
        out
    }
}

/// One address-list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// A single mailbox.
    Mailbox(Mailbox),
    /// A group.
    Group {
        /// Decoded group display name.
        display_name: String,
        /// Members.
        mailboxes: Vec<Mailbox>,
    },
}

/// A parsed address list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressList {
    /// Entries in wire order.
    pub addresses: Vec<Address>,
}

impl AddressList {
    /// All mailboxes, flattening groups.
    pub fn mailboxes(&self) -> impl Iterator<Item = &Mailbox> {
        self.addresses.iter().flat_map(|address| match address {
            Address::Mailbox(mailbox) => core::slice::from_ref(mailbox).iter(),
            Address::Group { mailboxes, .. } => mailboxes.iter(),
        })
    }

    /// Whether the list has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }
}

/// Parse an address list from an unfolded header value.
///
/// # Errors
///
/// Returns a typed [`AddressError`] for malformed syntax. Arbitrary bytes never
/// panic the parser.
pub fn parse_address_list(input: &[u8]) -> Result<AddressList> {
    let mut parser = Parser { input, index: 0 };
    let addresses = parser.parse_list(false, 0)?;
    Ok(AddressList { addresses })
}

struct Parser<'a> {
    input: &'a [u8],
    index: usize,
}

impl<'a> Parser<'a> {
    fn parse_list(&mut self, until_semicolon: bool, depth: usize) -> Result<Vec<Address>> {
        let mut result = Vec::new();
        loop {
            self.skip_cfws()?;
            if self.index >= self.input.len() {
                if until_semicolon {
                    return Err(Error::Address(AddressError::UnexpectedCharacter));
                }
                break;
            }
            match self.input[self.index] {
                b',' => {
                    self.index = self.index.saturating_add(1);
                    continue;
                }
                b';' => {
                    if until_semicolon {
                        self.index = self.index.saturating_add(1);
                        break;
                    }
                    return Err(Error::Address(AddressError::UnexpectedCharacter));
                }
                _ => {}
            }

            let start = self.index;
            let delimiter = self.scan_delimiter()?;
            match delimiter {
                Some((position, b'<')) => {
                    let display_name = phrase(&self.input[start..position])?;
                    self.index = position.saturating_add(1);
                    let mailbox = self.parse_angle_mailbox(display_name)?;
                    push_address(&mut result, Address::Mailbox(mailbox))?;
                    let ended = self.expect_separator(until_semicolon)?;
                    if until_semicolon && ended {
                        break;
                    }
                }
                Some((position, b':')) => {
                    if depth > 0 {
                        return Err(Error::Address(AddressError::UnexpectedCharacter));
                    }
                    let display_name = phrase(&self.input[start..position])?.unwrap_or_default();
                    self.index = position.saturating_add(1);
                    let mailboxes = self.parse_group()?;
                    push_address(
                        &mut result,
                        Address::Group {
                            display_name,
                            mailboxes,
                        },
                    )?;
                    let ended = self.expect_separator(until_semicolon)?;
                    if until_semicolon && ended {
                        break;
                    }
                }
                Some((position, b',' | b';')) => {
                    let mailbox = parse_addr_spec(&self.input[start..position])?;
                    push_address(&mut result, Address::Mailbox(mailbox))?;
                    self.index = position;
                    let ended = self.expect_separator(until_semicolon)?;
                    if until_semicolon && ended {
                        break;
                    }
                }
                Some((_position, _)) => {
                    return Err(Error::Address(AddressError::UnexpectedCharacter))
                }
                None => {
                    let mailbox = parse_addr_spec(&self.input[start..])?;
                    push_address(&mut result, Address::Mailbox(mailbox))?;
                    self.index = self.input.len();
                }
            }
        }
        Ok(result)
    }

    fn parse_group(&mut self) -> Result<Vec<Mailbox>> {
        let addresses = self.parse_list(true, 1)?;
        let mut mailboxes = Vec::new();
        for address in addresses {
            match address {
                Address::Mailbox(mailbox) => {
                    if mailboxes.len() >= MAX_ADDRESSES {
                        return Err(Error::Address(AddressError::TooManyAddresses));
                    }
                    mailboxes.push(mailbox);
                }
                Address::Group {
                    mailboxes: nested, ..
                } => {
                    if mailboxes.len().saturating_add(nested.len()) > MAX_ADDRESSES {
                        return Err(Error::Address(AddressError::TooManyAddresses));
                    }
                    mailboxes.extend(nested);
                }
            }
        }
        Ok(mailboxes)
    }

    fn parse_angle_mailbox(&mut self, display_name: Option<String>) -> Result<Mailbox> {
        let start = self.index;
        let mut quote = false;
        let mut escaped = false;
        let mut comment_depth = 0usize;
        while self.index < self.input.len() {
            let byte = self.input[self.index];
            if quote {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quote = false;
                }
            } else if comment_depth > 0 {
                if byte == b'\\' {
                    self.index = self.index.saturating_add(1);
                } else if byte == b'(' {
                    comment_depth = comment_depth.saturating_add(1);
                } else if byte == b')' {
                    comment_depth = comment_depth.saturating_sub(1);
                }
            } else {
                match byte {
                    b'"' => quote = true,
                    b'(' => comment_depth = 1,
                    b'<' => return Err(Error::Address(AddressError::UnexpectedCharacter)),
                    b'>' => {
                        let content = &self.input[start..self.index];
                        self.index = self.index.saturating_add(1);
                        let mut mailbox = parse_addr_spec(content)?;
                        mailbox.display_name = display_name;
                        return Ok(mailbox);
                    }
                    _ => {}
                }
            }
            self.index = self.index.saturating_add(1);
        }
        Err(Error::Address(AddressError::UnterminatedAngle))
    }

    fn expect_separator(&mut self, until_semicolon: bool) -> Result<bool> {
        self.skip_cfws()?;
        if self.index >= self.input.len() {
            if until_semicolon {
                return Err(Error::Address(AddressError::UnexpectedCharacter));
            }
            return Ok(false);
        }
        match self.input[self.index] {
            b',' => {
                self.index = self.index.saturating_add(1);
                Ok(false)
            }
            b';' if until_semicolon => {
                self.index = self.index.saturating_add(1);
                Ok(true)
            }
            _ => Err(Error::Address(AddressError::UnexpectedCharacter)),
        }
    }

    /// Find the first top-level `<`, `:`, `,` or `;`.
    fn scan_delimiter(&self) -> Result<Option<(usize, u8)>> {
        let mut index = self.index;
        let mut quote = false;
        let mut escaped = false;
        let mut comment_depth = 0usize;
        let mut bracket = false;
        while index < self.input.len() {
            let byte = self.input[index];
            if quote {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quote = false;
                } else if byte == 0 || byte == b'\r' || byte == b'\n' {
                    return Err(Error::Address(AddressError::UnexpectedCharacter));
                }
            } else if comment_depth > 0 {
                if byte == b'\\' {
                    index = index.saturating_add(1);
                } else if byte == b'(' {
                    comment_depth = comment_depth.saturating_add(1);
                } else if byte == b')' {
                    comment_depth = comment_depth.saturating_sub(1);
                }
            } else if bracket {
                if byte == b']' {
                    bracket = false;
                }
            } else {
                match byte {
                    b'"' => quote = true,
                    b'(' => comment_depth = 1,
                    b'[' => bracket = true,
                    b'<' | b':' | b',' | b';' => return Ok(Some((index, byte))),
                    b'\r' | b'\n' | 0 => {
                        return Err(Error::Address(AddressError::UnexpectedCharacter))
                    }
                    _ => {}
                }
            }
            index = index.saturating_add(1);
        }
        if quote {
            return Err(Error::Address(AddressError::UnterminatedQuotedString));
        }
        if comment_depth > 0 {
            return Err(Error::Address(AddressError::UnterminatedComment));
        }
        Ok(None)
    }

    fn skip_cfws(&mut self) -> Result<()> {
        loop {
            while self.index < self.input.len() && self.input[self.index].is_ascii_whitespace() {
                self.index = self.index.saturating_add(1);
            }
            if self.input.get(self.index).copied() == Some(b'(') {
                self.index = skip_comment(self.input, self.index)?;
                continue;
            }
            return Ok(());
        }
    }
}

fn push_address(result: &mut Vec<Address>, address: Address) -> Result<()> {
    if result.len() >= MAX_ADDRESSES {
        return Err(Error::Address(AddressError::TooManyAddresses));
    }
    result.push(address);
    Ok(())
}

fn parse_addr_spec(input: &[u8]) -> Result<Mailbox> {
    let stripped = strip_cfws(input)?;
    if stripped.is_empty() {
        return Err(Error::Address(AddressError::Empty));
    }
    let at = find_top_level_at(&stripped)?;
    let local_bytes = &stripped[..at];
    let domain_bytes = &stripped[at.saturating_add(1)..];
    if local_bytes.is_empty() {
        return Err(Error::Address(AddressError::InvalidLocalPart));
    }
    if domain_bytes.is_empty() {
        return Err(Error::Address(AddressError::InvalidDomain));
    }
    let local = parse_local_part(local_bytes)?;
    let domain = parse_domain(domain_bytes)?;
    Ok(Mailbox {
        display_name: None,
        local,
        domain,
    })
}

fn parse_local_part(input: &[u8]) -> Result<String> {
    if input.len() > MAX_LOCAL_PART {
        return Err(Error::Address(AddressError::TooLong));
    }
    if input.first().copied() == Some(b'"') {
        if input.last().copied() != Some(b'"') || input.len() < 2 {
            return Err(Error::Address(AddressError::InvalidLocalPart));
        }
        let mut out = Vec::new();
        let mut index = 1usize;
        let end = input.len().saturating_sub(1);
        while index < end {
            let byte = input[index];
            if byte == b'\\' {
                let escaped = input
                    .get(index.saturating_add(1))
                    .copied()
                    .ok_or(Error::Address(AddressError::InvalidLocalPart))?;
                if escaped == 0 || escaped == b'\r' || escaped == b'\n' {
                    return Err(Error::Address(AddressError::InvalidLocalPart));
                }
                out.push(escaped);
                index = index.saturating_add(2);
            } else if byte == b'"' || byte == 0 || byte == b'\r' || byte == b'\n' {
                return Err(Error::Address(AddressError::InvalidLocalPart));
            } else {
                out.push(byte);
                index = index.saturating_add(1);
            }
        }
        if out.is_empty() {
            return Err(Error::Address(AddressError::InvalidLocalPart));
        }
        return String::from_utf8(out).map_err(|_| Error::Address(AddressError::InvalidLocalPart));
    }

    if input.first().copied() == Some(b'.')
        || input.last().copied() == Some(b'.')
        || input.windows(2).any(|window| window == b"..")
    {
        return Err(Error::Address(AddressError::InvalidLocalPart));
    }
    if !input.iter().all(|byte| is_atext(*byte) || *byte == b'.') {
        return Err(Error::Address(AddressError::InvalidLocalPart));
    }
    core::str::from_utf8(input)
        .map(ToString::to_string)
        .map_err(|_| Error::Address(AddressError::InvalidLocalPart))
}

fn parse_domain(input: &[u8]) -> Result<String> {
    if input.len() > MAX_DOMAIN {
        return Err(Error::Address(AddressError::TooLong));
    }
    if input.first().copied() == Some(b'[') {
        if input.last().copied() != Some(b']') || input.len() < 3 {
            return Err(Error::Address(AddressError::InvalidDomain));
        }
        let inner = &input[1..input.len().saturating_sub(1)];
        if inner.iter().any(|byte| {
            *byte == 0
                || *byte == b'\r'
                || *byte == b'\n'
                || *byte == b'['
                || *byte == b']'
                || *byte == b'\\'
        }) {
            return Err(Error::Address(AddressError::InvalidDomain));
        }
        return core::str::from_utf8(input)
            .map(ToString::to_string)
            .map_err(|_| Error::Address(AddressError::InvalidDomain));
    }

    if input.first().copied() == Some(b'.')
        || input.last().copied() == Some(b'.')
        || input.windows(2).any(|window| window == b"..")
    {
        return Err(Error::Address(AddressError::InvalidDomain));
    }
    for label in input.split(|byte| *byte == b'.') {
        if label.is_empty() || label.first() == Some(&b'-') || label.last() == Some(&b'-') {
            return Err(Error::Address(AddressError::InvalidDomain));
        }
        if !label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
        {
            return Err(Error::Address(AddressError::InvalidDomain));
        }
    }
    core::str::from_utf8(input)
        .map(ToString::to_string)
        .map_err(|_| Error::Address(AddressError::InvalidDomain))
}

fn find_top_level_at(input: &[u8]) -> Result<usize> {
    let mut quote = false;
    let mut escaped = false;
    let mut at = None;
    for (index, byte) in input.iter().enumerate() {
        if quote {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quote = false;
            }
        } else if *byte == b'"' {
            quote = true;
        } else if *byte == b'@' {
            if at.is_some() {
                return Err(Error::Address(AddressError::InvalidDomain));
            }
            at = Some(index);
        }
    }
    at.ok_or(Error::Address(AddressError::MissingAt))
}

fn strip_cfws(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut index = 0usize;
    while index < input.len() {
        let byte = input[index];
        if byte == b'(' {
            index = skip_comment(input, index)?;
            continue;
        }
        if byte == b'"' {
            out.push(byte);
            index = index.saturating_add(1);
            let mut closed = false;
            while index < input.len() {
                let inner = input[index];
                out.push(inner);
                index = index.saturating_add(1);
                if inner == b'\\' {
                    let escaped = input
                        .get(index)
                        .copied()
                        .ok_or(Error::Address(AddressError::UnterminatedQuotedString))?;
                    out.push(escaped);
                    index = index.saturating_add(1);
                } else if inner == b'"' {
                    closed = true;
                    break;
                } else if inner == 0 || inner == b'\r' || inner == b'\n' {
                    return Err(Error::Address(AddressError::InvalidLocalPart));
                }
            }
            if !closed {
                return Err(Error::Address(AddressError::UnterminatedQuotedString));
            }
            continue;
        }
        out.push(byte);
        index = index.saturating_add(1);
    }

    let mut start = 0usize;
    while start < out.len() && out[start].is_ascii_whitespace() {
        start = start.saturating_add(1);
    }
    let mut end = out.len();
    while end > start && out[end.saturating_sub(1)].is_ascii_whitespace() {
        end = end.saturating_sub(1);
    }
    let trimmed = &out[start..end];
    let mut quote = false;
    let mut escaped = false;
    for byte in trimmed {
        if quote {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quote = false;
            }
        } else if *byte == b'"' {
            quote = true;
        } else if byte.is_ascii_whitespace() {
            return Err(Error::Address(AddressError::UnexpectedCharacter));
        }
    }
    Ok(trimmed.to_vec())
}

fn skip_comment(input: &[u8], start: usize) -> Result<usize> {
    if input.get(start).copied() != Some(b'(') {
        return Ok(start);
    }
    let mut depth = 1usize;
    let mut index = start.saturating_add(1);
    while index < input.len() {
        match input[index] {
            b'\\' => {
                index = index.saturating_add(2);
            }
            b'(' => {
                depth = depth.saturating_add(1);
                index = index.saturating_add(1);
            }
            b')' => {
                depth = depth.saturating_sub(1);
                index = index.saturating_add(1);
                if depth == 0 {
                    return Ok(index);
                }
            }
            _ => index = index.saturating_add(1),
        }
    }
    Err(Error::Address(AddressError::UnterminatedComment))
}

fn phrase(input: &[u8]) -> Result<Option<String>> {
    let mut out: Vec<u8> = Vec::new();
    let mut index = 0usize;
    let mut have_token = false;
    while index < input.len() {
        let byte = input[index];
        if byte.is_ascii_whitespace() {
            index = index.saturating_add(1);
            continue;
        }
        if byte == b'(' {
            index = skip_comment(input, index)?;
            continue;
        }
        if have_token {
            out.push(b' ');
        }
        have_token = true;
        if byte == b'"' {
            let (token, next) = quoted_token(input, index)?;
            out.extend_from_slice(&token);
            index = next;
        } else {
            let start = index;
            while index < input.len()
                && !input[index].is_ascii_whitespace()
                && input[index] != b'"'
                && input[index] != b'('
            {
                index = index.saturating_add(1);
            }
            out.extend_from_slice(&input[start..index]);
        }
    }
    if out.is_empty() {
        return Ok(None);
    }
    let decoded = decode_encoded_words(&out, MAX_DISPLAY_NAME);
    let trimmed = decoded.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

fn quoted_token(input: &[u8], start: usize) -> Result<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut index = start.saturating_add(1);
    while index < input.len() {
        let byte = input[index];
        if byte == b'"' {
            return Ok((out, index.saturating_add(1)));
        }
        if byte == b'\\' {
            let escaped = input
                .get(index.saturating_add(1))
                .copied()
                .ok_or(Error::Address(AddressError::UnterminatedQuotedString))?;
            out.push(escaped);
            index = index.saturating_add(2);
        } else if byte == 0 || byte == b'\r' || byte == b'\n' {
            return Err(Error::Address(AddressError::InvalidLocalPart));
        } else {
            out.push(byte);
            index = index.saturating_add(1);
        }
    }
    Err(Error::Address(AddressError::UnterminatedQuotedString))
}

fn is_atext(byte: u8) -> bool {
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
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}
