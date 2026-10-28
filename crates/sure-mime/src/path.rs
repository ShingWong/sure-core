//! Stable part paths.

use core::fmt;

use crate::error::{Error, LimitKind, Result};

/// Hard maximum nesting depth supported by [`PartPath`].
pub const MAX_DEPTH: usize = 32;

/// A fixed-size, allocation-free path to a MIME part.
///
/// The root part is the empty path. Children are numbered from zero in the
/// order their opening delimiters appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PartPath {
    len: u8,
    segments: [u16; MAX_DEPTH],
}

impl PartPath {
    /// The root part.
    pub const ROOT: Self = Self {
        len: 0,
        segments: [0; MAX_DEPTH],
    };

    /// Append a child index.
    ///
    /// # Errors
    ///
    /// Returns a typed depth-limit error when the hard depth is exhausted.
    pub fn child(self, index: u16) -> Result<Self> {
        let len = usize::from(self.len);
        if len >= MAX_DEPTH {
            return Err(Error::LimitExceeded {
                limit: LimitKind::MimeDepth,
                max: MAX_DEPTH,
                observed: len.saturating_add(1),
            });
        }
        let mut segments = self.segments;
        segments[len] = index;
        Ok(Self {
            #[allow(clippy::cast_possible_truncation)]
            len: (len + 1) as u8,
            segments,
        })
    }

    /// Number of segments; the root has depth zero.
    #[must_use]
    pub const fn depth(self) -> usize {
        self.len as usize
    }

    /// Whether this is the root part.
    #[must_use]
    pub const fn is_root(self) -> bool {
        self.len == 0
    }

    /// The path segments.
    #[must_use]
    pub fn as_slice(&self) -> &[u16] {
        &self.segments[..usize::from(self.len)]
    }
}

impl Default for PartPath {
    fn default() -> Self {
        Self::ROOT
    }
}

impl fmt::Display for PartPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str("root");
        }
        for (index, segment) in self.as_slice().iter().enumerate() {
            if index > 0 {
                f.write_str(".")?;
            }
            write!(f, "{segment}")?;
        }
        Ok(())
    }
}
