//! Streaming message parser and bounded convenience API.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::mem;

use crate::{
    decode::{Decoder, TransferEncoding},
    error::{Error, LimitKind, MultipartError, Result},
    events::{AttachmentMeta, Event, MessageSummary, PartMeta},
    header::{parse_header_block, HeaderBlock},
    limits::Limits,
    media::{sanitize_filename, ContentDisposition, DispositionKind, MediaType},
    path::PartPath,
};

/// Parse a whole message with a bounded amount of retained non-attachment data.
///
/// Attachment bytes are decoded and discarded; only metadata is retained. The
/// `body` field contains the concatenation of non-attachment decoded chunks, up
/// to [`Limits::max_body_bytes`].
///
/// # Errors
///
/// Returns the first typed parser error.
pub fn parse_message(input: &[u8], limits: &Limits) -> Result<ParsedMessage> {
    let mut parser = MessageParser::new(*limits)?;
    let mut parsed = ParsedMessage::default();
    {
        let mut sink = |event: Event| match event {
            Event::Headers { path, headers } if path.is_root() => {
                parsed.headers = headers;
            }
            Event::PartStart(meta) => {
                if meta.is_attachment {
                    parsed.attachments.push(AttachmentMeta {
                        meta: meta.clone(),
                        decoded_bytes: 0,
                    });
                }
                parsed.parts.push(meta);
            }
            Event::BodyChunk { data, .. } => parsed.body.extend_from_slice(&data),
            Event::AttachmentChunk { .. } => {
                // Deliberately dropped: attachment bytes never accumulate here.
            }
            Event::PartEnd {
                path,
                decoded_bytes,
                ..
            } => {
                if let Some(attachment) = parsed
                    .attachments
                    .iter_mut()
                    .find(|attachment| attachment.meta.path == path)
                {
                    attachment.decoded_bytes = decoded_bytes;
                }
            }
            Event::MessageEnd(summary) => parsed.summary = summary,
            Event::Headers { .. }
            | Event::MessageStart
            | Event::Preamble { .. }
            | Event::Epilogue { .. } => {}
        };
        parser.push(input, &mut sink)?;
        parser.finish(&mut sink)?;
    }
    Ok(parsed)
}

/// Bounded convenience result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedMessage {
    /// Root header block.
    pub headers: HeaderBlock,
    /// Every part, root included.
    pub parts: Vec<PartMeta>,
    /// Concatenated non-attachment decoded body bytes.
    pub body: Vec<u8>,
    /// Attachment metadata (no bytes).
    pub attachments: Vec<AttachmentMeta>,
    /// Parser summary.
    pub summary: MessageSummary,
}

/// Streaming parser.
///
/// Feed bytes with [`MessageParser::push`] and finish with
/// [`MessageParser::finish`]. After any error the parser returns
/// [`Error::AlreadyFailed`] and must be discarded.
pub struct MessageParser {
    limits: Limits,
    mode: Mode,
    frames: Vec<Frame>,
    root_active: Option<ActivePart>,
    started: bool,
    finished: bool,
    failed: bool,
    received: u64,
    position: u64,
    part_count: usize,
    attachment_count: usize,
    decoded_total: u64,
    encoded_total: u64,
    body_total: u64,
    max_depth: usize,
    scan_out: Vec<u8>,
    pending_boundary_lf: bool,
}

impl MessageParser {
    /// Create a parser with validated limits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLimits`] for an unusable limit set.
    pub fn new(limits: Limits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            mode: Mode::RootHeaders(HeaderCollector::new(PartPath::ROOT, 0)),
            frames: Vec::new(),
            root_active: None,
            started: false,
            finished: false,
            failed: false,
            received: 0,
            position: 0,
            part_count: 0,
            attachment_count: 0,
            decoded_total: 0,
            encoded_total: 0,
            body_total: 0,
            max_depth: 0,
            scan_out: Vec::new(),
            pending_boundary_lf: false,
        })
    }

    /// Create a parser with [`Limits::default`].
    ///
    /// # Errors
    ///
    /// The default limits are valid; this only exists for symmetry.
    pub fn with_defaults() -> Result<Self> {
        Self::new(Limits::default())
    }

    /// Feed a chunk of message bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed error on malformed input, a limit breach, or reuse after
    /// an earlier error/finish.
    pub fn push<F>(&mut self, input: &[u8], sink: &mut F) -> Result<()>
    where
        F: FnMut(Event),
    {
        if self.failed {
            return Err(Error::AlreadyFailed);
        }
        if self.finished {
            return Err(Error::Finished);
        }
        self.ensure_started(sink);
        let received = self.received.saturating_add(input.len() as u64);
        if received > self.limits.max_message_bytes as u64 {
            self.failed = true;
            return Err(
                LimitKind::MessageBytes.exceeded(self.limits.max_message_bytes, as_usize(received))
            );
        }
        self.received = received;
        if input.is_empty() {
            return Ok(());
        }
        let result = self.push_inner(input, sink);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Finish the message.
    ///
    /// # Errors
    ///
    /// Returns a typed error for truncated multipart input, a limit breach, or
    /// reuse after an earlier error/finish.
    pub fn finish<F>(&mut self, sink: &mut F) -> Result<MessageSummary>
    where
        F: FnMut(Event),
    {
        if self.failed {
            return Err(Error::AlreadyFailed);
        }
        if self.finished {
            return Err(Error::Finished);
        }
        self.ensure_started(sink);
        let result = self.finish_inner(sink);
        match result {
            Ok(summary) => Ok(summary),
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }

    fn ensure_started<F>(&mut self, sink: &mut F)
    where
        F: FnMut(Event),
    {
        if !self.started {
            self.started = true;
            sink(Event::MessageStart);
        }
    }

    fn push_inner<F>(&mut self, input: &[u8], sink: &mut F) -> Result<()>
    where
        F: FnMut(Event),
    {
        let mut position = 0usize;
        if self.pending_boundary_lf {
            self.pending_boundary_lf = false;
            if input.get(position).copied() == Some(b'\n') {
                position = position.saturating_add(1);
                self.position = self.position.saturating_add(1);
            }
        }
        while position < input.len() {
            if matches!(self.mode, Mode::RootHeaders(_) | Mode::PartHeaders(_)) {
                let limits = self.limits;
                let (used, done) = match &mut self.mode {
                    Mode::RootHeaders(collector) | Mode::PartHeaders(collector) => {
                        collector.feed(&input[position..], &limits)?
                    }
                    _ => return Err(Error::Multipart(MultipartError::UnexpectedContent)),
                };
                self.position = self.position.saturating_add(used as u64);
                position = position.saturating_add(used);
                if done {
                    self.complete_headers(sink)?;
                } else {
                    return Ok(());
                }
                continue;
            }

            match self.mode {
                Mode::Body => {}
                Mode::Done => return Err(Error::Finished),
                Mode::RootHeaders(_) | Mode::PartHeaders(_) => {}
            }

            if self.frames.is_empty() {
                if self.root_active.is_some() {
                    let data = &input[position..];
                    self.feed_root(data, sink)?;
                    self.position = self.position.saturating_add(data.len() as u64);
                    return Ok(());
                }
                return Err(Error::Multipart(MultipartError::UnexpectedContent));
            }

            let mut index = position;
            let mut boundary_seen = false;
            let mut out = mem::take(&mut self.scan_out);
            out.clear();
            let chunk_size = self.limits.max_chunk_bytes.max(1);
            while index < input.len() {
                let byte = input[index];
                index = index.saturating_add(1);
                let step = {
                    let frame = self
                        .frames
                        .last_mut()
                        .ok_or(Error::Multipart(MultipartError::UnexpectedContent))?;
                    frame.scanner.feed(byte, &mut out)?
                };
                self.position = self.position.saturating_add(1);
                match step {
                    ScanStep::Continue => {}
                    ScanStep::BoundaryOpen => {
                        if !out.is_empty() {
                            self.route_frame_content(&out, sink)?;
                            out.clear();
                        }
                        self.on_boundary_open(sink)?;
                        self.after_boundary(byte, &mut index, input);
                        boundary_seen = true;
                        break;
                    }
                    ScanStep::BoundaryClose => {
                        if !out.is_empty() {
                            self.route_frame_content(&out, sink)?;
                            out.clear();
                        }
                        self.on_boundary_close(sink)?;
                        self.after_boundary(byte, &mut index, input);
                        boundary_seen = true;
                        break;
                    }
                }
                if out.len() >= chunk_size {
                    self.route_frame_content(&out, sink)?;
                    out.clear();
                }
            }
            if !out.is_empty() {
                self.route_frame_content(&out, sink)?;
                out.clear();
            }
            self.scan_out = out;
            position = index;
            if boundary_seen {
                continue;
            }
            return Ok(());
        }
        Ok(())
    }

    fn finish_inner<F>(&mut self, sink: &mut F) -> Result<MessageSummary>
    where
        F: FnMut(Event),
    {
        self.pending_boundary_lf = false;
        if matches!(self.mode, Mode::RootHeaders(_) | Mode::PartHeaders(_)) {
            self.complete_headers(sink)?;
        }

        if self.frames.is_empty() {
            if let Some(part) = self.root_active.take() {
                let mut decoded_total = self.decoded_total;
                let mut encoded_total = self.encoded_total;
                let mut body_total = self.body_total;
                finish_active_part(
                    part,
                    &self.limits,
                    &mut decoded_total,
                    &mut encoded_total,
                    &mut body_total,
                    sink,
                )?;
                self.decoded_total = decoded_total;
                self.encoded_total = encoded_total;
                self.body_total = body_total;
            } else {
                return Err(Error::Multipart(MultipartError::UnexpectedContent));
            }
        } else {
            let mut out = mem::take(&mut self.scan_out);
            out.clear();
            {
                let frame = self
                    .frames
                    .last_mut()
                    .ok_or(Error::Multipart(MultipartError::UnexpectedContent))?;
                frame.scanner.finish(&mut out);
            }
            if !out.is_empty() {
                self.route_frame_content(&out, sink)?;
            }
            self.scan_out = out;

            if self.frames.len() != 1 {
                return Err(Error::Multipart(MultipartError::Unterminated));
            }
            let frame = self
                .frames
                .last()
                .ok_or(Error::Multipart(MultipartError::UnexpectedContent))?;
            if frame.state != FrameState::Epilogue {
                return Err(Error::Multipart(MultipartError::Unterminated));
            }
            let path = frame.path;
            sink(Event::PartEnd {
                path,
                decoded_bytes: 0,
                encoded_bytes: 0,
            });
            self.frames.clear();
        }

        let summary = self.summary();
        sink(Event::MessageEnd(summary));
        self.finished = true;
        Ok(summary)
    }

    fn summary(&self) -> MessageSummary {
        MessageSummary {
            parts: self.part_count,
            attachments: self.attachment_count,
            decoded_bytes: self.decoded_total,
            encoded_bytes: self.encoded_total,
            max_depth: self.max_depth,
        }
    }

    fn complete_headers<F>(&mut self, sink: &mut F) -> Result<()>
    where
        F: FnMut(Event),
    {
        let (mut collector, is_root) = match mem::replace(&mut self.mode, Mode::Done) {
            Mode::RootHeaders(collector) => (collector, true),
            Mode::PartHeaders(collector) => (collector, false),
            _ => return Err(Error::Multipart(MultipartError::UnexpectedContent)),
        };
        collector.finish(&self.limits)?;
        let raw = collector
            .buf
            .get(..collector.raw_len)
            .unwrap_or(collector.buf.as_slice());
        let block = parse_header_block(raw, collector.base_offset, &self.limits)?;
        let path = collector.path;
        let meta = build_meta(path, &block, &self.limits)?;
        self.register_part(&meta)?;
        sink(Event::Headers {
            path,
            headers: block,
        });
        sink(Event::PartStart(meta.clone()));

        if is_root {
            if meta.is_multipart {
                let boundary = meta
                    .boundary
                    .as_ref()
                    .ok_or(Error::Multipart(MultipartError::MissingBoundary))?
                    .as_bytes()
                    .to_vec();
                self.frames.push(Frame::new(path, boundary));
            } else {
                self.root_active = Some(ActivePart::new(meta));
            }
        } else if meta.is_multipart {
            let boundary = meta
                .boundary
                .as_ref()
                .ok_or(Error::Multipart(MultipartError::MissingBoundary))?
                .as_bytes()
                .to_vec();
            let frame = self
                .frames
                .last_mut()
                .ok_or(Error::Multipart(MultipartError::UnexpectedContent))?;
            frame.current = Some(Current::Container(meta.clone()));
            self.frames.push(Frame::new(path, boundary));
        } else {
            let frame = self
                .frames
                .last_mut()
                .ok_or(Error::Multipart(MultipartError::UnexpectedContent))?;
            frame.current = Some(Current::Streaming(ActivePart::new(meta)));
        }
        self.mode = Mode::Body;
        Ok(())
    }

    fn register_part(&mut self, meta: &PartMeta) -> Result<()> {
        self.part_count = self.part_count.saturating_add(1);
        if self.part_count > self.limits.max_parts {
            return Err(LimitKind::PartCount.exceeded(self.limits.max_parts, self.part_count));
        }
        if meta.depth > self.limits.max_mime_depth {
            return Err(LimitKind::MimeDepth.exceeded(self.limits.max_mime_depth, meta.depth));
        }
        if meta.depth > self.max_depth {
            self.max_depth = meta.depth;
        }
        if meta.is_attachment {
            self.attachment_count = self.attachment_count.saturating_add(1);
        }
        Ok(())
    }

    fn feed_root<F>(&mut self, data: &[u8], sink: &mut F) -> Result<()>
    where
        F: FnMut(Event),
    {
        let mut decoded_total = self.decoded_total;
        let mut encoded_total = self.encoded_total;
        let mut body_total = self.body_total;
        if let Some(part) = self.root_active.as_mut() {
            feed_active_part(
                part,
                data,
                &self.limits,
                &mut decoded_total,
                &mut encoded_total,
                &mut body_total,
                sink,
            )?;
        }
        self.decoded_total = decoded_total;
        self.encoded_total = encoded_total;
        self.body_total = body_total;
        Ok(())
    }

    fn feed_frame<F>(&mut self, data: &[u8], sink: &mut F) -> Result<()>
    where
        F: FnMut(Event),
    {
        let mut current = {
            let frame = self
                .frames
                .last_mut()
                .ok_or(Error::Multipart(MultipartError::UnexpectedContent))?;
            frame.current.take()
        };
        let mut decoded_total = self.decoded_total;
        let mut encoded_total = self.encoded_total;
        let mut body_total = self.body_total;
        let result = match current.as_mut() {
            Some(Current::Streaming(part)) => feed_active_part(
                part,
                data,
                &self.limits,
                &mut decoded_total,
                &mut encoded_total,
                &mut body_total,
                sink,
            ),
            _ => Ok(()),
        };
        self.decoded_total = decoded_total;
        self.encoded_total = encoded_total;
        self.body_total = body_total;
        if let Some(frame) = self.frames.last_mut() {
            frame.current = current;
        }
        result
    }

    fn route_frame_content<F>(&mut self, data: &[u8], sink: &mut F) -> Result<()>
    where
        F: FnMut(Event),
    {
        let (state, frame_path) = {
            let frame = self
                .frames
                .last()
                .ok_or(Error::Multipart(MultipartError::UnexpectedContent))?;
            (frame.state, frame.path)
        };
        match state {
            FrameState::Preamble => {
                self.emit_aux(Aux::Preamble, frame_path, data, sink);
                Ok(())
            }
            FrameState::Epilogue => {
                self.emit_aux(Aux::Epilogue, frame_path, data, sink);
                Ok(())
            }
            FrameState::Body => {
                let streaming = matches!(
                    self.frames.last().map(|frame| &frame.current),
                    Some(Some(Current::Streaming(_)))
                );
                if streaming {
                    return self.feed_frame(data, sink);
                }
                let container_path = match self.frames.last().map(|frame| &frame.current) {
                    Some(Some(Current::Container(meta))) => Some(meta.path),
                    _ => None,
                };
                if let Some(path) = container_path {
                    self.emit_aux(Aux::Epilogue, path, data, sink);
                    Ok(())
                } else {
                    Err(Error::Multipart(MultipartError::UnexpectedContent))
                }
            }
        }
    }

    fn emit_aux<F>(&self, aux: Aux, path: PartPath, data: &[u8], sink: &mut F)
    where
        F: FnMut(Event),
    {
        let chunk_size = self.limits.max_chunk_bytes.max(1);
        for chunk in data.chunks(chunk_size) {
            let event = match aux {
                Aux::Preamble => Event::Preamble {
                    path,
                    data: chunk.to_vec(),
                },
                Aux::Epilogue => Event::Epilogue {
                    path,
                    data: chunk.to_vec(),
                },
            };
            sink(event);
        }
    }

    /// Consume the optional LF of a CRLF delimiter and remember it when the
    /// CRLF is split across two `push` calls.
    fn after_boundary(&mut self, byte: u8, index: &mut usize, input: &[u8]) {
        if let Some(frame) = self.frames.last_mut() {
            frame.scanner.swallow_lf = false;
        }
        if byte == b'\r' {
            if input.get(*index).copied() == Some(b'\n') {
                *index = index.saturating_add(1);
                self.position = self.position.saturating_add(1);
            } else {
                self.pending_boundary_lf = true;
            }
        }
    }

    fn on_boundary_open<F>(&mut self, sink: &mut F) -> Result<()>
    where
        F: FnMut(Event),
    {
        {
            let frame = self
                .frames
                .last()
                .ok_or(Error::Multipart(MultipartError::UnexpectedContent))?;
            if frame.state == FrameState::Epilogue {
                return Err(Error::Multipart(MultipartError::BoundaryAfterClose));
            }
        }
        self.finish_current(sink)?;
        let path = {
            let frame = self
                .frames
                .last_mut()
                .ok_or(Error::Multipart(MultipartError::UnexpectedContent))?;
            frame.state = FrameState::Body;
            let index = frame.next_index;
            frame.next_index = frame.next_index.checked_add(1).ok_or_else(|| {
                LimitKind::PartCount.exceeded(usize::from(u16::MAX), usize::from(u16::MAX))
            })?;
            frame.path.child(index)?
        };
        if path.depth() > self.limits.max_mime_depth {
            return Err(LimitKind::MimeDepth.exceeded(self.limits.max_mime_depth, path.depth()));
        }
        self.mode = Mode::PartHeaders(HeaderCollector::new(path, self.position));
        Ok(())
    }

    fn on_boundary_close<F>(&mut self, sink: &mut F) -> Result<()>
    where
        F: FnMut(Event),
    {
        {
            let frame = self
                .frames
                .last()
                .ok_or(Error::Multipart(MultipartError::UnexpectedContent))?;
            if frame.state == FrameState::Epilogue {
                return Err(Error::Multipart(MultipartError::BoundaryAfterClose));
            }
        }
        self.finish_current(sink)?;
        {
            let frame = self
                .frames
                .last_mut()
                .ok_or(Error::Multipart(MultipartError::UnexpectedContent))?;
            frame.state = FrameState::Epilogue;
        }
        if self.frames.len() > 1 {
            self.frames.pop();
        }
        Ok(())
    }

    fn finish_current<F>(&mut self, sink: &mut F) -> Result<()>
    where
        F: FnMut(Event),
    {
        let current = {
            let frame = self
                .frames
                .last_mut()
                .ok_or(Error::Multipart(MultipartError::UnexpectedContent))?;
            frame.current.take()
        };
        match current {
            None => Ok(()),
            Some(Current::Container(meta)) => {
                sink(Event::PartEnd {
                    path: meta.path,
                    decoded_bytes: 0,
                    encoded_bytes: 0,
                });
                Ok(())
            }
            Some(Current::Streaming(part)) => {
                let mut decoded_total = self.decoded_total;
                let mut encoded_total = self.encoded_total;
                let mut body_total = self.body_total;
                let result = finish_active_part(
                    part,
                    &self.limits,
                    &mut decoded_total,
                    &mut encoded_total,
                    &mut body_total,
                    sink,
                );
                self.decoded_total = decoded_total;
                self.encoded_total = encoded_total;
                self.body_total = body_total;
                result
            }
        }
    }
}

struct HeaderCollector {
    path: PartPath,
    base_offset: u64,
    buf: Vec<u8>,
    line_len: usize,
    pending_cr: bool,
    raw_len: usize,
    done: bool,
}

impl HeaderCollector {
    fn new(path: PartPath, base_offset: u64) -> Self {
        Self {
            path,
            base_offset,
            buf: Vec::new(),
            line_len: 0,
            pending_cr: false,
            raw_len: 0,
            done: false,
        }
    }

    fn feed(&mut self, input: &[u8], limits: &Limits) -> Result<(usize, bool)> {
        let mut index = 0usize;
        while index < input.len() {
            let byte = input[index];
            if self.pending_cr {
                self.pending_cr = false;
                if byte == b'\n' {
                    self.push_byte(byte, limits)?;
                    index = index.saturating_add(1);
                    if self.end_line(2) {
                        return Ok((index, true));
                    }
                    continue;
                }
                if self.end_line(1) {
                    return Ok((index, true));
                }
            }
            match byte {
                b'\r' => {
                    self.push_byte(byte, limits)?;
                    self.pending_cr = true;
                    index = index.saturating_add(1);
                }
                b'\n' => {
                    self.push_byte(byte, limits)?;
                    index = index.saturating_add(1);
                    if self.end_line(1) {
                        return Ok((index, true));
                    }
                }
                _ => {
                    self.push_byte(byte, limits)?;
                    self.line_len = self.line_len.saturating_add(1);
                    if self.line_len > limits.max_header_line_len {
                        return Err(LimitKind::HeaderLineLength
                            .exceeded(limits.max_header_line_len, self.line_len));
                    }
                    index = index.saturating_add(1);
                }
            }
        }
        Ok((index, false))
    }

    fn finish(&mut self, limits: &Limits) -> Result<()> {
        if self.done {
            return Ok(());
        }
        if self.pending_cr {
            self.pending_cr = false;
            let _ = self.end_line(1);
        }
        if !self.done {
            self.done = true;
            self.raw_len = self.buf.len();
        }
        if self.buf.len() > limits.max_header_bytes {
            return Err(LimitKind::HeaderBytes.exceeded(limits.max_header_bytes, self.buf.len()));
        }
        Ok(())
    }

    fn push_byte(&mut self, byte: u8, limits: &Limits) -> Result<()> {
        if self.buf.len() >= limits.max_header_bytes {
            return Err(LimitKind::HeaderBytes
                .exceeded(limits.max_header_bytes, self.buf.len().saturating_add(1)));
        }
        self.buf.push(byte);
        Ok(())
    }

    fn end_line(&mut self, terminator_len: usize) -> bool {
        if self.line_len == 0 {
            self.done = true;
            self.raw_len = self.buf.len().saturating_sub(terminator_len);
            true
        } else {
            self.line_len = 0;
            false
        }
    }
}

struct ActivePart {
    meta: PartMeta,
    decoder: Decoder,
    out: Vec<u8>,
    decoded: u64,
    encoded: u64,
}

impl ActivePart {
    fn new(meta: PartMeta) -> Self {
        let decoder = Decoder::new(meta.transfer_encoding);
        Self {
            meta,
            decoder,
            out: Vec::new(),
            decoded: 0,
            encoded: 0,
        }
    }
}

struct Frame {
    path: PartPath,
    scanner: Scanner,
    state: FrameState,
    next_index: u16,
    current: Option<Current>,
}

impl Frame {
    fn new(path: PartPath, boundary: Vec<u8>) -> Self {
        Self {
            path,
            scanner: Scanner::new(boundary),
            state: FrameState::Preamble,
            next_index: 0,
            current: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameState {
    Preamble,
    Body,
    Epilogue,
}

enum Current {
    Streaming(ActivePart),
    Container(PartMeta),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Aux {
    Preamble,
    Epilogue,
}

enum Mode {
    RootHeaders(HeaderCollector),
    PartHeaders(HeaderCollector),
    Body,
    Done,
}

fn feed_active_part<F>(
    part: &mut ActivePart,
    data: &[u8],
    limits: &Limits,
    decoded_total: &mut u64,
    encoded_total: &mut u64,
    body_total: &mut u64,
    sink: &mut F,
) -> Result<()>
where
    F: FnMut(Event),
{
    let chunk_size = limits.max_chunk_bytes.max(1);
    for chunk in data.chunks(chunk_size) {
        let before = part.out.len();
        part.decoder.push(chunk, &mut part.out)?;
        let produced = part.out.len().saturating_sub(before) as u64;
        part.decoded = part.decoded.saturating_add(produced);
        part.encoded = part.encoded.saturating_add(chunk.len() as u64);
        *encoded_total = encoded_total.saturating_add(chunk.len() as u64);
        *decoded_total = decoded_total.saturating_add(produced);
        if part.meta.is_attachment {
            if part.decoded > limits.max_attachment_bytes as u64 {
                return Err(LimitKind::AttachmentBytes
                    .exceeded(limits.max_attachment_bytes, as_usize(part.decoded)));
            }
        } else {
            *body_total = body_total.saturating_add(produced);
            if *body_total > limits.max_body_bytes as u64 {
                return Err(
                    LimitKind::BodyBytes.exceeded(limits.max_body_bytes, as_usize(*body_total))
                );
            }
        }
        if *decoded_total > limits.max_decoded_bytes as u64 {
            return Err(LimitKind::DecodedBytes
                .exceeded(limits.max_decoded_bytes, as_usize(*decoded_total)));
        }
        if part.out.len() >= chunk_size {
            flush_part(part, sink);
        }
    }
    Ok(())
}

fn finish_active_part<F>(
    mut part: ActivePart,
    limits: &Limits,
    decoded_total: &mut u64,
    _encoded_total: &mut u64,
    body_total: &mut u64,
    sink: &mut F,
) -> Result<()>
where
    F: FnMut(Event),
{
    let before = part.out.len();
    part.decoder.finish(&mut part.out)?;
    let produced = part.out.len().saturating_sub(before) as u64;
    part.decoded = part.decoded.saturating_add(produced);
    *decoded_total = decoded_total.saturating_add(produced);
    if part.meta.is_attachment {
        if part.decoded > limits.max_attachment_bytes as u64 {
            return Err(LimitKind::AttachmentBytes
                .exceeded(limits.max_attachment_bytes, as_usize(part.decoded)));
        }
    } else {
        *body_total = body_total.saturating_add(produced);
        if *body_total > limits.max_body_bytes as u64 {
            return Err(LimitKind::BodyBytes.exceeded(limits.max_body_bytes, as_usize(*body_total)));
        }
    }
    if *decoded_total > limits.max_decoded_bytes as u64 {
        return Err(
            LimitKind::DecodedBytes.exceeded(limits.max_decoded_bytes, as_usize(*decoded_total))
        );
    }
    flush_part(&mut part, sink);
    sink(Event::PartEnd {
        path: part.meta.path,
        decoded_bytes: part.decoded,
        encoded_bytes: part.encoded,
    });
    Ok(())
}

fn flush_part<F>(part: &mut ActivePart, sink: &mut F)
where
    F: FnMut(Event),
{
    if part.out.is_empty() {
        return;
    }
    let data = mem::take(&mut part.out);
    if part.meta.is_attachment {
        sink(Event::AttachmentChunk {
            path: part.meta.path,
            data,
        });
    } else {
        sink(Event::BodyChunk {
            path: part.meta.path,
            data,
        });
    }
}

fn build_meta(path: PartPath, block: &HeaderBlock, limits: &Limits) -> Result<PartMeta> {
    let content_type = match block.get("content-type") {
        Some(header) => Some(MediaType::parse(header.value_trimmed())?),
        None => None,
    };
    let effective = content_type
        .clone()
        .unwrap_or_else(MediaType::default_text_plain);
    let transfer_encoding = match block.get("content-transfer-encoding") {
        Some(header) => TransferEncoding::parse(header.value_trimmed())?,
        None => TransferEncoding::Identity,
    };
    let disposition = match block.get("content-disposition") {
        Some(header) => Some(ContentDisposition::parse(header.value_trimmed())?),
        None => None,
    };
    let is_multipart = effective.is_multipart();
    let boundary = if is_multipart {
        effective.boundary().map(ToString::to_string)
    } else {
        None
    };
    if is_multipart {
        let boundary_value = boundary
            .as_deref()
            .ok_or(Error::Multipart(MultipartError::MissingBoundary))?;
        if boundary_value.is_empty()
            || boundary_value.len() > limits.max_boundary_len
            || !boundary_value
                .bytes()
                .all(|byte| (32..=126).contains(&byte))
        {
            return Err(Error::Multipart(MultipartError::InvalidBoundary));
        }
        if !transfer_encoding.is_identity() {
            return Err(Error::Multipart(MultipartError::TransferEncoding));
        }
    }

    let filename = disposition
        .as_ref()
        .and_then(ContentDisposition::filename)
        .or_else(|| {
            effective
                .param("name")
                .map(|parameter| parameter.value.as_str())
        })
        .map(sanitize_filename)
        .filter(|name| !name.is_empty());
    // A multipart container is always parsed as a container; attachment
    // semantics belong to its leaf parts. This avoids a container being routed
    // to a blob writer while its children are streamed separately.
    let is_attachment = !is_multipart
        && (matches!(
            disposition.as_ref().map(|value| &value.kind),
            Some(DispositionKind::Attachment)
        ) || filename.is_some());
    let content_id = block
        .get("content-id")
        .map(|header| String::from_utf8_lossy(header.value_trimmed()).into_owned());

    Ok(PartMeta {
        path,
        content_type,
        disposition,
        transfer_encoding,
        filename,
        content_id,
        is_attachment,
        is_multipart,
        boundary,
        depth: path.depth(),
        header_count: block.len(),
    })
}

fn as_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanStep {
    Continue,
    BoundaryOpen,
    BoundaryClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    Normal,
    Prefix,
    AfterBoundary,
    AfterDash,
    AfterClose,
    TrailingWsp,
}

struct Scanner {
    boundary: Vec<u8>,
    cand: Vec<u8>,
    mode: ScanMode,
    line_start: bool,
    pending_eol: [u8; 2],
    pending_eol_len: u8,
    pending_cr: bool,
    swallow_lf: bool,
}

impl Scanner {
    fn new(boundary: Vec<u8>) -> Self {
        Self {
            boundary,
            cand: Vec::new(),
            mode: ScanMode::Normal,
            line_start: true,
            pending_eol: [0; 2],
            pending_eol_len: 0,
            pending_cr: false,
            swallow_lf: false,
        }
    }

    fn feed(&mut self, byte: u8, out: &mut Vec<u8>) -> Result<ScanStep> {
        if self.swallow_lf {
            self.swallow_lf = false;
            if byte == b'\n' {
                return Ok(ScanStep::Continue);
            }
        }
        if self.pending_cr {
            self.pending_cr = false;
            if byte == b'\n' {
                self.eol(b"\r\n", out);
                return Ok(ScanStep::Continue);
            }
            self.eol(b"\r", out);
        }
        self.dispatch(byte, out)
    }

    fn dispatch(&mut self, byte: u8, out: &mut Vec<u8>) -> Result<ScanStep> {
        match self.mode {
            ScanMode::Normal => {
                if self.line_start {
                    match byte {
                        b'-' => {
                            self.cand.clear();
                            self.cand.push(b'-');
                            self.mode = ScanMode::Prefix;
                        }
                        b'\r' => {
                            self.flush_pending(out);
                            self.pending_cr = true;
                        }
                        b'\n' => {
                            self.flush_pending(out);
                            self.eol(b"\n", out);
                        }
                        _ => {
                            self.flush_pending(out);
                            out.push(byte);
                            self.line_start = false;
                        }
                    }
                } else {
                    match byte {
                        b'\r' => self.pending_cr = true,
                        b'\n' => self.eol(b"\n", out),
                        _ => out.push(byte),
                    }
                }
            }
            ScanMode::Prefix => {
                let index = self.cand.len();
                if self.prefix_byte(index) == Some(byte) {
                    self.cand.push(byte);
                    if self.cand.len() >= self.boundary.len().saturating_add(2) {
                        self.mode = ScanMode::AfterBoundary;
                    }
                } else {
                    self.mismatch(byte, out)?;
                }
            }
            ScanMode::AfterBoundary => match byte {
                b'-' => {
                    self.cand.push(byte);
                    self.mode = ScanMode::AfterDash;
                }
                b' ' | b'\t' => {
                    self.cand.push(byte);
                    self.mode = ScanMode::TrailingWsp;
                }
                b'\r' => {
                    self.finish_boundary(true);
                    return Ok(ScanStep::BoundaryOpen);
                }
                b'\n' => {
                    self.finish_boundary(false);
                    return Ok(ScanStep::BoundaryOpen);
                }
                _ => self.mismatch(byte, out)?,
            },
            ScanMode::AfterDash => {
                if byte == b'-' {
                    self.cand.push(byte);
                    self.mode = ScanMode::AfterClose;
                } else {
                    self.mismatch(byte, out)?;
                }
            }
            ScanMode::AfterClose => match byte {
                b' ' | b'\t' => self.cand.push(byte),
                b'\r' => {
                    self.finish_boundary(true);
                    return Ok(ScanStep::BoundaryClose);
                }
                b'\n' => {
                    self.finish_boundary(false);
                    return Ok(ScanStep::BoundaryClose);
                }
                _ => self.mismatch(byte, out)?,
            },
            ScanMode::TrailingWsp => match byte {
                b' ' | b'\t' => self.cand.push(byte),
                b'\r' => {
                    self.finish_boundary(true);
                    return Ok(ScanStep::BoundaryOpen);
                }
                b'\n' => {
                    self.finish_boundary(false);
                    return Ok(ScanStep::BoundaryOpen);
                }
                _ => self.mismatch(byte, out)?,
            },
        }
        Ok(ScanStep::Continue)
    }

    fn prefix_byte(&self, index: usize) -> Option<u8> {
        match index {
            0 | 1 => Some(b'-'),
            _ => self.boundary.get(index.saturating_sub(2)).copied(),
        }
    }

    fn mismatch(&mut self, byte: u8, out: &mut Vec<u8>) -> Result<()> {
        self.flush_pending(out);
        out.extend_from_slice(&self.cand);
        self.cand.clear();
        self.mode = ScanMode::Normal;
        self.line_start = false;
        match byte {
            b'\r' => self.pending_cr = true,
            b'\n' => self.eol(b"\n", out),
            _ => out.push(byte),
        }
        Ok(())
    }

    fn finish_boundary(&mut self, cr: bool) {
        self.cand.clear();
        self.mode = ScanMode::Normal;
        self.line_start = true;
        self.pending_eol_len = 0;
        self.pending_cr = false;
        if cr {
            self.swallow_lf = true;
        }
    }

    fn eol(&mut self, terminator: &[u8], out: &mut Vec<u8>) {
        if self.pending_eol_len > 0 {
            let length = usize::from(self.pending_eol_len);
            out.extend_from_slice(&self.pending_eol[..length]);
            self.pending_eol_len = 0;
        }
        let length = terminator.len().min(2);
        if let Some(target) = self.pending_eol.get_mut(..length) {
            if let Some(source) = terminator.get(..length) {
                target.copy_from_slice(source);
            }
        }
        self.pending_eol_len = length as u8;
        self.line_start = true;
    }

    fn flush_pending(&mut self, out: &mut Vec<u8>) {
        if self.pending_eol_len > 0 {
            let length = usize::from(self.pending_eol_len);
            out.extend_from_slice(&self.pending_eol[..length]);
            self.pending_eol_len = 0;
        }
    }

    fn finish(&mut self, out: &mut Vec<u8>) {
        if self.pending_cr {
            self.pending_cr = false;
            self.eol(b"\r", out);
        }
        if !self.cand.is_empty() {
            self.flush_pending(out);
            out.extend_from_slice(&self.cand);
            self.cand.clear();
        }
        self.flush_pending(out);
        self.mode = ScanMode::Normal;
    }
}
