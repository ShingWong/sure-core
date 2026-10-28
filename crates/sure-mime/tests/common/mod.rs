#![allow(dead_code)]

use sure_mime::{Error, Event, Limits, MessageParser, ParsedMessage};

/// Parse a message by feeding it in fixed-size chunks.
pub fn parse_chunked(
    input: &[u8],
    chunk_size: usize,
    limits: &Limits,
) -> Result<ParsedMessage, Error> {
    let mut parser = MessageParser::new(*limits)?;
    let mut parsed = ParsedMessage::default();
    {
        let mut sink = |event: Event| match event {
            Event::Headers { path, headers } if path.is_root() => parsed.headers = headers,
            Event::PartStart(meta) => {
                if meta.is_attachment {
                    parsed.attachments.push(sure_mime::AttachmentMeta {
                        meta: meta.clone(),
                        decoded_bytes: 0,
                    });
                }
                parsed.parts.push(meta);
            }
            Event::BodyChunk { data, .. } => parsed.body.extend_from_slice(&data),
            Event::AttachmentChunk { .. } => {}
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
        for chunk in input.chunks(chunk_size.max(1)) {
            parser.push(chunk, &mut sink)?;
        }
        parser.finish(&mut sink)?;
    }
    Ok(parsed)
}

/// Collect events with explicit split points.
pub fn events(input: &[u8], splits: &[usize], limits: &Limits) -> Result<Vec<Event>, Error> {
    let mut parser = MessageParser::new(*limits)?;
    let mut collected = Vec::new();
    let mut sink = |event: Event| collected.push(event);
    let mut last = 0usize;
    for split in splits {
        let end = (*split).min(input.len());
        if end < last {
            continue;
        }
        parser.push(&input[last..end], &mut sink)?;
        last = end;
    }
    if last < input.len() {
        parser.push(&input[last..], &mut sink)?;
    }
    parser.finish(&mut sink)?;
    Ok(collected)
}
