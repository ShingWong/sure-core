mod common;

use common::{events, parse_chunked};
use sure_mime::{parse_message, Error, Event, Limits, MessageParser};

const MESSAGE: &[u8] = b"From: a@example.com\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
caf=C3=A9 and line=\r\n\
break\r\n\
--b\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=\"x.bin\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
AAECAwQFBgcICQ==\r\n\
--b--\r\n";

#[test]
fn split_at_every_byte_matches_whole_message() {
    let whole = parse_message(MESSAGE, &Limits::default()).unwrap();
    for chunk_size in 1..=MESSAGE.len() {
        let chunked = parse_chunked(MESSAGE, chunk_size, &Limits::default()).unwrap();
        assert_eq!(chunked.body, whole.body, "chunk size {chunk_size}");
        assert_eq!(chunked.parts, whole.parts, "chunk size {chunk_size}");
        assert_eq!(
            chunked.attachments, whole.attachments,
            "chunk size {chunk_size}"
        );
        assert_eq!(chunked.summary, whole.summary, "chunk size {chunk_size}");
    }
}

#[test]
fn arbitrary_split_points_match_whole_message() {
    let whole = parse_message(MESSAGE, &Limits::default()).unwrap();
    for step in [2usize, 3, 5, 7, 11, 13, 17, 31] {
        let splits: Vec<usize> = (step..MESSAGE.len()).step_by(step).collect();
        let collected = events(MESSAGE, &splits, &Limits::default()).unwrap();
        let body: Vec<u8> = collected
            .iter()
            .filter_map(|event| match event {
                Event::BodyChunk { data, .. } => Some(data.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(body, whole.body, "step {step}");
    }
}

#[test]
fn empty_pushes_are_harmless() {
    let mut parser = MessageParser::new(Limits::default()).unwrap();
    let mut collected = Vec::new();
    let mut sink = |event: Event| collected.push(event);
    parser.push(b"", &mut sink).unwrap();
    parser.push(b"Subject: a\r\n", &mut sink).unwrap();
    parser.push(b"", &mut sink).unwrap();
    parser.push(b"\r\nbody", &mut sink).unwrap();
    let summary = parser.finish(&mut sink).unwrap();
    assert_eq!(summary.parts, 1);
    assert!(matches!(collected.first(), Some(Event::MessageStart)));
    assert!(matches!(collected.last(), Some(Event::MessageEnd(_))));
}

#[test]
fn body_only_message_streams_chunks() {
    let mut parser = MessageParser::new(Limits::default()).unwrap();
    let mut body = Vec::new();
    let mut sink = |event: Event| {
        if let Event::BodyChunk { data, .. } = event {
            body.extend_from_slice(&data);
        }
    };
    for chunk in [b"\r\nabc".as_slice(), b"def", b"ghi"] {
        parser.push(chunk, &mut sink).unwrap();
    }
    parser.finish(&mut sink).unwrap();
    assert_eq!(body, b"abcdefghi");
}

#[test]
fn nested_split_at_every_byte() {
    let message = b"Content-Type: multipart/mixed; boundary=outer\r\n\r\n\
--outer\r\n\
Content-Type: multipart/alternative; boundary=inner\r\n\
\r\n\
--inner\r\n\
Content-Type: text/plain\r\n\
\r\n\
plain\r\n\
--inner\r\n\
Content-Type: text/html\r\n\
\r\n\
<p>html</p>\r\n\
--inner--\r\n\
--outer--\r\n";
    let whole = parse_message(message, &Limits::default()).unwrap();
    for chunk_size in 1..=message.len() {
        let chunked = parse_chunked(message, chunk_size, &Limits::default()).unwrap();
        assert_eq!(chunked.body, whole.body, "chunk size {chunk_size}");
        assert_eq!(chunked.summary, whole.summary, "chunk size {chunk_size}");
    }
}

#[test]
fn finish_without_any_input_is_empty_message() {
    let mut parser = MessageParser::new(Limits::default()).unwrap();
    let mut collected = Vec::new();
    let mut sink = |event: Event| collected.push(event);
    let summary = parser.finish(&mut sink).unwrap();
    assert_eq!(summary.parts, 1);
    assert_eq!(parser.push(b"x", &mut sink).unwrap_err(), Error::Finished);
}
