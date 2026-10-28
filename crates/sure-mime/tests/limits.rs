#![allow(clippy::field_reassign_with_default)]

use sure_mime::{parse_message, Error, Event, LimitKind, Limits, MessageParser};

fn assert_limit(error: Error, expected: LimitKind) {
    match error {
        Error::LimitExceeded { limit, .. } => assert_eq!(limit, expected),
        other => panic!("expected limit error, got {other:?}"),
    }
}

#[test]
fn rejects_invalid_limits() {
    let mut limits = Limits::default();
    limits.max_header_bytes = 0;
    assert!(matches!(limits.validate(), Err(Error::InvalidLimits(_))));

    let mut limits = Limits::default();
    limits.max_mime_depth = 0;
    assert!(matches!(limits.validate(), Err(Error::InvalidLimits(_))));

    let mut limits = Limits::default();
    limits.max_body_bytes = limits.max_decoded_bytes + 1;
    assert!(matches!(limits.validate(), Err(Error::InvalidLimits(_))));

    let mut limits = Limits::default();
    limits.max_boundary_len = 71;
    assert!(matches!(limits.validate(), Err(Error::InvalidLimits(_))));

    assert!(MessageParser::new(limits).is_err());
}

#[test]
fn enforces_message_bytes() {
    let mut limits = Limits::default();
    limits.max_message_bytes = 10;
    let error = parse_message(b"Subject: a\r\n\r\nbody", &limits).unwrap_err();
    assert_limit(error, LimitKind::MessageBytes);
}

#[test]
fn accepts_exactly_the_message_byte_limit() {
    let input = b"Subject: a\r\n\r\nbody";
    let mut limits = Limits::default();
    limits.max_message_bytes = input.len();
    assert!(parse_message(input, &limits).is_ok());
}

#[test]
fn enforces_header_bytes() {
    let mut limits = Limits::default();
    limits.max_header_bytes = 24;
    limits.max_header_line_len = 24;
    let error = parse_message(b"A: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\n\r\nbody", &limits).unwrap_err();
    assert_limit(error, LimitKind::HeaderBytes);
}

#[test]
fn enforces_header_count() {
    let mut limits = Limits::default();
    limits.max_header_count = 1;
    let error = parse_message(b"A: 1\r\nB: 2\r\n\r\nbody", &limits).unwrap_err();
    assert_limit(error, LimitKind::HeaderCount);
}

#[test]
fn enforces_header_line_length() {
    let mut limits = Limits::default();
    limits.max_header_line_len = 8;
    let error = parse_message(b"Subject: long\r\n\r\nbody", &limits).unwrap_err();
    assert_limit(error, LimitKind::HeaderLineLength);
}

#[test]
fn enforces_decoded_bytes() {
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 5;
    limits.max_body_bytes = 5;
    limits.max_attachment_bytes = 5;
    // Two 4-byte attachments: each is under the per-attachment bound, but the
    // total decoded bytes exceed the global bound.
    let input = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n\
--B\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=a.bin\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
AAECAw==\r\n\
--B\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=b.bin\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
AAECAw==\r\n\
--B--\r\n";
    let error = parse_message(input, &limits).unwrap_err();
    assert_limit(error, LimitKind::DecodedBytes);
}

#[test]
fn enforces_body_bytes() {
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 16;
    limits.max_body_bytes = 3;
    limits.max_attachment_bytes = 16;
    let error = parse_message(b"\r\nhello", &limits).unwrap_err();
    assert_limit(error, LimitKind::BodyBytes);
}

#[test]
fn enforces_attachment_bytes() {
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 16;
    limits.max_body_bytes = 16;
    limits.max_attachment_bytes = 3;
    let input = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n\
--B\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=x.bin\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
AAECAwQ=\r\n\
--B--\r\n";
    let error = parse_message(input, &limits).unwrap_err();
    assert_limit(error, LimitKind::AttachmentBytes);
}

#[test]
fn enforces_part_count() {
    let mut limits = Limits::default();
    limits.max_parts = 1;
    let input = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n\r\nx\r\n--B--\r\n";
    let error = parse_message(input, &limits).unwrap_err();
    assert_limit(error, LimitKind::PartCount);
}

#[test]
fn enforces_depth() {
    let mut limits = Limits::default();
    limits.max_mime_depth = 1;
    let input = b"Content-Type: multipart/mixed; boundary=a\r\n\r\n\
--a\r\n\
Content-Type: multipart/mixed; boundary=b\r\n\r\n\
--b\r\n\
Content-Type: text/plain\r\n\r\n\
x\r\n\
--b--\r\n\
--a--\r\n";
    let error = parse_message(input, &limits).unwrap_err();
    assert_limit(error, LimitKind::MimeDepth);
}

#[test]
fn chunk_size_bounds_every_emitted_chunk() {
    let mut limits = Limits::default();
    limits.max_chunk_bytes = 4;
    let input = b"\r\n0123456789";
    let mut parser = MessageParser::new(limits).unwrap();
    let mut chunks = Vec::new();
    let mut sink = |event: Event| {
        if let Event::BodyChunk { data, .. } = event {
            chunks.push(data);
        }
    };
    parser.push(input, &mut sink).unwrap();
    parser.finish(&mut sink).unwrap();
    assert_eq!(chunks.concat(), b"0123456789");
    assert!(chunks.iter().all(|chunk| chunk.len() <= 4));
}

#[test]
fn boundary_length_uses_a_typed_multipart_error() {
    let boundary = "b".repeat(71);
    let input =
        format!("Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n--{boundary}--\r\n");
    let error = parse_message(input.as_bytes(), &Limits::default()).unwrap_err();
    assert!(matches!(error, Error::Multipart(_)));
}
