#![allow(clippy::field_reassign_with_default)]

use sure_mime::{parse_message, Error, Limits, MessageParser};

#[test]
fn truncated_headers_are_a_valid_empty_body() {
    let parsed = parse_message(b"Subject: only headers\r\n", &Limits::default()).unwrap();
    assert_eq!(parsed.headers.len(), 1);
    assert!(parsed.body.is_empty());
    assert_eq!(parsed.summary.parts, 1);
}

#[test]
fn empty_input_is_a_valid_empty_message() {
    let parsed = parse_message(b"", &Limits::default()).unwrap();
    assert!(parsed.headers.is_empty());
    assert!(parsed.body.is_empty());
    assert_eq!(parsed.summary.parts, 1);
}

#[test]
fn truncated_multipart_is_rejected() {
    let error = parse_message(
        b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n\r\nbody",
        &Limits::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::Multipart(_)));
}

#[test]
fn header_bomb_is_bounded() {
    let mut input = Vec::new();
    for index in 0..2_000 {
        input.extend_from_slice(format!("X-{index}: value\r\n").as_bytes());
    }
    input.extend_from_slice(b"\r\nbody");
    let error = parse_message(&input, &Limits::default()).unwrap_err();
    assert!(matches!(
        error,
        Error::LimitExceeded {
            limit: sure_mime::LimitKind::HeaderCount,
            ..
        }
    ));
}

#[test]
fn body_bomb_is_bounded() {
    let mut limits = Limits::default();
    limits.max_body_bytes = 64;
    limits.max_decoded_bytes = 64;
    limits.max_attachment_bytes = 64;
    let mut input = b"\r\n".to_vec();
    input.extend(core::iter::repeat(b'a').take(1_000));
    let error = parse_message(&input, &limits).unwrap_err();
    assert!(matches!(
        error,
        Error::LimitExceeded {
            limit: sure_mime::LimitKind::BodyBytes,
            ..
        }
    ));
}

#[test]
fn base64_bomb_is_bounded() {
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 64;
    limits.max_body_bytes = 64;
    limits.max_attachment_bytes = 64;
    let mut input = b"Content-Transfer-Encoding: base64\r\n\r\n".to_vec();
    input.extend_from_slice(&vec![b'A'; 10_000]);
    let error = parse_message(&input, &limits).unwrap_err();
    assert!(matches!(
        error,
        Error::LimitExceeded {
            limit: sure_mime::LimitKind::DecodedBytes | sure_mime::LimitKind::BodyBytes,
            ..
        }
    ));
}

#[test]
fn quoted_printable_bomb_is_bounded() {
    let mut limits = Limits::default();
    limits.max_body_bytes = 8;
    limits.max_decoded_bytes = 8;
    limits.max_attachment_bytes = 8;
    let input = b"\r\n=41=41=41=41=41=41=41=41=41=41";
    let error = parse_message(input, &limits).unwrap_err();
    assert!(matches!(
        error,
        Error::LimitExceeded {
            limit: sure_mime::LimitKind::BodyBytes,
            ..
        }
    ));
}

#[test]
fn deeply_nested_multipart_is_rejected() {
    let mut input = Vec::new();
    let depth = 40;
    input.extend_from_slice(b"Content-Type: multipart/mixed; boundary=b0\r\n\r\n");
    for level in 1..depth {
        input.extend_from_slice(format!("--b{}\r\n", level - 1).as_bytes());
        input.extend_from_slice(
            format!("Content-Type: multipart/mixed; boundary=b{level}\r\n\r\n").as_bytes(),
        );
    }
    for level in (0..depth).rev() {
        input.extend_from_slice(format!("--b{level}--\r\n").as_bytes());
    }
    let error = parse_message(&input, &Limits::default()).unwrap_err();
    assert!(matches!(
        error,
        Error::LimitExceeded {
            limit: sure_mime::LimitKind::MimeDepth,
            ..
        }
    ));
}

#[test]
fn malformed_part_content_type_is_rejected() {
    let input = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n\
--B\r\n\
Content-Type: not-a-media-type\r\n\
\r\nbody\r\n\
--B--\r\n";
    assert!(parse_message(input, &Limits::default()).is_err());
}

#[test]
fn malformed_part_disposition_is_rejected() {
    let input = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n\
--B\r\n\
Content-Disposition: attachment; filename=\"unterminated\r\n\
\r\nbody\r\n\
--B--\r\n";
    assert!(parse_message(input, &Limits::default()).is_err());
}

#[test]
fn nul_in_header_is_rejected() {
    let error = parse_message(b"Subject: a\0b\r\n\r\nbody", &Limits::default()).unwrap_err();
    assert!(matches!(error, Error::Header(_)));
}

#[test]
fn boundary_in_body_is_only_a_delimiter_at_line_start() {
    let input = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n\
--B\r\n\
Content-Type: text/plain\r\n\
\r\n\
x--B y\r\n\
--B--\r\n";
    let parsed = parse_message(input, &Limits::default()).unwrap();
    assert_eq!(parsed.body, b"x--B y");
}

#[test]
fn unknown_transfer_encoding_is_rejected() {
    let input = b"Content-Transfer-Encoding: x-uuencode\r\n\r\nbody";
    assert_eq!(
        parse_message(input, &Limits::default()).unwrap_err(),
        Error::UnsupportedTransferEncoding
    );
}

#[test]
fn arbitrary_small_inputs_never_panic() {
    // Deterministic pseudo-random corpus; property tests cover wider input.
    let mut state = 0x1234_5678_9abc_def0u64;
    for length in 0..512usize {
        let mut input = Vec::with_capacity(length);
        for _ in 0..length {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            input.push((state & 0xff) as u8);
        }
        let _ = parse_message(&input, &Limits::hardened());
    }
}

#[test]
fn parser_cannot_be_reused_after_error() {
    let mut parser = MessageParser::new(Limits::default()).unwrap();
    let mut sink = |_event| {};
    let error = parser
        .push(b"Content-Type: multipart/mixed\r\n\r\nx", &mut sink)
        .unwrap_err();
    assert!(matches!(error, Error::Multipart(_)));
    assert_eq!(
        parser.push(b"more", &mut sink).unwrap_err(),
        Error::AlreadyFailed
    );
}

#[test]
fn parser_cannot_finish_twice() {
    let mut parser = MessageParser::new(Limits::default()).unwrap();
    let mut sink = |_event| {};
    parser.push(b"Subject: a\r\n\r\nbody", &mut sink).unwrap();
    parser.finish(&mut sink).unwrap();
    assert_eq!(parser.finish(&mut sink).unwrap_err(), Error::Finished);
}
