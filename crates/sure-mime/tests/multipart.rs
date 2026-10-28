#![allow(clippy::field_reassign_with_default)]

mod common;

use common::{events, parse_chunked};
use sure_mime::{
    parse_address_list, parse_message, Address, Error, Event, LimitKind, Limits, MultipartError,
};

const SIMPLE: &[u8] = b"From: a@example.com\r\n\
To: b@example.com\r\n\
Subject: test\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
\r\n\
preamble text\r\n\
--BOUND\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
Hello=20world\r\n\
--BOUND\r\n\
Content-Type: application/octet-stream; name=\"file.bin\"\r\n\
Content-Disposition: attachment; filename=\"file.bin\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
AAECAwQ=\r\n\
--BOUND--\r\n\
epilogue text\r\n";

#[test]
fn parses_multipart_with_preamble_and_epilogue() {
    let parsed = parse_message(SIMPLE, &Limits::default()).unwrap();
    assert_eq!(parsed.summary.parts, 3);
    assert_eq!(parsed.summary.attachments, 1);
    assert_eq!(parsed.body, b"Hello world");
    assert_eq!(parsed.attachments.len(), 1);
    let attachment = &parsed.attachments[0];
    assert_eq!(attachment.meta.filename.as_deref(), Some("file.bin"));
    assert_eq!(attachment.decoded_bytes, 5);
    assert!(attachment.meta.is_attachment);
    assert!(attachment.meta.disposition.is_some());
    assert_eq!(attachment.meta.path.as_slice(), &[1]);
}

#[test]
fn emits_preamble_and_epilogue() {
    let collected = events(SIMPLE, &[], &Limits::default()).unwrap();
    let preamble: Vec<u8> = collected
        .iter()
        .filter_map(|event| match event {
            Event::Preamble { data, .. } => Some(data.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    let epilogue: Vec<u8> = collected
        .iter()
        .filter_map(|event| match event {
            Event::Epilogue { data, .. } => Some(data.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(preamble, b"preamble text");
    assert_eq!(epilogue, b"epilogue text\r\n");
}

#[test]
fn attachment_bytes_are_not_in_the_body() {
    let parsed = parse_message(SIMPLE, &Limits::default()).unwrap();
    assert!(!parsed.body.contains(&0));
    assert_eq!(parsed.body.len(), "Hello world".len());
}

#[test]
fn split_at_every_byte_matches_single_push() {
    let whole = parse_message(SIMPLE, &Limits::default()).unwrap();
    for chunk_size in 1..=SIMPLE.len() {
        let chunked = parse_chunked(SIMPLE, chunk_size, &Limits::default()).unwrap();
        assert_eq!(chunked.parts, whole.parts, "chunk size {chunk_size}");
        assert_eq!(chunked.body, whole.body, "chunk size {chunk_size}");
        assert_eq!(
            chunked.attachments, whole.attachments,
            "chunk size {chunk_size}"
        );
    }
}

#[test]
fn accepts_lf_and_bare_cr_line_endings() {
    let lf = SIMPLE
        .iter()
        .copied()
        .filter(|byte| *byte != b'\r')
        .collect::<Vec<_>>();
    let cr = SIMPLE
        .iter()
        .copied()
        .filter(|byte| *byte != b'\n')
        .collect::<Vec<_>>();
    for input in [lf.as_slice(), cr.as_slice()] {
        let parsed = parse_message(input, &Limits::default()).unwrap();
        assert_eq!(parsed.body, b"Hello world");
        assert_eq!(parsed.summary.parts, 3);
    }
}

#[test]
fn boundary_like_body_text_is_not_a_delimiter() {
    let input = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n\
--B\r\n\
Content-Type: text/plain\r\n\
\r\n\
line1\r\n\
--Bxyz\r\n\
line2 --B\r\n\
--B--\r\n";
    let parsed = parse_message(input, &Limits::default()).unwrap();
    assert_eq!(parsed.body, b"line1\r\n--Bxyz\r\nline2 --B");
}

#[test]
fn accepts_trailing_whitespace_on_delimiters() {
    let input = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n\
--B \r\n\
Content-Type: text/plain\r\n\
\r\n\
body\r\n\
--B-- \r\n";
    let parsed = parse_message(input, &Limits::default()).unwrap();
    assert_eq!(parsed.body, b"body");
}

#[test]
fn parses_nested_multipart() {
    let input = b"Content-Type: multipart/mixed; boundary=outer\r\n\r\n\
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
    let parsed = parse_message(input, &Limits::default()).unwrap();
    assert_eq!(parsed.summary.parts, 4);
    assert_eq!(parsed.summary.max_depth, 2);
    assert_eq!(parsed.body, b"plain<p>html</p>");
    assert_eq!(parsed.parts[2].path.as_slice(), &[0, 0]);
    assert_eq!(parsed.parts[3].path.as_slice(), &[0, 1]);
}

#[test]
fn parses_part_without_headers() {
    let input = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n\
--B\r\n\
\r\n\
just a body\r\n\
--B--\r\n";
    let parsed = parse_message(input, &Limits::default()).unwrap();
    assert_eq!(parsed.body, b"just a body");
    assert_eq!(parsed.summary.parts, 2);
    assert!(parsed.parts[1].content_type.is_none());
}

#[test]
fn inline_with_filename_is_an_attachment() {
    let input = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n\
--B\r\n\
Content-Type: image/png\r\n\
Content-Disposition: inline; filename=\"x.png\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
AAEC\r\n\
--B--\r\n";
    let parsed = parse_message(input, &Limits::default()).unwrap();
    assert_eq!(parsed.attachments.len(), 1);
    assert_eq!(
        parsed.attachments[0].meta.filename.as_deref(),
        Some("x.png")
    );
    assert_eq!(parsed.attachments[0].decoded_bytes, 3);
}

#[test]
fn message_rfc822_is_not_recursed() {
    let input = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n\
--B\r\n\
Content-Type: message/rfc822\r\n\
\r\n\
Subject: inner\r\n\
\r\n\
inner body\r\n\
--B--\r\n";
    let parsed = parse_message(input, &Limits::default()).unwrap();
    assert_eq!(parsed.summary.parts, 2);
    assert_eq!(parsed.body, b"Subject: inner\r\n\r\ninner body");
}

#[test]
fn multipart_container_is_not_treated_as_an_attachment() {
    let input = b"Content-Type: multipart/mixed; boundary=B\r\n\
Content-Disposition: attachment; filename=container\r\n\
\r\n\
--B\r\n\
Content-Type: text/plain\r\n\
\r\n\
body\r\n\
--B--\r\n";
    let parsed = parse_message(input, &Limits::default()).unwrap();
    assert_eq!(parsed.summary.parts, 2);
    assert_eq!(parsed.summary.attachments, 0);
    assert_eq!(parsed.body, b"body");
}

#[test]
fn missing_boundary_is_an_error() {
    let input = b"Content-Type: multipart/mixed\r\n\r\nbody";
    let error = parse_message(input, &Limits::default()).unwrap_err();
    assert_eq!(error, Error::Multipart(MultipartError::MissingBoundary));
}

#[test]
fn unterminated_multipart_is_an_error() {
    let input = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n\r\nbody";
    let error = parse_message(input, &Limits::default()).unwrap_err();
    assert_eq!(error, Error::Multipart(MultipartError::Unterminated));
}

#[test]
fn boundary_after_close_is_an_error() {
    let input = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n\
--B\r\n\r\nbody\r\n\
--B--\r\n\
--B\r\n\r\nagain\r\n\
--B--\r\n";
    let error = parse_message(input, &Limits::default()).unwrap_err();
    assert_eq!(error, Error::Multipart(MultipartError::BoundaryAfterClose));
}

#[test]
fn transfer_encoding_on_multipart_is_an_error() {
    let input = b"Content-Type: multipart/mixed; boundary=B\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n--B--\r\n";
    let error = parse_message(input, &Limits::default()).unwrap_err();
    assert_eq!(error, Error::Multipart(MultipartError::TransferEncoding));
}

#[test]
fn enforces_part_count() {
    let mut limits = Limits::default();
    limits.max_parts = 2;
    let error = parse_message(SIMPLE, &limits).unwrap_err();
    assert!(matches!(
        error,
        Error::LimitExceeded {
            limit: LimitKind::PartCount,
            ..
        }
    ));
}

#[test]
fn enforces_depth() {
    let input = b"Content-Type: multipart/mixed; boundary=a\r\n\r\n\
--a\r\n\
Content-Type: multipart/mixed; boundary=b\r\n\
\r\n\
--b\r\n\
Content-Type: multipart/mixed; boundary=c\r\n\
\r\n\
--c--\r\n\
--b--\r\n\
--a--\r\n";
    let mut limits = Limits::default();
    limits.max_mime_depth = 1;
    let error = parse_message(input, &limits).unwrap_err();
    assert!(matches!(
        error,
        Error::LimitExceeded {
            limit: LimitKind::MimeDepth,
            ..
        }
    ));
}

#[test]
fn boundary_length_is_bounded() {
    let boundary = "a".repeat(71);
    let input =
        format!("Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n--{boundary}--\r\n");
    let error = parse_message(input.as_bytes(), &Limits::default()).unwrap_err();
    assert_eq!(error, Error::Multipart(MultipartError::InvalidBoundary));
}

#[test]
fn headers_are_attached_to_the_right_parts() {
    let parsed = parse_message(SIMPLE, &Limits::default()).unwrap();
    assert_eq!(
        parsed.headers.first_value("subject"),
        Some(b"test".as_slice())
    );
    assert_eq!(parsed.parts[0].path.as_slice(), &[] as &[u16]);
    assert_eq!(parsed.parts[1].path.as_slice(), &[0]);
    assert_eq!(parsed.parts[2].path.as_slice(), &[1]);
    assert_eq!(parsed.parts[2].header_count, 3);
}

#[test]
fn addresses_in_headers_parse() {
    let parsed = parse_message(SIMPLE, &Limits::default()).unwrap();
    let from = parsed.headers.first_value("from").unwrap();
    let list = parse_address_list(from).unwrap();
    match &list.addresses[0] {
        Address::Mailbox(mailbox) => assert_eq!(mailbox.address(), "a@example.com"),
        Address::Group { .. } => panic!("expected mailbox"),
    }
}
