use sure_mime::{parse_header_block, Error, HeaderError, LimitKind, Limits};

fn limits() -> Limits {
    Limits::default()
}

#[test]
fn parses_simple_headers_in_order() {
    let input = b"From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n";
    let block = parse_header_block(input, 0, &limits()).unwrap();
    assert_eq!(block.len(), 3);
    assert_eq!(block.headers[0].name(), "From");
    assert_eq!(block.headers[0].value_trimmed(), b"a@example.com");
    assert_eq!(block.headers[1].name(), "To");
    assert_eq!(block.headers[2].name(), "Subject");
    assert_eq!(block.first_value("subject"), Some(b"hi".as_slice()));
}

#[test]
fn unfolds_folded_headers_and_preserves_raw_form() {
    let input = b"Subject: Hello\r\n World\r\nX-Test: 1\r\n";
    let block = parse_header_block(input, 0, &limits()).unwrap();
    assert_eq!(block.headers[0].value_trimmed(), b"Hello World");
    assert_eq!(block.headers[0].raw, b"Subject: Hello\r\n World\r\n");
    assert_eq!(block.headers[1].raw, b"X-Test: 1\r\n");
}

#[test]
fn preserves_duplicates_in_wire_order() {
    let input = b"Received: one\r\nReceived: two\r\nReceived: three\r\n";
    let block = parse_header_block(input, 0, &limits()).unwrap();
    let values: Vec<_> = block
        .get_all("received")
        .map(|header| header.value_trimmed().to_vec())
        .collect();
    assert_eq!(
        values,
        vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
    );
    assert_eq!(
        block.get_last("received").unwrap().value_trimmed(),
        b"three"
    );
}

#[test]
fn accepts_lf_and_bare_cr_and_normalises_raw_to_crlf() {
    for input in [
        b"Subject: hi\nX: 1\n".as_slice(),
        b"Subject: hi\rX: 1\r".as_slice(),
    ] {
        let block = parse_header_block(input, 0, &limits()).unwrap();
        assert_eq!(block.len(), 2);
        assert_eq!(block.headers[0].raw, b"Subject: hi\r\n");
        assert_eq!(block.headers[1].raw, b"X: 1\r\n");
    }
}

#[test]
fn records_offsets() {
    let input = b"A: 1\r\nB: 2\r\n";
    let block = parse_header_block(input, 100, &limits()).unwrap();
    assert_eq!(block.headers[0].offset, 100);
    assert_eq!(block.headers[1].offset, 100 + 6);
}

#[test]
fn rejects_missing_colon() {
    let error = parse_header_block(b"Subject hi\r\n", 0, &limits()).unwrap_err();
    assert_eq!(error, Error::Header(HeaderError::MissingColon));
}

#[test]
fn rejects_continuation_without_field() {
    let error = parse_header_block(b" folded\r\n", 0, &limits()).unwrap_err();
    assert_eq!(error, Error::Header(HeaderError::ContinuationWithoutField));
}

#[test]
fn rejects_empty_and_invalid_names() {
    assert_eq!(
        parse_header_block(b": value\r\n", 0, &limits()).unwrap_err(),
        Error::Header(HeaderError::EmptyName)
    );
    assert!(matches!(
        parse_header_block(b"Bad Name: value\r\n", 0, &limits()).unwrap_err(),
        Error::Header(HeaderError::InvalidNameByte(_))
    ));
    assert!(matches!(
        parse_header_block(b"Bad\xff: value\r\n", 0, &limits()).unwrap_err(),
        Error::Header(HeaderError::InvalidNameByte(_))
    ));
}

#[test]
fn rejects_nul_bytes() {
    assert_eq!(
        parse_header_block(b"X: a\0b\r\n", 0, &limits()).unwrap_err(),
        Error::Header(HeaderError::NulByte)
    );
}

#[test]
fn enforces_header_count() {
    let mut limits = limits();
    limits.max_header_count = 2;
    let error = parse_header_block(b"A: 1\r\nB: 2\r\nC: 3\r\n", 0, &limits).unwrap_err();
    assert!(matches!(
        error,
        Error::LimitExceeded {
            limit: LimitKind::HeaderCount,
            ..
        }
    ));
}

#[test]
fn enforces_line_length() {
    let mut limits = limits();
    limits.max_header_line_len = 8;
    let error = parse_header_block(b"Subject: longer\r\n", 0, &limits).unwrap_err();
    assert!(matches!(
        error,
        Error::LimitExceeded {
            limit: LimitKind::HeaderLineLength,
            ..
        }
    ));
}

#[test]
fn enforces_header_bytes() {
    let mut limits = limits();
    limits.max_header_bytes = 16;
    limits.max_header_line_len = 16;
    let error = parse_header_block(b"Subject: 0123456789\r\n", 0, &limits).unwrap_err();
    assert!(matches!(
        error,
        Error::LimitExceeded {
            limit: LimitKind::HeaderBytes,
            ..
        }
    ));
}
