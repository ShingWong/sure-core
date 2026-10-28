use sure_mime::{
    canonicalize_body, canonicalize_header, canonicalize_headers, parse_header_block,
    Canonicalization, DkimBodyCanonicalizer, Error, Header, Limits,
};

fn header(name: &str, value: &str) -> Header {
    let raw = format!("{name}: {value}\r\n");
    parse_header_block(raw.as_bytes(), 0, &Limits::default())
        .unwrap()
        .headers
        .remove(0)
}

#[test]
fn simple_header_is_raw() {
    let header = header("Subject", "Hello\r\n World");
    assert_eq!(
        canonicalize_header(&header, Canonicalization::Simple),
        b"Subject: Hello\r\n World\r\n"
    );
}

#[test]
fn relaxed_header_lowercases_and_collapses() {
    let header = header("Subject", "  Hello   World  ");
    assert_eq!(
        canonicalize_header(&header, Canonicalization::Relaxed),
        b"subject:Hello World\r\n"
    );
}

#[test]
fn header_selection_uses_last_unused_occurrence() {
    let input = b"Received: one\r\nReceived: two\r\nSubject: hi\r\n";
    let block = parse_header_block(input, 0, &Limits::default()).unwrap();
    let out = canonicalize_headers(
        &block.headers,
        &["received", "received", "subject"],
        Canonicalization::Simple,
    )
    .unwrap();
    assert_eq!(
        out,
        b"Received: two\r\nReceived: one\r\nSubject: hi\r\n".to_vec()
    );
}

#[test]
fn missing_selected_header_is_an_error() {
    let block = parse_header_block(b"Subject: hi\r\n", 0, &Limits::default()).unwrap();
    let error =
        canonicalize_headers(&block.headers, &["from"], Canonicalization::Simple).unwrap_err();
    assert!(matches!(error, Error::Dkim(_)));
}

#[test]
fn simple_body_removes_trailing_empty_lines() {
    assert_eq!(
        canonicalize_body(
            b"a\r\n\r\n\r\n",
            Canonicalization::Simple,
            &Limits::default()
        )
        .unwrap(),
        b"a\r\n"
    );
    assert_eq!(
        canonicalize_body(b"", Canonicalization::Simple, &Limits::default()).unwrap(),
        b"\r\n"
    );
    assert_eq!(
        canonicalize_body(b"a\n", Canonicalization::Simple, &Limits::default()).unwrap(),
        b"a\r\n"
    );
}

#[test]
fn relaxed_body_collapses_and_strips() {
    assert_eq!(
        canonicalize_body(
            b" a  b \r\n\r\n",
            Canonicalization::Relaxed,
            &Limits::default()
        )
        .unwrap(),
        b" a b\r\n"
    );
    assert_eq!(
        canonicalize_body(b"", Canonicalization::Relaxed, &Limits::default()).unwrap(),
        b"\r\n"
    );
}

#[test]
fn body_canonicalizer_split_at_every_byte() {
    let input = b"line one  \r\n\r\nline\ttwo\r\n\r\n\r\n";
    for canon in [Canonicalization::Simple, Canonicalization::Relaxed] {
        let expected = canonicalize_body(input, canon, &Limits::default()).unwrap();
        for split in 0..=input.len() {
            let mut canonicalizer = DkimBodyCanonicalizer::new(canon, &Limits::default());
            canonicalizer.push(&input[..split]).unwrap();
            canonicalizer.push(&input[split..]).unwrap();
            assert_eq!(canonicalizer.finish().unwrap(), expected, "split {split}");
        }
    }
}

#[test]
fn body_canonicalizer_rejects_reuse() {
    let mut canonicalizer =
        DkimBodyCanonicalizer::new(Canonicalization::Simple, &Limits::default());
    canonicalizer.push(b"a").unwrap();
    canonicalizer.finish().unwrap();
    assert!(canonicalizer.push(b"b").is_err());
    assert!(canonicalizer.finish().is_err());
}
