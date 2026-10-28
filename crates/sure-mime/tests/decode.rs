use sure_mime::{
    decode::decode_all, encoded_word::decode_encoded_words, parse_parameters, Decoder, Error,
    LimitKind, Limits, TransferEncoding,
};

fn decode(encoding: TransferEncoding, input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decode_all(encoding, input, &mut out)?;
    Ok(out)
}

#[test]
fn parses_transfer_encoding_names() {
    assert_eq!(
        TransferEncoding::parse(b"7bit").unwrap(),
        TransferEncoding::SevenBit
    );
    assert_eq!(
        TransferEncoding::parse(b"8BIT").unwrap(),
        TransferEncoding::EightBit
    );
    assert_eq!(
        TransferEncoding::parse(b"binary").unwrap(),
        TransferEncoding::Binary
    );
    assert_eq!(
        TransferEncoding::parse(b"base64").unwrap(),
        TransferEncoding::Base64
    );
    assert_eq!(
        TransferEncoding::parse(b"quoted-printable").unwrap(),
        TransferEncoding::QuotedPrintable
    );
    assert_eq!(
        TransferEncoding::parse(b"identity").unwrap(),
        TransferEncoding::Identity
    );
    assert!(TransferEncoding::parse(b"x-uuencode").is_err());
}

#[test]
fn decodes_base64_vectors() {
    assert_eq!(decode(TransferEncoding::Base64, b"").unwrap(), b"");
    assert_eq!(decode(TransferEncoding::Base64, b"TQ==").unwrap(), b"M");
    assert_eq!(decode(TransferEncoding::Base64, b"TWE=").unwrap(), b"Ma");
    assert_eq!(decode(TransferEncoding::Base64, b"TWFu").unwrap(), b"Man");
    assert_eq!(decode(TransferEncoding::Base64, b"TQ").unwrap(), b"M");
    assert_eq!(decode(TransferEncoding::Base64, b"TWE").unwrap(), b"Ma");
    assert_eq!(
        decode(TransferEncoding::Base64, b"T W\r\nF u\t").unwrap(),
        b"Man"
    );
}

#[test]
fn base64_split_at_every_byte() {
    let input = b"VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==";
    let expected = b"The quick brown fox jumps over the lazy dog";
    for split in 0..=input.len() {
        let mut decoder = Decoder::new(TransferEncoding::Base64);
        let mut out = Vec::new();
        decoder.push(&input[..split], &mut out).unwrap();
        decoder.push(&input[split..], &mut out).unwrap();
        decoder.finish(&mut out).unwrap();
        assert_eq!(out, expected, "split at {split}");
    }
}

#[test]
fn base64_carries_partial_quads() {
    let mut decoder = Decoder::new(TransferEncoding::Base64);
    let mut out = Vec::new();
    for chunk in [b"T".as_slice(), b"W", b"F", b"u"] {
        decoder.push(chunk, &mut out).unwrap();
    }
    decoder.finish(&mut out).unwrap();
    assert_eq!(out, b"Man");
}

#[test]
fn rejects_invalid_base64() {
    assert!(matches!(
        decode(TransferEncoding::Base64, b"TQ$=").unwrap_err(),
        Error::Decode(_)
    ));
    assert!(matches!(
        decode(TransferEncoding::Base64, b"T===").unwrap_err(),
        Error::Decode(_)
    ));
    assert!(matches!(
        decode(TransferEncoding::Base64, b"TQ==TQ==").unwrap_err(),
        Error::Decode(_)
    ));
    assert!(matches!(
        decode(TransferEncoding::Base64, b"T").unwrap_err(),
        Error::Decode(_)
    ));
}

#[test]
fn decodes_quoted_printable() {
    assert_eq!(
        decode(TransferEncoding::QuotedPrintable, b"a=3Db").unwrap(),
        b"a=b"
    );
    assert_eq!(
        decode(TransferEncoding::QuotedPrintable, b"line=\r\nbreak").unwrap(),
        b"linebreak"
    );
    assert_eq!(
        decode(TransferEncoding::QuotedPrintable, b"caf=C3=A9").unwrap(),
        "café".as_bytes()
    );
}

#[test]
fn quoted_printable_split_at_every_byte() {
    let input = b"a=3Db=\r\ncaf=C3=A9";
    let expected = b"a=bcaf\xc3\xa9";
    for split in 0..=input.len() {
        let mut decoder = Decoder::new(TransferEncoding::QuotedPrintable);
        let mut out = Vec::new();
        decoder.push(&input[..split], &mut out).unwrap();
        decoder.push(&input[split..], &mut out).unwrap();
        decoder.finish(&mut out).unwrap();
        assert_eq!(out, expected, "split at {split}");
    }
}

#[test]
fn rejects_invalid_quoted_printable() {
    assert!(matches!(
        decode(TransferEncoding::QuotedPrintable, b"a=ZZ").unwrap_err(),
        Error::Decode(_)
    ));
    assert!(matches!(
        decode(TransferEncoding::QuotedPrintable, b"a=").unwrap_err(),
        Error::Decode(_)
    ));
    assert!(matches!(
        decode(TransferEncoding::QuotedPrintable, b"a=\rX").unwrap_err(),
        Error::Decode(_)
    ));
}

#[test]
fn identity_passes_bytes_through() {
    let bytes = b"8-bit \xff\x00 bytes";
    assert_eq!(decode(TransferEncoding::Identity, bytes).unwrap(), bytes);
}

#[test]
fn decodes_encoded_words_b_and_q() {
    assert_eq!(decode_encoded_words(b"=?utf-8?B?Y2Fmw6k=?=", 1024), "café");
    assert_eq!(decode_encoded_words(b"=?utf-8?Q?caf=C3=A9?=", 1024), "café");
    assert_eq!(
        decode_encoded_words(b"=?iso-8859-1?Q?caf=E9?=", 1024),
        "café"
    );
}

#[test]
fn removes_whitespace_between_adjacent_encoded_words() {
    assert_eq!(
        decode_encoded_words(b"=?utf-8?B?SGVsbG8=?= =?utf-8?B?V29ybGQ=?=", 1024),
        "HelloWorld"
    );
}

#[test]
fn preserves_malformed_encoded_words() {
    let input = b"=??Q?abc?=";
    assert_eq!(
        decode_encoded_words(input, 1024),
        String::from_utf8_lossy(input)
    );
    let input = b"=?utf-8?B?###?=";
    assert_eq!(
        decode_encoded_words(input, 1024),
        String::from_utf8_lossy(input)
    );
    let input = b"=?x-unknown?Q?abc?=";
    assert_eq!(
        decode_encoded_words(input, 1024),
        String::from_utf8_lossy(input)
    );
}

#[test]
fn bounds_encoded_word_output() {
    let decoded = decode_encoded_words(b"=?utf-8?B?SGVsbG8gV29ybGQ=?=", 5);
    assert_eq!(decoded, "Hello");
}

#[test]
fn limits_are_checked_by_the_caller_not_the_decoder() {
    // The decoder itself is allocation-free with respect to declared lengths;
    // parser limits are exercised in the limits integration test.
    let limits = Limits::hardened();
    assert!(limits.validate().is_ok());
    let _ = parse_parameters(b"charset=utf-8").unwrap();
    let _ = LimitKind::AttachmentBytes.exceeded(1, 2);
}
