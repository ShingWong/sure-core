use sure_mime::{
    parse_parameters, sanitize_filename, ContentDisposition, DispositionKind, Error, MediaType,
    ParamError,
};

#[test]
fn parses_content_type_and_parameters() {
    let media = MediaType::parse(b"text/plain; charset=utf-8; format=flowed").unwrap();
    assert_eq!(media.type_, "text");
    assert_eq!(media.subtype, "plain");
    assert_eq!(media.param("charset").unwrap().value, "utf-8");
    assert_eq!(media.param("format").unwrap().value, "flowed");
    assert!(!media.is_multipart());
}

#[test]
fn parses_quoted_parameter_values() {
    let params = parse_parameters(br#"filename="a;b.txt"; title="say \"hi\"""#).unwrap();
    assert_eq!(params[0].name, "filename");
    assert_eq!(params[0].value, "a;b.txt");
    assert_eq!(params[1].value, "say \"hi\"");
}

#[test]
fn decodes_rfc2231_single_extended_parameter() {
    let media =
        MediaType::parse(b"application/octet-stream; filename*=utf-8''caf%C3%A9.txt").unwrap();
    let parameter = media.param("filename").unwrap();
    assert_eq!(parameter.value, "café.txt");
    assert_eq!(parameter.charset.as_deref(), Some("utf-8"));
}

#[test]
fn decodes_rfc2231_continuations() {
    let params =
        parse_parameters(b"filename*0*=utf-8''caf%C3%A9; filename*1*=.txt; filename*2*=_extra")
            .unwrap();
    assert_eq!(params.len(), 1);
    assert_eq!(params[0].value, "café.txt_extra");
}

#[test]
fn decodes_rfc2231_language_and_latin1() {
    let params = parse_parameters(b"filename*=iso-8859-1'en'caf%E9.txt").unwrap();
    assert_eq!(params[0].value, "café.txt");
    assert_eq!(params[0].charset.as_deref(), Some("iso-8859-1"));
    assert_eq!(params[0].language.as_deref(), Some("en"));
}

#[test]
fn decodes_non_extended_utf8_parameter() {
    let params = parse_parameters("filename=\"café.txt\"".as_bytes()).unwrap();
    assert_eq!(params[0].value, "café.txt");
}

#[test]
fn rejects_duplicate_parameter() {
    let error = parse_parameters(b"charset=utf-8; charset=us-ascii").unwrap_err();
    assert_eq!(error, Error::Param(ParamError::DuplicateParameter));
}

#[test]
fn rejects_non_contiguous_continuations() {
    let error = parse_parameters(b"filename*0*=utf-8''a; filename*2*=b").unwrap_err();
    assert_eq!(error, Error::Param(ParamError::NonContiguousSections));
}

#[test]
fn rejects_duplicate_section() {
    let error = parse_parameters(b"filename*0*=utf-8''a; filename*0*=b").unwrap_err();
    assert_eq!(error, Error::Param(ParamError::DuplicateSection));
}

#[test]
fn rejects_bad_percent_escape() {
    let error = parse_parameters(b"filename*=utf-8''bad%ZZ").unwrap_err();
    assert_eq!(error, Error::Param(ParamError::InvalidPercent));
}

#[test]
fn rejects_unsupported_charset() {
    let error = parse_parameters(b"filename*=x-unknown''abc").unwrap_err();
    assert_eq!(error, Error::Param(ParamError::UnsupportedCharset));
}

#[test]
fn rejects_unterminated_quote() {
    let error = parse_parameters(b"filename=\"abc").unwrap_err();
    assert_eq!(error, Error::Param(ParamError::UnterminatedQuotedString));
}

#[test]
fn rejects_missing_equals() {
    let error = parse_parameters(b"charset").unwrap_err();
    assert_eq!(error, Error::Param(ParamError::MissingEquals));
}

#[test]
fn parses_content_disposition() {
    let disposition = ContentDisposition::parse(b"attachment; filename=\"report.pdf\"").unwrap();
    assert_eq!(disposition.kind, DispositionKind::Attachment);
    assert_eq!(disposition.filename(), Some("report.pdf"));
}

#[test]
fn parses_inline_disposition() {
    let disposition = ContentDisposition::parse(b"inline").unwrap();
    assert_eq!(disposition.kind, DispositionKind::Inline);
    assert_eq!(disposition.filename(), None);
}

#[test]
fn sanitizes_filenames() {
    assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
    assert_eq!(sanitize_filename("..\\..\\windows\\evil.exe"), "evil.exe");
    assert_eq!(sanitize_filename(".."), "attachment");
    assert_eq!(sanitize_filename("a\u{0}b.txt"), "a_b.txt");
    assert_eq!(sanitize_filename("   "), "attachment");
    let long = "a".repeat(300);
    assert_eq!(sanitize_filename(&long).len(), 255);
}

#[test]
fn rejects_invalid_media_type() {
    assert!(MediaType::parse(b"not-a-media-type").is_err());
    assert!(MediaType::parse(b"text/").is_err());
    assert!(MediaType::parse(b"/plain").is_err());
}
