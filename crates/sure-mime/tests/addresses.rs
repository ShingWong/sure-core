use sure_mime::{parse_address_list, Address, AddressError, Error, Mailbox};

fn mailbox(address: &str) -> Mailbox {
    let list = parse_address_list(address.as_bytes()).unwrap();
    match &list.addresses[0] {
        Address::Mailbox(mailbox) => mailbox.clone(),
        Address::Group { .. } => panic!("expected mailbox"),
    }
}

#[test]
fn parses_bare_addr_spec() {
    let parsed = mailbox("user@example.com");
    assert_eq!(parsed.local, "user");
    assert_eq!(parsed.domain, "example.com");
    assert_eq!(parsed.display_name, None);
    assert_eq!(parsed.address(), "user@example.com");
}

#[test]
fn parses_display_name() {
    let parsed = mailbox("John Doe <john@example.com>");
    assert_eq!(parsed.display_name.as_deref(), Some("John Doe"));
    assert_eq!(parsed.address(), "john@example.com");
}

#[test]
fn parses_quoted_display_name_with_comma() {
    let parsed = mailbox("\"Doe, Jane\" <jane@example.com>");
    assert_eq!(parsed.display_name.as_deref(), Some("Doe, Jane"));
}

#[test]
fn parses_quoted_local_part() {
    let parsed = mailbox("\"a b\"@example.com");
    assert_eq!(parsed.local, "a b");
    assert_eq!(parsed.domain, "example.com");
    assert_eq!(parsed.address(), "\"a b\"@example.com");
}

#[test]
fn parses_domain_literal() {
    let parsed = mailbox("user@[192.0.2.1]");
    assert_eq!(parsed.domain, "[192.0.2.1]");
}

#[test]
fn strips_comments() {
    let parsed = mailbox("user@example.com (work)");
    assert_eq!(parsed.address(), "user@example.com");
    let parsed = mailbox("John (middle) Doe <john@example.com>");
    assert_eq!(parsed.display_name.as_deref(), Some("John Doe"));
}

#[test]
fn parses_address_list_and_groups() {
    let list =
        parse_address_list(b"a@example.com, Friends: b@example.com, c@example.com;, d@example.com")
            .unwrap();
    assert_eq!(list.addresses.len(), 3);
    assert!(matches!(list.addresses[0], Address::Mailbox(_)));
    match &list.addresses[1] {
        Address::Group {
            display_name,
            mailboxes,
        } => {
            assert_eq!(display_name, "Friends");
            assert_eq!(mailboxes.len(), 2);
        }
        Address::Mailbox(_) => panic!("expected group"),
    }
    assert_eq!(list.mailboxes().count(), 4);
}

#[test]
fn decodes_encoded_word_display_name() {
    let parsed = mailbox("=?utf-8?B?Sm9obiBEb2U=?= <john@example.com>");
    assert_eq!(parsed.display_name.as_deref(), Some("John Doe"));
}

#[test]
fn rejects_missing_at() {
    let error = parse_address_list(b"not-an-address").unwrap_err();
    assert_eq!(error, Error::Address(AddressError::MissingAt));
}

#[test]
fn rejects_empty_element() {
    let error = parse_address_list(b"<>").unwrap_err();
    assert_eq!(error, Error::Address(AddressError::Empty));
}

#[test]
fn rejects_unterminated_angle() {
    let error = parse_address_list(b"John <john@example.com").unwrap_err();
    assert_eq!(error, Error::Address(AddressError::UnterminatedAngle));
}

#[test]
fn rejects_unterminated_quote() {
    let error = parse_address_list(b"\"John <john@example.com>").unwrap_err();
    assert_eq!(
        error,
        Error::Address(AddressError::UnterminatedQuotedString)
    );
}

#[test]
fn rejects_unterminated_comment() {
    let error = parse_address_list(b"john@example.com (oops").unwrap_err();
    assert_eq!(error, Error::Address(AddressError::UnterminatedComment));
}

#[test]
fn rejects_two_at_signs() {
    let error = parse_address_list(b"a@b@c").unwrap_err();
    assert!(matches!(
        error,
        Error::Address(AddressError::InvalidDomain | AddressError::MissingAt)
    ));
}

#[test]
fn rejects_invalid_local_and_domain() {
    assert!(parse_address_list(b"a..b@example.com").is_err());
    assert!(parse_address_list(b".a@example.com").is_err());
    assert!(parse_address_list(b"a@-example.com").is_err());
    assert!(parse_address_list(b"a@example..com").is_err());
    assert!(parse_address_list(b"a@example com").is_err());
}

#[test]
fn accepts_trailing_comma() {
    let list = parse_address_list(b"a@example.com,").unwrap();
    assert_eq!(list.addresses.len(), 1);
}

#[test]
fn bounds_address_count() {
    let mut input = String::new();
    for _ in 0..10_001 {
        input.push_str("a@b,");
    }
    let error = parse_address_list(input.as_bytes()).unwrap_err();
    assert_eq!(error, Error::Address(AddressError::TooManyAddresses));
}
