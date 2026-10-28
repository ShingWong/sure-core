mod common;

use common::parse_chunked;
use proptest::prelude::*;
use sure_mime::{
    canonicalize_body, decode_encoded_words, parse_address_list, parse_header_block, parse_message,
    parse_parameters, Canonicalization, Limits,
};

fn limits() -> Limits {
    Limits::hardened()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, .. ProptestConfig::default() })]

    #[test]
    fn arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let limits = limits();
        let _ = parse_message(&data, &limits);
        let _ = parse_header_block(&data, 0, &limits);
        let _ = parse_parameters(&data);
        let _ = parse_address_list(&data);
        let _ = decode_encoded_words(&data, 256);
        let _ = canonicalize_body(&data, Canonicalization::Simple, &limits);
        let _ = canonicalize_body(&data, Canonicalization::Relaxed, &limits);
    }

    #[test]
    fn chunking_preserves_success_or_failure(
        data in prop::collection::vec(any::<u8>(), 0..1024),
        chunk_size in 1usize..64,
    ) {
        let limits = limits();
        let whole = parse_message(&data, &limits);
        let chunked = parse_chunked(&data, chunk_size, &limits);
        prop_assert_eq!(whole.is_ok(), chunked.is_ok());
        if let (Ok(whole), Ok(chunked)) = (whole, chunked) {
            prop_assert_eq!(whole.body, chunked.body);
            prop_assert_eq!(whole.parts.len(), chunked.parts.len());
            prop_assert_eq!(whole.summary, chunked.summary);
        }
    }

    #[test]
    fn header_block_never_exceeds_limits(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let limits = limits();
        if let Ok(block) = parse_header_block(&data, 0, &limits) {
            prop_assert!(block.len() <= limits.max_header_count);
            for header in &block.headers {
                prop_assert!(header.raw.len() <= limits.max_header_bytes);
            }
        }
    }

    #[test]
    fn encoded_word_output_is_bounded(data in prop::collection::vec(any::<u8>(), 0..2048), max in 0usize..256) {
        let decoded = decode_encoded_words(&data, max);
        prop_assert!(decoded.len() <= max);
    }

    #[test]
    fn parameters_are_never_unbounded(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok(parameters) = parse_parameters(&data) {
            prop_assert!(parameters.len() <= 256);
        }
    }

    #[test]
    fn addresses_are_never_unbounded(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok(list) = parse_address_list(&data) {
            prop_assert!(list.addresses.len() <= data.len().saturating_add(1));
        }
    }
}
