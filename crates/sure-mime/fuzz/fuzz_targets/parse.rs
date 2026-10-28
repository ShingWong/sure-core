#![no_main]

use libfuzzer_sys::fuzz_target;
use sure_mime::{
    canonicalize_body, decode_encoded_words, parse_address_list, parse_header_block, parse_message,
    parse_parameters, Canonicalization, Decoder, Limits, MessageParser, TransferEncoding,
};

fuzz_target!(|data: &[u8]| {
    let limits = Limits::hardened();

    let _ = parse_message(data, &limits);
    let _ = parse_header_block(data, 0, &limits);
    let _ = parse_parameters(data);
    let _ = parse_address_list(data);
    let _ = decode_encoded_words(data, 4096);
    let _ = canonicalize_body(data, Canonicalization::Simple, &limits);
    let _ = canonicalize_body(data, Canonicalization::Relaxed, &limits);

    // Arbitrary chunk splits through the streaming API.
    if let Ok(mut parser) = MessageParser::new(limits) {
        let mut sink = |_event| {};
        let mut offset = 0usize;
        let mut step = usize::from(data.first().copied().unwrap_or(1)).max(1);
        while offset < data.len() {
            let end = offset.saturating_add(step).min(data.len());
            if parser.push(&data[offset..end], &mut sink).is_err() {
                break;
            }
            offset = end;
            step = step.saturating_add(1);
        }
        let _ = parser.finish(&mut sink);
    }

    // Streaming decoders with one-byte input chunks.
    for encoding in [TransferEncoding::Base64, TransferEncoding::QuotedPrintable] {
        let mut decoder = Decoder::new(encoding);
        let mut out = Vec::new();
        for byte in data {
            if decoder.push(&[*byte], &mut out).is_err() {
                break;
            }
        }
        let _ = decoder.finish(&mut out);
    }
});
