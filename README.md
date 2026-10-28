# sure-core

Foundational, portable Rust crates for the Sure stack. The first crate is
**`sure-mime` v0.1**: a pure, bounded, streaming MIME / RFC 5322 parser with
DKIM canonicalization primitives.

This workspace does **not** contain UI, webmail, control-plane, queue, crypto,
transport or Node-agent code. Those are separate Phase 1 workstreams described
in `PHASE-1-BUILD-SPEC.md` in the architecture workspace.

## Status

| crate | version | state |
|---|---|---|
| `sure-mime` | 0.1.0 | implemented subset, security gate passing |

`sure-mime` is deliberately a **subset** of MIME, not a claim of full RFC 5322
or RFC 2045-2049 conformance. See [Scope](#scope) and
[`docs/security-validation.md`](docs/security-validation.md).

## Non-negotiable properties

- `#![forbid(unsafe_code)]` in the crate.
- No filesystem, network, process, clock or environment access.
- `no_std` + `alloc`; builds for `wasm32-unknown-unknown` and `wasm32-wasip2`.
- Zero runtime dependencies.
- No panics, `unwrap` or `expect` on input paths.
- Every allocation and every emitted chunk is bounded by a fixed `Limits`
  value.
- Attachment bytes are emitted in bounded chunks and never retained by the
  parser.

## Scope

Implemented in v0.1:

1. RFC 5322 header blocks with folding, unfolding, duplicates and wire order.
2. Basic mailbox/address-list parsing for `From`, `To`, `Cc`, `Reply-To`.
3. `Content-Type` / `Content-Disposition` parameters, quoted strings and
   RFC 2231 continuation / charset / language forms.
4. Multipart parsing with preamble, epilogue, nesting, closing delimiters and
   line-start-only boundary matching.
5. Streaming identity / 7bit / 8bit / binary / base64 / quoted-printable
   decoding with carry state across chunks.
6. RFC 2047 encoded-word decoding with a bounded, literal fallback.
7. DKIM `simple` and `relaxed` header/body canonicalization (formatting only).
8. Streaming `push` / `finish` parser plus a bounded `parse_message` helper.
9. A fixed `Limits` struct covering header bytes/count, line length, MIME
   depth, part count, message bytes, decoded/body bytes, attachment bytes,
   boundary length and chunk size.

Not implemented in v0.1 (intentional):

- Full RFC 5322 address obs-syntax, source routes, or UTF-8 SMTP address
  local parts.
- `message/rfc822` recursion, `multipart/digest` special casing, or
  `multipart/signed` verification.
- Any cryptography, DKIM signing/verification, canonicalized-body hashing, or
  key handling.
- Charsets other than US-ASCII, UTF-8 and ISO-8859-1 for parameters/encoded
  words.
- MIME header charset conversion for body text.
- A streaming serializer.

## Usage

```rust
use sure_mime::{Limits, parse_message};

let input = b"Subject: hi\r\nContent-Type: text/plain\r\n\r\nHello\r\n";
let parsed = parse_message(input, &Limits::default())?;
assert_eq!(parsed.headers.first_value("subject"), Some(b"hi".as_slice()));
assert_eq!(parsed.body, b"Hello\r\n");
# Ok::<(), sure_mime::Error>(())
```

Streaming:

```rust
use sure_mime::{Event, Limits, MessageParser};

let mut parser = MessageParser::new(Limits::default())?;
let mut sink = |event: Event| {
    if let Event::AttachmentChunk { data, .. } = event {
        // Hand `data` to the host's blob writer. It is a bounded chunk.
        let _ = data.len();
    }
};
for chunk in [b"Subject: hi\r\n\r\n".as_slice(), b"body"] {
    parser.push(chunk, &mut sink)?;
}
parser.finish(&mut sink)?;
# Ok::<(), sure_mime::Error>(())
```

## Build and test

The Rust toolchain is expected under `~/.cargo/bin` on the development host:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo fmt --check
cargo test --all-features
cargo test --release --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --no-deps
cargo check --target wasm32-unknown-unknown --no-default-features
cargo check --target wasm32-wasip2 --no-default-features
```

Fuzzing requires nightly and `cargo-fuzz`:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
cd crates/sure-mime
cargo +nightly fuzz run parse
```

## License

MIT. Runtime dependencies: none. Dev dependencies are limited to `proptest`
(MIT/Apache-2.0). `deny.toml` enforces the allowlist and rejects
GPL/AGPL/SSPL-style licenses.
