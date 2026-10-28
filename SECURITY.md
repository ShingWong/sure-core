# Security policy

## Supported versions

| version | supported |
|---|---|
| `sure-mime` 0.1.x | yes |

## Reporting a vulnerability

Report privately through the repository's GitHub Security Advisory flow once the
repository has a public remote. Do not open a public issue for a memory-safety,
denial-of-service or parser-differential finding.

Include:

- the exact input bytes (or a minimized corpus file),
- the parser configuration (`Limits`),
- the build/commit hash and target,
- observed behaviour and expected behaviour.

## Threat model

The parser is designed for untrusted mail:

- **Attacker controls** every input byte, including line endings, header
  folding, boundary-like text, charset names, parameter continuations and
  transfer-encoded bodies.
- **Attacker does not control** the compiled code, the `Limits` passed by the
  host, or memory outside the process.
- **Assets** are host availability and memory, attachment/blob storage
  integrity, and the integrity of parsed metadata used for policy decisions.

The parser is a pure function of its input and limits. It has no ambient
authority: no filesystem, network, process, clock or environment access, and no
`unsafe`.

## Invariants

1. No `unsafe` code (`#![forbid(unsafe_code)]`).
2. No input path panics or uses `unwrap`/`expect`; malformed input returns a
   typed `Error`.
3. Header buffering is bounded by `max_header_bytes`; header count and physical
   line length are separately bounded.
4. Part count and nesting depth are bounded; `PartPath` is fixed-size.
5. Boundary matching occurs only at a line start, with the closing delimiter
   and trailing transport padding recognised.
6. Transfer decoding carries state across chunk boundaries; an incomplete
   base64/QP sequence at `finish` returns a typed error rather than being
   guessed.
7. Decoded bytes, non-attachment body bytes and per-attachment bytes are
   counted with checked/saturating arithmetic and bounded.
8. Attachment bytes are emitted in chunks no larger than the configured chunk
   bound and are not retained by the parser.
9. Malformed RFC 2047 encoded words are preserved literally; output is bounded.
10. No cryptographic claim is made. DKIM canonicalization is formatting only.

## Host responsibilities

- Choose explicit `Limits`; do not raise them to fit a single message without a
  capacity review.
- Treat `is_attachment`, `filename` and content types as untrusted metadata.
  `sanitize_filename` is a display/storage hint, not a path.
- Write attachment chunks with backpressure and cancellation; do not buffer a
  whole attachment in memory.
- Apply a timeout/fuel limit at the Wasm or task boundary; the parser bounds
  bytes, not CPU time.
- Do not use `sure-mime` as an authentication result. DKIM verification requires
  a crypto provider and a separate verifier.

## Out of scope for v0.1

- Cryptographic verification or signing.
- Full RFC 5322 obs-syntax.
- Charset conversion outside the documented set.
- `message/rfc822` recursion.
- HTML sanitisation, URL filtering or malware scanning.
- Multi-message archive semantics.

See [`docs/security-validation.md`](docs/security-validation.md) for the test
matrix, commands and residual risks.
