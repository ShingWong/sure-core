# Security validation — `sure-mime` v0.1

**Date:** 2026-10-28
**Crate:** `sure-mime` 0.1.0 (`crates/sure-mime`)
**Toolchain:** rustc/cargo 1.99.1 (stable, x86_64-unknown-linux-gnu)
**Status:** Phase 1 v0.1 validation complete for the documented subset. This is
not a claim of full RFC 5322 / MIME conformance and not a cryptographic
validation.

---

## 1. Scope

Validated in this pass:

- RFC 5322 header blocks with folding, unfolding, duplicates and wire order.
- Basic mailbox/address-list parsing for `From`/`To`/`Cc`/`Reply-To`.
- `Content-Type` / `Content-Disposition` parameters, quoted strings and RFC 2231
  continuation/charset/language forms.
- Multipart parsing with preamble, epilogue, nesting, closing delimiters and
  line-start-only boundary matching.
- Streaming identity/7bit/8bit/binary/base64/quoted-printable decoding.
- RFC 2047 encoded-word decoding with a bounded literal fallback.
- DKIM `simple`/`relaxed` header and body canonicalization (formatting only).
- Streaming `push`/`finish` API and bounded `parse_message`.

Out of scope: cryptography, DKIM verification/signing, `message/rfc822`
recursion, full address obs-syntax, charsets outside the documented set, HTML
sanitisation, MIME serialization, OPFS/SQLite, queue, transport, UI.

---

## 2. Threat model

The attacker controls every input byte: line endings, folding, duplicate
headers, boundaries (including boundary-like body text), parameter
continuations, charsets, base64/QP payloads, truncation and chunk boundaries.
The attacker does **not** control the compiled code or the `Limits` chosen by the
host.

Assets:

- host availability (CPU/memory) while parsing;
- integrity of attachment/blob writes and part metadata used for policy;
- integrity of decoded body bytes and DKIM canonicalized bytes.

The parser has no ambient authority: no filesystem, network, process, clock or
environment access, no `unsafe`, and no runtime dependencies. Time and
randomness are host concerns.

---

## 3. Invariants enforced

1. `#![forbid(unsafe_code)]`; no code-level `unsafe` appears in `src/` (the
   word may appear in documentation).
2. No input-path `unwrap`/`expect`/`panic!`; malformed input returns a typed
   `Error`. Tests may use `unwrap`.
3. Header buffering is bounded by `max_header_bytes`; header count and physical
   line length are separately bounded.
4. MIME depth is fixed (`PartPath` is a 32-segment array) and part count is
   bounded by `Limits`.
5. Boundary matching occurs only at a line start; the closing delimiter and
   trailing transport padding are recognised; boundary-like text is content.
6. The CRLF immediately before a delimiter belongs to the delimiter, not the
   part body.
7. Transfer decoders carry state across chunks; complete-padding and partial
   tail rules are explicit; invalid or truncated input is a typed error.
8. Decoded, body and per-attachment byte counts use saturating arithmetic and
   are checked before further growth.
9. Attachment bytes are emitted as bounded `AttachmentChunk`s; the parser does
   not retain them. `parse_message` drops them immediately.
10. RFC 2047 malformed words are preserved literally; output is bounded and the
    malformed-word fallback is linear in the input (no repeated rescanning).
11. Address lists are capped at 10 000 entries; a single display name is capped
    at 1 024 bytes; local/domain lengths are capped.
12. DKIM canonicalization is deterministic formatting; no crypto claim is made.

---

## 4. Limits and defaults

| Limit | Default | Hardened | Failure |
|---|---:|---:|---|
| header bytes per block | 1 MiB | 64 KiB | `LimitKind::HeaderBytes` |
| header count per block | 1 000 | 256 | `HeaderCount` |
| physical header line | 4 096 | 2 048 | `HeaderLineLength` |
| MIME depth (root 0) | 32 | 8 | `MimeDepth` |
| parts incl. root | 1 000 | 128 | `PartCount` |
| message bytes | 64 MiB | 8 MiB | `MessageBytes` |
| decoded bytes total | 64 MiB | 8 MiB | `DecodedBytes` |
| non-attachment decoded total | 32 MiB | 4 MiB | `BodyBytes` |
| one attachment | 32 MiB | 4 MiB | `AttachmentBytes` |
| boundary length | 70 | 70 | `Multipart(InvalidBoundary)` |
| event chunk | 16 KiB | 8 KiB | bounded chunks, not an error |

`Limits::validate` rejects zero, inconsistent or unrepresentable sets rather
than clamping. Tests cover every row, exact-boundary acceptance and invalid
sets.

---

## 5. Test matrix and results

Tests are self-contained and run in both debug and release. Counts are the
number of `#[test]` cases in each integration file; each property test runs 128
generated cases with proptest's default seeded RNG.

| File | Cases | What it covers |
|---|---:|---|
| `tests/headers.rs` | 12 | folding/unfolding, duplicates/order, CRLF/LF/CR, offsets, invalid names, NUL, continuation-without-field, count/line/byte limits |
| `tests/addresses.rs` | 17 | bare/display/quoted/domain-literal/comments/groups, encoded display names, malformed quotes/angles/comments, missing/multiple `@`, invalid local/domain, trailing comma, address-count bound |
| `tests/params.rs` | 17 | quoted strings/escapes, RFC 2231 single/continuation/charset/language, Latin-1, duplicate/non-contiguous/duplicate sections, bad percent, unsupported charset, unterminated quote, filename sanitisation |
| `tests/multipart.rs` | 21 | preamble/epilogue, nesting, no-header part, closing/trailing-WSP delimiters, boundary-like text, LF/CR, missing/unterminated/boundary-after-close, multipart CTE, part/depth limits, container/attachment semantics, split-at-every-byte |
| `tests/decode.rs` | 14 | identity, base64 vectors/unpadded/whitespace/invalid padding/trailing, QP escapes/soft breaks/invalid/truncated, both decoders split at every byte, encoded words |
| `tests/dkim.rs` | 8 | simple/relaxed header, last-unused selection, missing header, simple/relaxed body vectors, split-at-every-byte, reuse errors |
| `tests/limits.rs` | 13 | every limit, exact-boundary acceptance, invalid limits, chunk bound |
| `tests/malformed.rs` | 16 | truncated headers/multipart, header/body/base64/QP bombs, deep nesting, malformed part headers, boundary-in-body, unknown CTE, deterministic random corpus, reuse/finish errors |
| `tests/properties.rs` | 6 | arbitrary bytes never panic across parser/headers/params/addresses/encoded words/DKIM; chunking preserves success/failure and result; bounds hold |
| `tests/streaming.rs` | 6 | split at every byte (simple and nested), arbitrary split points, empty pushes, body-only chunks, finish/reuse |

Total: **130 integration tests**, all passing in debug and release.

### 5.1 Adversarial cases exercised

- Header bombs (2 000 fields), long folded headers, NUL bytes, invalid field
  names.
- Body bombs (1 000 bytes with a tiny limit), base64 and QP expansion bombs.
- 40-level nested multipart against a 32-level hard limit.
- Boundary-like body text (`--Bxyz`, `text --B`), closing delimiter with trailing
  whitespace, boundary after close.
- Truncated header block, truncated multipart, missing boundary, multipart with
  a transfer encoding.
- Base64/QP split at every byte, including padding and soft-break boundaries.
- LF-only and CR-only variants of a multipart message.
- CRLF delimiter split across `push` calls.
- Deterministic pseudo-random byte corpus (512 lengths) through the hardened
  limits.

### 5.2 Findings fixed during validation

Validation found and fixed real issues rather than only confirming happy paths:

1. **Bare-CR header state** — a pending CR was not cleared when the next byte
   was not LF, causing CR-only header blocks to terminate early. Fixed and
   covered by `accepts_lf_and_bare_cr_line_endings`.
2. **CRLF delimiter split across pushes** — a boundary ending in CR at the end
   of a chunk could leave the following LF to be misread as an empty header
   line. Added `pending_boundary_lf` and covered it with split-at-every-byte
   tests.
3. **Preamble/epilogue granularity** — scanner content was routed one byte at a
   time; output is now coalesced up to `max_chunk_bytes`, reducing event churn
   without changing bytes.
4. **Encoded-word fallback cost** — a malformed `=?` could cause repeated
   rescans of a long token. The fallback now copies the shaped word or the
   whitespace-delimited token once, keeping the scan linear.
5. **Address-list bounds** — added a 10 000-entry cap and per-group cap so a
   dense address list cannot grow without a bound.

---

## 6. Commands run and results

All commands were run from the repository root with
`export PATH="$HOME/.cargo/bin:$PATH"`.

| Command | Result |
|---|---|
| `cargo fmt --all --check` | **PASS** (RC 0) |
| `cargo test --all-features` | **PASS** — 130 tests, 0 failed |
| `cargo test --release --all-features` | **PASS** — 130 tests, 0 failed |
| `cargo clippy --all-targets --all-features -- -D warnings` | **PASS** (RC 0) |
| `cargo doc --no-deps --all-features` | **PASS** (RC 0) |
| `cargo check --target wasm32-unknown-unknown --no-default-features` | **PASS** (RC 0) |
| `cargo check --target wasm32-wasip2 --no-default-features` | **PASS** (RC 0) |
| `cargo check --manifest-path crates/sure-mime/fuzz/Cargo.toml` | **PASS** (RC 0; target type-checks, not a fuzz run) |
| `cargo tree -p sure-mime` | runtime graph: `sure-mime` only; `proptest` under `[dev-dependencies]` |
| `cargo deny check licenses bans advisories sources` | **PASS** — `advisories ok, bans ok, licenses ok, sources ok` |
| `cargo audit` | **PASS** — RC 0, 51 crate dependencies scanned, no vulnerability reported |
| `python3 scripts/sbom.py > sbom.cdx.json` | **PASS** — CycloneDX 1.5 SBOM, 51 components |
| `python3 scripts/licenses.py` | permissive graph; runtime dependencies zero; see `docs/dependency-licenses.md` |

Grep gates (also encoded in CI):

```bash
# Code-level unsafe only; doc comments may mention the word.
! grep -rnE '^[[:space:]]*(pub[[:space:]]+)?(unsafe[[:space:]]+(fn|impl|trait)|unsafe[[:space:]]*\{)' crates/sure-mime/src
! grep -rnE '\.unwrap\(\)|\.expect\(|panic!\(' crates/sure-mime/src
```

Both pass. (`#![forbid(unsafe_code)]` is the compile-time backstop.)

### 6.1 Tool installation

`cargo-deny 0.20.2` and `cargo-audit 0.22.2` were installed user-level with
`cargo install --locked`. No system packages were modified and no `sudo` was
used. The Rust WASM targets (`wasm32-unknown-unknown`, `wasm32-wasip2`) were
installed with `rustup target add` at user level.

### 6.2 Fuzzing status

**Fuzz run not performed.** `cargo-fuzz` requires nightly, and nightly was not
installed in this pass. The target type-checks on stable with
`cargo check --manifest-path crates/sure-mime/fuzz/Cargo.toml` (PASS); this is
not a fuzz run. The target and seed corpus are committed:

```text
crates/sure-mime/fuzz/fuzz_targets/parse.rs
crates/sure-mime/fuzz/corpus/parse/{simple,multipart,nested,base64,quoted-printable,boundary-like}.eml
```

Exact commands for the next pass:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
cd crates/sure-mime
cargo +nightly fuzz run parse -- -max_total_time=60
cargo +nightly fuzz run parse -- -runs=100000
```

Do not claim a fuzz run until the log and corpus count are attached.

---

## 7. Residual risks

| Risk | Why it remains | Next step |
|---|---|---|
| No fuzz run yet | nightly/cargo-fuzz not installed | run the commands in §6.2; add regressions |
| No differential oracle | no reference parser in the gate | compare against `mailparse`/Postfix corpus later |
| CPU time is not bounded | library bounds bytes, not instructions | host/Wasm fuel/timeout is mandatory |
| Charset coverage | only US-ASCII/UTF-8/ISO-8859-1 | add an audited edge decoder or a documented rejection policy |
| Address obs-syntax | v0.1 basic grammar | add obs-syntax after corpus evidence |
| `message/rfc822` opaque | no recursion in v0.1 | decide recursion policy and depth bound |
| Base64 non-canonical unused bits | padding is validated; unused bits are not | decide strict/lenient policy with corpus |
| QP line length/trailing WSP | not enforced | add if required by the target profile |
| Preamble/epilogue content | emitted, not interpreted | host decides whether to ignore or reject |
| Header values up to 1 MiB | bounded but large | lower limits at the host or add a per-header semantic cap |
| No authentication claim | DKIM is formatting only | crypto provider + verifier in `sure-crypt` |
| `parse_message` body retention | bounded by `max_body_bytes` | hosts handling large mail should use the event API |

No memory-safety issue was found: the crate is `no_std`, has no runtime
dependencies, and contains no `unsafe`. The property tests and split-at-every-byte
tests found no panic.

---

## 8. Manual review checklist

- [x] Every loop/recursion has a bound; MIME depth and part count are explicit.
- [x] Length/count arithmetic uses checked or saturating operations.
- [x] Every slice/index is derived from a checked length (`get`/`get_mut` where
      the invariant is not local).
- [x] Every allocation has a corresponding limit check (headers, parts, decoded
      bytes, chunks, addresses, parameters, DKIM output).
- [x] Boundary/delimiter logic is line-start-only and handles CRLF, LF, bare CR
      and chunk splits.
- [x] Decoder carry state is reset at `finish`; incomplete input is a typed
      error.
- [x] Attachment bytes are not retained; chunks are bounded; `parse_message`
      drops attachment chunks.
- [x] Errors do not contain attacker-controlled text.
- [x] Missing multipart boundary / unknown transfer encoding / malformed
      security-relevant metadata fail closed.
- [x] DKIM canonicalization matches the test vectors; no crypto claim.
- [x] Dependency/licence graph reviewed; no GPL/AGPL/SSPL; runtime deps zero.
- [x] This document updated with commands, results and residual risks.

---

## 9. Not covered by v0.1

- DKIM signing/verification, hash/HMAC, key handling, SPF/DMARC/ARC.
- Full RFC 5322 address obs-syntax, source routes, UTF-8 SMTP local parts.
- `message/rfc822` recursion, `multipart/digest`, `multipart/signed`.
- Charset conversion outside the documented set.
- HTML/URL sanitisation, malware scanning, archive semantics.
- Queue, transport/STARTTLS, storage, node agent, UI, webmail, WORM, billing,
  device relay, Apple platforms.
