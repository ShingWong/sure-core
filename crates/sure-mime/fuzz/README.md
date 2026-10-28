# Fuzzing sure-mime

`cargo-fuzz` is not installed on the build host used for v0.1, and the fuzz
target requires a nightly toolchain. The target is committed and has **not**
been claimed as run in `docs/security-validation.md`.

Exact commands:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
cd crates/sure-mime
cargo +nightly fuzz run parse -- -max_total_time=60
cargo +nightly fuzz run parse -- -runs=100000
cargo +nightly fuzz tmin parse crates/sure-mime/fuzz/artifacts/parse/<crash>
```

The seed corpus lives in `corpus/parse/`. Add regression inputs there when a
crash is fixed; the property and split-at-every-byte tests are the always-on
gate, the fuzzer is the exploratory gate.
