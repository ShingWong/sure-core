# Dependency licence inventory — `sure-mime` v0.1

Generated from `cargo metadata --format-version 1` on 2026-10-28 with
`scripts/licenses.py`. This is a declared-licence inventory, not a legal opinion.

**Runtime dependencies: none.** Every package below is a dev/build dependency of
`proptest` (tests only) except `sure-mime` itself. `cargo tree -p sure-mime`
shows the runtime graph as a single node.

| package | version | declared licence |
|---|---|---|
| autocfg | 1.5.1 | Apache-2.0 OR MIT |
| bit-set | 0.11.1 | Apache-2.0 OR MIT |
| bit-vec | 0.10.1 | Apache-2.0 OR MIT |
| bitflags | 2.13.2 | MIT OR Apache-2.0 |
| borsh | 1.8.1 | MIT OR Apache-2.0 |
| borsh-derive | 1.8.1 | Apache-2.0 |
| bytes | 1.12.1 | MIT |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 |
| cfg_aliases | 0.2.2 | MIT |
| chacha20 | 0.10.2 | MIT OR Apache-2.0 |
| core_detect | 1.0.0 | MIT/Apache-2.0 |
| cpufeatures | 0.3.1 | MIT OR Apache-2.0 |
| equivalent | 1.0.3 | Apache-2.0 OR MIT |
| errno | 0.3.14 | MIT OR Apache-2.0 |
| fastrand | 2.5.0 | Apache-2.0 OR MIT |
| fnv | 1.0.7 | Apache-2.0 / MIT |
| getrandom | 0.4.3 | MIT OR Apache-2.0 |
| hashbrown | 0.17.1 | MIT OR Apache-2.0 |
| indexmap | 2.14.2 | Apache-2.0 OR MIT |
| libc | 0.2.191 | MIT OR Apache-2.0 |
| linux-raw-sys | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| memchr | 2.8.3 | Unlicense OR MIT |
| num-traits | 0.2.19 | MIT OR Apache-2.0 |
| once_cell | 1.21.4 | MIT OR Apache-2.0 |
| proc-macro-crate | 3.5.0 | MIT OR Apache-2.0 |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 |
| proptest | 1.12.0 | MIT OR Apache-2.0 |
| quick-error | 1.2.3 | MIT/Apache-2.0 |
| quote | 1.0.47 | MIT OR Apache-2.0 |
| r-efi | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| rand | 0.10.3 | MIT OR Apache-2.0 |
| rand_core | 0.10.1 | MIT OR Apache-2.0 |
| rand_xorshift | 0.5.0 | MIT OR Apache-2.0 |
| regex-syntax | 0.8.11 | MIT OR Apache-2.0 |
| rustix | 1.1.6 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| rusty-fork | 0.3.1 | MIT/Apache-2.0 |
| serde | 1.0.229 | MIT OR Apache-2.0 |
| serde_core | 1.0.229 | MIT OR Apache-2.0 |
| serde_derive | 1.0.229 | MIT OR Apache-2.0 |
| sure-mime | 0.1.0 | MIT |
| syn | 3.0.9 | MIT OR Apache-2.0 |
| tempfile | 3.27.0 | MIT OR Apache-2.0 |
| toml_datetime | 1.1.2+spec-1.1.0 | MIT OR Apache-2.0 |
| toml_edit | 0.25.17+spec-1.1.0 | MIT OR Apache-2.0 |
| toml_parser | 1.1.5+spec-1.1.0 | MIT OR Apache-2.0 |
| unarray | 0.1.4 | MIT OR Apache-2.0 |
| unicode-ident | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| wait-timeout | 0.2.1 | MIT/Apache-2.0 |
| windows-link | 0.2.1 | MIT OR Apache-2.0 |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 |
| winnow | 1.0.4 | MIT |

## Notes

- `r-efi` is a target-only dependency (`target_os = "uefi"`) with an
  `MIT OR Apache-2.0 OR LGPL-2.1-or-later` expression; the permissive options
  are selected. It is not in the Linux/WASM build.
- No GPL, AGPL, SSPL, Commons Clause, non-commercial or proprietary licence was
  found in the resolved graph.
- Dev dependencies never ship in a `sure-mime` artifact. The runtime crate has
  zero dependencies by construction.
- `cargo-deny` is the authoritative gate; see `deny.toml` and the CI supply-chain
  job.
- The separate fuzz workspace (`crates/sure-mime/fuzz`) has its own committed
  `Cargo.lock` and is not part of the shipped `sure-mime` artifact. Its handful
  of dependencies (`libfuzzer-sys`, `cc`, `jobserver`, `shlex`) are
  MIT/Apache-2.0 and are excluded from the main SBOM.
