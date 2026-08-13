# Dependency inventory

The application has seven direct dependencies, all exact-version pinned. Hashes below
are the crates.io registry package checksums recorded in `Cargo.lock`; upstream source
is the corresponding RustCrypto/Dalek project published through crates.io. Cargo also
checks every vendored file through `.cargo-checksum.json`.

| Direct crate | Version | Registry package SHA-256 | Purpose |
| --- | ---: | --- | --- |
| `chacha20poly1305` | 0.10.1 | `10cd79432192d1c0f4e1a0fef9527696cc039165d729fb41b3f4f4f354c2dc35` | XChaCha20-Poly1305 AEAD |
| `ed25519-dalek` | 2.2.0 | `70e796c081cee67dc755e1a36a0a172b897fab85fc3f6bc48307991f64e4eca9` | Ed25519 signing/strict verification |
| `getrandom` | 0.2.16 | `335ff9f135e4384c8150d6f27c6daed433577f86b4750418338c01a1a2528592` | OS CSPRNG access |
| `hkdf` | 0.12.4 | `7b5f8eb2ad728638ea2c7d47a21db23b7b58a72ed6a38256b8a1849f15fbbdf7` | HKDF-SHA-256 |
| `sha2` | 0.10.9 | `a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283` | SHA-256 fingerprints/extraction |
| `x25519-dalek` | 2.0.1 | `c7e468321c81fb07fa7f4c636c3972b9100f0346e5b6a9f2bd0603a52f7ed277` | static and ephemeral X25519 |
| `zeroize` | 1.8.1 | `ced3678a2879b30306d323f4542626697a464a97c0a07c9aebf7ebca65cd4dde` | best-effort secret cleanup |

No dependency was added for CLI parsing, serialization, filesystem layout, logging,
networking, async execution, databases, or JSON.

## Active transitive crates

The locked normal/build tree contains: `aead 0.5.2`, `block-buffer 0.10.4`, `cfg-if
1.0.4`, `chacha20 0.9.1`, `cipher 0.4.4`, `cpufeatures 0.2.17`, `crypto-common 0.1.7`,
`curve25519-dalek 4.1.3`, `digest 0.10.7`, `ed25519 2.2.3`, `generic-array 0.14.7`,
`hmac 0.12.1`, `inout 0.1.4`, `libc 0.2.189`, `opaque-debug 0.3.1`, `poly1305
0.8.0`, `proc-macro2 1.0.107`, `quote 1.0.47`, `rand_core 0.6.4`, `rustc_version
0.4.1`, `semver 1.0.28`, `signature 2.2.0`, `subtle 2.6.1`, `syn 2.0.119`,
`typenum 1.20.1`, `unicode-ident 1.0.24`, `universal-hash 0.5.1`, `version_check
0.9.5`, and `zeroize_derive 1.5.0`.

Their roles are limited to RustCrypto traits and primitive internals, constant-time
selection, type-level buffer sizes, Ed25519/Curve25519 arithmetic, OS bindings and CPU
feature detection, secret-zeroization derive support, and build-time compiler/version
or procedural-macro support. Run `cargo tree --locked --edges normal,build` for the
authoritative graph.

`Cargo.lock` and `vendor/` also retain optional/target resolution sources such as
`base64ct`, `const-oid`, `der`, `fiat-crypto`, `pkcs8`, `serde`, `serde_core`,
`serde_derive`, `spki`, `syn 3`, and `wasi`. They are not active in the host runtime
tree shown by Cargo, but are vendored so the lock remains portable and fully offline.

## Unsafe boundary

Project code forbids unsafe Rust. Vendored dependencies contain audited-library unsafe
for OS calls (`getrandom`, `libc`, target `wasi`), CPU feature detection and optimized
arithmetic (`cpufeatures`, `sha2`, `chacha20`, `poly1305`, `curve25519-dalek`),
constant-time/type-level buffer internals, and procedural-macro/parser internals. This
is the unavoidable third-party boundary. It is source-visible under `vendor/`; no FFI
cryptographic library or project-authored unsafe block exists. Dependency updates must
re-run source review, `cargo tree`, vectors, malformed tests, and offline builds rather
than silently running `cargo update`.

