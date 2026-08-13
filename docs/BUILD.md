# Offline build

The repository pins Rust 1.97.1 (`rustc 1.97.1 (8bab26f4f 2026-07-14)`) in
`rust-toolchain.toml`, pins direct dependency versions in `Cargo.toml`, commits the
complete resolution in `Cargo.lock`, and replaces crates.io with `vendor/` in
`.cargo/config.toml`. Cargo is forced offline.

Required source-build tools are the pinned Rust toolchain (including rustfmt) and the
platform's native linker. No build script downloads or installs anything.

```sh
./build.sh
```

The script runs formatting, locked/offline checking, tests, and a release build. It
then copies the result to one of:

```text
dist/macos-arm64/sealed
dist/macos-x64/sealed
dist/linux-arm64/sealed
dist/linux-x64/sealed
```

On Windows, `build.ps1` writes `dist/windows-x64/sealed.exe`. The tiny top-level
launchers only select an already present binary. They contain no installation or
network logic.

Direct Cargo verification:

```sh
cargo build --release --offline --locked
```

Cargo validates vendored files against each crate's `.cargo-checksum.json`, whose
package checksum corresponds to the registry checksum in `Cargo.lock`. `verify-build.sh`
performs two clean release builds at the same controlled path and compares their
hashes on one host.

Release flags are one codegen unit, fat LTO, optimization level 3, abort-on-panic, and
symbol stripping. Official target triples are planned as:

```text
aarch64-apple-darwin
x86_64-apple-darwin
x86_64-unknown-linux-gnu
aarch64-unknown-linux-gnu
x86_64-pc-windows-msvc
```

Same-host/same-path equality is not proof of cross-path or cross-platform
reproducibility. In particular, current Apple linker UUID generation can reflect
pre-strip path-dependent material. The project does not claim byte-for-byte
reproducibility across checkout paths or build hosts until independently tested.
