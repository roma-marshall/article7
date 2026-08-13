# Sealed

Sealed is an experimental, offline-first protocol and Rust CLI for authenticated,
independent encrypted letters. It signs, encrypts, and pads a body into an opaque
binary blob that can cross any byte-preserving transport. The transport is never
trusted and the cryptographic core has no networking code, accounts, servers,
telemetry, database, or message history.

Sealed is **not** a messenger, anonymity network, email system, blockchain, web
application, or production-ready steganography system. It has not received an
independent professional cryptographic audit. Do not rely on it for safety-critical
communications yet.

## Security model

V1 uses Ed25519 signatures, static and per-letter ephemeral X25519, HKDF-SHA-256,
and XChaCha20-Poly1305. A recipient must pin and independently compare a contact's
fingerprint. A mathematically valid signature from an unpinned identity is reported
as `UNKNOWN`, never trusted. Outer blobs contain only an ephemeral public key, a
random nonce, and authenticated ciphertext; padding is encrypted and final sizes
are powers of two.

The transport may intercept, retain, modify, delete, delay, and replay blobs. V1
protects content confidentiality and authentication when endpoints and private keys
remain secure. It does not hide transport-level sender/recipient metadata or timing.

Important limitations:

- Later compromise of a recipient's static X25519 key can expose recorded old blobs.
  V1 does **not** provide full forward secrecy.
- Local deletion after opening is not a cryptographic one-open guarantee. Copies can
  be replayed, and SSDs/filesystems may retain physical data.
- The outer format has no recognizable header, but no formal PURB or uniform-random
  indistinguishability claim is made.
- Linguistic steganography is an interface and research plan only; no production
  encoder is shipped.
- Malware, keyloggers, screenshots, cameras, compromised operating systems, physical
  coercion, and deliberate forwarding are out of scope.

Read [the threat model](docs/THREAT_MODEL.md), [cryptographic construction](docs/CRYPTOGRAPHY.md),
and [protocol bytes](docs/PROTOCOL.md) before evaluating or using the software.

## Use

Release bundles may include a tiny `./sealed` or `sealed.cmd` launcher plus the
appropriate prebuilt native binary under `dist/`. The launcher performs no download
or installation. This source tree does not pretend that unbuilt cross-platform
binaries are present. After a source build, simply launch the guided terminal:

```sh
./build.sh
./sealed
```

Running `./sealed` without arguments opens an interactive menu that shows identity
status and pinned contacts, then guides the user through identity creation, profile
exchange, contact verification, sealing, and opening. Letters can be entered as
multiple lines; a line containing only `.` finishes the body. ANSI colors are disabled
when `NO_COLOR` is set.

The explicit commands remain available for scripts and advanced use:

```sh
# Create an identity. Choose an unlock-key path on separate media when prompted.
./sealed init

# Export the public profile without unlocking private keys.
./sealed identity export > alice.pub

# Pin Bob, then verify the displayed fingerprint out of band.
./sealed trust bob.pub

# Seal stdin to a new file. The CLI prompts for the unlock-key path.
./sealed seal bob --output letter.bin

# Open and logically delete letter.bin after successful output.
./sealed open letter.bin

# Advanced: retain the ciphertext.
./sealed open letter.bin --keep
```

For scripts, `--unlock-key PATH` or the path-only `SEALED_UNLOCK_KEY` environment
variable avoids the terminal prompt. `SEALED_HOME` overrides `~/.sealed` for isolated
testing. Never put the unlock-key file inside the state directory.

Private plaintext is written only to stdout and kept in memory inside a best-effort
zeroizing buffer. Sealing emits a blob to stdout unless `--output` is supplied. Keep
diagnostics and trust status on stderr when redirecting data.

## Build and audit

The exact Rust 1.97.1 toolchain is pinned. All crate sources are checked into
`vendor/`; Cargo is configured offline. A source build requires Rust and a native
linker, but no network access:

```sh
./build.sh
```

Windows PowerShell:

```powershell
.\build.ps1
```

The underlying invariant is:

```sh
cargo build --release --offline --locked
```

`build.sh` checks formatting, compiles, tests, builds the release binary, and places
it in the matching `dist/<platform>/` directory. See [BUILD.md](docs/BUILD.md) and
[DEPENDENCIES.md](docs/DEPENDENCIES.md). No known backdoors are intentionally present;
the source is designed for independent audit, not trust in its authors or generated
code.

Licensed under the MIT License.
