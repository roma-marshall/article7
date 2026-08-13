# Protocol v1

This document defines the byte-level CLASSICAL_V1 implementation. Integers are
unsigned big-endian. Every length is checked before slicing or allocation. The
maximum body is 1,048,576 bytes and the maximum outer blob is 2,097,152 bytes.

## Public profile

Profiles are canonical UTF-8 text ending in LF:

```text
sealed-profile-v1
ed25519=<64 lowercase hex characters>
x25519=<64 lowercase hex characters>
fingerprint=<64 lowercase hex characters>
```

The fingerprint is:

```text
SHA-256(
  UTF8("sealed/fingerprint/v1") ||
  U8(1) ||
  Ed25519_public[32] ||
  X25519_public[32]
)
```

Parsers recompute it. Profiles are public; their readable marker is not part of an
encrypted-letter blob.

## Contact root and steganography key

For each profile form `endpoint = Ed25519_public || X25519_public` (64 bytes). Let
`first` and `second` be the two endpoints in unsigned lexicographic byte order.

```text
shared = X25519(local_static_secret, peer_static_public)

contact_root = HKDF-SHA-256(
  salt = UTF8("sealed/contact-root/extract/v1"),
  IKM  = shared,
  info = UTF8("sealed/contact-root/expand/v1") || first || second,
  L    = 32
)

K_stego = HKDF-SHA-256(
  salt = UTF8("sealed/contact-subkey/extract/v1"),
  IKM  = contact_root,
  info = UTF8("sealed/steganography/v1"),
  L    = 32
)
```

An all-zero X25519 shared secret is rejected. `K_stego` is not a message-encryption
key and is never transmitted.

## Signed internal message

The signature input is exactly:

```text
UTF8("sealed/message-signature/v1") ||
U8(protocol_version=1) ||
U8(crypto_suite=1) ||
sender_Ed25519_public[32] ||
sender_X25519_public[32] ||
recipient_fingerprint[32] ||
message_id[32] ||
U32BE(body_length) ||
body[body_length]
```

The Ed25519 signature is deterministic over those bytes. The padded plaintext is:

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 1 | protocol version, `0x01` |
| 1 | 1 | crypto suite, `0x01` (CLASSICAL_V1) |
| 2 | 32 | sender Ed25519 public key |
| 34 | 32 | sender static X25519 public key |
| 66 | 32 | recipient profile fingerprint |
| 98 | 32 | random 256-bit message ID |
| 130 | 4 | body length, U32BE |
| 134 | variable | body |
| 134 + body length | 64 | Ed25519 signature |
| following | variable | random padding |

The version, suite, identities, signature, lengths, body, message ID, and padding are
all inside AEAD encryption.

## Message key and outer blob

Each letter creates a fresh random 32-byte X25519 secret and public key. Let `E` be
the 32-byte ephemeral public key and `R` the recipient's 32-byte static X25519 public
key:

```text
shared = X25519(ephemeral_secret, R)

K_message = HKDF-SHA-256(
  salt = UTF8("sealed/message-key/extract/v1"),
  IKM  = shared,
  info = UTF8("sealed/message-key/expand/v1") || E || R,
  L    = 32
)
```

An all-zero shared secret is rejected. A fresh 24-byte OS-random nonce `N` is used
with XChaCha20-Poly1305. Associated data is:

```text
UTF8("sealed/outer-aead/v1") || E || N
```

The fixed outer layout is:

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 32 | ephemeral X25519 public bytes |
| 32 | 24 | XChaCha nonce |
| 56 | remaining | ciphertext with 16-byte Poly1305 tag |

There is no magic, sender, recipient, timestamp, version, suite, or protocol name in
plaintext. CLASSICAL_V1 uses this one layout; later suites require a separate careful
negotiation/format design, not an added recognizable header.

The smallest power of two at least `72 + 198 + body_length` is selected, with a
minimum of 512 and maximum of 2,097,152. Random bytes pad the internal message until
the final outer blob equals that bucket exactly. Appending or truncating bytes makes
the outer length invalid; changing any existing byte fails authentication.

## Opening and failures

Before AEAD authentication, only the fixed outer offsets and total-size rule are
parsed. The recipient derives the key, authenticates, then parses the inner record,
checks recipient binding, performs strict Ed25519 verification, and separately looks
for an exact pinned profile. Blob-related failures collapse to `Cannot open blob.` at
the CLI boundary. A valid unpinned signer is `UNKNOWN`, not trusted.

The public deterministic vector is [classical-v1.txt](../tests/vectors/classical-v1.txt).

## Future paper encoding

Paper/manual transport is a representation above the unchanged binary blob, not
encryption. A future `encode-paper`/`decode-paper` format should use a human-friendly
Base32-style alphabet that removes `0/O` and `1/I/l`, groups symbols, and authenticates
transcription blocks with checksums. It requires its own canonical specification and
error analysis before implementation.

