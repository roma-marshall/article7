# Cryptographic construction

**Status:** experimental, not independently audited. This document records each v1
operation so reviewers can evaluate concrete inputs and reuse rules. No construction
here should be treated as novel cryptographic research.

## Randomness and identity generation

- **Input:** operating-system CSPRNG output; the root-entropy API can additionally mix
  opaque human-event bytes after OS randomness.
- **Output:** independent 32-byte Ed25519 secret, X25519 static secret, unlock key,
  message ID, per-letter X25519 secret, nonce, and padding as applicable.
- **Key/nonce/domain:** no key or nonce. Optional extra root entropy is extracted with
  SHA-256 and `sealed/root-entropy/v1`; OS randomness remains mandatory.
- **Authenticated:** not applicable.
- **Reuse:** identity secrets persist; unlock keys persist. Ephemeral secrets, message
  IDs, nonces, and padding are fresh for every letter. Human input is never treated as
  a quantified or sufficient entropy source.

V1 calls `getrandom`, which delegates to the OS CSPRNG. It contains no application
PRNG. Interactive mouse collection is left behind the `AdditionalEntropySource`
boundary and is not implemented because terminal event handling is not reliably
portable; OS randomness is sufficient.

## Fingerprint

- **Input:** profile version and both public keys.
- **Output:** 32-byte SHA-256 digest, displayed as grouped uppercase hexadecimal.
- **Key/nonce/domain:** unkeyed; domain `sealed/fingerprint/v1`; no nonce.
- **Authenticated:** nothing by itself. The user authenticates it out of band.
- **Reuse:** stable for a profile and intentionally public.

## Contact root

- **Input:** static X25519 DH shared secret and the two lexicographically ordered
  `Ed25519_public || X25519_public` endpoint values.
- **Output:** 32-byte `contact_root`.
- **Key:** DH result as HKDF input keying material.
- **Nonce:** none.
- **Domain:** salt `sealed/contact-root/extract/v1`; info begins
  `sealed/contact-root/expand/v1` followed by the two ordered endpoints.
- **Authenticated:** identities are context-bound in derivation, but authenticity
  ultimately depends on out-of-band fingerprint verification and pinning.
- **Reuse:** root persists for this exact contact pair and is never used directly as
  an AEAD or steganography key.

All-zero X25519 results are rejected.

## Steganography subkey

- **Input:** contact root.
- **Output/key:** 32-byte `K_stego`.
- **Nonce:** construction-specific and unresolved because no production encoder ships.
- **Domain:** HKDF salt `sealed/contact-subkey/extract/v1`, info
  `sealed/steganography/v1`.
- **Authenticated:** not applicable at this layer; decoded bytes remain AEAD-protected.
- **Reuse:** scoped only to steganography for one contact. It is never transmitted and
  never used for message encryption.

## Message signature

- **Input:** domain, version, suite, both sender public keys, recipient fingerprint,
  256-bit message ID, U32BE body length, and body.
- **Output:** 64-byte Ed25519 signature.
- **Key:** sender's long-term Ed25519 private key.
- **Nonce:** Ed25519 is deterministic; no external nonce.
- **Domain:** `sealed/message-signature/v1`.
- **Authenticated:** every listed input. Padding is not signed but is inside AEAD.
- **Reuse:** the signing key signs independent messages safely under Ed25519's standard
  deterministic construction. The domain prevents cross-protocol interpretation.

Opening uses `ed25519-dalek::VerifyingKey::verify_strict`. Mathematical validity and
pinned trust remain separate results.

## Per-letter message key

- **Input:** fresh ephemeral-secret/recipient-static X25519 result, ephemeral public
  key, and recipient static X25519 public key.
- **Output/key:** 32-byte `K_message`.
- **Nonce:** none for HKDF.
- **Domain:** salt `sealed/message-key/extract/v1`; info
  `sealed/message-key/expand/v1 || ephemeral_public || recipient_static_public`.
- **Authenticated:** key context is later bound through AEAD associated data and the
  signed recipient fingerprint inside the plaintext.
- **Reuse:** the ephemeral secret is fresh per message, so the key is fresh. It is used
  for exactly one XChaCha encryption and is never `K_stego`.

All-zero X25519 results are rejected. Message-key and shared-secret storage is
best-effort zeroized on drop where crate types support it.

## Letter AEAD

- **Input:** fully serialized and randomly padded inner message.
- **Output:** ciphertext plus 16-byte tag.
- **Key:** `K_message`.
- **Nonce:** fresh OS-random 24-byte XChaCha nonce.
- **Domain/AAD:** `sealed/outer-aead/v1 || ephemeral_public || nonce`.
- **Authenticated:** the complete inner plaintext, all padding, visible ephemeral
  public bytes, and visible nonce.
- **Reuse:** a per-letter key and random 192-bit nonce are generated each time. Neither
  key nor nonce is intentionally reused.

## Private identity at rest

- **Input:** `profile_version || Ed25519_secret || X25519_static_secret` (65 bytes).
- **Output:** `nonce[24] || XChaCha20-Poly1305_ciphertext_and_tag[81]` (105 bytes).
- **Key:** independent OS-random 256-bit unlock key stored at a user-selected separate
  path.
- **Nonce:** fresh OS-random 24-byte nonce whenever an identity is created.
- **Domain/AAD:** `sealed/identity-at-rest/v1`.
- **Authenticated:** version and both private keys, plus the fixed domain.
- **Reuse:** the unlock key protects one identity file. V1 does not yet provide key
  rotation/re-encryption, so the nonce is generated once. It must never be reused with
  the same unlock key for a second encryption.

The decrypted private keys are checked against `identity.pub`. No password KDF exists
in v1; a weak human password is never silently substituted for the random unlock key.

## Known limits

V1's sender-ephemeral/recipient-static design does **not** provide full forward
secrecy. Anyone who records old ciphertext and later obtains the recipient's static
X25519 secret can derive old message keys. Do not retrofit a custom ratchet. Future
work must evaluate established signed-prekey, one-time-prekey, or asynchronous
ratcheting designs.

Likewise, static keys and stateless blobs cannot guarantee cryptographic one-time
opening. Logical file deletion is only local lifecycle behavior. The raw X25519 public
key and fixed layout are not claimed to be formally uniform random or a PURB.

Zeroization is best effort: compiler transformations, copies, swap, crash dumps,
filesystems, and SSD wear-leveling can defeat physical erasure claims.

