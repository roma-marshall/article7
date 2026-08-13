# Threat model

## Protected goal

Given uncompromised endpoints, correctly pinned public profiles, and secret private
keys, an adversary controlling transport should not learn a letter body, modify
authenticated content undetectably, or impersonate an already pinned sender without a
visible key mismatch.

The transport may intercept, copy, retain forever, modify, replace, truncate, append,
delete, delay, reorder, and replay blobs. It may feed random data or another person's
blob. Depending on the chosen transport, it may also observe sender/receiver network
identities, timing, frequency, and padded sizes.

The unauthenticated surface accepts only a power-of-two length check and fixed offsets
for 32 ephemeral-key bytes and 24 nonce bytes. Other failures are externally
`Cannot open blob.`.

## Trust establishment

Public profiles can cross hostile transport. Users must compare the complete
fingerprint in person, by voice, on paper, or over another independently trusted
channel. A pinned alias is immutable: importing different key material under that
alias is a hard `IDENTITY MISMATCH / POSSIBLE MITM` event. Valid signatures from
unrecognized profiles remain `UNKNOWN`.

## Explicitly not solved

- Endpoint malware, compromised operating systems, keyloggers, memory inspection,
  screen capture, cameras, copy/paste, manual transcription, deliberate forwarding,
  physical coercion, and theft of unlocked media.
- Availability: hostile transport can delete or delay every blob.
- Traffic metadata: content cryptography does not hide transport participants, timing,
  location, frequency, or which application sent bytes.
- Full forward secrecy: later theft of the recipient's static X25519 secret can expose
  previously recorded blobs.
- Cryptographic one-open behavior: an attacker can copy and replay a blob. No replay
  database exists. Local consume behavior is not a protocol guarantee.
- Guaranteed physical deletion: journaling filesystems, snapshots, backups, flash
  translation layers, and SSD wear-leveling can retain data.
- Formal random-blob indistinguishability: no PURB or Elligator encoding is used.
- Production linguistic steganographic security or statistical undetectability.

Adding persistent replay state could expose a durable message-history signal and
still would not stop copies restored with old state. That privacy/state trade-off is
unresolved. Adding asynchronous forward secrecy requires an established protocol,
not an improvised ratchet.

## Layer boundaries

- Cryptography protects body confidentiality, integrity, sender signature, and
  recipient binding.
- Power-of-two padding reduces exact length leakage but reveals a bucket.
- A future keyed steganography layer may conceal the ciphertext form but cannot repair
  weak cryptography.
- A future optional transport may reduce network metadata. It is outside this core.

The maintainers and AI-generated code are not trust roots. Users and independent
reviewers must be able to verify the specification, source, dependencies, vectors,
and builds without trusting project infrastructure.

