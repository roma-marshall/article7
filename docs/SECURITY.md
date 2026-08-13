# Security engineering notes

The application crates use `#![forbid(unsafe_code)]`. No private keys, shared secrets,
unlock keys, message keys, plaintexts, or padding are logged. There is no developer
key, recovery path, escrow recipient, telemetry, update channel, remote configuration,
networking, or hardcoded secret.

Private scalar arrays, unlock keys, message keys, decrypted identity bytes, plaintext
bodies, and generated padding use explicit or drop-based `zeroize` handling where
practical. This is best effort, not a guarantee against compiler copies, swap, crash
dumps, snapshots, SSD remapping, or compromised endpoints.

The CLI refuses symlinks for state files and incoming blobs, bounds every file read,
uses create-new semantics for secrets and contacts, applies mode 0600 to files and
0700 to state directories on Unix, and never overwrites a pinned contact. Windows ACL
hardening remains a platform-specific audit item; ordinary Rust permission APIs do not
provide an equivalent Unix-mode guarantee.

On Unix, the optional interactive selector invokes the system `/bin/stty` utility only
to capture arrow keys from `/dev/tty`; it restores the prior terminal mode on normal
return and uses numeric selection if raw terminal setup fails. This UI boundary is
outside the cryptographic core and has no network capability.

Do not report a blob parsing detail as a public CLI error. Pre-authentication and
post-authentication malformed-message failures intentionally collapse to
`Cannot open blob.`. Developer diagnostics must not print secrets if later added.

See the repository [SECURITY.md](../SECURITY.md) for vulnerability reporting.
