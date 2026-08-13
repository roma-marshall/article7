pub const PROTOCOL_VERSION: u8 = 1;
pub const CRYPTO_SUITE_CLASSICAL_V1: u8 = 1;
pub const PROFILE_VERSION: u8 = 1;

pub const ED25519_PUBLIC_LEN: usize = 32;
pub const ED25519_SECRET_LEN: usize = 32;
pub const X25519_PUBLIC_LEN: usize = 32;
pub const X25519_SECRET_LEN: usize = 32;
pub const FINGERPRINT_LEN: usize = 32;
pub const MESSAGE_ID_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const MESSAGE_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const EPHEMERAL_PUBLIC_LEN: usize = 32;
pub const AEAD_TAG_LEN: usize = 16;

pub const OUTER_OVERHEAD: usize = EPHEMERAL_PUBLIC_LEN + NONCE_LEN + AEAD_TAG_LEN;
pub const INTERNAL_FIXED_LEN: usize = 1
    + 1
    + ED25519_PUBLIC_LEN
    + X25519_PUBLIC_LEN
    + FINGERPRINT_LEN
    + MESSAGE_ID_LEN
    + 4
    + SIGNATURE_LEN;

pub const MIN_BLOB_LEN: usize = 512;
pub const MAX_BODY_LEN: usize = 1024 * 1024;
pub const MAX_BLOB_LEN: usize = 2 * 1024 * 1024;

pub const PROFILE_PREFIX: &str = "sealed-profile-v1";
pub const UNLOCK_PREFIX: &str = "sealed-unlock-v1";

pub const FINGERPRINT_DOMAIN: &[u8] = b"sealed/fingerprint/v1";
pub const CONTACT_ROOT_SALT: &[u8] = b"sealed/contact-root/extract/v1";
pub const CONTACT_ROOT_INFO: &[u8] = b"sealed/contact-root/expand/v1";
pub const SUBKEY_SALT: &[u8] = b"sealed/contact-subkey/extract/v1";
pub const STEGO_INFO: &[u8] = b"sealed/steganography/v1";
pub const MESSAGE_KEY_SALT: &[u8] = b"sealed/message-key/extract/v1";
pub const MESSAGE_KEY_INFO: &[u8] = b"sealed/message-key/expand/v1";
pub const SIGNATURE_DOMAIN: &[u8] = b"sealed/message-signature/v1";
pub const OUTER_AAD_DOMAIN: &[u8] = b"sealed/outer-aead/v1";
pub const IDENTITY_AAD_DOMAIN: &[u8] = b"sealed/identity-at-rest/v1";

pub fn padded_blob_len(body_len: usize) -> Option<usize> {
    if body_len > MAX_BODY_LEN {
        return None;
    }
    let required = INTERNAL_FIXED_LEN
        .checked_add(body_len)?
        .checked_add(OUTER_OVERHEAD)?;
    let mut bucket = MIN_BLOB_LEN;
    while bucket < required {
        bucket = bucket.checked_mul(2)?;
    }
    (bucket <= MAX_BLOB_LEN).then_some(bucket)
}

pub fn valid_blob_len(length: usize) -> bool {
    (MIN_BLOB_LEN..=MAX_BLOB_LEN).contains(&length) && length.is_power_of_two()
}

