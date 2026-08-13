#![forbid(unsafe_code)]

use sealed::identity::{IdentitySecrets, PublicProfile};
use sealed::message::serialize_internal;
use sealed::protocol::{
    INTERNAL_FIXED_LEN, MAX_BODY_LEN, MIN_BLOB_LEN, OUTER_OVERHEAD, padded_blob_len,
    valid_blob_len,
};

#[test]
fn profile_encoding_is_canonical_and_self_validating() {
    let profile = PublicProfile::new([1; 32], [2; 32]);
    let encoded = profile.encode();
    assert_eq!(PublicProfile::parse(&encoded).unwrap(), profile);

    let mut tampered = encoded;
    let index = tampered.iter().position(|byte| *byte == b'1').unwrap();
    tampered[index] = b'2';
    assert!(PublicProfile::parse(&tampered).is_err());
}

#[test]
fn padding_uses_complete_power_of_two_outer_buckets() {
    for body_len in [0, 1, 100, 1000, MAX_BODY_LEN] {
        let blob_len = padded_blob_len(body_len).unwrap();
        assert!(blob_len >= MIN_BLOB_LEN);
        assert!(blob_len.is_power_of_two());
        assert!(blob_len >= OUTER_OVERHEAD + INTERNAL_FIXED_LEN + body_len);
        assert!(valid_blob_len(blob_len));
    }
    assert!(padded_blob_len(MAX_BODY_LEN + 1).is_none());
    assert!(!valid_blob_len(0));
    assert!(!valid_blob_len(MIN_BLOB_LEN + 1));
}

#[test]
fn internal_serialization_is_deterministic() {
    let sender = IdentitySecrets::from_bytes([0x11; 32], [0x22; 32]);
    let sender_profile = sender.public_profile();
    let recipient = IdentitySecrets::from_bytes([0x33; 32], [0x44; 32]);
    let recipient_profile = recipient.public_profile();
    let message_id = [0x66; 32];
    let first = serialize_internal(
        &sender,
        &sender_profile,
        &recipient_profile,
        &message_id,
        b"vector letter",
        &[0x88; 7],
    )
    .unwrap();
    let second = serialize_internal(
        &sender,
        &sender_profile,
        &recipient_profile,
        &message_id,
        b"vector letter",
        &[0x88; 7],
    )
    .unwrap();
    assert_eq!(*first, *second);
}

