#![forbid(unsafe_code)]

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use sealed::crypto::{
    derive_contact_root, derive_message_key_recipient, derive_message_key_sender,
    derive_stego_key, outer_aad,
};
use sealed::format::hex_encode;
use sealed::identity::IdentitySecrets;
use sealed::message::serialize_internal;
use sealed::protocol::{INTERNAL_FIXED_LEN, OUTER_OVERHEAD};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn classical_v1_public_vector_is_stable() {
    let vector = parse_vector(include_str!("vectors/classical-v1.txt"));
    let alice = IdentitySecrets::from_bytes([0x11; 32], [0x22; 32]);
    let alice_profile = alice.public_profile();
    let bob = IdentitySecrets::from_bytes([0x33; 32], [0x44; 32]);
    let bob_profile = bob.public_profile();
    let contact_root = derive_contact_root(&alice, &alice_profile, &bob_profile).unwrap();
    let stego_key = derive_stego_key(&contact_root).unwrap();
    let ephemeral_secret = StaticSecret::from([0x55; 32]);
    let ephemeral_public = PublicKey::from(&ephemeral_secret).to_bytes();
    let message_key = derive_message_key_sender(
        &ephemeral_secret,
        &ephemeral_public,
        &bob_profile.agreement_public,
    )
    .unwrap();
    let recipient_message_key = derive_message_key_recipient(
        bob.agreement_secret_for_test(),
        &ephemeral_public,
        &bob_profile.agreement_public,
    )
    .unwrap();
    assert_eq!(*message_key, *recipient_message_key);

    let nonce = [0x77; 24];
    let message_id = [0x66; 32];
    let body = b"vector letter";
    let padding_len = 512 - OUTER_OVERHEAD - INTERNAL_FIXED_LEN - body.len();
    let padding = vec![0x88; padding_len];
    let internal = serialize_internal(
        &alice,
        &alice_profile,
        &bob_profile,
        &message_id,
        body,
        &padding,
    )
    .unwrap();
    let aad = outer_aad(&ephemeral_public, &nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(message_key.as_ref()).unwrap();
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &internal,
                aad: &aad,
            },
        )
        .unwrap();
    let mut blob = Vec::new();
    blob.extend_from_slice(&ephemeral_public);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    assert_field(&vector, "alice_fingerprint", &hex_encode(&alice_profile.fingerprint));
    assert_field(&vector, "bob_fingerprint", &hex_encode(&bob_profile.fingerprint));
    assert_field(&vector, "contact_root", &hex_encode(contact_root.as_ref()));
    assert_field(&vector, "stego_key", &hex_encode(stego_key.as_ref()));
    assert_field(&vector, "ephemeral_public", &hex_encode(&ephemeral_public));
    assert_field(&vector, "message_key", &hex_encode(message_key.as_ref()));
    assert_field(
        &vector,
        "internal_sha256",
        &hex_encode(&Sha256::digest(&internal)),
    );
    assert_field(&vector, "blob", &hex_encode(&blob));
}

fn parse_vector(input: &str) -> BTreeMap<&str, &str> {
    input
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_once('=').expect("vector line must contain '='"))
        .collect()
}

fn assert_field(vector: &BTreeMap<&str, &str>, name: &str, actual: &str) {
    assert_eq!(vector.get(name).copied(), Some(actual), "vector field {name}");
}

