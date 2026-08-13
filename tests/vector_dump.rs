#![forbid(unsafe_code)]

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use sealed::crypto::{
    derive_contact_root, derive_message_key_sender, derive_stego_key, outer_aad,
};
use sealed::format::hex_encode;
use sealed::identity::IdentitySecrets;
use sealed::message::serialize_internal;
use sealed::protocol::{INTERNAL_FIXED_LEN, OUTER_OVERHEAD};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn dump_vectors() {
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

    println!("alice_fingerprint={}", hex_encode(&alice_profile.fingerprint));
    println!("bob_fingerprint={}", hex_encode(&bob_profile.fingerprint));
    println!("contact_root={}", hex_encode(&contact_root));
    println!("stego_key={}", hex_encode(&stego_key));
    println!("ephemeral_public={}", hex_encode(&ephemeral_public));
    println!("message_key={}", hex_encode(&message_key));
    println!("internal_sha256={}", hex_encode(&Sha256::digest(&internal)));
    println!("blob={}", hex_encode(&blob));
}

