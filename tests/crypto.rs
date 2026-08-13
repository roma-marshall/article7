#![forbid(unsafe_code)]

use sealed::contact::Contact;
use sealed::crypto::{derive_contact_root, derive_stego_key};
use sealed::identity::{
    IdentitySecrets, decrypt_private_identity, encrypt_private_identity, fingerprint,
};
use sealed::message::{self, SenderTrust};
use sealed::protocol::{MAX_BODY_LEN, padded_blob_len};

fn alice() -> (IdentitySecrets, sealed::identity::PublicProfile) {
    let secrets = IdentitySecrets::from_bytes([0x11; 32], [0x22; 32]);
    let profile = secrets.public_profile();
    (secrets, profile)
}

fn bob() -> (IdentitySecrets, sealed::identity::PublicProfile) {
    let secrets = IdentitySecrets::from_bytes([0x33; 32], [0x44; 32]);
    let profile = secrets.public_profile();
    (secrets, profile)
}

#[test]
fn contact_and_stego_derivations_are_symmetric() {
    let (alice_secrets, alice_profile) = alice();
    let (bob_secrets, bob_profile) = bob();
    let alice_root = derive_contact_root(&alice_secrets, &alice_profile, &bob_profile).unwrap();
    let bob_root = derive_contact_root(&bob_secrets, &bob_profile, &alice_profile).unwrap();
    assert_eq!(*alice_root, *bob_root);
    assert_eq!(
        *derive_stego_key(&alice_root).unwrap(),
        *derive_stego_key(&bob_root).unwrap()
    );
}

#[test]
fn encrypted_private_identity_round_trips_and_rejects_tampering() {
    let (secrets, profile) = alice();
    let unlock = [0xa5; 32];
    let encrypted = encrypt_private_identity(&secrets, &unlock).unwrap();
    assert_eq!(
        decrypt_private_identity(&encrypted, &unlock)
            .unwrap()
            .public_profile(),
        profile
    );

    for index in 0..encrypted.len() {
        let mut tampered = encrypted.clone();
        tampered[index] ^= 1;
        assert!(decrypt_private_identity(&tampered, &unlock).is_err());
    }
    assert!(decrypt_private_identity(&encrypted, &[0xa4; 32]).is_err());
}

#[test]
fn sealed_letter_round_trips_and_identical_bodies_differ() {
    let (alice_secrets, alice_profile) = alice();
    let (bob_secrets, bob_profile) = bob();
    let contact = Contact {
        alias: "alice".to_owned(),
        profile: alice_profile.clone(),
    };
    let first = message::seal(&alice_secrets, &alice_profile, &bob_profile, b"hello").unwrap();
    let second = message::seal(&alice_secrets, &alice_profile, &bob_profile, b"hello").unwrap();
    assert_ne!(first, second);
    assert_eq!(first.len(), padded_blob_len(5).unwrap());
    assert!(first.len().is_power_of_two());

    let opened = message::open(&bob_secrets, &bob_profile, &[contact], &first).unwrap();
    assert_eq!(&*opened.body, b"hello");
    assert_eq!(
        opened.sender_trust,
        SenderTrust::Pinned {
            alias: "alice".to_owned()
        }
    );
}

#[test]
fn valid_unpinned_sender_is_not_reported_as_trusted() {
    let (alice_secrets, alice_profile) = alice();
    let (bob_secrets, bob_profile) = bob();
    let blob = message::seal(&alice_secrets, &alice_profile, &bob_profile, b"hello").unwrap();
    let opened = message::open(&bob_secrets, &bob_profile, &[], &blob).unwrap();
    assert_eq!(opened.sender_trust, SenderTrust::Unknown);
}

#[test]
fn wrong_recipient_cannot_open() {
    let (alice_secrets, alice_profile) = alice();
    let (_, bob_profile) = bob();
    let mallory = IdentitySecrets::from_bytes([0x55; 32], [0x77; 32]);
    let mallory_profile = mallory.public_profile();
    let blob = message::seal(&alice_secrets, &alice_profile, &bob_profile, b"hello").unwrap();
    assert!(message::open(&mallory, &mallory_profile, &[], &blob).is_err());
}

#[test]
fn fingerprint_changes_when_either_public_key_changes() {
    let original = fingerprint(1, &[1; 32], &[2; 32]);
    assert_ne!(original, fingerprint(1, &[3; 32], &[2; 32]));
    assert_ne!(original, fingerprint(1, &[1; 32], &[3; 32]));
}

#[test]
fn oversized_body_is_rejected_without_allocation() {
    let (alice_secrets, alice_profile) = alice();
    let (_, bob_profile) = bob();
    let body = vec![0_u8; MAX_BODY_LEN + 1];
    assert!(message::seal(&alice_secrets, &alice_profile, &bob_profile, &body).is_err());
}
