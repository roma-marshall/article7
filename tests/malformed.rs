#![forbid(unsafe_code)]

use sealed::identity::IdentitySecrets;
use sealed::message;
use sealed::protocol::MAX_BLOB_LEN;

fn identities() -> (
    IdentitySecrets,
    sealed::identity::PublicProfile,
    IdentitySecrets,
    sealed::identity::PublicProfile,
) {
    let alice = IdentitySecrets::from_bytes([0x11; 32], [0x22; 32]);
    let alice_profile = alice.public_profile();
    let bob = IdentitySecrets::from_bytes([0x33; 32], [0x44; 32]);
    let bob_profile = bob.public_profile();
    (alice, alice_profile, bob, bob_profile)
}

#[test]
fn every_blob_byte_is_authenticated() {
    let (alice, alice_profile, bob, bob_profile) = identities();
    let blob = message::seal(&alice, &alice_profile, &bob_profile, b"authenticated").unwrap();
    for index in 0..blob.len() {
        let mut tampered = blob.clone();
        tampered[index] ^= 1;
        assert!(
            message::open(&bob, &bob_profile, &[], &tampered).is_err(),
            "byte {index} was not authenticated"
        );
    }
}

#[test]
fn every_truncation_and_appended_data_is_rejected() {
    let (alice, alice_profile, bob, bob_profile) = identities();
    let blob = message::seal(&alice, &alice_profile, &bob_profile, b"truncation").unwrap();
    for length in 0..blob.len() {
        assert!(message::open(&bob, &bob_profile, &[], &blob[..length]).is_err());
    }
    let mut appended = blob;
    appended.push(0);
    assert!(message::open(&bob, &bob_profile, &[], &appended).is_err());
}

#[test]
fn random_and_boundary_sized_inputs_never_open_or_panic() {
    let (_, _, bob, bob_profile) = identities();
    for length in [
        0,
        1,
        31,
        32,
        55,
        56,
        255,
        256,
        511,
        512,
        1024,
        MAX_BLOB_LEN + 1,
    ] {
        let input = vec![0x5a; length];
        assert!(message::open(&bob, &bob_profile, &[], &input).is_err());
    }
}
