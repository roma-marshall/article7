#![forbid(unsafe_code)]

use sealed::error::Error;
use sealed::identity::IdentitySecrets;
use sealed::storage::StatePaths;
use std::fs;
use std::path::PathBuf;

#[test]
fn pinned_identity_is_never_silently_replaced() {
    let sandbox = test_directory();
    fs::create_dir(&sandbox).unwrap();
    let state = StatePaths::from_root(sandbox.join("state"));
    let unlock = sandbox.join("separate-unlock.key");
    let local_profile = state.initialize(&unlock).unwrap();
    assert_eq!(state.load_identity(&unlock).unwrap().1, local_profile);

    let bob = IdentitySecrets::from_bytes([0x33; 32], [0x44; 32]);
    let bob_profile_path = sandbox.join("bob.pub");
    fs::write(&bob_profile_path, bob.public_profile().encode()).unwrap();
    state.trust_profile(&bob_profile_path, "bob").unwrap();
    state.trust_profile(&bob_profile_path, "bob").unwrap();

    let impostor = IdentitySecrets::from_bytes([0x55; 32], [0x66; 32]);
    fs::write(&bob_profile_path, impostor.public_profile().encode()).unwrap();
    assert!(matches!(
        state.trust_profile(&bob_profile_path, "bob"),
        Err(Error::IdentityMismatch)
    ));
    assert_eq!(state.contact("bob").unwrap().profile, bob.public_profile());

    fs::remove_dir_all(&sandbox).unwrap();
}

#[test]
fn wrong_unlock_key_is_rejected() {
    let sandbox = test_directory();
    fs::create_dir(&sandbox).unwrap();
    let state = StatePaths::from_root(sandbox.join("state"));
    let unlock = sandbox.join("unlock.key");
    state.initialize(&unlock).unwrap();
    let wrong = sandbox.join("wrong.key");
    let mut bytes = fs::read(&unlock).unwrap();
    let digit = bytes
        .iter_mut()
        .rev()
        .find(|byte| byte.is_ascii_hexdigit())
        .unwrap();
    *digit = if *digit == b'0' { b'1' } else { b'0' };
    fs::write(&wrong, bytes).unwrap();
    assert!(state.load_identity(&wrong).is_err());
    fs::remove_dir_all(&sandbox).unwrap();
}

fn test_directory() -> PathBuf {
    let mut random = [0_u8; 8];
    getrandom::getrandom(&mut random).unwrap();
    std::env::temp_dir().join(format!(
        "sealed-test-{}-{}",
        std::process::id(),
        u64::from_be_bytes(random)
    ))
}

