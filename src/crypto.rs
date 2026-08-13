use crate::error::{Error, Result};
use crate::identity::{IdentitySecrets, PublicProfile};
use crate::protocol::{
    CONTACT_ROOT_INFO, CONTACT_ROOT_SALT, CRYPTO_SUITE_CLASSICAL_V1, MESSAGE_KEY_INFO,
    MESSAGE_KEY_SALT, OUTER_AAD_DOMAIN, PROTOCOL_VERSION, SIGNATURE_DOMAIN, STEGO_INFO,
    SUBKEY_SALT,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub fn derive_contact_root(
    local_secrets: &IdentitySecrets,
    local_profile: &PublicProfile,
    peer_profile: &PublicProfile,
) -> Result<Zeroizing<[u8; 32]>> {
    if local_secrets.public_profile() != *local_profile {
        return Err(Error::InvalidInput("local public profile does not match private identity"));
    }
    let local_secret = StaticSecret::from(*local_secrets.agreement_secret());
    let peer_public = X25519PublicKey::from(peer_profile.agreement_public);
    let shared = local_secret.diffie_hellman(&peer_public);
    reject_all_zero(shared.as_bytes())?;

    let local_material = local_profile.canonical_key_material();
    let peer_material = peer_profile.canonical_key_material();
    let (first, second) = if local_material <= peer_material {
        (&local_material, &peer_material)
    } else {
        (&peer_material, &local_material)
    };
    let mut info = Vec::with_capacity(CONTACT_ROOT_INFO.len() + 128);
    info.extend_from_slice(CONTACT_ROOT_INFO);
    info.extend_from_slice(first);
    info.extend_from_slice(second);
    hkdf_32(Some(CONTACT_ROOT_SALT), shared.as_bytes(), &info)
}

pub fn derive_stego_key(contact_root: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    hkdf_32(Some(SUBKEY_SALT), contact_root, STEGO_INFO)
}

pub fn derive_message_key_sender(
    ephemeral_secret: &StaticSecret,
    ephemeral_public: &[u8; 32],
    recipient_agreement_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let recipient_public = X25519PublicKey::from(*recipient_agreement_public);
    let shared = ephemeral_secret.diffie_hellman(&recipient_public);
    reject_all_zero(shared.as_bytes())?;
    derive_message_key_from_shared(
        shared.as_bytes(),
        ephemeral_public,
        recipient_agreement_public,
    )
}

pub fn derive_message_key_recipient(
    recipient_agreement_secret: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_agreement_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let recipient_secret = StaticSecret::from(*recipient_agreement_secret);
    let ephemeral_public_key = X25519PublicKey::from(*ephemeral_public);
    let shared = recipient_secret.diffie_hellman(&ephemeral_public_key);
    reject_all_zero(shared.as_bytes())?;
    derive_message_key_from_shared(
        shared.as_bytes(),
        ephemeral_public,
        recipient_agreement_public,
    )
}

pub fn signature_input(
    sender: &PublicProfile,
    recipient_fingerprint: &[u8; 32],
    message_id: &[u8; 32],
    body: &[u8],
) -> Result<Vec<u8>> {
    let body_len = u32::try_from(body.len())
        .map_err(|_| Error::InvalidInput("message body is too large"))?;
    let mut input = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 134 + body.len());
    input.extend_from_slice(SIGNATURE_DOMAIN);
    input.push(PROTOCOL_VERSION);
    input.push(CRYPTO_SUITE_CLASSICAL_V1);
    input.extend_from_slice(&sender.identity_public);
    input.extend_from_slice(&sender.agreement_public);
    input.extend_from_slice(recipient_fingerprint);
    input.extend_from_slice(message_id);
    input.extend_from_slice(&body_len.to_be_bytes());
    input.extend_from_slice(body);
    Ok(input)
}

pub fn sign_message(
    secrets: &IdentitySecrets,
    sender: &PublicProfile,
    recipient_fingerprint: &[u8; 32],
    message_id: &[u8; 32],
    body: &[u8],
) -> Result<[u8; 64]> {
    if secrets.public_profile() != *sender {
        return Err(Error::InvalidInput("sender public profile does not match private identity"));
    }
    let input = signature_input(sender, recipient_fingerprint, message_id, body)?;
    let signing_key = SigningKey::from_bytes(secrets.identity_secret());
    Ok(signing_key.sign(&input).to_bytes())
}

pub fn verify_message_signature(
    sender: &PublicProfile,
    recipient_fingerprint: &[u8; 32],
    message_id: &[u8; 32],
    body: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<()> {
    let verifying_key =
        VerifyingKey::from_bytes(&sender.identity_public).map_err(|_| Error::Authentication)?;
    let signature = Signature::from_bytes(signature_bytes);
    let input = signature_input(sender, recipient_fingerprint, message_id, body)?;
    verifying_key
        .verify_strict(&input, &signature)
        .map_err(|_| Error::Authentication)
}

pub fn outer_aad(ephemeral_public: &[u8; 32], nonce: &[u8; 24]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(OUTER_AAD_DOMAIN.len() + 56);
    aad.extend_from_slice(OUTER_AAD_DOMAIN);
    aad.extend_from_slice(ephemeral_public);
    aad.extend_from_slice(nonce);
    aad
}

fn derive_message_key_from_shared(
    shared: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_agreement_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut info = Vec::with_capacity(MESSAGE_KEY_INFO.len() + 64);
    info.extend_from_slice(MESSAGE_KEY_INFO);
    info.extend_from_slice(ephemeral_public);
    info.extend_from_slice(recipient_agreement_public);
    hkdf_32(Some(MESSAGE_KEY_SALT), shared, &info)
}

fn hkdf_32(salt: Option<&[u8]>, input: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(salt, input);
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(info, output.as_mut())
        .map_err(|_| Error::InvalidInput("HKDF output length is invalid"))?;
    Ok(output)
}

fn reject_all_zero(shared: &[u8; 32]) -> Result<()> {
    if shared.iter().all(|byte| *byte == 0) {
        Err(Error::Authentication)
    } else {
        Ok(())
    }
}

