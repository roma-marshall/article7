use crate::contact::Contact;
use crate::crypto::{
    derive_message_key_recipient, derive_message_key_sender, outer_aad, sign_message,
    verify_message_signature,
};
use crate::entropy::random_array;
use crate::error::{Error, Result};
use crate::format::Reader;
use crate::identity::{IdentitySecrets, PublicProfile};
use crate::protocol::{
    CRYPTO_SUITE_CLASSICAL_V1, EPHEMERAL_PUBLIC_LEN, INTERNAL_FIXED_LEN, MAX_BODY_LEN, NONCE_LEN,
    OUTER_OVERHEAD, PROTOCOL_VERSION, SIGNATURE_LEN, padded_blob_len, valid_blob_len,
};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SenderTrust {
    Pinned { alias: String },
    Unknown,
}

pub struct OpenedLetter {
    pub body: Zeroizing<Vec<u8>>,
    pub message_id: [u8; 32],
    pub sender: PublicProfile,
    pub sender_trust: SenderTrust,
}

struct ParsedMessage {
    sender: PublicProfile,
    recipient_fingerprint: [u8; 32],
    message_id: [u8; 32],
    body: Zeroizing<Vec<u8>>,
    signature: [u8; SIGNATURE_LEN],
}

pub fn seal(
    sender_secrets: &IdentitySecrets,
    sender_profile: &PublicProfile,
    recipient: &PublicProfile,
    body: &[u8],
) -> Result<Vec<u8>> {
    if body.len() > MAX_BODY_LEN {
        return Err(Error::InvalidInput("message body exceeds the 1 MiB limit"));
    }
    let ephemeral_seed = Zeroizing::new(random_array::<32>()?);
    let ephemeral_secret = StaticSecret::from(*ephemeral_seed);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret).to_bytes();
    let nonce = random_array::<NONCE_LEN>()?;
    let message_id = random_array::<32>()?;
    let blob_len = padded_blob_len(body.len()).ok_or(Error::InvalidInput(
        "message cannot fit a supported padding bucket",
    ))?;
    let plaintext_len = blob_len - OUTER_OVERHEAD;
    let padding_len = plaintext_len - INTERNAL_FIXED_LEN - body.len();
    let padding = Zeroizing::new(random_bytes(padding_len)?);

    let internal = serialize_internal(
        sender_secrets,
        sender_profile,
        recipient,
        &message_id,
        body,
        &padding,
    )?;
    if internal.len() != plaintext_len {
        return Err(Error::InvalidInput("internal padding calculation failed"));
    }

    let message_key = derive_message_key_sender(
        &ephemeral_secret,
        &ephemeral_public,
        &recipient.agreement_public,
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(message_key.as_ref())
        .map_err(|_| Error::Authentication)?;
    let aad = outer_aad(&ephemeral_public, &nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &internal,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Authentication)?;

    let mut blob = Vec::with_capacity(blob_len);
    blob.extend_from_slice(&ephemeral_public);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    if blob.len() != blob_len {
        return Err(Error::InvalidInput("outer padding calculation failed"));
    }
    Ok(blob)
}

pub fn open(
    recipient_secrets: &IdentitySecrets,
    recipient_profile: &PublicProfile,
    contacts: &[Contact],
    blob: &[u8],
) -> Result<OpenedLetter> {
    if !valid_blob_len(blob.len()) || blob.len() < OUTER_OVERHEAD {
        return Err(Error::CannotOpen);
    }
    if recipient_secrets.public_profile() != *recipient_profile {
        return Err(Error::CannotOpen);
    }

    let ephemeral_public: [u8; EPHEMERAL_PUBLIC_LEN] = blob[..EPHEMERAL_PUBLIC_LEN]
        .try_into()
        .map_err(|_| Error::CannotOpen)?;
    let nonce: [u8; NONCE_LEN] = blob[EPHEMERAL_PUBLIC_LEN..EPHEMERAL_PUBLIC_LEN + NONCE_LEN]
        .try_into()
        .map_err(|_| Error::CannotOpen)?;
    let ciphertext = &blob[EPHEMERAL_PUBLIC_LEN + NONCE_LEN..];
    let message_key = derive_message_key_recipient(
        recipient_secrets.agreement_secret(),
        &ephemeral_public,
        &recipient_profile.agreement_public,
    )
    .map_err(|_| Error::CannotOpen)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(message_key.as_ref()).map_err(|_| Error::CannotOpen)?;
    let aad = outer_aad(&ephemeral_public, &nonce);
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::CannotOpen)?;
    let plaintext = Zeroizing::new(plaintext);
    let parsed = parse_internal(&plaintext).map_err(|_| Error::CannotOpen)?;
    if parsed.recipient_fingerprint != recipient_profile.fingerprint {
        return Err(Error::CannotOpen);
    }
    verify_message_signature(
        &parsed.sender,
        &parsed.recipient_fingerprint,
        &parsed.message_id,
        &parsed.body,
        &parsed.signature,
    )
    .map_err(|_| Error::CannotOpen)?;

    let sender_trust = contacts
        .iter()
        .find(|contact| contact.profile == parsed.sender)
        .map(|contact| SenderTrust::Pinned {
            alias: contact.alias.clone(),
        })
        .unwrap_or(SenderTrust::Unknown);

    Ok(OpenedLetter {
        body: parsed.body,
        message_id: parsed.message_id,
        sender: parsed.sender,
        sender_trust,
    })
}

pub fn serialize_internal(
    sender_secrets: &IdentitySecrets,
    sender_profile: &PublicProfile,
    recipient: &PublicProfile,
    message_id: &[u8; 32],
    body: &[u8],
    padding: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if body.len() > MAX_BODY_LEN {
        return Err(Error::InvalidInput("message body exceeds the 1 MiB limit"));
    }
    let body_len =
        u32::try_from(body.len()).map_err(|_| Error::InvalidInput("message body is too large"))?;
    let signature = sign_message(
        sender_secrets,
        sender_profile,
        &recipient.fingerprint,
        message_id,
        body,
    )?;
    let capacity = INTERNAL_FIXED_LEN
        .checked_add(body.len())
        .and_then(|length| length.checked_add(padding.len()))
        .ok_or(Error::InvalidInput("internal message length overflow"))?;
    let mut output = Zeroizing::new(Vec::with_capacity(capacity));
    output.push(PROTOCOL_VERSION);
    output.push(CRYPTO_SUITE_CLASSICAL_V1);
    output.extend_from_slice(&sender_profile.identity_public);
    output.extend_from_slice(&sender_profile.agreement_public);
    output.extend_from_slice(&recipient.fingerprint);
    output.extend_from_slice(message_id);
    output.extend_from_slice(&body_len.to_be_bytes());
    output.extend_from_slice(body);
    output.extend_from_slice(&signature);
    output.extend_from_slice(padding);
    Ok(output)
}

fn parse_internal(plaintext: &[u8]) -> Result<ParsedMessage> {
    if plaintext.len() < INTERNAL_FIXED_LEN {
        return Err(Error::InvalidInput("internal message is truncated"));
    }
    let mut reader = Reader::new(plaintext);
    if reader.byte()? != PROTOCOL_VERSION {
        return Err(Error::InvalidInput("unsupported protocol version"));
    }
    if reader.byte()? != CRYPTO_SUITE_CLASSICAL_V1 {
        return Err(Error::InvalidInput("unsupported cryptographic suite"));
    }
    let identity_public = reader.array::<32>()?;
    let agreement_public = reader.array::<32>()?;
    let sender = PublicProfile::new(identity_public, agreement_public);
    let recipient_fingerprint = reader.array::<32>()?;
    let message_id = reader.array::<32>()?;
    let body_len = usize::try_from(reader.u32_be()?)
        .map_err(|_| Error::InvalidInput("invalid body length"))?;
    if body_len > MAX_BODY_LEN || body_len > reader.remaining().saturating_sub(SIGNATURE_LEN) {
        return Err(Error::InvalidInput("invalid body length"));
    }
    let body = Zeroizing::new(reader.take(body_len)?.to_vec());
    let signature = reader.array::<SIGNATURE_LEN>()?;
    let _authenticated_padding = reader.take(reader.remaining())?;
    Ok(ParsedMessage {
        sender,
        recipient_fingerprint,
        message_id,
        body,
        signature,
    })
}

fn random_bytes(length: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0_u8; length];
    crate::entropy::fill_random(&mut bytes)?;
    Ok(bytes)
}
