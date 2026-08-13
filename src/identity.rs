use crate::entropy::random_array;
use crate::error::{Error, Result};
use crate::format::{hex_decode, hex_encode};
use crate::protocol::{
    ED25519_SECRET_LEN, FINGERPRINT_DOMAIN, IDENTITY_AAD_DOMAIN, NONCE_LEN, PROFILE_PREFIX,
    PROFILE_VERSION, UNLOCK_PREFIX, X25519_SECRET_LEN,
};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const PRIVATE_PLAINTEXT_LEN: usize = 1 + ED25519_SECRET_LEN + X25519_SECRET_LEN;
const PRIVATE_FILE_MAX_LEN: usize = NONCE_LEN + PRIVATE_PLAINTEXT_LEN + 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicProfile {
    pub version: u8,
    pub identity_public: [u8; 32],
    pub agreement_public: [u8; 32],
    pub fingerprint: [u8; 32],
}

impl PublicProfile {
    pub fn new(identity_public: [u8; 32], agreement_public: [u8; 32]) -> Self {
        let fingerprint = fingerprint(PROFILE_VERSION, &identity_public, &agreement_public);
        Self {
            version: PROFILE_VERSION,
            identity_public,
            agreement_public,
            fingerprint,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        format!(
            "{PROFILE_PREFIX}\ned25519={}\nx25519={}\nfingerprint={}\n",
            hex_encode(&self.identity_public),
            hex_encode(&self.agreement_public),
            hex_encode(&self.fingerprint)
        )
        .into_bytes()
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 512 {
            return Err(Error::InvalidInput("public profile is too large"));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| Error::InvalidInput("public profile is not UTF-8"))?;
        let mut lines = text.lines();
        if lines.next() != Some(PROFILE_PREFIX) {
            return Err(Error::InvalidInput("unsupported public profile"));
        }
        let identity_public = parse_field::<32>(lines.next(), "ed25519=")?;
        let agreement_public = parse_field::<32>(lines.next(), "x25519=")?;
        let supplied_fingerprint = parse_field::<32>(lines.next(), "fingerprint=")?;
        if lines.next().is_some() {
            return Err(Error::InvalidInput("unexpected public profile field"));
        }
        let profile = Self::new(identity_public, agreement_public);
        if profile.fingerprint != supplied_fingerprint {
            return Err(Error::InvalidInput("public profile fingerprint is invalid"));
        }
        Ok(profile)
    }

    pub fn canonical_key_material(&self) -> [u8; 64] {
        let mut material = [0_u8; 64];
        material[..32].copy_from_slice(&self.identity_public);
        material[32..].copy_from_slice(&self.agreement_public);
        material
    }

    pub fn formatted_fingerprint(&self) -> String {
        format_fingerprint(&self.fingerprint)
    }
}

pub struct IdentitySecrets {
    identity_secret: [u8; ED25519_SECRET_LEN],
    agreement_secret: [u8; X25519_SECRET_LEN],
}

impl IdentitySecrets {
    pub fn generate() -> Result<(Self, PublicProfile)> {
        let identity_secret = random_array::<ED25519_SECRET_LEN>()?;
        let agreement_secret = random_array::<X25519_SECRET_LEN>()?;
        let secrets = Self {
            identity_secret,
            agreement_secret,
        };
        let profile = secrets.public_profile();
        Ok((secrets, profile))
    }

    pub fn from_bytes(
        identity_secret: [u8; ED25519_SECRET_LEN],
        agreement_secret: [u8; X25519_SECRET_LEN],
    ) -> Self {
        Self {
            identity_secret,
            agreement_secret,
        }
    }

    pub fn public_profile(&self) -> PublicProfile {
        let signing_key = SigningKey::from_bytes(&self.identity_secret);
        let agreement_secret = StaticSecret::from(self.agreement_secret);
        let agreement_public = X25519PublicKey::from(&agreement_secret);
        PublicProfile::new(
            signing_key.verifying_key().to_bytes(),
            agreement_public.to_bytes(),
        )
    }

    pub(crate) fn identity_secret(&self) -> &[u8; ED25519_SECRET_LEN] {
        &self.identity_secret
    }

    pub(crate) fn agreement_secret(&self) -> &[u8; X25519_SECRET_LEN] {
        &self.agreement_secret
    }
}

impl Drop for IdentitySecrets {
    fn drop(&mut self) {
        self.identity_secret.zeroize();
        self.agreement_secret.zeroize();
    }
}

pub fn fingerprint(
    profile_version: u8,
    identity_public: &[u8; 32],
    agreement_public: &[u8; 32],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(FINGERPRINT_DOMAIN)
        .chain_update([profile_version])
        .chain_update(identity_public)
        .chain_update(agreement_public)
        .finalize()
        .into()
}

pub fn format_fingerprint(fingerprint: &[u8; 32]) -> String {
    let hex = hex_encode(fingerprint).to_ascii_uppercase();
    let mut output = String::with_capacity(hex.len() + 15);
    for (index, chunk) in hex.as_bytes().chunks(4).enumerate() {
        if index != 0 {
            output.push('-');
        }
        for byte in chunk {
            output.push(*byte as char);
        }
    }
    output
}

pub fn encode_unlock_key(unlock_key: &[u8; 32]) -> Vec<u8> {
    format!("{UNLOCK_PREFIX}\n{}\n", hex_encode(unlock_key)).into_bytes()
}

pub fn parse_unlock_key(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if bytes.len() > 128 {
        return Err(Error::InvalidInput("unlock key file is too large"));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::InvalidInput("unlock key file is not UTF-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(UNLOCK_PREFIX) {
        return Err(Error::InvalidInput("unsupported unlock key file"));
    }
    let encoded = lines
        .next()
        .ok_or(Error::InvalidInput("unlock key is missing"))?;
    if lines.next().is_some() {
        return Err(Error::InvalidInput("unexpected unlock key field"));
    }
    Ok(Zeroizing::new(hex_decode(encoded)?))
}

pub fn encrypt_private_identity(
    secrets: &IdentitySecrets,
    unlock_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let nonce = random_array::<NONCE_LEN>()?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(PRIVATE_PLAINTEXT_LEN));
    plaintext.push(PROFILE_VERSION);
    plaintext.extend_from_slice(secrets.identity_secret());
    plaintext.extend_from_slice(secrets.agreement_secret());

    let cipher = XChaCha20Poly1305::new(unlock_key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: IDENTITY_AAD_DOMAIN,
            },
        )
        .map_err(|_| Error::Authentication)?;
    let mut encoded = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(&ciphertext);
    Ok(encoded)
}

pub fn decrypt_private_identity(
    encrypted: &[u8],
    unlock_key: &[u8; 32],
) -> Result<IdentitySecrets> {
    if encrypted.len() != PRIVATE_FILE_MAX_LEN {
        return Err(Error::Authentication);
    }
    let (nonce, ciphertext) = encrypted.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(unlock_key.into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: IDENTITY_AAD_DOMAIN,
            },
        )
        .map_err(|_| Error::Authentication)?;
    let plaintext = Zeroizing::new(plaintext);
    if plaintext.len() != PRIVATE_PLAINTEXT_LEN || plaintext[0] != PROFILE_VERSION {
        return Err(Error::Authentication);
    }
    let identity_secret = plaintext[1..33]
        .try_into()
        .map_err(|_| Error::Authentication)?;
    let agreement_secret = plaintext[33..65]
        .try_into()
        .map_err(|_| Error::Authentication)?;
    Ok(IdentitySecrets::from_bytes(
        identity_secret,
        agreement_secret,
    ))
}

fn parse_field<const N: usize>(line: Option<&str>, prefix: &'static str) -> Result<[u8; N]> {
    let line = line.ok_or(Error::InvalidInput("public profile field is missing"))?;
    let encoded = line
        .strip_prefix(prefix)
        .ok_or(Error::InvalidInput("invalid public profile field"))?;
    hex_decode(encoded)
}
