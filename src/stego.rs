use crate::error::Result;

/// Boundary for a future independently reviewed, keyed steganographic encoder.
///
/// V1 deliberately ships no production linguistic implementation.
pub trait StegoEncoder {
    fn encode(&self, stego_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// Boundary for a future independently reviewed, keyed steganographic decoder.
pub trait StegoDecoder {
    fn decode(&self, stego_key: &[u8; 32], cover_text: &[u8]) -> Result<Vec<u8>>;
}
