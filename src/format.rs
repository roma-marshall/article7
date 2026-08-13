use crate::error::{Error, Result};

pub fn hex_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(ALPHABET[(byte >> 4) as usize] as char);
        encoded.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub fn hex_decode<const N: usize>(encoded: &str) -> Result<[u8; N]> {
    if encoded.len() != N * 2 {
        return Err(Error::InvalidInput("invalid hexadecimal length"));
    }
    let mut decoded = [0_u8; N];
    let bytes = encoded.as_bytes();
    for (index, output) in decoded.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        *output = (high << 4) | low;
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::InvalidInput("invalid hexadecimal character")),
    }
}

pub struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u32_be(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::InvalidInput("malformed binary input"))
    }

    pub fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(Error::InvalidInput("malformed binary input"))?;
        if end > self.input.len() {
            return Err(Error::InvalidInput("truncated binary input"));
        }
        let output = &self.input[self.offset..end];
        self.offset = end;
        Ok(output)
    }

    pub fn remaining(&self) -> usize {
        self.input.len() - self.offset
    }
}
