use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub fn fill_random(destination: &mut [u8]) -> Result<()> {
    getrandom::getrandom(destination).map_err(|_| Error::Randomness)
}

pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    fill_random(&mut bytes)?;
    Ok(bytes)
}

pub trait AdditionalEntropySource {
    fn collect(&mut self) -> Result<Vec<u8>>;
}

pub fn root_seed(additional: Option<&mut dyn AdditionalEntropySource>) -> Result<[u8; 32]> {
    let mut os_random = random_array::<32>()?;
    let mut human_bytes = match additional {
        Some(source) => source.collect()?,
        None => Vec::new(),
    };
    let digest = Sha256::new()
        .chain_update(b"sealed/root-entropy/v1")
        .chain_update(os_random)
        .chain_update((human_bytes.len() as u64).to_be_bytes())
        .chain_update(&human_bytes)
        .finalize();
    os_random.zeroize();
    human_bytes.zeroize();
    Ok(digest.into())
}
