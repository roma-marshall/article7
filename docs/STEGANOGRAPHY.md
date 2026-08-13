# Steganography status

V1 derives `K_stego` with an independent HKDF domain and defines `StegoEncoder` and
`StegoDecoder` traits. It deliberately ships no linguistic implementation.

Natural, mundane, semantically coherent English with keyed recoverability and low
statistical detectability is a research problem. A synonym-to-bit table, phrasebook,
or publicly decodable substitution scheme would not meet the goal. No online LLM,
API, or network dependency belongs in the offline core.

A future design may investigate keyed arithmetic/range coding over a fixed local
language-model distribution, distribution-preserving linguistic steganography, and
carefully bounded mundane domains such as errands, timing, food, home, work, weather,
and simple questions. The model, tokenization, probability quantization, key schedule,
error behavior, capacity, and complete decoder must be versioned and deterministic.

Any serious candidate requires independent steganographic and statistical review.
Detection or decoding failure must never weaken the underlying AEAD ciphertext.
Security depends on `K_stego`, not secrecy of the algorithm. “Boring is good” is a UX
goal, not a security claim.

