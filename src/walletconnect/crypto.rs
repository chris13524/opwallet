//! WalletConnect v2 message crypto: X25519 key agreement, HKDF session key
//! derivation and ChaCha20-Poly1305 "type 0" envelopes.
//!
//! Session keys are not seed material, but they are still kept in
//! zeroize-on-drop wrappers.

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Fill an array from the OS RNG.
pub fn random_array<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut out = Zeroizing::new([0u8; N]);
    getrandom::fill(&mut *out).map_err(|e| anyhow!("OS RNG failed: {e}"))?;
    Ok(out)
}

/// 32-byte symmetric key for a pairing or session topic.
#[derive(Clone)]
pub struct SymKey(Zeroizing<[u8; 32]>);

impl SymKey {
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = alloy_primitives::hex::decode(hex).context("symKey is not valid hex")?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("symKey must be 32 bytes"))?;
        Ok(Self(Zeroizing::new(arr)))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Hex encoding, for the saved-sessions file.
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(alloy_primitives::hex::encode(&self.0[..]))
    }

    /// The topic a symmetric key implies: sha256(key), hex encoded.
    pub fn topic(&self) -> String {
        alloy_primitives::hex::encode(Sha256::digest(&self.0[..]))
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(&Key::from(*self.0))
    }
}

/// Raw key bytes; only for building test fixtures such as pairing URIs.
#[doc(hidden)]
pub fn decrypt_key_bytes_for_test(key: &SymKey) -> [u8; 32] {
    *key.0
}

/// Encrypt `plaintext` into a base64 type-0 envelope: `0x00 || iv(12) || ciphertext`.
pub fn encrypt(key: &SymKey, plaintext: &[u8]) -> Result<String> {
    let iv = random_array::<12>()?;
    let ciphertext = key
        .cipher()
        .encrypt(&Nonce::from(*iv), plaintext)
        .map_err(|_| anyhow!("encryption failed"))?;
    let mut envelope = Vec::with_capacity(13 + ciphertext.len());
    envelope.push(0);
    envelope.extend_from_slice(&iv[..]);
    envelope.extend_from_slice(&ciphertext);
    Ok(B64.encode(envelope))
}

/// Decrypt a base64 envelope. Only type 0 (symmetric) envelopes are supported;
/// type 1 is used by one-click auth / link mode which this wallet does not do.
pub fn decrypt(key: &SymKey, envelope: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = B64.decode(envelope.trim()).context("envelope is not valid base64")?;
    if bytes.len() < 1 + 12 + 16 {
        bail!("envelope too short");
    }
    match bytes[0] {
        0 => {}
        1 => bail!("type 1 envelopes (wc_sessionAuthenticate / link mode) are not supported"),
        t => bail!("unknown envelope type {t}"),
    }
    let nonce: [u8; 12] = bytes[1..13].try_into().expect("length checked");
    let plaintext = key
        .cipher()
        .decrypt(&Nonce::from(nonce), &bytes[13..])
        .map_err(|_| anyhow!("decryption failed (wrong key or corrupted message)"))?;
    Ok(Zeroizing::new(plaintext))
}

/// Ephemeral X25519 key pair used to derive a session key with the peer.
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Result<Self> {
        let seed = random_array::<32>()?;
        let secret = StaticSecret::from(*seed);
        let public = PublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    pub fn public_hex(&self) -> String {
        alloy_primitives::hex::encode(self.public.as_bytes())
    }

    /// Derive the shared session key: HKDF-SHA256(X25519(self, peer)).
    pub fn derive_session_key(&self, peer_public_hex: &str) -> Result<SymKey> {
        let peer = alloy_primitives::hex::decode(peer_public_hex)
            .context("peer public key is not valid hex")?;
        let peer: [u8; 32] =
            peer.try_into().map_err(|_| anyhow!("peer public key must be 32 bytes"))?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
        let mut okm = [0u8; 32];
        Hkdf::<Sha256>::new(None, shared.as_bytes())
            .expand(&[], &mut okm)
            .map_err(|_| anyhow!("HKDF failed"))?;
        Ok(SymKey::from_bytes(okm))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip_and_tamper_detection() {
        let key = SymKey::from_bytes(*random_array::<32>().unwrap());
        let env = encrypt(&key, b"{\"hello\":1}").unwrap();
        let bytes = B64.decode(&env).unwrap();
        assert_eq!(bytes[0], 0);
        assert_eq!(bytes.len(), 1 + 12 + 11 + 16);
        assert_eq!(&decrypt(&key, &env).unwrap()[..], b"{\"hello\":1}");

        let other = SymKey::from_bytes(*random_array::<32>().unwrap());
        assert!(decrypt(&other, &env).is_err());
        let mut tampered = bytes.clone();
        tampered[20] ^= 1;
        assert!(decrypt(&key, &B64.encode(tampered)).is_err());
        let mut type1 = bytes;
        type1[0] = 1;
        assert!(decrypt(&key, &B64.encode(type1)).unwrap_err().to_string().contains("type 1"));
    }

    #[test]
    fn both_sides_derive_the_same_session_key() {
        let a = KeyPair::generate().unwrap();
        let b = KeyPair::generate().unwrap();
        let ka = a.derive_session_key(&b.public_hex()).unwrap();
        let kb = b.derive_session_key(&a.public_hex()).unwrap();
        assert_eq!(&ka.0[..], &kb.0[..]);
        assert_eq!(ka.topic(), kb.topic());
        assert_eq!(ka.topic().len(), 64);
        assert!(a.derive_session_key("zz").is_err());
    }

    #[test]
    fn symkey_topic_matches_sha256() {
        let key = SymKey::from_hex(&"11".repeat(32)).unwrap();
        assert_eq!(key.topic(), alloy_primitives::hex::encode(Sha256::digest([0x11u8; 32])));
        assert!(SymKey::from_hex("abcd").is_err());
    }
}
