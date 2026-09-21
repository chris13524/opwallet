//! Key material handling: BIP-39 mnemonics, BIP-32/44 derivation and EIP-191
//! message signing, implemented in-crate so every intermediate secret
//! (entropy, phrase, seed, extended keys) lives in a [`SecretBuf`] or a
//! `Zeroizing` wrapper and is wiped as soon as it is no longer needed.
//!
//! Error messages never contain any part of a phrase.

use std::sync::LazyLock;

use alloy_primitives::{Address, B256, Signature, hex};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{Context, Result, anyhow, bail};
use hmac::{Hmac, Mac};
use k256::elliptic_curve::{PrimeField, sec1::ToEncodedPoint};
use sha2::{Digest, Sha256, Sha512};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::secret::SecretBuf;

/// Standard Ethereum derivation path (BIP-44, coin type 60, first account).
pub const DEFAULT_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";

/// Word counts BIP-39 allows.
pub const ALLOWED_WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];

/// Longest word in the English list (used for constant-time comparison padding).
const MAX_WORD_LEN: usize = 8;

/// PBKDF2 rounds mandated by BIP-39.
const PBKDF2_ROUNDS: u32 = 2048;

/// The official BIP-39 English wordlist
/// (sha256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda).
static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let words: Vec<&str> = include_str!("bip39-english.txt").lines().collect();
    assert_eq!(words.len(), 2048, "embedded wordlist is corrupt");
    words
});

/// Look a word up in the wordlist without early exit, so timing does not
/// depend on which word (if any) matched.
fn word_index(word: &str) -> Option<u16> {
    if word.is_empty() || word.len() > MAX_WORD_LEN || !word.is_ascii() {
        return None;
    }
    let mut probe = [0u8; MAX_WORD_LEN];
    probe[..word.len()].copy_from_slice(word.as_bytes());
    let mut found = Choice::from(0u8);
    let mut index = 0u16;
    for (i, w) in WORDS.iter().enumerate() {
        let mut cand = [0u8; MAX_WORD_LEN];
        cand[..w.len()].copy_from_slice(w.as_bytes());
        let eq = cand.ct_eq(&probe);
        index = u16::conditional_select(&index, &(i as u16), eq);
        found |= eq;
    }
    if bool::from(found) { Some(index) } else { None }
}

fn checksum_bits(word_count: usize) -> usize {
    word_count / 3
}

fn entropy_bytes(word_count: usize) -> usize {
    word_count * 4 / 3
}

/// Generate a fresh BIP-39 English mnemonic from OS randomness.
pub fn generate_mnemonic(word_count: usize) -> Result<SecretBuf> {
    if !ALLOWED_WORD_COUNTS.contains(&word_count) {
        bail!("word count must be one of {ALLOWED_WORD_COUNTS:?}, got {word_count}");
    }
    let ent_len = entropy_bytes(word_count);
    // entropy || checksum byte, so 11-bit windows can be read uniformly.
    let mut bits = Zeroizing::new(vec![0u8; ent_len + 1]);
    getrandom::fill(&mut bits[..ent_len]).map_err(|e| anyhow!("OS RNG failed: {e}"))?;
    bits[ent_len] = Sha256::digest(&bits[..ent_len])[0];

    let mut phrase = SecretBuf::with_capacity(word_count * (MAX_WORD_LEN + 1))?;
    for w in 0..word_count {
        let index = read_bits11(&bits, w * 11);
        if w > 0 {
            phrase.push_str(" ")?;
        }
        phrase.push_str(WORDS[index as usize])?;
    }
    Ok(phrase)
}

fn read_bits11(bytes: &[u8], offset: usize) -> u16 {
    let mut v = 0u16;
    for b in 0..11 {
        let pos = offset + b;
        let bit = (bytes[pos / 8] >> (7 - pos % 8)) & 1;
        v = (v << 1) | u16::from(bit);
    }
    v
}

fn write_bits11(bytes: &mut [u8], offset: usize, value: u16) {
    for b in 0..11 {
        let pos = offset + b;
        let bit = ((value >> (10 - b)) & 1) as u8;
        bytes[pos / 8] |= bit << (7 - pos % 8);
    }
}

/// Validate a phrase (word count, wordlist membership, checksum) and return
/// its canonical form: lowercase words separated by single spaces.
pub fn canonicalize_mnemonic(phrase: &str) -> Result<SecretBuf> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let count = words.len();
    if !ALLOWED_WORD_COUNTS.contains(&count) {
        bail!("seed phrase has {count} words; expected one of {ALLOWED_WORD_COUNTS:?}");
    }
    let ent_len = entropy_bytes(count);
    let mut bits = Zeroizing::new(vec![0u8; ent_len + 1]);
    let mut canonical = SecretBuf::with_capacity(count * (MAX_WORD_LEN + 1))?;
    let mut lowered = Zeroizing::new(String::with_capacity(MAX_WORD_LEN));
    for (i, word) in words.iter().enumerate() {
        lowered.clear();
        lowered.push_str(&word.to_ascii_lowercase());
        let index = word_index(&lowered).ok_or_else(|| {
            anyhow!("word #{} of the seed phrase is not in the BIP-39 English wordlist", i + 1)
        })?;
        write_bits11(&mut bits, i * 11, index);
        if i > 0 {
            canonical.push_str(" ")?;
        }
        canonical.push_str(&lowered)?;
    }
    let cs_bits = checksum_bits(count);
    let expected = Sha256::digest(&bits[..ent_len])[0] >> (8 - cs_bits);
    let actual = bits[ent_len] >> (8 - cs_bits);
    if !bool::from(expected.ct_eq(&actual)) {
        bail!("seed phrase checksum is invalid (a word is wrong or out of order)");
    }
    Ok(canonical)
}

/// BIP-39 seed: PBKDF2-HMAC-SHA512(phrase, "mnemonic" || passphrase, 2048).
fn mnemonic_to_seed(canonical_phrase: &[u8], passphrase: &str) -> Result<SecretBuf> {
    let mut salt = Zeroizing::new(Vec::with_capacity(8 + passphrase.len()));
    salt.extend_from_slice(b"mnemonic");
    salt.extend_from_slice(passphrase.as_bytes());
    let mut seed = SecretBuf::zeroed(64)?;
    pbkdf2::pbkdf2_hmac::<Sha512>(canonical_phrase, &salt, PBKDF2_ROUNDS, seed.as_mut_bytes());
    Ok(seed)
}

/// Parse `m/44'/60'/0'/0/0` style paths (`'`, `h` or `H` mark hardened steps).
fn parse_path(path: &str) -> Result<Vec<u32>> {
    let mut parts = path.trim().split('/');
    if parts.next().map(str::trim) != Some("m") {
        bail!("derivation path must start with `m/`");
    }
    parts
        .map(|p| {
            let p = p.trim();
            let (num, hardened) = match p.strip_suffix(['\'', 'h', 'H']) {
                Some(n) => (n, true),
                None => (p, false),
            };
            let n: u32 = num.parse().with_context(|| format!("bad path component {p:?}"))?;
            if n >= 0x8000_0000 {
                bail!("path component {p:?} is out of range");
            }
            Ok(if hardened { n | 0x8000_0000 } else { n })
        })
        .collect()
}

fn field_bytes(bytes: &[u8]) -> Result<k256::FieldBytes> {
    let arr: [u8; 32] = bytes.try_into().context("expected 32 bytes")?;
    Ok(k256::FieldBytes::from(arr))
}

/// A BIP-32 extended private key held entirely in locked memory.
struct ExtKey {
    key: SecretBuf,
    chain: SecretBuf,
}

impl ExtKey {
    fn master(seed: &[u8]) -> Result<Self> {
        let mut mac =
            Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").expect("any key length works");
        mac.update(seed);
        let i = Zeroizing::new(mac.finalize().into_bytes());
        Self::from_parts(&i[..32], &i[32..])
    }

    fn from_parts(key: &[u8], chain: &[u8]) -> Result<Self> {
        // Reject the (astronomically unlikely) invalid scalar as BIP-32 requires.
        let scalar = k256::Scalar::from_repr(field_bytes(key)?);
        if !bool::from(scalar.is_some()) || bool::from(scalar.unwrap().is_zero()) {
            bail!("derived key is invalid; try another derivation path");
        }
        Ok(Self { key: SecretBuf::from_slice(key)?, chain: SecretBuf::from_slice(chain)? })
    }

    fn scalar(&self) -> k256::Scalar {
        let repr = field_bytes(self.key.as_bytes()).expect("validated in from_parts");
        k256::Scalar::from_repr(repr).expect("validated in from_parts")
    }

    fn child(&self, index: u32) -> Result<Self> {
        let mut data = Zeroizing::new([0u8; 37]);
        if index & 0x8000_0000 != 0 {
            data[0] = 0;
            data[1..33].copy_from_slice(self.key.as_bytes());
        } else {
            let secret = k256::SecretKey::from_slice(self.key.as_bytes())
                .map_err(|_| anyhow!("invalid parent key"))?;
            let point = secret.public_key().to_encoded_point(true);
            data[..33].copy_from_slice(point.as_bytes());
        }
        data[33..].copy_from_slice(&index.to_be_bytes());

        let mut mac =
            Hmac::<Sha512>::new_from_slice(self.chain.as_bytes()).expect("any key length works");
        mac.update(&data[..]);
        let i = Zeroizing::new(mac.finalize().into_bytes());

        let il = k256::Scalar::from_repr(field_bytes(&i[..32])?);
        if !bool::from(il.is_some()) {
            bail!("derived key is invalid; try another derivation path");
        }
        let child = il.unwrap() + self.scalar();
        let child_bytes = Zeroizing::new(child.to_repr());
        Self::from_parts(&child_bytes[..], &i[32..])
    }
}

/// A wallet derived from a mnemonic at a specific derivation path. Holds only
/// the final secp256k1 key (zeroized on drop), never the phrase or seed.
pub struct Wallet {
    signer: PrivateKeySigner,
    derivation_path: String,
}

impl Wallet {
    /// Derive a wallet from a mnemonic phrase at `derivation_path`.
    pub fn from_mnemonic(phrase: &str, derivation_path: &str) -> Result<Self> {
        Self::from_mnemonic_with_passphrase(phrase, "", derivation_path)
    }

    pub fn from_mnemonic_with_passphrase(
        phrase: &str,
        passphrase: &str,
        derivation_path: &str,
    ) -> Result<Self> {
        let steps = parse_path(derivation_path)
            .with_context(|| format!("invalid derivation path {derivation_path:?}"))?;
        let canonical = canonicalize_mnemonic(phrase)?;
        let seed = mnemonic_to_seed(canonical.as_bytes(), passphrase)?;
        drop(canonical);
        let mut key = ExtKey::master(seed.as_bytes())?;
        drop(seed);
        for step in steps {
            key = key.child(step)?;
        }
        let signer = PrivateKeySigner::from_slice(key.key.as_bytes())
            .map_err(|_| anyhow!("derived key is invalid"))?;
        Ok(Self { signer, derivation_path: derivation_path.to_string() })
    }

    /// Checksummed (EIP-55) Ethereum address.
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    pub fn derivation_path(&self) -> &str {
        &self.derivation_path
    }

    /// Sign an arbitrary message using EIP-191 `personal_sign` semantics.
    /// Returns the 65-byte `r || s || v` signature as 0x-prefixed hex.
    pub fn sign_message(&self, message: &[u8]) -> Result<String> {
        let sig: Signature = self.signer.sign_message_sync(message).context("signing failed")?;
        Ok(hex::encode_prefixed(sig.as_bytes()))
    }

    /// Sign a 32-byte digest directly (EIP-712 hashes, transaction hashes).
    pub fn sign_hash(&self, hash: &B256) -> Result<Signature> {
        self.signer.sign_hash_sync(hash).context("signing failed")
    }

    /// Compare the address stored in 1Password against the one derived from the
    /// stored phrase. Any mismatch means the record is corrupted or was edited.
    pub fn verify_stored_address(&self, stored: &str) -> Result<()> {
        let stored_addr: Address = stored
            .trim()
            .parse()
            .with_context(|| format!("stored wallet address {stored:?} is not a valid address"))?;
        let derived = self.address();
        if stored_addr != derived {
            bail!(
                "ADDRESS MISMATCH: 1Password says {stored_addr} but the seed phrase derives \
                 {derived} at {}. Do not use this wallet until you understand why.",
                self.derivation_path
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Hardhat / Anvil well-known test mnemonic.
    const TEST_PHRASE: &str = "test test test test test test test test test test test junk";
    const TEST_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    #[test]
    fn wordlist_matches_bip39_reference() {
        let digest = Sha256::digest(include_str!("bip39-english.txt").as_bytes());
        assert_eq!(
            hex::encode(digest),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        assert_eq!(word_index("abandon"), Some(0));
        assert_eq!(word_index("zoo"), Some(2047));
        assert_eq!(word_index("junk"), Some(970));
        assert_eq!(word_index("ab"), None);
        assert_eq!(word_index("abandonx"), None);
        assert_eq!(word_index(""), None);
    }

    #[test]
    fn bip39_reference_vectors() {
        // From the BIP-39 spec test vectors (passphrase "TREZOR").
        let cases = [
            (
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            ),
            (
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
            ),
            (
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
                "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
            ),
        ];
        for (phrase, seed_hex) in cases {
            let canonical = canonicalize_mnemonic(phrase).unwrap();
            assert_eq!(canonical.as_str().unwrap(), phrase);
            let seed = mnemonic_to_seed(canonical.as_bytes(), "TREZOR").unwrap();
            assert_eq!(hex::encode(seed.as_bytes()), seed_hex);
        }
    }

    #[test]
    fn bip32_reference_vector_1() {
        // BIP-32 test vector 1: seed 000102...0f, chain m/0H/1/2H/2/1000000000.
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let mut key = ExtKey::master(&seed).unwrap();
        assert_eq!(
            hex::encode(key.key.as_bytes()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        let expected = [
            (0x8000_0000u32, "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"),
            (1, "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"),
            (0x8000_0002, "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"),
            (2, "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"),
            (1000000000, "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"),
        ];
        for (index, priv_hex) in expected {
            key = key.child(index).unwrap();
            assert_eq!(hex::encode(key.key.as_bytes()), priv_hex);
        }
    }

    #[test]
    fn derives_known_addresses() {
        let w = Wallet::from_mnemonic(TEST_PHRASE, DEFAULT_DERIVATION_PATH).unwrap();
        assert_eq!(w.address().to_string(), TEST_ADDR);
        let w = Wallet::from_mnemonic(TEST_PHRASE, "m/44'/60'/0'/0/1").unwrap();
        assert_eq!(w.address().to_string(), "0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
        // Alternative hardened markers and sloppy whitespace/case are accepted.
        let w = Wallet::from_mnemonic(
            &format!("  {} ", TEST_PHRASE.to_uppercase()),
            "m/44h/60H/0'/0/1",
        )
        .unwrap();
        assert_eq!(w.address().to_string(), "0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
    }

    #[test]
    fn rejects_bad_paths() {
        assert!(parse_path("44'/60'/0'/0/0").is_err());
        assert!(parse_path("m/x").is_err());
        assert!(parse_path("m/2147483648").is_err());
        assert_eq!(
            parse_path("m/44'/60'/0'/0/0").unwrap(),
            [0x8000002c, 0x8000003c, 0x80000000, 0, 0]
        );
        assert!(Wallet::from_mnemonic(TEST_PHRASE, "bogus").is_err());
    }

    #[test]
    fn verify_accepts_lowercase_and_rejects_mismatch() {
        let w = Wallet::from_mnemonic(TEST_PHRASE, DEFAULT_DERIVATION_PATH).unwrap();
        w.verify_stored_address(&TEST_ADDR.to_lowercase()).unwrap();
        let err =
            w.verify_stored_address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap_err();
        assert!(err.to_string().contains("ADDRESS MISMATCH"));
    }

    #[test]
    fn generated_mnemonics_are_valid_and_unique() {
        for n in ALLOWED_WORD_COUNTS {
            let a = generate_mnemonic(n).unwrap();
            let b = generate_mnemonic(n).unwrap();
            assert_eq!(a.as_str().unwrap().split_whitespace().count(), n);
            assert_ne!(a.as_bytes(), b.as_bytes());
            canonicalize_mnemonic(a.as_str().unwrap()).unwrap();
        }
        assert!(generate_mnemonic(13).is_err());
    }

    #[test]
    fn invalid_phrases_do_not_leak_words() {
        let err = canonicalize_mnemonic(
            "test test test test test test test test test test test zebrafish",
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("word #12"), "{msg}");
        assert!(!msg.contains("zebrafish"), "{msg}");
        let err = canonicalize_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon").unwrap_err();
        assert!(format!("{err:#}").contains("checksum"));
        assert!(canonicalize_mnemonic("test test").is_err());
    }

    #[test]
    fn signs_message_eip191() {
        let w = Wallet::from_mnemonic(TEST_PHRASE, DEFAULT_DERIVATION_PATH).unwrap();
        let sig = w.sign_message(b"hello").unwrap();
        assert_eq!(sig.len(), 2 + 65 * 2);
        let parsed = Signature::from_raw(&hex::decode(&sig).unwrap()).unwrap();
        assert_eq!(parsed.recover_address_from_msg(b"hello").unwrap(), w.address());
    }
}
