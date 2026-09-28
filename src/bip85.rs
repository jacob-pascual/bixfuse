//! BIP-85 entropy derivation and BIP85-DRNG-SHAKE256.

use bitcoin::NetworkKind;
use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::secp256k1::{All, Secp256k1};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use shake::Shake256;
use shake::digest::{ExtendableOutput, Update, XofReader};

/// The BIP-85 purpose, `m/83696968'`.
pub const PURPOSE: u32 = 83696968;

/// A derived key or its output is not a valid secp256k1 key.
/// BIP-85 requires a hard fail, so the caller must not retry with other bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidKey;

pub struct Root {
    secp: Secp256k1<All>,
    master: Xpriv,
}

impl Root {
    /// The root of a BIP-39 mnemonic with the empty passphrase.
    /// The wordlist language is detected.
    pub fn from_mnemonic(phrase: &str) -> Result<Self, bip39::Error> {
        let mnemonic = bip39::Mnemonic::parse_normalized(phrase)?;
        Ok(Self::from_master(
            Xpriv::new_master(NetworkKind::Main, &mnemonic.to_seed(""))
                .expect("a 64-byte seed is a valid BIP-32 seed"),
        ))
    }

    pub fn from_master(master: Xpriv) -> Self {
        Self {
            secp: Secp256k1::new(),
            master,
        }
    }

    /// The 64 bytes of entropy at `m/83696968'/{path[0]}'/{path[1]}'/...`.
    /// Every element of `path` must be less than 2^31.
    pub fn entropy(&self, path: &[u32]) -> Result<[u8; 64], InvalidKey> {
        let path: Vec<ChildNumber> = std::iter::once(PURPOSE)
            .chain(path.iter().copied())
            .map(|i| ChildNumber::from_hardened_idx(i).expect("path index is less than 2^31"))
            .collect();
        let key = self
            .master
            .derive_priv(&self.secp, &path)
            .map_err(|_| InvalidKey)?;
        let mut mac = Hmac::<Sha512>::new_from_slice(b"bip-entropy-from-k").unwrap();
        Mac::update(&mut mac, &key.private_key.secret_bytes());
        Ok(mac.finalize().into_bytes().into())
    }
}

/// BIP85-DRNG-SHAKE256: a SHAKE256 stream seeded with 64 bytes of entropy.
pub struct Drng(shake::Shake256Reader);

impl Drng {
    pub fn new(entropy: &[u8; 64]) -> Self {
        let mut shake = Shake256::default();
        shake.update(entropy);
        Self(shake.finalize_xof())
    }

    pub fn read(&mut self, buf: &mut [u8]) {
        self.0.read(buf);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::str::FromStr;

    /// The master key of the BIP-85 test vectors.
    pub const XPRV: &str = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";

    pub fn root() -> Root {
        Root::from_master(Xpriv::from_str(XPRV).unwrap())
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn bip85_test_case_1() {
        assert_eq!(
            hex(&root().entropy(&[0, 0]).unwrap()),
            "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"
        );
    }

    #[test]
    fn bip85_test_case_2() {
        assert_eq!(
            hex(&root().entropy(&[0, 1]).unwrap()),
            "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e"
        );
    }

    #[test]
    fn drng_test_vector() {
        let mut drng = Drng::new(&root().entropy(&[0, 0]).unwrap());
        // Two reads give the same stream as one read of 80 bytes.
        let mut out = [0u8; 80];
        drng.read(&mut out[..1]);
        drng.read(&mut out[1..]);
        assert_eq!(
            hex(&out),
            "b78b1ee6b345eae6836c2d53d33c64cdaf9a696487be81b03e822dc84b3f1cd883d7559e53d175f243e4c349e822a957bbff9224bc5dde9492ef54e8a439f6bc8c7355b87a925a37ee405a7502991111"
        );
    }

    #[test]
    fn mnemonic_root() {
        let root = Root::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n",
        )
        .unwrap();
        assert_eq!(
            root.master.to_string(),
            "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
        );
    }

    #[test]
    fn mnemonic_bad_checksum() {
        assert!(
            Root::from_mnemonic(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
            )
            .is_err()
        );
    }
}
