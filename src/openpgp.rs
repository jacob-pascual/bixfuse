//! OpenPGP (RFC 4880) transferable keys for the BIP-85 RSA GPG application.
//!
//! The primary key has the Certify flag. The three sub keys have the flags
//! that BIP-85 gives to sub keys 0, 1, and 2: Encrypt, Authenticate, Sign.
//! All keys and signatures have the creation time that BIP-85 requires.
//! RSA PKCS#1 v1.5 signatures are deterministic, so the output is too.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use num_bigint::BigUint;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::rsa::RsaKey;

/// The Bitcoin genesis block time, 2009-01-03 18:15:05 UTC.
pub const CREATION_TIME: u32 = 1231006505;

const TAG_SIGNATURE: u8 = 2;
const TAG_SECRET_KEY: u8 = 5;
const TAG_PUBLIC_KEY: u8 = 6;
const TAG_SECRET_SUBKEY: u8 = 7;
const TAG_USER_ID: u8 = 13;
const TAG_PUBLIC_SUBKEY: u8 = 14;

const SIG_POSITIVE_CERTIFICATION: u8 = 0x13;
const SIG_SUBKEY_BINDING: u8 = 0x18;
const SIG_PRIMARY_KEY_BINDING: u8 = 0x19;

const SUBPACKET_CREATION_TIME: u8 = 2;
const SUBPACKET_PREFERRED_SYMMETRIC: u8 = 11;
const SUBPACKET_ISSUER: u8 = 16;
const SUBPACKET_PREFERRED_HASH: u8 = 21;
const SUBPACKET_PREFERRED_COMPRESSION: u8 = 22;
const SUBPACKET_KEY_SERVER_PREFERENCES: u8 = 23;
const SUBPACKET_KEY_FLAGS: u8 = 27;
const SUBPACKET_FEATURES: u8 = 30;
const SUBPACKET_EMBEDDED_SIGNATURE: u8 = 32;
const SUBPACKET_ISSUER_FINGERPRINT: u8 = 33;

const FLAG_CERTIFY: u8 = 0x01;
const FLAG_SIGN: u8 = 0x02;
const FLAG_ENCRYPT: u8 = 0x04 | 0x08;
const FLAG_AUTHENTICATE: u8 = 0x20;

/// Key flags of sub keys 0, 1, and 2, in BIP-85 order.
const SUBKEY_FLAGS: [u8; 3] = [FLAG_ENCRYPT, FLAG_AUTHENTICATE, FLAG_SIGN];

const PUBKEY_RSA: u8 = 1;
const HASH_SHA256: u8 = 8;

/// The ASN.1 DigestInfo prefix of SHA-256 for EMSA-PKCS1-v1_5 (RFC 8017).
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];

fn mpi(x: &BigUint) -> Vec<u8> {
    let mut out = (x.bits() as u16).to_be_bytes().to_vec();
    out.extend(x.to_bytes_be());
    out
}

/// The length encoding of new-format packets and of signature subpackets.
fn length(len: usize) -> Vec<u8> {
    match len {
        0..192 => vec![len as u8],
        192..8384 => {
            let len = len - 192;
            vec![(len >> 8) as u8 + 192, len as u8]
        }
        _ => {
            let mut out = vec![0xff];
            out.extend((len as u32).to_be_bytes());
            out
        }
    }
}

fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0xc0 | tag];
    out.extend(length(body.len()));
    out.extend(body);
    out
}

fn subpacket(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut out = length(data.len() + 1);
    out.push(kind);
    out.extend(data);
    out
}

struct Key<'a> {
    rsa: &'a RsaKey,
    /// The body of the public key packet.
    public: Vec<u8>,
    fingerprint: [u8; 20],
}

impl<'a> Key<'a> {
    fn new(rsa: &'a RsaKey) -> Self {
        let mut public = vec![4];
        public.extend(CREATION_TIME.to_be_bytes());
        public.push(PUBKEY_RSA);
        public.extend(mpi(&rsa.n));
        public.extend(mpi(&rsa.e));
        let fingerprint = Sha1::digest(Self::hash_context(&public)).into();
        Self {
            rsa,
            public,
            fingerprint,
        }
    }

    /// The form of a public key that signatures hash.
    fn hash_context(public: &[u8]) -> Vec<u8> {
        let mut out = vec![0x99];
        out.extend((public.len() as u16).to_be_bytes());
        out.extend(public);
        out
    }

    fn key_id(&self) -> &[u8] {
        &self.fingerprint[12..]
    }

    /// The body of the secret key packet, not encrypted. OpenPGP requires
    /// p < q and u = p^-1 mod q, the same as `RsaKey`.
    fn secret(&self) -> Vec<u8> {
        let mut secret = Vec::new();
        for x in [&self.rsa.d, &self.rsa.p, &self.rsa.q, &self.rsa.u] {
            secret.extend(mpi(x));
        }
        let checksum = secret.iter().fold(0u16, |sum, b| sum.wrapping_add(*b as u16));
        let mut out = self.public.clone();
        out.push(0);
        out.extend(secret);
        out.extend(checksum.to_be_bytes());
        out
    }

    /// RSASSA-PKCS1-v1_5 with SHA-256 of an already computed digest.
    fn sign(&self, digest: &[u8]) -> BigUint {
        let k = self.rsa.n.bits().div_ceil(8) as usize;
        let mut em = vec![0xff; k];
        em[0] = 0;
        em[1] = 1;
        let t = k - SHA256_DIGEST_INFO.len() - digest.len();
        em[t - 1] = 0;
        em[t..t + SHA256_DIGEST_INFO.len()].copy_from_slice(&SHA256_DIGEST_INFO);
        em[k - digest.len()..].copy_from_slice(digest);
        BigUint::from_bytes_be(&em).modpow(&self.rsa.d, &self.rsa.n)
    }

    /// The body of a version 4 signature packet over `context`.
    fn signature(&self, kind: u8, context: &[u8], mut hashed: Vec<u8>) -> Vec<u8> {
        hashed.splice(
            0..0,
            subpacket(SUBPACKET_CREATION_TIME, &CREATION_TIME.to_be_bytes()),
        );
        let mut issuer_fingerprint = vec![4];
        issuer_fingerprint.extend(self.fingerprint);
        hashed.extend(subpacket(SUBPACKET_ISSUER_FINGERPRINT, &issuer_fingerprint));

        let mut body = vec![4, kind, PUBKEY_RSA, HASH_SHA256];
        body.extend((hashed.len() as u16).to_be_bytes());
        body.extend(&hashed);
        let mut hasher = Sha256::new();
        hasher.update(context);
        hasher.update(&body);
        hasher.update([4, 0xff]);
        hasher.update((body.len() as u32).to_be_bytes());
        let digest = hasher.finalize();

        let unhashed = subpacket(SUBPACKET_ISSUER, self.key_id());
        body.extend((unhashed.len() as u16).to_be_bytes());
        body.extend(unhashed);
        body.extend(&digest[..2]);
        body.extend(mpi(&self.sign(&digest)));
        body
    }
}

/// Builds the packets of a transferable key, secret or public.
fn transferable_key(user_id: &str, primary: &RsaKey, subkeys: [&RsaKey; 3], secret: bool) -> Vec<u8> {
    let primary = Key::new(primary);
    let primary_context = Key::hash_context(&primary.public);
    let mut out = if secret {
        packet(TAG_SECRET_KEY, &primary.secret())
    } else {
        packet(TAG_PUBLIC_KEY, &primary.public)
    };

    out.extend(packet(TAG_USER_ID, user_id.as_bytes()));
    let mut context = primary_context.clone();
    context.push(0xb4);
    context.extend((user_id.len() as u32).to_be_bytes());
    context.extend(user_id.as_bytes());
    let hashed = [
        subpacket(SUBPACKET_KEY_FLAGS, &[FLAG_CERTIFY]),
        subpacket(SUBPACKET_PREFERRED_SYMMETRIC, &[9, 8, 7]), // AES-256, AES-192, AES-128
        subpacket(SUBPACKET_PREFERRED_HASH, &[10, 9, 8, 11]), // SHA-512, SHA-384, SHA-256, SHA-224
        subpacket(SUBPACKET_PREFERRED_COMPRESSION, &[2, 3, 1]), // ZLIB, BZip2, ZIP
        subpacket(SUBPACKET_FEATURES, &[0x01]),               // Modification Detection
        subpacket(SUBPACKET_KEY_SERVER_PREFERENCES, &[0x80]), // No-modify
    ]
    .concat();
    let certification = primary.signature(SIG_POSITIVE_CERTIFICATION, &context, hashed);
    out.extend(packet(TAG_SIGNATURE, &certification));

    for (subkey, flags) in subkeys.into_iter().zip(SUBKEY_FLAGS) {
        let subkey = Key::new(subkey);
        out.extend(if secret {
            packet(TAG_SECRET_SUBKEY, &subkey.secret())
        } else {
            packet(TAG_PUBLIC_SUBKEY, &subkey.public)
        });
        let context = [primary_context.as_slice(), &Key::hash_context(&subkey.public)].concat();
        let mut hashed = subpacket(SUBPACKET_KEY_FLAGS, &[flags]);
        if flags & FLAG_SIGN != 0 {
            // A signing sub key must also sign the primary key (RFC 4880 5.2.1).
            let back = subkey.signature(SIG_PRIMARY_KEY_BINDING, &context, Vec::new());
            hashed.extend(subpacket(SUBPACKET_EMBEDDED_SIGNATURE, &back));
        }
        let binding = primary.signature(SIG_SUBKEY_BINDING, &context, hashed);
        out.extend(packet(TAG_SIGNATURE, &binding));
    }
    out
}

/// The CRC-24 of RFC 4880 6.1.
fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xb704ce;
    for byte in data {
        crc ^= (*byte as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x1000000 != 0 {
                crc ^= 0x1864cfb;
            }
        }
    }
    crc & 0xffffff
}

fn armor(kind: &str, data: &[u8]) -> String {
    let mut out = format!("-----BEGIN PGP {kind}-----\n\n");
    for line in STANDARD.encode(data).as_bytes().chunks(64) {
        out += std::str::from_utf8(line).unwrap();
        out += "\n";
    }
    out += "=";
    out += &STANDARD.encode(&crc24(data).to_be_bytes()[1..]);
    out + &format!("\n-----END PGP {kind}-----")
}

/// The armored transferable secret key, not encrypted.
pub fn secret_key(user_id: &str, primary: &RsaKey, subkeys: [&RsaKey; 3]) -> String {
    armor(
        "PRIVATE KEY BLOCK",
        &transferable_key(user_id, primary, subkeys, true),
    )
}

/// The armored transferable public key.
pub fn public_key(user_id: &str, primary: &RsaKey, subkeys: [&RsaKey; 3]) -> String {
    armor(
        "PUBLIC KEY BLOCK",
        &transferable_key(user_id, primary, subkeys, false),
    )
}

/// The upper-case hex fingerprint of the public key `rsa`.
pub fn fingerprint(rsa: &RsaKey) -> String {
    Key::new(rsa)
        .fingerprint
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The check value of CRC-24/OPENPGP.
    #[test]
    fn crc24_check_value() {
        assert_eq!(crc24(b"123456789"), 0x21cf02);
    }

    #[test]
    fn length_forms() {
        assert_eq!(length(191), [191]);
        assert_eq!(length(192), [192, 0]);
        assert_eq!(length(8383), [223, 255]);
        assert_eq!(length(8384), [255, 0, 0, 0x20, 0xc0]);
    }
}
