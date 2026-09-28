//! OpenSSH encodings of RSA and Ed25519 keys: the `openssh-key-v1` private
//! key format (PROTOCOL.key in the OpenSSH source) and the public key line.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::SigningKey;
use num_bigint::BigUint;

use crate::rsa::RsaKey;

fn put_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend((s.len() as u32).to_be_bytes());
    buf.extend(s);
}

fn put_mpint(buf: &mut Vec<u8>, x: &BigUint) {
    let mut bytes = x.to_bytes_be();
    if bytes == [0] {
        bytes.clear();
    } else if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    put_string(buf, &bytes);
}

fn rsa_public_blob(key: &RsaKey) -> Vec<u8> {
    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-rsa");
    put_mpint(&mut blob, &key.e);
    put_mpint(&mut blob, &key.n);
    blob
}

fn ed25519_public_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-ed25519");
    put_string(&mut blob, public);
    blob
}

/// `<key type> <base64>`, with an empty comment.
fn public_line(key_type: &str, blob: &[u8]) -> String {
    format!("{key_type} {}", STANDARD.encode(blob))
}

/// An unencrypted `openssh-key-v1` private key with an empty comment.
/// `private_fields` are the key type and the key-specific fields.
/// `ssh-keygen` writes a random check integer. This function writes 0, so
/// that the output is deterministic.
fn private_key(public_blob: &[u8], private_fields: &[u8]) -> String {
    let mut private = Vec::new();
    private.extend(0u32.to_be_bytes());
    private.extend(0u32.to_be_bytes());
    private.extend(private_fields);
    put_string(&mut private, b"");
    // Pad to the cipher block size, 8 for "none", with the bytes 1, 2, 3, ...
    let mut pad = 1u8;
    while private.len() % 8 != 0 {
        private.push(pad);
        pad += 1;
    }

    let mut blob = b"openssh-key-v1\0".to_vec();
    put_string(&mut blob, b"none");
    put_string(&mut blob, b"none");
    put_string(&mut blob, b"");
    blob.extend(1u32.to_be_bytes());
    put_string(&mut blob, public_blob);
    put_string(&mut blob, &private);

    let encoded = STANDARD.encode(blob);
    let mut out = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for line in encoded.as_bytes().chunks(70) {
        out += std::str::from_utf8(line).unwrap();
        out += "\n";
    }
    out + "-----END OPENSSH PRIVATE KEY-----"
}

/// `ssh-rsa <base64>`.
pub fn rsa_public_key(key: &RsaKey) -> String {
    public_line("ssh-rsa", &rsa_public_blob(key))
}

pub fn rsa_private_key(key: &RsaKey) -> String {
    let mut fields = Vec::new();
    put_string(&mut fields, b"ssh-rsa");
    put_mpint(&mut fields, &key.n);
    put_mpint(&mut fields, &key.e);
    put_mpint(&mut fields, &key.d);
    // OpenSSH expects iqmp = q^-1 mod p.
    put_mpint(&mut fields, &key.q.modinv(&key.p).unwrap());
    put_mpint(&mut fields, &key.p);
    put_mpint(&mut fields, &key.q);
    private_key(&rsa_public_blob(key), &fields)
}

/// `ssh-ed25519 <base64>` for the RFC 8032 private key (seed) `seed`.
pub fn ed25519_public_key(seed: &[u8; 32]) -> String {
    let public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
    public_line("ssh-ed25519", &ed25519_public_blob(&public))
}

pub fn ed25519_private_key(seed: &[u8; 32]) -> String {
    let public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
    let mut fields = Vec::new();
    put_string(&mut fields, b"ssh-ed25519");
    put_string(&mut fields, &public);
    // OpenSSH keeps the seed followed by the public key.
    put_string(&mut fields, &[seed.as_slice(), &public].concat());
    private_key(&ed25519_public_blob(&public), &fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Computed independently with Python `cryptography` for the seed
    /// `hex/32/0` of the mnemonic "abandon ... about".
    #[test]
    fn ed25519_public_key_vector() {
        let seed: [u8; 32] = (0..32)
            .map(|i| {
                u8::from_str_radix(
                    &"e477d4694160a384b28ee2f72b54edcf0822fd6e1ee1780447455cdbed8f8c45"
                        [2 * i..2 * i + 2],
                    16,
                )
                .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        assert_eq!(
            ed25519_public_key(&seed),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBLNnAEuWd15WSVVNTQRA/UUz7wRqzkKU26yArVE7HVd"
        );
    }
}
