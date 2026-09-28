//! OpenSSH encodings of an RSA key: the `openssh-key-v1` private key format
//! (PROTOCOL.key in the OpenSSH source) and the `ssh-rsa` public key line.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
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

fn public_blob(key: &RsaKey) -> Vec<u8> {
    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-rsa");
    put_mpint(&mut blob, &key.e);
    put_mpint(&mut blob, &key.n);
    blob
}

/// `ssh-rsa <base64>`, with an empty comment.
pub fn public_key(key: &RsaKey) -> String {
    format!("ssh-rsa {}", STANDARD.encode(public_blob(key)))
}

/// An unencrypted `openssh-key-v1` private key with an empty comment.
/// `ssh-keygen` writes a random check integer. This function writes 0, so
/// that the output is deterministic.
pub fn private_key(key: &RsaKey) -> String {
    let mut private = Vec::new();
    private.extend(0u32.to_be_bytes());
    private.extend(0u32.to_be_bytes());
    put_string(&mut private, b"ssh-rsa");
    put_mpint(&mut private, &key.n);
    put_mpint(&mut private, &key.e);
    put_mpint(&mut private, &key.d);
    // OpenSSH expects iqmp = q^-1 mod p.
    put_mpint(&mut private, &key.q.modinv(&key.p).unwrap());
    put_mpint(&mut private, &key.p);
    put_mpint(&mut private, &key.q);
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
    put_string(&mut blob, &public_blob(key));
    put_string(&mut blob, &private);

    let encoded = STANDARD.encode(blob);
    let mut out = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for line in encoded.as_bytes().chunks(70) {
        out += std::str::from_utf8(line).unwrap();
        out += "\n";
    }
    out + "-----END OPENSSH PRIVATE KEY-----"
}
