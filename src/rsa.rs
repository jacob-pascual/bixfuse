//! RSA key generation, ported from pycryptodome 3.x.
//!
//! BIP-85 does not fix an RSA algorithm. The BIP-85 reference implementation
//! (ethankosakovsky/bip85) calls pycryptodome
//! `RSA.generate(bits, randfunc=drng.read, e=65537)`, so this port reads the
//! DRNG bytes in the same order and gets the same keys. Each function names
//! the pycryptodome function that it ports.

use num_bigint::BigUint;
use num_integer::Integer;

use crate::bip85::Drng;

const E: u32 = 65537;

/// An RSA private key. As in pycryptodome, `p < q` and `u = p^-1 mod q`.
pub struct RsaKey {
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
    pub p: BigUint,
    pub q: BigUint,
    pub u: BigUint,
}

/// `Crypto.PublicKey.RSA.generate`
pub fn generate(bits: u64, drng: &mut Drng) -> RsaKey {
    assert!(bits >= 1024, "RSA modulus length must be >= 1024");
    let e = BigUint::from(E);
    let one = BigUint::from(1u32);
    let size_q = bits / 2;
    let size_p = bits - size_q;
    let min_q = (&one << (2 * size_q - 1)).sqrt();
    let min_p = (&one << (2 * size_p - 1)).sqrt();
    let min_distance = &one << (bits / 2 - 100);
    loop {
        let p = generate_probable_prime(size_p, drng, |c| *c > min_p && (c - 1u32).gcd(&e) == one);
        let q = generate_probable_prime(size_q, drng, |c| {
            let distance = if *c > p { c - &p } else { &p - c };
            *c > min_q && (c - 1u32).gcd(&e) == one && distance > min_distance
        });
        let n = &p * &q;
        let lcm = (&p - 1u32).lcm(&(&q - 1u32));
        let d = e.modinv(&lcm).expect("gcd(e, p - 1) = gcd(e, q - 1) = 1");
        // pycryptodome loops while both of these are true. The prime filters
        // make `n` exactly `bits` long, so the first pass always ends the loop.
        if n.bits() == bits || d >= &one << (bits / 2) {
            let (p, q) = if p > q { (q, p) } else { (p, q) };
            let u = p.modinv(&q).expect("p and q are distinct primes");
            return RsaKey { n, e, d, p, q, u };
        }
    }
}

/// `Crypto.Math.Primality.generate_probable_prime`
fn generate_probable_prime(
    exact_bits: u64,
    drng: &mut Drng,
    prime_filter: impl Fn(&BigUint) -> bool,
) -> BigUint {
    loop {
        let candidate = random(exact_bits, true, drng) | BigUint::from(1u32);
        if prime_filter(&candidate) && test_probable_prime(&candidate, drng) {
            return candidate;
        }
    }
}

/// `Crypto.Math.Primality.test_probable_prime`
///
/// pycryptodome also checks membership in the first 100 primes and does
/// trial division. The membership check cannot match, because every
/// candidate has at least 512 bits. The trial division has no effect in
/// pycryptodome: it calls `map()` and never consumes the lazy result. Trial
/// division here would skip Miller-Rabin bases that pycryptodome reads from
/// the DRNG, so this port must not do it.
fn test_probable_prime(candidate: &BigUint, drng: &mut Drng) -> bool {
    const MR_RANGES: [(u64, usize); 10] = [
        (220, 30),
        (280, 20),
        (390, 15),
        (512, 10),
        (620, 7),
        (740, 6),
        (890, 5),
        (1200, 4),
        (1700, 3),
        (3700, 2),
    ];
    let bit_size = candidate.bits();
    let iterations = MR_RANGES
        .iter()
        .find(|(limit, _)| bit_size < *limit)
        .map_or(1, |(_, iterations)| *iterations);
    miller_rabin_test(candidate, iterations, drng) && lucas_test(candidate)
}

/// `Crypto.Math.Primality.miller_rabin_test`, for an odd candidate > 5.
fn miller_rabin_test(candidate: &BigUint, iterations: usize, drng: &mut Drng) -> bool {
    let one = BigUint::from(1u32);
    let minus_one = candidate - 1u32;
    let a = minus_one.trailing_zeros().unwrap();
    let m = &minus_one >> a;
    'iteration: for _ in 0..iterations {
        let base = random_range(&BigUint::from(2u32), &(candidate - 2u32), drng);
        let mut z = base.modpow(&m, candidate);
        if z == one || z == minus_one {
            continue;
        }
        for _ in 1..a {
            z = z.modpow(&BigUint::from(2u32), candidate);
            if z == minus_one {
                continue 'iteration;
            }
            if z == one {
                return false;
            }
        }
        return false;
    }
    true
}

/// `Crypto.Math.Primality.lucas_test`, for an odd candidate > 5.
///
/// pycryptodome computes with signed integers and reduces mod `candidate`.
/// This port computes mod `candidate` from the start. Both give the same
/// residues, so the result is the same.
fn lucas_test(candidate: &BigUint) -> bool {
    let n = candidate;
    let root = n.sqrt();
    if &root * &root == *n {
        return false;
    }
    // D takes the values 5, -7, 9, -11, 13, ...
    let mut d: i64 = 5;
    loop {
        match jacobi(d, n) {
            0 => return false,
            -1 => break,
            _ => d = if d > 0 { -(d + 2) } else { -d + 2 },
        }
    }
    let d_mod = if d >= 0 {
        BigUint::from(d as u64) % n
    } else {
        n - (BigUint::from(d.unsigned_abs()) % n)
    };
    // (x / 2) mod n for x < 2n: add n if x is odd, then halve.
    let half = |x: BigUint| -> BigUint {
        let x = if x.is_odd() { x + n } else { x };
        (x >> 1u32) % n
    };
    let k = n + 1u32;
    let mut u = BigUint::from(1u32);
    let mut v = BigUint::from(1u32);
    for i in (0..k.bits() - 1).rev() {
        let u_temp = (&u * &v) % n;
        let v_temp = half((&u * &u % n * &d_mod + &v * &v) % n);
        if k.bit(i) {
            u = half(&u_temp + &v_temp);
            v = half((&v_temp + &u_temp * &d_mod) % n);
        } else {
            u = u_temp;
            v = v_temp;
        }
    }
    u == BigUint::ZERO
}

/// The Jacobi symbol (a / n) for an odd n > 0.
fn jacobi(a: i64, n: &BigUint) -> i32 {
    let mut a = if a >= 0 {
        BigUint::from(a as u64) % n
    } else {
        (n - BigUint::from(a.unsigned_abs()) % n) % n
    };
    let mut n = n.clone();
    let mut result = 1;
    while a != BigUint::ZERO {
        let zeros = a.trailing_zeros().unwrap();
        a >>= zeros;
        let n_mod_8 = (&n % 8u32).to_u32_digits().first().copied().unwrap_or(0);
        if zeros % 2 == 1 && (n_mod_8 == 3 || n_mod_8 == 5) {
            result = -result;
        }
        std::mem::swap(&mut a, &mut n);
        let a_mod_4 = (&n % 4u32).to_u32_digits().first().copied().unwrap_or(0);
        let n_mod_4 = (&a % 4u32).to_u32_digits().first().copied().unwrap_or(0);
        if a_mod_4 == 3 && n_mod_4 == 3 {
            result = -result;
        }
        a %= &n;
    }
    if n == BigUint::from(1u32) { result } else { 0 }
}

/// `Crypto.Math._IntegerBase.IntegerBase.random`
fn random(bits: u64, exact: bool, drng: &mut Drng) -> BigUint {
    let bytes_needed = ((bits - 1) / 8 + 1) as usize;
    let significant_bits_msb = 8 - (bytes_needed as u64 * 8 - bits);
    let mut buf = vec![0u8; bytes_needed];
    drng.read(&mut buf[..1]);
    if exact {
        buf[0] |= 1 << (significant_bits_msb - 1);
    }
    buf[0] &= ((1u16 << significant_bits_msb) - 1) as u8;
    drng.read(&mut buf[1..]);
    BigUint::from_bytes_be(&buf)
}

/// `Crypto.Math._IntegerBase.IntegerBase.random_range`
fn random_range(min_inclusive: &BigUint, max_inclusive: &BigUint, drng: &mut Drng) -> BigUint {
    let norm_maximum = max_inclusive - min_inclusive;
    let bits_needed = norm_maximum.bits();
    loop {
        let candidate = random(bits_needed, false, drng);
        if candidate <= norm_maximum {
            return candidate + min_inclusive;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bip85::Root;
    use crate::bip85::tests::root;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = body.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let len_bytes: Vec<u8> = len
                .to_be_bytes()
                .into_iter()
                .skip_while(|b| *b == 0)
                .collect();
            out.push(0x80 | len_bytes.len() as u8);
            out.extend(len_bytes);
        }
        out.extend(body);
        out
    }

    fn der_int(x: &BigUint) -> Vec<u8> {
        let mut bytes = x.to_bytes_be();
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0);
        }
        der(0x02, &bytes)
    }

    /// pycryptodome `export_key(format='PEM', pkcs=1)`.
    fn pkcs1_pem(key: &RsaKey) -> String {
        let fields = [
            BigUint::ZERO,
            key.n.clone(),
            key.e.clone(),
            key.d.clone(),
            key.p.clone(),
            key.q.clone(),
            &key.d % (&key.p - 1u32),
            &key.d % (&key.q - 1u32),
            key.q.modinv(&key.p).unwrap(),
        ];
        let body: Vec<u8> = fields.iter().flat_map(der_int).collect();
        let der = der(0x30, &body);
        let mut pem = String::from("-----BEGIN RSA PRIVATE KEY-----\n");
        for chunk in der.chunks(48) {
            pem += &base64::engine::general_purpose::STANDARD.encode(chunk);
            pem += "\n";
        }
        pem + "-----END RSA PRIVATE KEY-----"
    }

    fn pem_sha256(root: &Root, path: &[u32], bits: u64) -> String {
        let mut drng = Drng::new(&root.entropy(path).unwrap());
        let key = generate(bits, &mut drng);
        Sha256::digest(pkcs1_pem(&key).as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The vectors of ethankosakovsky/bip85 `bip85/tests/test_bip85rsa.py`.
    #[test]
    fn reference_2048_mnemonic() {
        let root = Root::from_mnemonic(
            "install scatter logic circle pencil average fall shoe quantum disease suspect usage",
        )
        .unwrap();
        assert_eq!(
            pem_sha256(&root, &[0, 0], 2048),
            "64ff572798a6534c76eda9fd2d7e906a737a1bad893dec31ae3d0488e3f19ed9"
        );
    }

    #[test]
    fn reference_2048() {
        assert_eq!(
            pem_sha256(&root(), &[0, 1], 2048),
            "54196fdcbb0cb55c56b14a7068ea633dc784dde21cbe4e7f30f857ec88f9ac36"
        );
    }

    #[test]
    fn reference_4096() {
        assert_eq!(
            pem_sha256(&root(), &[0, 2], 4096),
            "c03f358f4aad4a0216881ec258ed6923201d174f52069bc9bcd341bb611696d5"
        );
    }

    #[test]
    fn jacobi_small_values() {
        // (a / 15) for a = 0..15, from the definition.
        let want = [0, 1, 1, 0, 1, 0, 0, -1, 1, 0, 0, -1, 0, -1, -1];
        for (a, want) in want.iter().enumerate() {
            assert_eq!(jacobi(a as i64, &BigUint::from(15u32)), *want, "a = {a}");
            assert_eq!(
                jacobi(a as i64 - 15, &BigUint::from(15u32)),
                *want,
                "a = {a} - 15"
            );
        }
    }
}
