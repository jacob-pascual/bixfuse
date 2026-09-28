//! The BIP-85 applications that need no RSA key.
//!
//! Each function takes the 64 bytes of entropy of its derivation path and
//! returns the text of the output, without the trailing newline.

use base64::Engine;
use bech32::{Bech32, ByteIterExt, Fe32IterExt, Hrp};
use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpriv};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{NetworkKind, PrivateKey};
use kem::{Decapsulator, KeyExport};
use unicode_normalization::UnicodeNormalization;

use crate::bip85::{Drng, InvalidKey};

/// The words are in Unicode NFC, as in the BIP-39 wordlist files and bipsea.
/// The `bip39` crate keeps its wordlists in NFKD.
pub fn bip39(entropy: &[u8; 64], language: bip39::Language, words: usize) -> String {
    let bytes = words * 4 / 3;
    let mnemonic = bip39::Mnemonic::from_entropy_in(language, &entropy[..bytes])
        .expect("12 to 24 words is a valid entropy length");
    mnemonic
        .words()
        .collect::<Vec<_>>()
        .join(" ")
        .nfc()
        .collect()
}

pub fn wif(entropy: &[u8; 64]) -> Result<String, InvalidKey> {
    let key = PrivateKey::from_slice(&entropy[..32], NetworkKind::Main).map_err(|_| InvalidKey)?;
    Ok(key.to_wif())
}

pub fn xprv(entropy: &[u8; 64]) -> Result<String, InvalidKey> {
    let xprv = Xpriv {
        network: NetworkKind::Main,
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::Normal { index: 0 },
        private_key: SecretKey::from_slice(&entropy[32..]).map_err(|_| InvalidKey)?,
        chain_code: ChainCode::from(<[u8; 32]>::try_from(&entropy[..32]).unwrap()),
    };
    Ok(xprv.to_string())
}

pub fn hex(entropy: &[u8; 64], num_bytes: usize) -> String {
    entropy[..num_bytes]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn base64(entropy: &[u8; 64], pwd_len: usize) -> String {
    let mut s = base64::engine::general_purpose::STANDARD.encode(entropy);
    s.truncate(pwd_len);
    s
}

/// The alphabet of RFC 1924 and of Python `base64.b85encode`.
const BASE85: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

pub fn base85(entropy: &[u8; 64], pwd_len: usize) -> String {
    let mut s = String::with_capacity(80);
    for chunk in entropy.chunks(4) {
        let mut value = u32::from_be_bytes(chunk.try_into().unwrap());
        let mut digits = [0u8; 5];
        for digit in digits.iter_mut().rev() {
            *digit = BASE85[(value % 85) as usize];
            value /= 85;
        }
        s.extend(digits.map(char::from));
    }
    s.truncate(pwd_len);
    s
}

pub fn dice(entropy: &[u8; 64], sides: u32, rolls: u32) -> String {
    // ceil(log2(sides)), computed exactly.
    let bits_per_roll = u32::BITS - (sides - 1).leading_zeros();
    let bytes_per_roll = bits_per_roll.div_ceil(8) as usize;
    let width = (sides - 1).to_string().len();
    let mut drng = Drng::new(entropy);
    let mut out = Vec::with_capacity(rolls as usize);
    while out.len() < rolls as usize {
        let mut buf = [0u8; 4];
        drng.read(&mut buf[4 - bytes_per_roll..]);
        let trial = u32::from_be_bytes(buf) >> (8 * bytes_per_roll as u32 - bits_per_roll);
        if trial < sides {
            out.push(format!("{trial:0width$}"));
        }
    }
    out.join(",")
}

pub fn nostr(entropy: &[u8; 64]) -> Result<String, InvalidKey> {
    let key = SecretKey::from_slice(&entropy[..32]).map_err(|_| InvalidKey)?;
    Ok(bech32::encode::<Bech32>(Hrp::parse("nsec").unwrap(), &key.secret_bytes()).unwrap())
}

pub fn age_private(entropy: &[u8; 64]) -> String {
    bech32::encode_upper::<Bech32>(Hrp::parse("age-secret-key-").unwrap(), &entropy[..32]).unwrap()
}

pub fn age_public(entropy: &[u8; 64]) -> String {
    let secret: [u8; 32] = entropy[..32].try_into().unwrap();
    let public = x25519_dalek::x25519(secret, x25519_dalek::X25519_BASEPOINT_BYTES);
    bech32::encode::<Bech32>(Hrp::parse("age").unwrap(), &public).unwrap()
}

/// The age post-quantum (MLKEM768-X25519) identity of the first 32 bytes.
pub fn age_pq_private(entropy: &[u8; 64]) -> String {
    bech32::encode_upper::<Bech32>(Hrp::parse("age-secret-key-pq-").unwrap(), &entropy[..32])
        .unwrap()
}

/// The age post-quantum recipient: the X-Wing encapsulation key (1216 bytes)
/// of the first 32 bytes. The age specification uses Bech32 without a length
/// limit, and the recipient has 1959 characters. `bech32::encode` refuses
/// strings longer than the code length, so this function uses the encoder
/// iterators, which compute the same checksum without the length check.
pub fn age_pq_public(entropy: &[u8; 64]) -> String {
    let seed: [u8; 32] = entropy[..32].try_into().unwrap();
    let key = x_wing::DecapsulationKey::from(seed)
        .encapsulation_key()
        .to_bytes();
    key.iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32>(&Hrp::parse("age1pq").unwrap())
        .chars()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip85::Root;
    use crate::bip85::tests::root;
    use bip39::Language;

    #[test]
    fn bip39_vectors() {
        let r = root();
        assert_eq!(
            bip39(&r.entropy(&[39, 0, 12, 0]).unwrap(), Language::English, 12),
            "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"
        );
        assert_eq!(
            bip39(&r.entropy(&[39, 0, 18, 0]).unwrap(), Language::English, 18),
            "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token"
        );
        assert_eq!(
            bip39(&r.entropy(&[39, 0, 24, 0]).unwrap(), Language::English, 24),
            "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano"
        );
    }

    #[test]
    fn wif_vector() {
        assert_eq!(
            wif(&root().entropy(&[2, 0]).unwrap()).unwrap(),
            "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp"
        );
    }

    #[test]
    fn xprv_vector() {
        assert_eq!(
            xprv(&root().entropy(&[32, 0]).unwrap()).unwrap(),
            "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX"
        );
    }

    #[test]
    fn hex_vector() {
        assert_eq!(
            hex(&root().entropy(&[128169, 64, 0]).unwrap(), 64),
            "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c"
        );
    }

    #[test]
    fn base64_vector() {
        assert_eq!(
            base64(&root().entropy(&[707764, 21, 0]).unwrap(), 21),
            "dKLoepugzdVJvdL56ogNV"
        );
    }

    #[test]
    fn base85_vector() {
        assert_eq!(
            base85(&root().entropy(&[707785, 12, 0]).unwrap(), 12),
            "_s`{TW89)i4`"
        );
    }

    #[test]
    fn dice_vector() {
        assert_eq!(
            dice(&root().entropy(&[89101, 6, 10, 0]).unwrap(), 6, 10),
            "1,0,0,2,0,1,5,5,2,4"
        );
    }

    #[test]
    fn nostr_vectors() {
        let r = root();
        assert_eq!(
            nostr(&r.entropy(&[128002, 1, 1]).unwrap()).unwrap(),
            "nsec1lahtplxlrmu852sxkrtcsn2ftdyx6ra2yy8flq8j8ltyn4hpznfq23uvqz"
        );
        assert_eq!(
            nostr(&r.entropy(&[128002, 1, 2]).unwrap()).unwrap(),
            "nsec1j9mzs6yk2g5g76vrezspmdgk6p5h65vcmnuaayqst9l4uv30hfhqje0jyh"
        );
        assert_eq!(
            nostr(&r.entropy(&[128002, 2, 1]).unwrap()).unwrap(),
            "nsec1lgh8ss53k87ng7arvfr89ccfpjevac6ts4n3sqekuw4zjrgzw9dsq3uelh"
        );
    }

    /// The vector of bitcoin/bips#2174.
    #[test]
    fn age_vector() {
        let e = root().entropy(&[128169, 32, 0]).unwrap();
        assert_eq!(
            hex(&e, 32),
            "ea3ceb0b02ee8e587779c63f4b7b3a21e950a213f1ec53cab608d13e8796e6dc"
        );
        assert_eq!(
            age_private(&e),
            "AGE-SECRET-KEY-1AG7WKZCZA689SAMECCL5K7E6Y854PGSN78K98J4KPRGNAPUKUMWQWNNT4U"
        );
        assert_eq!(
            age_public(&e),
            "age1m0hhzxelxsxnxm4ennvdpk75j8s7mn5w4tt3e4ntug5qx256wslqmdz8e9"
        );
    }

    /// The post-quantum vector of bitcoin/bips#2174. The PR gives the
    /// SHA-256 of the recipient instead of the 1959 characters.
    #[test]
    fn age_pq_vector() {
        use sha2::{Digest, Sha256};
        let e = root().entropy(&[128169, 32, 0]).unwrap();
        assert_eq!(
            age_pq_private(&e),
            "AGE-SECRET-KEY-PQ-1AG7WKZCZA689SAMECCL5K7E6Y854PGSN78K98J4KPRGNAPUKUMWQ5AN2M5"
        );
        let recipient = age_pq_public(&e);
        assert_eq!(recipient.len(), 1959);
        assert!(recipient.starts_with("age1pq1"));
        assert_eq!(
            Sha256::digest(recipient.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "855bd04ee0cd6cfdf5717fb946d859824a79fbbdf6304dadcc11dbb91abe0df6"
        );
    }

    /// Outputs of bipsea 4.0.0 (`bipsea derive -x <XPRV> ...`) for cases
    /// that have no BIP-85 test vector.
    #[test]
    fn bipsea_cross_checks() {
        let r = root();
        let cases = [
            (
                Language::Japanese,
                1,
                12,
                0,
                "おまいり にんてい こふん ぎんいろ にんい ぜんご ひめい まほう たたみ さとう ざいたく あてな",
            ),
            (
                Language::Korean,
                2,
                12,
                0,
                "분필 생활 밀리미터 차남 고객 연락 코끼리 휴일 범인 축하 예절 주먹",
            ),
            (
                Language::Spanish,
                3,
                12,
                5,
                "ropa musgo igual asno junco pelea fachada cuesta retrato acudir aldea célula",
            ),
            (
                Language::SimplifiedChinese,
                4,
                18,
                4,
                "古 志 李 探 挤 螺 栏 端 缸 三 使 奉 寒 接 兼 酒 表 外",
            ),
            (
                Language::TraditionalChinese,
                5,
                21,
                2,
                "箭 響 易 氮 元 熟 只 吉 疾 火 倒 統 塗 縫 拔 誣 烯 床 池 重 著",
            ),
            (
                Language::French,
                6,
                12,
                6,
                "cerveau vigueur scandale parler édifier sceptre étrange perplexe adorer dénicher erreur clivage",
            ),
            (
                Language::Italian,
                7,
                12,
                7,
                "cifrare dubbio nettuno rubrica arenile affetto davanti sillaba fetta specie mantide ripieno",
            ),
            (
                Language::Czech,
                8,
                24,
                3,
                "mobil dotknout nakonec kohout soutok dozorce zhotovit uklidnit osoba manko zasunout posudek chyba kobyla cinkot lopuch masopust poledne uzdravit odcizit sekunda nerv odvaha svah",
            ),
            (
                Language::Portuguese,
                9,
                15,
                1,
                "acusador tarraxa custear reenvio roseira rabisco tingido ineficaz magnata moeda anomalia enjoar espreita cirurgia galocha",
            ),
        ];
        for (language, code, words, index, want) in cases {
            let e = r.entropy(&[39, code, words as u32, index]).unwrap();
            assert_eq!(bip39(&e, language, words), want, "{language:?}");
        }
        assert_eq!(
            dice(&r.entropy(&[89101, 100, 8, 0]).unwrap(), 100, 8),
            "79,06,92,77,73,02,55,28"
        );
        assert_eq!(
            dice(&r.entropy(&[89101, 1000000, 4, 9]).unwrap(), 1000000, 4),
            "936073,147111,067771,865978"
        );
        assert_eq!(
            dice(
                &r.entropy(&[89101, 2147483647, 3, 5]).unwrap(),
                2147483647,
                3
            ),
            "1947580742,0278320120,0004449472"
        );
        assert_eq!(
            base85(&r.entropy(&[707785, 80, 7]).unwrap(), 80),
            "bGwVuu}C@coHUM43nW^{HU!_x8->k9d7z`9$f6n}5cBRYwE}^xXSrd3r3?gO?=KgmCAshh;5clr@)YwE"
        );
        assert_eq!(
            base64(&r.entropy(&[707764, 86, 7]).unwrap(), 86),
            "6beTC2h1Oj8MLSWRg+TKs3pAP2u+ZLnUTdyiip0dM+Rt5es+HHN3tREgYUye62BI1caHuM7SBfIzbmGxb0cl4g"
        );
        assert_eq!(
            hex(&r.entropy(&[128169, 16, 2147483647]).unwrap(), 16),
            "1fc45072ea908074ba96e498d05b2a90"
        );
    }

    /// The examples of the first request, for the mnemonic "abandon ... about".
    #[test]
    fn abandon_about_examples() {
        let r = Root::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        )
        .unwrap();
        assert_eq!(
            bip39(&r.entropy(&[39, 0, 12, 0]).unwrap(), Language::English, 12),
            "prosper short ramp prepare exchange stove life snack client enough purpose fold"
        );
        assert_eq!(
            hex(&r.entropy(&[128169, 32, 0]).unwrap(), 32),
            "e477d4694160a384b28ee2f72b54edcf0822fd6e1ee1780447455cdbed8f8c45"
        );
    }
}
