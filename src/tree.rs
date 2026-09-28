//! The filesystem tree: which paths exist, what `ls` shows, and what each
//! file contains. SPEC.md section 5 defines the layout: visible directories
//! for the BIP-85 applications, hidden directories for encodings.

use std::collections::HashMap;
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};

use bip39::Language;

use crate::bip85::{Drng, InvalidKey, Root};
use crate::rsa::RsaKey;
use crate::{apps, openpgp, openssh, rsa};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Dir,
    File,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The path does not exist or is not a file.
    NotFound,
    /// BIP-85 requires a hard fail for this output.
    InvalidKey,
}

impl From<InvalidKey> for Error {
    fn from(_: InvalidKey) -> Self {
        Error::InvalidKey
    }
}

/// The largest hardened BIP-32 index.
const MAX_INDEX: u32 = (1 << 31) - 1;

const APP_HEX: u32 = 128169;
const APP_RSA: u32 = 828365;

/// The RSA key of the flat default names in the hidden directories.
const DEFAULT_RSA_BITS: u32 = 4096;

/// Directory name, wordlist, and BIP-85 language code.
const LANGUAGES: [(&str, Language, u32); 10] = [
    ("english", Language::English, 0),
    ("japanese", Language::Japanese, 1),
    ("korean", Language::Korean, 2),
    ("spanish", Language::Spanish, 3),
    ("chinese_simplified", Language::SimplifiedChinese, 4),
    ("chinese_traditional", Language::TraditionalChinese, 5),
    ("french", Language::French, 6),
    ("italian", Language::Italian, 7),
    ("czech", Language::Czech, 8),
    ("portuguese", Language::Portuguese, 9),
];

const APPS: [&str; 9] = [
    "base64", "base85", "bip39", "dice", "hex", "nostr", "rsa", "wif", "xprv",
];
const WORDS: [&str; 5] = ["12", "15", "18", "21", "24"];
const HEX_BYTES: RangeInclusive<u32> = 16..=64;
const BASE64_LEN: RangeInclusive<u32> = 20..=86;
const BASE85_LEN: RangeInclusive<u32> = 10..=80;
const RSA_BITS: RangeInclusive<u32> = 1024..=8192;
const RSA_BITS_LISTED: [&str; 3] = ["2048", "3072", "4096"];
const SUB_KEYS: [&str; 3] = ["0", "1", "2"];
const DICE_SIDES: RangeInclusive<u32> = 2..=MAX_INDEX;
const DICE_ROLLS: RangeInclusive<u32> = 1..=10000;
const RSA_PEM: &str = "private.pem";
const SSH_RSA_FILES: [&str; 2] = ["id_rsa", "id_rsa.pub"];
const SSH_ED25519_FILES: [&str; 2] = ["id_ed25519", "id_ed25519.pub"];
const AGE_FILES: [&str; 2] = ["private.age", "public.age"];
const PGP_FILES: [&str; 2] = ["public.asc", "secret.asc"];

enum Node {
    /// A directory and the entries that `ls` shows.
    Dir(Vec<(String, Kind)>),
    File(Output),
}

/// A file. `rsa` is an RSA derivation path below `m/83696968'`:
/// `[828365, key_bits, key_index]` or `[828365, key_bits, key_index, sub_key]`.
enum Output {
    Bip39 {
        language: Language,
        code: u32,
        words: u32,
        index: u32,
    },
    Wif {
        index: u32,
    },
    Xprv {
        index: u32,
    },
    Hex {
        num_bytes: u32,
        index: u32,
    },
    Base64 {
        pwd_len: u32,
        index: u32,
    },
    Base85 {
        pwd_len: u32,
        index: u32,
    },
    Dice {
        sides: u32,
        rolls: u32,
        index: u32,
    },
    Nostr {
        identity: u32,
        account_index: u32,
    },
    RsaPem {
        rsa: Vec<u32>,
    },
    SshRsaPrivate {
        rsa: Vec<u32>,
    },
    SshRsaPublic {
        rsa: Vec<u32>,
    },
    /// The seed of an Ed25519 or age key is `hex/32/{index}`.
    SshEd25519Private {
        index: u32,
    },
    SshEd25519Public {
        index: u32,
    },
    AgePrivate {
        index: u32,
    },
    AgePublic {
        index: u32,
    },
    PgpSecret {
        bits: u32,
        key_index: u32,
    },
    PgpPublic {
        bits: u32,
        key_index: u32,
    },
}

/// A number in canonical decimal form (no sign, no leading zero) in `range`.
fn number(s: &str, range: RangeInclusive<u32>) -> Option<u32> {
    let canonical = s == "0" || (s.starts_with(|c| ('1'..='9').contains(&c)));
    if !canonical || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok().filter(|n| range.contains(n))
}

fn index(s: &str) -> Option<u32> {
    number(s, 0..=MAX_INDEX)
}

fn language(s: &str) -> Option<(Language, u32)> {
    LANGUAGES
        .iter()
        .find(|(name, _, _)| *name == s)
        .map(|(_, language, code)| (*language, *code))
}

/// The RSA derivation path of `{key_bits}/{key_index}`.
fn rsa_path(bits: &str, key_index: &str) -> Option<Vec<u32>> {
    Some(vec![APP_RSA, number(bits, RSA_BITS)?, index(key_index)?])
}

/// The RSA derivation path of `{key_bits}/{key_index}/{sub_key}`.
fn rsa_sub_path(bits: &str, key_index: &str, sub_key: &str) -> Option<Vec<u32>> {
    let mut path = rsa_path(bits, key_index)?;
    path.push(number(sub_key, 0..=2)?);
    Some(path)
}

fn default_rsa_path() -> Vec<u32> {
    vec![APP_RSA, DEFAULT_RSA_BITS, 0]
}

fn entries<'a>(names: impl IntoIterator<Item = &'a str>, kind: Kind) -> Vec<(String, Kind)> {
    names
        .into_iter()
        .map(|name| (name.to_string(), kind))
        .collect()
}

/// A directory that lists sub directories `dirs` and files `files`.
fn dir(dirs: &[&str], files: &[&str]) -> Node {
    let mut listing = entries(dirs.iter().copied(), Kind::Dir);
    listing.extend(entries(files.iter().copied(), Kind::File));
    Node::Dir(listing)
}

fn listed_numbers(range: RangeInclusive<u32>) -> Vec<(String, Kind)> {
    range.map(|n| (n.to_string(), Kind::Dir)).collect()
}

/// An unlisted directory: its entries exist, but `ls` does not show them.
fn unlisted() -> Node {
    Node::Dir(Vec::new())
}

pub struct Tree {
    root: Root,
    gpg_user_id: Option<String>,
    rsa_keys: Mutex<HashMap<Vec<u32>, Arc<RsaKey>>>,
    contents: Mutex<HashMap<Vec<String>, Arc<[u8]>>>,
}

impl Tree {
    /// `gpg_user_id` enables the `.gnupg` directory.
    pub fn new(root: Root, gpg_user_id: Option<String>) -> Self {
        Self {
            root,
            gpg_user_id,
            rsa_keys: Mutex::default(),
            contents: Mutex::default(),
        }
    }

    pub fn kind(&self, path: &[&str]) -> Option<Kind> {
        match self.node(path)? {
            Node::Dir(_) => Some(Kind::Dir),
            Node::File(_) => Some(Kind::File),
        }
    }

    /// The entries that `ls` shows. Empty if `path` is not a directory.
    pub fn list(&self, path: &[&str]) -> Vec<(String, Kind)> {
        match self.node(path) {
            Some(Node::Dir(entries)) => entries,
            _ => Vec::new(),
        }
    }

    /// The contents of a file, with the trailing newline. Computed once.
    pub fn read(&self, path: &[&str]) -> Result<Arc<[u8]>, Error> {
        let key: Vec<String> = path.iter().map(|s| s.to_string()).collect();
        if let Some(contents) = self.contents.lock().unwrap().get(&key) {
            return Ok(contents.clone());
        }
        let Some(Node::File(output)) = self.node(path) else {
            return Err(Error::NotFound);
        };
        let contents: Arc<[u8]> = format!("{}\n", self.text(&output)?).into_bytes().into();
        self.contents.lock().unwrap().insert(key, contents.clone());
        Ok(contents)
    }

    fn node(&self, path: &[&str]) -> Option<Node> {
        match path.first() {
            Some(&".ssh") => Self::ssh_node(&path[1..]),
            Some(&".age") => Self::age_node(&path[1..]),
            Some(&".gnupg") if self.gpg_user_id.is_some() => Self::gnupg_node(&path[1..]),
            _ => self.visible_node(path),
        }
    }

    /// The root and the BIP-85 applications (SPEC.md section 5.1).
    fn visible_node(&self, path: &[&str]) -> Option<Node> {
        use Node::{Dir, File};
        use Output::*;
        let node = match *path {
            [] => {
                let mut hidden = vec![".age", ".ssh"];
                if self.gpg_user_id.is_some() {
                    hidden.push(".gnupg");
                }
                dir(&[hidden.as_slice(), APPS.as_slice()].concat(), &[])
            }

            ["bip39"] => Dir(entries(LANGUAGES.iter().map(|l| l.0), Kind::Dir)),
            ["bip39", lang] => {
                language(lang)?;
                Dir(entries(WORDS, Kind::Dir))
            }
            ["bip39", lang, words] => {
                language(lang)?;
                WORDS.contains(&words).then_some(())?;
                unlisted()
            }
            ["bip39", lang, words, i] => {
                let (language, code) = language(lang)?;
                WORDS.contains(&words).then_some(())?;
                let words = number(words, 12..=24)?;
                File(Bip39 {
                    language,
                    code,
                    words,
                    index: index(i)?,
                })
            }

            ["wif"] | ["xprv"] => unlisted(),
            ["wif", i] => File(Wif { index: index(i)? }),
            ["xprv", i] => File(Xprv { index: index(i)? }),

            ["hex"] => Dir(listed_numbers(HEX_BYTES)),
            ["base64"] => Dir(listed_numbers(BASE64_LEN)),
            ["base85"] => Dir(listed_numbers(BASE85_LEN)),
            ["hex", n] => {
                number(n, HEX_BYTES)?;
                unlisted()
            }
            ["base64", n] => {
                number(n, BASE64_LEN)?;
                unlisted()
            }
            ["base85", n] => {
                number(n, BASE85_LEN)?;
                unlisted()
            }
            ["hex", n, i] => File(Hex {
                num_bytes: number(n, HEX_BYTES)?,
                index: index(i)?,
            }),
            ["base64", n, i] => File(Base64 {
                pwd_len: number(n, BASE64_LEN)?,
                index: index(i)?,
            }),
            ["base85", n, i] => File(Base85 {
                pwd_len: number(n, BASE85_LEN)?,
                index: index(i)?,
            }),

            ["dice"] => unlisted(),
            ["dice", sides] => {
                number(sides, DICE_SIDES)?;
                unlisted()
            }
            ["dice", sides, rolls] => {
                number(sides, DICE_SIDES)?;
                number(rolls, DICE_ROLLS)?;
                unlisted()
            }
            ["dice", sides, rolls, i] => File(Dice {
                sides: number(sides, DICE_SIDES)?,
                rolls: number(rolls, DICE_ROLLS)?,
                index: index(i)?,
            }),

            // BIP-85 reserves identity 0 and account index 0.
            ["nostr"] => unlisted(),
            ["nostr", identity] => {
                number(identity, 1..=MAX_INDEX)?;
                unlisted()
            }
            ["nostr", identity, account_index] => File(Nostr {
                identity: number(identity, 1..=MAX_INDEX)?,
                account_index: number(account_index, 1..=MAX_INDEX)?,
            }),

            ["rsa"] => Dir(entries(RSA_BITS_LISTED, Kind::Dir)),
            ["rsa", bits] => {
                number(bits, RSA_BITS)?;
                unlisted()
            }
            ["rsa", bits, key_index] => {
                rsa_path(bits, key_index)?;
                dir(&SUB_KEYS, &[RSA_PEM])
            }
            ["rsa", bits, key_index, RSA_PEM] => File(RsaPem {
                rsa: rsa_path(bits, key_index)?,
            }),
            ["rsa", bits, key_index, sub_key] => {
                rsa_sub_path(bits, key_index, sub_key)?;
                dir(&[], &[RSA_PEM])
            }
            ["rsa", bits, key_index, sub_key, RSA_PEM] => File(RsaPem {
                rsa: rsa_sub_path(bits, key_index, sub_key)?,
            }),

            _ => return None,
        };
        Some(node)
    }

    /// `/.ssh` (SPEC.md section 5.2).
    fn ssh_node(path: &[&str]) -> Option<Node> {
        use Node::File;
        use Output::*;
        let ed25519 = |i: &str, name: &str| -> Option<Node> {
            let index = index(i)?;
            match name {
                "id_ed25519" => Some(File(SshEd25519Private { index })),
                "id_ed25519.pub" => Some(File(SshEd25519Public { index })),
                _ => None,
            }
        };
        let rsa = |rsa: Vec<u32>, name: &str| -> Option<Node> {
            match name {
                "id_rsa" => Some(File(SshRsaPrivate { rsa })),
                "id_rsa.pub" => Some(File(SshRsaPublic { rsa })),
                _ => None,
            }
        };
        let node = match *path {
            [] => dir(
                &["ed25519", "rsa"],
                &[SSH_ED25519_FILES, SSH_RSA_FILES].concat(),
            ),
            [name @ ("id_ed25519" | "id_ed25519.pub")] => ed25519("0", name)?,
            [name @ ("id_rsa" | "id_rsa.pub")] => rsa(default_rsa_path(), name)?,

            ["ed25519"] => unlisted(),
            ["ed25519", i] => {
                index(i)?;
                dir(&[], &SSH_ED25519_FILES)
            }
            ["ed25519", i, name] => ed25519(i, name)?,

            ["rsa"] => Node::Dir(entries(RSA_BITS_LISTED, Kind::Dir)),
            ["rsa", bits] => {
                number(bits, RSA_BITS)?;
                unlisted()
            }
            ["rsa", bits, key_index] => {
                rsa_path(bits, key_index)?;
                dir(&SUB_KEYS, &SSH_RSA_FILES)
            }
            ["rsa", bits, key_index, name @ ("id_rsa" | "id_rsa.pub")] => {
                rsa(rsa_path(bits, key_index)?, name)?
            }
            ["rsa", bits, key_index, sub_key] => {
                rsa_sub_path(bits, key_index, sub_key)?;
                dir(&[], &SSH_RSA_FILES)
            }
            ["rsa", bits, key_index, sub_key, name] => {
                rsa(rsa_sub_path(bits, key_index, sub_key)?, name)?
            }

            _ => return None,
        };
        Some(node)
    }

    /// `/.age` (SPEC.md section 5.2).
    fn age_node(path: &[&str]) -> Option<Node> {
        use Node::File;
        use Output::*;
        let age = |i: &str, name: &str| -> Option<Node> {
            let index = index(i)?;
            match name {
                "private.age" => Some(File(AgePrivate { index })),
                "public.age" => Some(File(AgePublic { index })),
                _ => None,
            }
        };
        let node = match *path {
            [] => dir(&["x25519"], &AGE_FILES),
            ["x25519"] => unlisted(),
            [name] => age("0", name)?,
            ["x25519", i] => {
                index(i)?;
                dir(&[], &AGE_FILES)
            }
            ["x25519", i, name] => age(i, name)?,
            _ => return None,
        };
        Some(node)
    }

    /// `/.gnupg` (SPEC.md section 5.2). It exists only with a user ID.
    fn gnupg_node(path: &[&str]) -> Option<Node> {
        use Node::File;
        use Output::*;
        let pgp = |rsa: Vec<u32>, name: &str| -> Option<Node> {
            let (bits, key_index) = (rsa[1], rsa[2]);
            match name {
                "secret.asc" => Some(File(PgpSecret { bits, key_index })),
                "public.asc" => Some(File(PgpPublic { bits, key_index })),
                _ => None,
            }
        };
        let node = match *path {
            [] => dir(&["rsa"], &PGP_FILES),
            ["rsa"] => Node::Dir(entries(RSA_BITS_LISTED, Kind::Dir)),
            [name] => pgp(default_rsa_path(), name)?,
            ["rsa", bits] => {
                number(bits, RSA_BITS)?;
                unlisted()
            }
            ["rsa", bits, key_index] => {
                rsa_path(bits, key_index)?;
                dir(&[], &PGP_FILES)
            }
            ["rsa", bits, key_index, name] => pgp(rsa_path(bits, key_index)?, name)?,
            _ => return None,
        };
        Some(node)
    }

    fn text(&self, output: &Output) -> Result<String, InvalidKey> {
        use Output::*;
        let entropy = |path: &[u32]| self.root.entropy(path);
        let seed = |index: u32| -> Result<[u8; 32], InvalidKey> {
            Ok(entropy(&[APP_HEX, 32, index])?[..32].try_into().unwrap())
        };
        let text = match *output {
            Bip39 {
                language,
                code,
                words,
                index,
            } => apps::bip39(
                &entropy(&[39, code, words, index])?,
                language,
                words as usize,
            ),
            Wif { index } => apps::wif(&entropy(&[2, index])?)?,
            Xprv { index } => apps::xprv(&entropy(&[32, index])?)?,
            Hex { num_bytes, index } => {
                apps::hex(&entropy(&[APP_HEX, num_bytes, index])?, num_bytes as usize)
            }
            Base64 { pwd_len, index } => {
                apps::base64(&entropy(&[707764, pwd_len, index])?, pwd_len as usize)
            }
            Base85 { pwd_len, index } => {
                apps::base85(&entropy(&[707785, pwd_len, index])?, pwd_len as usize)
            }
            Dice {
                sides,
                rolls,
                index,
            } => apps::dice(&entropy(&[89101, sides, rolls, index])?, sides, rolls),
            Nostr {
                identity,
                account_index,
            } => apps::nostr(&entropy(&[128002, identity, account_index])?)?,
            RsaPem { ref rsa } => self.rsa_key(rsa)?.to_pkcs1_pem(),
            SshRsaPrivate { ref rsa } => openssh::rsa_private_key(&*self.rsa_key(rsa)?),
            SshRsaPublic { ref rsa } => openssh::rsa_public_key(&*self.rsa_key(rsa)?),
            SshEd25519Private { index } => openssh::ed25519_private_key(&seed(index)?),
            SshEd25519Public { index } => openssh::ed25519_public_key(&seed(index)?),
            AgePrivate { index } => apps::age_private(&entropy(&[APP_HEX, 32, index])?),
            AgePublic { index } => apps::age_public(&entropy(&[APP_HEX, 32, index])?),
            PgpSecret { bits, key_index } | PgpPublic { bits, key_index } => {
                let user_id = self
                    .gpg_user_id
                    .as_deref()
                    .expect("OpenPGP files need a user ID");
                let primary = self.rsa_key(&[APP_RSA, bits, key_index])?;
                let subkeys: Vec<Arc<RsaKey>> = (0..3)
                    .map(|sub_key| self.rsa_key(&[APP_RSA, bits, key_index, sub_key]))
                    .collect::<Result<_, _>>()?;
                let subkeys = [&*subkeys[0], &*subkeys[1], &*subkeys[2]];
                if matches!(output, PgpSecret { .. }) {
                    openpgp::secret_key(user_id, &primary, subkeys)
                } else {
                    openpgp::public_key(user_id, &primary, subkeys)
                }
            }
        };
        Ok(text)
    }

    /// The RSA key at `path`, where `path[1]` is the key size in bits.
    fn rsa_key(&self, path: &[u32]) -> Result<Arc<RsaKey>, InvalidKey> {
        if let Some(key) = self.rsa_keys.lock().unwrap().get(path) {
            return Ok(key.clone());
        }
        let mut drng = Drng::new(&self.root.entropy(path)?);
        let key = Arc::new(rsa::generate(path[1] as u64, &mut drng));
        self.rsa_keys
            .lock()
            .unwrap()
            .insert(path.to_vec(), key.clone());
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const USER_ID: &str = "Test <test@example.org>";

    fn tree(gpg_user_id: Option<&str>) -> Tree {
        Tree::new(
            Root::from_mnemonic(MNEMONIC).unwrap(),
            gpg_user_id.map(String::from),
        )
    }

    fn split(path: &str) -> Vec<&str> {
        path.split('/').filter(|s| !s.is_empty()).collect()
    }

    fn read(tree: &Tree, path: &str) -> String {
        String::from_utf8(tree.read(&split(path)).unwrap().to_vec()).unwrap()
    }

    fn names(tree: &Tree, path: &str) -> Vec<String> {
        tree.list(&split(path))
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    #[test]
    fn first_request_examples() {
        let t = tree(None);
        assert_eq!(
            read(&t, "/bip39/english/12/0"),
            "prosper short ramp prepare exchange stove life snack client enough purpose fold\n"
        );
        assert_eq!(
            read(&t, "/hex/32/0"),
            "e477d4694160a384b28ee2f72b54edcf0822fd6e1ee1780447455cdbed8f8c45\n"
        );
    }

    #[test]
    fn every_file_kind_exists() {
        let t = tree(Some(USER_ID));
        let files = [
            "bip39/japanese/24/5",
            "wif/0",
            "xprv/0",
            "hex/64/2147483647",
            "base64/86/1",
            "base85/10/1",
            "dice/6/10/0",
            "nostr/1/1",
            "rsa/2048/0/private.pem",
            "rsa/2048/0/2/private.pem",
            ".ssh/id_ed25519",
            ".ssh/id_ed25519.pub",
            ".ssh/ed25519/9/id_ed25519",
            ".ssh/ed25519/9/id_ed25519.pub",
            ".ssh/rsa/2048/0/id_rsa",
            ".ssh/rsa/2048/0/id_rsa.pub",
            ".ssh/rsa/2048/0/1/id_rsa.pub",
            ".age/private.age",
            ".age/public.age",
            ".age/x25519/9/private.age",
            ".age/x25519/9/public.age",
            ".gnupg/rsa/2048/0/public.asc",
        ];
        for path in files {
            assert_eq!(t.kind(&split(path)), Some(Kind::File), "{path}");
            let text = read(&t, path);
            assert!(
                text.ends_with('\n') && !text.ends_with("\n\n"),
                "{path}: {text:?}"
            );
        }
    }

    #[test]
    fn encodings_use_the_bip85_outputs() {
        let t = tree(Some(USER_ID));
        let entropy = t.root.entropy(&[APP_HEX, 32, 7]).unwrap();
        let seed: [u8; 32] = entropy[..32].try_into().unwrap();
        assert_eq!(
            read(&t, ".age/x25519/7/private.age"),
            format!("{}\n", apps::age_private(&entropy))
        );
        assert_eq!(
            read(&t, ".ssh/ed25519/7/id_ed25519.pub"),
            format!("{}\n", openssh::ed25519_public_key(&seed))
        );
        let key = t.rsa_key(&[APP_RSA, 2048, 3, 1]).unwrap();
        assert_eq!(
            read(&t, "rsa/2048/3/1/private.pem"),
            format!("{}\n", key.to_pkcs1_pem())
        );
        assert_eq!(
            read(&t, ".ssh/rsa/2048/3/1/id_rsa.pub"),
            format!("{}\n", openssh::rsa_public_key(&key))
        );
    }

    #[test]
    fn flat_defaults_are_index_0() {
        let t = tree(Some(USER_ID));
        let same = [
            (".ssh/id_ed25519", ".ssh/ed25519/0/id_ed25519"),
            (".ssh/id_ed25519.pub", ".ssh/ed25519/0/id_ed25519.pub"),
            (".age/private.age", ".age/x25519/0/private.age"),
            (".age/public.age", ".age/x25519/0/public.age"),
        ];
        for (flat, indexed) in same {
            assert_eq!(read(&t, flat), read(&t, indexed), "{flat}");
        }
        // The 4096-bit defaults: compare the key paths, not the slow contents.
        let ssh_rsa = |path: &str| match t.node(&split(path)) {
            Some(Node::File(Output::SshRsaPrivate { rsa })) => rsa,
            _ => panic!("{path} is not an OpenSSH RSA key"),
        };
        assert_eq!(ssh_rsa(".ssh/id_rsa"), [APP_RSA, 4096, 0]);
        assert_eq!(ssh_rsa(".ssh/rsa/4096/0/id_rsa"), [APP_RSA, 4096, 0]);
        let pgp = |path: &str| match t.node(&split(path)) {
            Some(Node::File(Output::PgpSecret { bits, key_index })) => (bits, key_index),
            _ => panic!("{path} is not an OpenPGP secret key"),
        };
        assert_eq!(pgp(".gnupg/secret.asc"), (4096, 0));
        assert_eq!(pgp(".gnupg/rsa/4096/0/secret.asc"), (4096, 0));
    }

    #[test]
    fn listings() {
        let t = tree(None);
        assert_eq!(
            names(&t, "/"),
            [
                ".age", ".ssh", "base64", "base85", "bip39", "dice", "hex", "nostr", "rsa", "wif",
                "xprv"
            ]
        );
        assert_eq!(names(&t, "bip39").len(), 10);
        assert_eq!(names(&t, "bip39/czech"), WORDS);
        assert!(names(&t, "bip39/czech/12").is_empty());
        assert_eq!(names(&t, "hex").len(), 49);
        assert_eq!(names(&t, "base64").len(), 67);
        assert_eq!(names(&t, "base85").len(), 71);
        assert_eq!(names(&t, "rsa"), RSA_BITS_LISTED);
        assert_eq!(names(&t, "rsa/4096/0"), ["0", "1", "2", "private.pem"]);
        assert_eq!(names(&t, "rsa/4096/0/1"), [RSA_PEM]);
        assert_eq!(
            names(&t, ".ssh"),
            [
                "ed25519",
                "rsa",
                "id_ed25519",
                "id_ed25519.pub",
                "id_rsa",
                "id_rsa.pub"
            ]
        );
        assert!(names(&t, ".ssh/ed25519").is_empty());
        assert_eq!(names(&t, ".ssh/ed25519/3"), SSH_ED25519_FILES);
        assert_eq!(names(&t, ".ssh/rsa"), RSA_BITS_LISTED);
        assert_eq!(
            names(&t, ".ssh/rsa/2048/0"),
            ["0", "1", "2", "id_rsa", "id_rsa.pub"]
        );
        assert_eq!(names(&t, ".ssh/rsa/2048/0/2"), SSH_RSA_FILES);
        assert_eq!(names(&t, ".age"), ["x25519", "private.age", "public.age"]);
        assert_eq!(names(&t, ".age/x25519/3"), AGE_FILES);

        let with_gpg = tree(Some(USER_ID));
        assert!(names(&with_gpg, "/").contains(&".gnupg".to_string()));
        assert_eq!(
            names(&with_gpg, ".gnupg"),
            ["rsa", "public.asc", "secret.asc"]
        );
        assert_eq!(names(&with_gpg, ".gnupg/rsa"), RSA_BITS_LISTED);
        assert_eq!(names(&with_gpg, ".gnupg/rsa/3072/5"), PGP_FILES);
    }

    #[test]
    fn missing_paths() {
        let t = tree(None);
        let missing = [
            "nope",
            "age/x25519/0/private.age",
            "hex/base64/32/0",
            "hex/32/007",
            "hex/32/+7",
            "hex/32/2147483648",
            "hex/15/0",
            "hex/65/0",
            "hex/32/0/x",
            "bip39/klingon/12/0",
            "bip39/english/13/0",
            "bip39/english/012/0",
            "base64/19/0",
            "base85/81/0",
            "rsa/2048/0/openssh-key-v1",
            "rsa/1023/0/private.pem",
            "rsa/8193/0/private.pem",
            "rsa/2048/0/3/private.pem",
            "dice/1/1/0",
            "dice/2147483648/1/0",
            "dice/6/0/0",
            "dice/6/10001/0",
            "nostr/0/1",
            "nostr/1/0",
            ".ssh/id_rsa/x",
            ".ssh/id_dsa",
            ".ssh/ed25519/01/id_ed25519",
            ".ssh/ed25519/0/id_rsa",
            ".ssh/rsa/2048/0/3/id_rsa",
            ".ssh/rsa/2048/0/private.pem",
            ".age/key.txt",
            ".age/x25519/0/other.age",
            ".gnupg",
            ".gnupg/secret.asc",
        ];
        for path in missing {
            assert_eq!(t.kind(&split(path)), None, "{path}");
            assert_eq!(t.read(&split(path)), Err(Error::NotFound), "{path}");
        }
        let with_gpg = tree(Some(USER_ID));
        for path in [".gnupg/rsa/2048/0/0/secret.asc", ".gnupg/key.asc"] {
            assert_eq!(with_gpg.kind(&split(path)), None, "{path}");
        }
    }

    #[test]
    fn directories_are_not_files() {
        let t = tree(None);
        assert_eq!(t.kind(&split("rsa/2048/0")), Some(Kind::Dir));
        assert_eq!(t.read(&split("rsa/2048/0")), Err(Error::NotFound));
    }
}
