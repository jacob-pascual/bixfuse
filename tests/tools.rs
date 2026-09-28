//! Checks of the key files with the reference tools: age-keygen, ssh-keygen, gpg.
//! The tools must be on PATH. The Nix build and the dev shell supply them.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use bixfuse::bip85::{Drng, Root};
use bixfuse::{apps, openpgp, openssh, rsa};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Runs `cmd` with `stdin` as input and returns its standard output.
fn run(cmd: &mut Command, stdin: &[u8]) -> String {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start {cmd:?}: {e}"));
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{cmd:?} failed: {:?}", out.status);
    String::from_utf8(out.stdout).unwrap()
}

/// A private temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bixfuse-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }

    /// Writes `contents` to a file with mode 0600 and returns its path.
    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn rsa_key(path: &[u32], bits: u64) -> rsa::RsaKey {
    let root = Root::from_mnemonic(MNEMONIC).unwrap();
    rsa::generate(bits, &mut Drng::new(&root.entropy(path).unwrap()))
}

/// Checks that ssh-keygen derives `public` from `private`, and that a
/// signature with `private` verifies with `public`.
fn check_ssh_key_pair(name: &str, private: &str, public: &str) {
    let dir = TempDir::new(name);
    let private_path = dir.write("key", &format!("{private}\n"));
    let public_path = dir.write("key.pub", &format!("{public}\n"));

    let derived = run(
        Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(&private_path),
        b"",
    );
    assert_eq!(derived, format!("{public}\n"), "{name}");

    let message = b"bixfuse\n";
    let signature = run(
        Command::new("ssh-keygen")
            .args(["-Y", "sign", "-n", "file", "-f"])
            .arg(&private_path),
        message,
    );
    let signature = dir.write("message.sig", &signature);
    run(
        Command::new("ssh-keygen")
            .args(["-Y", "check-novalidate", "-n", "file", "-f"])
            .arg(&public_path)
            .arg("-s")
            .arg(&signature),
        message,
    );
}

#[test]
fn ssh_keygen_reads_the_rsa_keys() {
    let key = rsa_key(&[828365, 2048, 0], 2048);
    let public = openssh::rsa_public_key(&key);
    // The signature checks that d, p, q, and iqmp are consistent with n and e.
    check_ssh_key_pair("ssh-rsa", &openssh::rsa_private_key(&key), &public);
    // ssh-keygen also reads the PKCS#1 PEM of the visible rsa directory.
    check_ssh_key_pair("ssh-rsa-pem", &key.to_pkcs1_pem(), &public);
}

#[test]
fn ssh_keygen_reads_the_ed25519_keys() {
    let root = Root::from_mnemonic(MNEMONIC).unwrap();
    for index in [0, 1] {
        // m/83696968'/838372'/25519'/{index}' (SPEC.md section 5.3)
        let entropy = root.entropy(&[838372, 25519, index]).unwrap();
        let seed: [u8; 32] = entropy[..32].try_into().unwrap();
        check_ssh_key_pair(
            &format!("ssh-ed25519-{index}"),
            &openssh::ed25519_private_key(&seed),
            &openssh::ed25519_public_key(&seed),
        );
    }
}

/// Runs gpg with its own home directory and returns its standard output.
fn gpg(home: &TempDir, args: &[&str], stdin: &[u8]) -> String {
    run(
        Command::new("gpg")
            .arg("--homedir")
            .arg(&home.0)
            .args(["--batch", "--no-tty", "--quiet"])
            .args(args),
        stdin,
    )
}

#[test]
fn gpg_imports_and_uses_the_keys() {
    let user_id = "bixfuse test <test@example.org>";
    let primary = rsa_key(&[828365, 2048, 0], 2048);
    let subkeys = [0, 1, 2].map(|i| rsa_key(&[828365, 2048, 0, i], 2048));
    let subkey_refs = [&subkeys[0], &subkeys[1], &subkeys[2]];

    // Fingerprints computed independently with pycryptodome and hashlib.
    let want = [
        "ECC1557BE1B91255FAC1BB370ABFE55998DF2870",
        "0E386D5BC7544E7FA995DCC3D71A9B79015544DF",
        "3B80FD0797D9009EDEDF89B71584621D397D069A",
        "E5D9723337BE4A16E6FE5F80087E8D7C5A2E8E12",
    ];
    let got: Vec<String> = std::iter::once(&primary)
        .chain(&subkeys)
        .map(openpgp::fingerprint)
        .collect();
    assert_eq!(got, want);

    let secret_home = TempDir::new("gpg-secret");
    let secret = format!("{}\n", openpgp::secret_key(user_id, &primary, subkey_refs));
    gpg(&secret_home, &["--import"], secret.as_bytes());

    let listing = gpg(&secret_home, &["--with-colons", "--list-secret-keys"], b"");
    let keys: Vec<(&str, &str)> = listing
        .lines()
        .map(|line| line.split(':').collect::<Vec<_>>())
        .filter(|f| f[0] == "sec" || f[0] == "ssb")
        .map(|f| (f[0], f[11]))
        .collect();
    // The primary key shows its own flag (c) and the flags of its sub keys (ESA).
    assert_eq!(
        keys,
        [("sec", "cESCA"), ("ssb", "e"), ("ssb", "a"), ("ssb", "s")]
    );
    let fingerprints: Vec<&str> = listing
        .lines()
        .filter_map(|line| line.strip_prefix("fpr:::::::::"))
        .map(|rest| rest.trim_end_matches(':'))
        .collect();
    assert_eq!(fingerprints, want);

    // All 4 self-signatures are good: 1 user ID certification, 3 sub key bindings.
    let sigs = gpg(&secret_home, &["--with-colons", "--check-signatures"], b"");
    let good = sigs.lines().filter(|l| l.starts_with("sig:!:")).count();
    assert_eq!(good, 4, "{sigs}");

    // The authentication sub key is the same key as sub key 1 in OpenSSH form.
    let ssh = gpg(&secret_home, &["--export-ssh-key", want[0]], b"");
    let ssh: Vec<&str> = ssh.split_whitespace().take(2).collect();
    assert_eq!(ssh.join(" "), openssh::rsa_public_key(&subkeys[1]));

    let message = b"bixfuse\n";
    let signed = gpg(
        &secret_home,
        &["--armor", "--sign", "--local-user", want[0]],
        message,
    );
    let encrypted = gpg(
        &secret_home,
        &[
            "--armor",
            "--trust-model",
            "always",
            "--encrypt",
            "--recipient",
            want[0],
        ],
        message,
    );
    assert_eq!(
        gpg(&secret_home, &["--decrypt"], encrypted.as_bytes()),
        "bixfuse\n"
    );

    // The public key alone verifies the signature.
    let public_home = TempDir::new("gpg-public");
    let public = format!("{}\n", openpgp::public_key(user_id, &primary, subkey_refs));
    gpg(&public_home, &["--import"], public.as_bytes());
    let listing = gpg(&public_home, &["--with-colons", "--list-keys"], b"");
    assert!(listing.lines().any(|l| l.starts_with("pub:")));
    assert!(!listing.lines().any(|l| l.starts_with("sec:")));
    gpg(&public_home, &["--verify"], signed.as_bytes());

    for home in [&secret_home, &public_home] {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(&home.0)
            .args(["--kill", "all"])
            .status();
    }
}

/// Checks that age-keygen derives `recipient` from `identity`, and that a
/// file encrypted to `recipient` decrypts with `identity`.
fn check_age_key_pair(name: &str, identity: &str, recipient: &str) {
    let derived = run(
        Command::new("age-keygen").arg("-y"),
        format!("{identity}\n").as_bytes(),
    );
    assert_eq!(derived, format!("{recipient}\n"), "{name}");

    let dir = TempDir::new(name);
    let identity_path = dir.write("identity", &format!("{identity}\n"));
    let message = b"bixfuse\n";
    let encrypted = run(
        Command::new("age").args(["--encrypt", "--armor", "--recipient", recipient]),
        message,
    );
    let decrypted = run(
        Command::new("age")
            .args(["--decrypt", "--identity"])
            .arg(&identity_path),
        encrypted.as_bytes(),
    );
    assert_eq!(decrypted.as_bytes(), message, "{name}");
}

#[test]
fn age_reads_the_keys() {
    let root = Root::from_mnemonic(MNEMONIC).unwrap();
    for index in [0, 1, 2147483647] {
        // m/83696968'/657169'/25519'/{index}' and m/83696968'/657169'/768'/{index}'
        let x25519 = root.entropy(&[657169, 25519, index]).unwrap();
        check_age_key_pair(
            &format!("age-x25519-{index}"),
            &apps::age_private(&x25519),
            &apps::age_public(&x25519),
        );
        let pq = root.entropy(&[657169, 768, index]).unwrap();
        check_age_key_pair(
            &format!("age-pq-{index}"),
            &apps::age_pq_private(&pq),
            &apps::age_pq_public(&pq),
        );
    }
}
