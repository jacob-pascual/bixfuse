//! Checks of the key files with the reference tools: age-keygen, ssh-keygen, gpg.
//! The tools must be on PATH. The Nix build and the dev shell supply them.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use bixfuse::bip85::{Drng, Root};
use bixfuse::{apps, openssh, rsa};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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

#[test]
fn ssh_keygen_reads_the_private_key() {
    let key = rsa_key(&[828365, 2048, 0], 2048);
    let dir = TempDir::new("ssh");
    let private = dir.write("id_rsa", &format!("{}\n", openssh::private_key(&key)));
    let public = dir.write("id_rsa.pub", &format!("{}\n", openssh::public_key(&key)));

    let derived = run(Command::new("ssh-keygen").arg("-y").arg("-f").arg(&private), b"");
    assert_eq!(derived, format!("{}\n", openssh::public_key(&key)));

    // A signature with the private key verifies with the public key, so
    // d, p, q, and iqmp are consistent with n and e.
    let message = b"bixfuse\n";
    let signature = run(
        Command::new("ssh-keygen").args(["-Y", "sign", "-n", "file", "-f"]).arg(&private),
        message,
    );
    let signature = dir.write("message.sig", &signature);
    run(
        Command::new("ssh-keygen")
            .args(["-Y", "check-novalidate", "-n", "file", "-f"])
            .arg(&public)
            .arg("-s")
            .arg(&signature),
        message,
    );
}

#[test]
fn age_keygen_derives_the_same_recipient() {
    let root = Root::from_mnemonic(MNEMONIC).unwrap();
    for index in [0, 1, 2147483647] {
        let entropy = root.entropy(&[128169, 32, index]).unwrap();
        let identity = format!("{}\n", apps::age_private(&entropy));
        let recipient = run(Command::new("age-keygen").arg("-y"), identity.as_bytes());
        assert_eq!(recipient, format!("{}\n", apps::age_public(&entropy)));
    }
}
