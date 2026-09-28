//! Checks of the key files with the reference tools: age-keygen, ssh-keygen, gpg.
//! The tools must be on PATH. The Nix build and the dev shell supply them.

use std::io::Write;
use std::process::{Command, Stdio};

use bixfuse::apps;
use bixfuse::bip85::Root;

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
