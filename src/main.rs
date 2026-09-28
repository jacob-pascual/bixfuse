use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use bixfuse::bip85::Root;
use bixfuse::fs::Bixfuse;
use bixfuse::mnemonic;
use bixfuse::tree::Tree;
use clap::Parser;
use fuser::{Config, MountOption, Session};

/// Mount a read-only filesystem of BIP-85 secrets derived from a BIP-39 mnemonic.
///
/// The mnemonic comes from standard input, or else from --mnemonic-file, or
/// else from the first of these files that exists: /etc/mnemonic,
/// $XDG_CONFIG_HOME/bixfuse/mnemonic, ./mnemonic, ./mnemonic.txt.
/// When standard input is not a terminal, bixfuse reads it to the end.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// A file with a BIP-39 mnemonic of 12 to 24 words.
    #[arg(long, value_name = "PATH")]
    mnemonic_file: Option<PathBuf>,

    /// OpenPGP user ID for the RSA GPG files, for example "Alice <alice@example.org>".
    /// Without it, the directory .gnupg does not exist.
    #[arg(long, value_name = "USER_ID")]
    gpg_user_id: Option<String>,

    /// An existing directory to mount the filesystem on.
    mountpoint: PathBuf,
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("bixfuse: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), String> {
    // Reading a terminal would wait for typing, or stop a background job.
    let stdin = if std::io::stdin().is_terminal() {
        None
    } else {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|e| format!("standard input: {e}"))?;
        Some(text)
    };
    let defaults = mnemonic::default_paths(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    );
    let (source, phrase) = mnemonic::choose(stdin, args.mnemonic_file, &defaults)?;
    let root = Root::from_mnemonic(&phrase).map_err(|e| format!("{source}: {e}"))?;

    // SAFETY: getuid and getgid cannot fail and have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let fs = Bixfuse::new(Tree::new(root, args.gpg_user_id), uid, gid);

    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::RO,
        MountOption::FSName("bixfuse".to_string()),
        MountOption::DefaultPermissions,
    ];
    let mountpoint = args.mountpoint.display();
    let mut session = Session::new(fs, &args.mountpoint, &config)
        .map_err(|e| format!("cannot mount on {mountpoint}: {e}"))?;

    // On SIGINT or SIGTERM, unmount. Then `run` returns.
    let mut unmounter = session.unmount_callable();
    ctrlc::set_handler(move || {
        if let Err(e) = unmounter.unmount() {
            eprintln!("bixfuse: cannot unmount: {e}");
        }
    })
    .map_err(|e| e.to_string())?;

    session.run().map_err(|e| e.to_string())
}
