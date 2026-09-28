use std::path::PathBuf;
use std::process::ExitCode;

use bixfuse::bip85::Root;
use bixfuse::fs::Bixfuse;
use bixfuse::input::{self, Source};
use bixfuse::tree::Tree;
use bixfuse::user_id::user_id;
use clap::Parser;
use fuser::{Config, MountOption, Session};

/// Mount a read-only filesystem of BIP-85 secrets derived from a BIP-39 mnemonic.
///
/// Without --mnemonic-file, the mnemonic comes from the first of these files
/// that exists: /etc/mnemonic, $XDG_CONFIG_HOME/bixfuse/mnemonic, ./mnemonic,
/// ./mnemonic.txt.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// A file with a BIP-39 mnemonic of 12 to 24 words, or - for standard input.
    #[arg(long, value_name = "PATH")]
    mnemonic_file: Option<PathBuf>,

    /// A file with the BIP-39 passphrase, or - for standard input. One
    /// trailing newline is removed. Without it, the passphrase is empty.
    #[arg(long, value_name = "PATH")]
    passphrase_file: Option<PathBuf>,

    /// The name in the OpenPGP user ID of the .gnupg keys.
    /// Default: the full name of the current user in the user database.
    #[arg(long, value_name = "NAME")]
    gpg_name: Option<String>,

    /// The email in the OpenPGP user ID of the .gnupg keys.
    /// Default: <user name>@<fully qualified host name>.
    #[arg(long, value_name = "EMAIL")]
    gpg_email: Option<String>,

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
    let defaults = input::default_mnemonic_paths(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    );
    let mnemonic_source = input::mnemonic_source(args.mnemonic_file, &defaults)?;
    let passphrase_source = args.passphrase_file.map(Source::from);
    if mnemonic_source == Source::Stdin && passphrase_source == Some(Source::Stdin) {
        return Err(
            "--mnemonic-file and --passphrase-file cannot both read standard input".to_string(),
        );
    }
    let phrase = mnemonic_source.read(std::io::stdin())?;
    let passphrase = match &passphrase_source {
        Some(source) => source.read(std::io::stdin())?,
        None => String::new(),
    };
    let root = Root::from_mnemonic(&phrase, input::passphrase(&passphrase))
        .map_err(|e| format!("{mnemonic_source}: {e}"))?;
    let user_id = user_id(args.gpg_name, args.gpg_email)?;

    // SAFETY: getuid and getgid cannot fail and have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let fs = Bixfuse::new(Tree::new(root, user_id), uid, gid);

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
