use std::path::PathBuf;
use std::process::ExitCode;

use bixfuse::bip85::Root;
use bixfuse::fs::Bixfuse;
use bixfuse::tree::Tree;
use clap::Parser;
use fuser::{Config, MountOption, Session};

/// Mount a read-only filesystem of BIP-85 secrets derived from a BIP-39 mnemonic.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// OpenPGP user ID for the RSA GPG files, for example "Alice <alice@example.org>".
    /// Without it, the directory .gnupg does not exist.
    #[arg(long, value_name = "USER_ID")]
    gpg_user_id: Option<String>,

    /// A file with a BIP-39 mnemonic of 12 to 24 words.
    mnemonic_file: PathBuf,

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
    let file = args.mnemonic_file.display();
    let phrase =
        std::fs::read_to_string(&args.mnemonic_file).map_err(|e| format!("{file}: {e}"))?;
    let root = Root::from_mnemonic(&phrase).map_err(|e| format!("{file}: {e}"))?;

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
