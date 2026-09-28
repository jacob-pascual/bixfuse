use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bixfuse::bip85::Root;
use bixfuse::fs::Bixfuse;
use bixfuse::input::{self, Source};
use bixfuse::tree::{self, Tree};
use bixfuse::user_id::user_id;
use clap::{Parser, Subcommand};
use fuser::{Config, MountOption, Session};

/// Mount a read-only filesystem of BIP-85 secrets derived from a BIP-39 mnemonic.
///
/// Without --mnemonic-file, the mnemonic comes from the first of these files
/// that exists: /etc/mnemonic, $XDG_CONFIG_HOME/bixfuse/mnemonic, ./mnemonic,
/// ./mnemonic.txt.
#[derive(Parser)]
#[command(version, subcommand_negates_reqs = true)]
struct Args {
    #[command(flatten)]
    inputs: Inputs,

    /// An existing directory to mount the filesystem on.
    #[arg(required = true)]
    mountpoint: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Args)]
struct Inputs {
    /// A file with a BIP-39 mnemonic of 12 to 24 words, or - for standard input.
    #[arg(long, global = true, value_name = "PATH")]
    mnemonic_file: Option<PathBuf>,

    /// A file with the BIP-39 passphrase, or - for standard input. One
    /// trailing newline is removed. Without it, the passphrase is empty.
    #[arg(long, global = true, value_name = "PATH")]
    passphrase_file: Option<PathBuf>,

    /// The name in the OpenPGP user ID of the .gnupg keys.
    /// Default: the full name of the current user in the user database.
    #[arg(long, global = true, value_name = "NAME")]
    gpg_name: Option<String>,

    /// The email in the OpenPGP user ID of the .gnupg keys.
    /// Default: <user name>@<fully qualified host name>.
    #[arg(long, global = true, value_name = "EMAIL")]
    gpg_email: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Write files of the filesystem to standard output, without a mount.
    Cat {
        /// Paths in the filesystem, for example bip39/english/12/0 or
        /// .ssh/id_ed25519.pub.
        #[arg(required = true)]
        paths: Vec<String>,
    },
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
    let Inputs {
        mnemonic_file,
        passphrase_file,
        gpg_name,
        gpg_email,
    } = args.inputs;
    let defaults = input::default_mnemonic_paths(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    );
    let mnemonic_source = input::mnemonic_source(mnemonic_file, &defaults)?;
    let passphrase_source = passphrase_file.map(Source::from);
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

    match args.command {
        Some(Command::Cat { paths }) => {
            // The default user ID looks up the host name, which can wait for
            // the network. Only the .gnupg files need it.
            let gnupg = |path: &String| path.trim_start_matches('/').starts_with(".gnupg");
            let user_id = if paths.iter().any(gnupg) {
                user_id(gpg_name, gpg_email)?
            } else {
                String::new()
            };
            cat(&Tree::new(root, user_id), &paths)
        }
        None => {
            let tree = Tree::new(root, user_id(gpg_name, gpg_email)?);
            let mountpoint = args.mountpoint.expect("clap requires a mount point");
            mount(tree, &mountpoint)
        }
    }
}

fn cat(tree: &Tree, paths: &[String]) -> Result<(), String> {
    let mut stdout = std::io::stdout().lock();
    for path in paths {
        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let contents = tree.read(&components).map_err(|e| match e {
            tree::Error::NotFound => format!("{path}: no such file"),
            tree::Error::InvalidKey => format!("{path}: BIP-85 gives no valid key here"),
        })?;
        stdout
            .write_all(&contents)
            .map_err(|e| format!("standard output: {e}"))?;
    }
    stdout.flush().map_err(|e| format!("standard output: {e}"))
}

fn mount(tree: Tree, mountpoint: &Path) -> Result<(), String> {
    // SAFETY: getuid and getgid cannot fail and have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let fs = Bixfuse::new(tree, uid, gid);

    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::RO,
        MountOption::FSName("bixfuse".to_string()),
        MountOption::DefaultPermissions,
    ];
    let mut session = Session::new(fs, mountpoint, &config)
        .map_err(|e| format!("cannot mount on {}: {e}", mountpoint.display()))?;

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
