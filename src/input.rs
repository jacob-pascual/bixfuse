//! The mnemonic and passphrase inputs (SPEC.md section 4).

use std::ffi::OsString;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Where an input comes from. The path `-` means standard input.
#[derive(Debug, PartialEq, Eq)]
pub enum Source {
    Stdin,
    File(PathBuf),
}

impl From<PathBuf> for Source {
    fn from(path: PathBuf) -> Self {
        if path.as_os_str() == "-" {
            Source::Stdin
        } else {
            Source::File(path)
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Source::Stdin => write!(f, "standard input"),
            Source::File(path) => write!(f, "{}", path.display()),
        }
    }
}

impl Source {
    /// Reads the whole input. `stdin` is read only for `Source::Stdin`.
    pub fn read(&self, mut stdin: impl Read) -> Result<String, String> {
        let mut text = String::new();
        match self {
            Source::Stdin => stdin.read_to_string(&mut text).map(|_| ()),
            Source::File(path) => std::fs::read_to_string(path).map(|file| text = file),
        }
        .map_err(|e| format!("{self}: {e}"))?;
        Ok(text)
    }
}

/// The files to try for the mnemonic without `--mnemonic-file`, in order.
/// `$XDG_CONFIG_HOME` must be absolute, as the XDG Base Directory
/// Specification requires; otherwise it is `$HOME/.config`.
pub fn default_mnemonic_paths(
    xdg_config_home: Option<OsString>,
    home: Option<OsString>,
) -> Vec<PathBuf> {
    let config = xdg_config_home
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| home.map(|home| Path::new(&home).join(".config")));
    let mut paths = vec![PathBuf::from("/etc/mnemonic")];
    paths.extend(config.map(|config| config.join("bixfuse/mnemonic")));
    paths.push(PathBuf::from("./mnemonic"));
    paths.push(PathBuf::from("./mnemonic.txt"));
    paths
}

/// The source of the mnemonic: `--mnemonic-file` if it is given, else the
/// first of `defaults` that exists.
pub fn mnemonic_source(flag: Option<PathBuf>, defaults: &[PathBuf]) -> Result<Source, String> {
    if let Some(path) = flag {
        return Ok(path.into());
    }
    match defaults.iter().find(|path| path.exists()) {
        Some(path) => Ok(Source::File(path.clone())),
        None => Err(format!(
            "no mnemonic: --mnemonic-file is not given, and none of these files exists: {}",
            defaults
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// The passphrase in the text of a passphrase file: the text without one
/// trailing line ending. Other white space is part of the passphrase.
pub fn passphrase(text: &str) -> &str {
    text.strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dash_is_stdin() {
        assert_eq!(Source::from(PathBuf::from("-")), Source::Stdin);
        assert_eq!(
            Source::from(PathBuf::from("./-")),
            Source::File(PathBuf::from("./-"))
        );
        assert_eq!(
            Source::Stdin.read("words\n".as_bytes()),
            Ok("words\n".to_string())
        );
    }

    #[test]
    fn default_paths_order() {
        assert_eq!(
            default_mnemonic_paths(Some("/xdg".into()), Some("/home/a".into())),
            [
                "/etc/mnemonic",
                "/xdg/bixfuse/mnemonic",
                "./mnemonic",
                "./mnemonic.txt"
            ]
            .map(PathBuf::from)
        );
        // A relative or missing XDG_CONFIG_HOME falls back to $HOME/.config.
        for xdg in [Some("relative".into()), None] {
            assert_eq!(
                default_mnemonic_paths(xdg, Some("/home/a".into()))[1],
                PathBuf::from("/home/a/.config/bixfuse/mnemonic")
            );
        }
        assert_eq!(default_mnemonic_paths(None, None).len(), 3);
    }

    #[test]
    fn flag_wins_over_defaults() {
        let existing = std::env::temp_dir();
        assert_eq!(
            mnemonic_source(Some("/a/file".into()), &[existing]),
            Ok(Source::File("/a/file".into()))
        );
    }

    #[test]
    fn first_existing_default() {
        let existing = std::env::temp_dir();
        let defaults = [PathBuf::from("/nonexistent/a"), existing.clone()];
        assert_eq!(mnemonic_source(None, &defaults), Ok(Source::File(existing)));
    }

    #[test]
    fn nothing_found_lists_the_paths() {
        let defaults = [
            PathBuf::from("/nonexistent/a"),
            PathBuf::from("/nonexistent/b"),
        ];
        let error = mnemonic_source(None, &defaults).unwrap_err();
        assert!(error.contains("/nonexistent/a, /nonexistent/b"), "{error}");
    }

    #[test]
    fn unreadable_file_names_the_path() {
        let error = Source::File("/nonexistent/m".into())
            .read(&b""[..])
            .unwrap_err();
        assert!(error.starts_with("/nonexistent/m: "), "{error}");
    }

    #[test]
    fn passphrase_loses_one_line_ending() {
        assert_eq!(passphrase("TREZOR\n"), "TREZOR");
        assert_eq!(passphrase("TREZOR\r\n"), "TREZOR");
        assert_eq!(passphrase("TREZOR"), "TREZOR");
        assert_eq!(passphrase(" two  spaces \n\n"), " two  spaces \n");
        assert_eq!(passphrase(""), "");
    }
}
