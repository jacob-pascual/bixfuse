//! The choice of the mnemonic source (SPEC.md section 4).

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

/// Where the mnemonic came from.
#[derive(Debug, PartialEq, Eq)]
pub enum Source {
    Stdin,
    File(PathBuf),
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Source::Stdin => write!(f, "standard input"),
            Source::File(path) => write!(f, "{}", path.display()),
        }
    }
}

/// The files to try when neither standard input nor `--mnemonic-file` gives
/// a mnemonic, in order. `$XDG_CONFIG_HOME` must be absolute, as the XDG Base
/// Directory Specification requires; otherwise it is `$HOME/.config`.
pub fn default_paths(xdg_config_home: Option<OsString>, home: Option<OsString>) -> Vec<PathBuf> {
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

/// Chooses the mnemonic and returns it with its source.
///
/// `stdin` is the text of standard input, or `None` if standard input is a
/// terminal. Standard input gives a mnemonic if it has a non-whitespace
/// character. It is an error if both standard input and `file` give one,
/// because they can be two different seeds. Without either, the first of
/// `defaults` that exists is used; an error in that file does not fall
/// through to the next one.
pub fn choose(
    stdin: Option<String>,
    file: Option<PathBuf>,
    defaults: &[PathBuf],
) -> Result<(Source, String), String> {
    let stdin = stdin.filter(|text| !text.trim().is_empty());
    let read = |path: PathBuf| {
        std::fs::read_to_string(&path)
            .map(|text| (Source::File(path.clone()), text))
            .map_err(|e| format!("{}: {e}", path.display()))
    };
    match (stdin, file) {
        (Some(_), Some(path)) => Err(format!(
            "a mnemonic is on standard input and --mnemonic-file {} is given; use only one",
            path.display()
        )),
        (Some(text), None) => Ok((Source::Stdin, text)),
        (None, Some(path)) => read(path),
        (None, None) => match defaults.iter().find(|path| path.exists()) {
            Some(path) => read(path.clone()),
            None => Err(format!(
                "no mnemonic: standard input is empty, --mnemonic-file is not given, and none of these files exists: {}",
                defaults
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n";

    /// A temporary directory, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("bixfuse-mnemonic-{name}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn write(&self, name: &str, text: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, text).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn default_paths_order() {
        assert_eq!(
            default_paths(Some("/xdg".into()), Some("/home/a".into())),
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
                default_paths(xdg, Some("/home/a".into()))[1],
                PathBuf::from("/home/a/.config/bixfuse/mnemonic")
            );
        }
        assert_eq!(default_paths(None, None).len(), 3);
    }

    #[test]
    fn stdin() {
        assert_eq!(
            choose(Some(MNEMONIC.into()), None, &[]),
            Ok((Source::Stdin, MNEMONIC.into()))
        );
    }

    #[test]
    fn file_flag() {
        let dir = TempDir::new("flag");
        let path = dir.write("m", MNEMONIC);
        // A terminal (None) or an empty standard input does not count.
        for stdin in [None, Some(String::new()), Some(" \n".into())] {
            assert_eq!(
                choose(stdin, Some(path.clone()), &[]),
                Ok((Source::File(path.clone()), MNEMONIC.into()))
            );
        }
    }

    #[test]
    fn stdin_and_file_flag_is_an_error() {
        let dir = TempDir::new("both");
        let path = dir.write("m", MNEMONIC);
        let error = choose(Some(MNEMONIC.into()), Some(path), &[]).unwrap_err();
        assert!(error.contains("use only one"), "{error}");
    }

    #[test]
    fn first_existing_default() {
        let dir = TempDir::new("defaults");
        let second = dir.write("second", MNEMONIC);
        let third = dir.write("third", "other\n");
        let defaults = [dir.0.join("missing"), second.clone(), third];
        assert_eq!(
            choose(None, None, &defaults),
            Ok((Source::File(second), MNEMONIC.into()))
        );
    }

    #[test]
    fn unreadable_default_does_not_fall_through() {
        let dir = TempDir::new("unreadable");
        let directory = dir.0.join("a-directory");
        std::fs::create_dir_all(&directory).unwrap();
        let next = dir.write("next", MNEMONIC);
        let error = choose(None, None, &[directory.clone(), next]).unwrap_err();
        assert!(
            error.starts_with(&directory.display().to_string()),
            "{error}"
        );
    }

    #[test]
    fn nothing_found_lists_the_paths() {
        let defaults = [
            PathBuf::from("/nonexistent/a"),
            PathBuf::from("/nonexistent/b"),
        ];
        let error = choose(Some("\n".into()), None, &defaults).unwrap_err();
        assert!(error.contains("/nonexistent/a, /nonexistent/b"), "{error}");
    }
}
