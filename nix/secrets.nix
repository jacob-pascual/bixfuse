# What the NixOS and home-manager modules share: the options of
# bixfuse.secrets.<name>, the path of each secret, and the shell code that
# installs secrets and key files (SPEC.md section 10).
{ lib }:
let
  inherit (lib) mkOption types;

  maxIndex = 2147483647;
  index = mkOption {
    type = types.ints.between 0 maxIndex;
    default = 0;
    description = "The index.";
  };
  public = mkOption {
    type = types.bool;
    default = false;
    description = "The public key instead of the private key.";
  };
  bits = mkOption {
    type = types.ints.between 1024 8192;
    default = 4096;
    description = "The RSA key size in bits.";
  };
  subKey = mkOption {
    type = types.nullOr (types.ints.between 0 2);
    default = null;
    description = "The RSA GPG sub key: 0 (encryption), 1 (authentication), or 2 (signature).";
  };
  sub = s: lib.optionalString (s != null) "/${toString s}";
  pub = p: lib.optionalString p ".pub";
  str = toString;

  # Each kind of type.<kind>: its options, and the path of SPEC.md section 5
  # for its values.
  kinds = {
    bip39 = {
      options = {
        language = mkOption {
          type = types.enum [
            "english"
            "japanese"
            "korean"
            "spanish"
            "chinese_simplified"
            "chinese_traditional"
            "french"
            "italian"
            "czech"
            "portuguese"
          ];
          default = "english";
          description = "The wordlist.";
        };
        words = mkOption {
          type = types.enum [
            12
            15
            18
            21
            24
          ];
          default = 12;
          description = "The number of words.";
        };
        inherit index;
      };
      path = t: "bip39/${t.language}/${str t.words}/${str t.index}";
    };
    wif = {
      options = { inherit index; };
      path = t: "wif/${str t.index}";
    };
    xprv = {
      options = { inherit index; };
      path = t: "xprv/${str t.index}";
    };
    hex = {
      options = {
        bytes = mkOption {
          type = types.ints.between 16 64;
          default = 32;
          description = "The number of bytes.";
        };
        inherit index;
      };
      path = t: "hex/${str t.bytes}/${str t.index}";
    };
    base64 = {
      options = {
        length = mkOption {
          type = types.ints.between 20 86;
          description = "The password length.";
        };
        inherit index;
      };
      path = t: "base64/${str t.length}/${str t.index}";
    };
    base85 = {
      options = {
        length = mkOption {
          type = types.ints.between 10 80;
          description = "The password length.";
        };
        inherit index;
      };
      path = t: "base85/${str t.length}/${str t.index}";
    };
    dice = {
      options = {
        sides = mkOption {
          type = types.ints.between 2 maxIndex;
          default = 6;
          description = "The number of sides.";
        };
        rolls = mkOption {
          type = types.ints.between 1 10000;
          description = "The number of rolls.";
        };
        inherit index;
      };
      path = t: "dice/${str t.sides}/${str t.rolls}/${str t.index}";
    };
    nostr = {
      options = {
        identity = mkOption {
          type = types.ints.between 1 maxIndex;
          default = 1;
          description = "The identity (0 is reserved by BIP-85).";
        };
        account = mkOption {
          type = types.ints.between 1 maxIndex;
          default = 1;
          description = "The account index (0 is reserved by BIP-85).";
        };
      };
      path = t: "nostr/${str t.identity}/${str t.account}";
    };
    rsa = {
      options = { inherit bits index subKey; };
      path = t: "rsa/${str t.bits}/${str t.index}${sub t.subKey}/private.pem";
    };
    sshEd25519 = {
      options = { inherit index public; };
      path = t: ".ssh/ed25519/${str t.index}/id_ed25519${pub t.public}";
    };
    sshRsa = {
      options = {
        inherit
          bits
          index
          subKey
          public
          ;
      };
      path = t: ".ssh/rsa/${str t.bits}/${str t.index}${sub t.subKey}/id_rsa${pub t.public}";
    };
    age = {
      options = { inherit index public; };
      path = t: ".age/x25519/${str t.index}/${if t.public then "public" else "private"}.age";
    };
    agePq = {
      options = { inherit index public; };
      path = t: ".age/mlkem768x25519/${str t.index}/${if t.public then "public" else "private"}.age";
    };
    gpg = {
      options = { inherit bits index public; };
      path = t: ".gnupg/rsa/${str t.bits}/${str t.index}/${if t.public then "public" else "secret"}.asc";
    };
  };

  # The path of SPEC.md section 5 of a secret, or null if the secret does
  # not set exactly one of type.<kind> and derivation.
  pathOf =
    secret:
    let
      kindsSet = lib.filterAttrs (_: value: value != null) secret.type;
      count = lib.length (lib.attrNames kindsSet) + (if secret.derivation != null then 1 else 0);
    in
    if count != 1 then
      null
    else if secret.derivation != null then
      secret.derivation
    else
      let
        kind = lib.head (lib.attrNames kindsSet);
      in
      kinds.${kind}.path kindsSet.${kind};
in
rec {
  inherit pathOf;

  # The type of bixfuse.secrets.<name>. `secretsDir` may contain a shell
  # variable, for example ''${XDG_RUNTIME_DIR}. `extraOptions` are the options
  # that only one module has.
  secretType =
    {
      secretsDir,
      extraOptions ? { },
    }:
    types.submodule (
      { name, config, ... }:
      {
        options = {
          name = mkOption {
            type = types.str;
            default = name;
            description = "The file name of the secret in the secrets directory.";
          };
          type = lib.mapAttrs (
            kind: k:
            mkOption {
              type = types.nullOr (types.submodule { inherit (k) options; });
              default = null;
              description = "The secret as a value of kind ${kind}.";
            }
          ) kinds;
          derivation = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "bip39/english/12/0";
            description = "The secret as a path of the bixfuse filesystem.";
          };
          path = mkOption {
            type = types.str;
            default = "${secretsDir}/${config.name}";
            defaultText = lib.literalExpression ''"''${secretsDir}/''${name}"'';
            description = "The path of the secret. Outside the secrets directory, it is a symlink.";
          };
          mode = mkOption {
            type = types.str;
            default = "0400";
            description = "The file mode of the secret.";
          };
        }
        // extraOptions;
      }
    );

  # Assertions: each secret sets exactly one of type.<kind> and derivation,
  # and the mnemonic file is not in the Nix store.
  assertions =
    prefix: cfg:
    [
      {
        assertion = !lib.hasPrefix builtins.storeDir cfg.mnemonicFile;
        message = "${prefix}.mnemonicFile: the mnemonic must not be in the Nix store.";
      }
    ]
    ++ lib.mapAttrsToList (name: secret: {
      assertion = pathOf secret != null;
      message = "${prefix}.secrets.${name}: set exactly one of type.<kind> and derivation.";
    }) cfg.secrets;

  # A shell function `bixfuse_write_key PATH TARGET MODE`: it writes the file
  # PATH of the bixfuse filesystem to TARGET. If TARGET exists with other
  # contents, it fails and changes nothing. `cat` is the bixfuse cat command
  # without the path.
  writeKeyFunction = cat: ''
    bixfuse_write_key() {
      local tmp
      mkdir -p "$(dirname "$2")"
      tmp="$(mktemp "$2.bixfuse.XXXXXX")"
      if ! ${cat} -- "$1" > "$tmp"; then
        rm -f "$tmp"
        return 1
      fi
      if [ -e "$2" ] && ! cmp -s "$tmp" "$2"; then
        rm -f "$tmp"
        echo "[bixfuse] $2 exists with a different key. Move it away, and bixfuse writes the key of the mnemonic." >&2
        return 1
      fi
      chmod "$3" "$tmp"
      mv -f "$tmp" "$2"
    }
  '';

  # A script that installs the secrets in a new generation directory of
  # `secretsMountPoint`, points `secretsDir` to it, and removes the old
  # generations. `mountRamfs` mounts a ramfs on `secretsMountPoint` first.
  # `chown` sets owner and group of each secret.
  installScript =
    {
      pkgs,
      cat,
      secretsDir,
      secretsMountPoint,
      secrets,
      mountRamfs ? false,
      chown ? false,
    }:
    let
      install =
        secret:
        let
          target = ''"$generation"/${lib.escapeShellArg secret.name}'';
        in
        ''
          mkdir -p "$(dirname ${target})"
          (umask 0377 && ${cat} -- ${lib.escapeShellArg (pathOf secret)} > ${target}.tmp)
          chmod ${secret.mode} ${target}.tmp
          ${lib.optionalString chown "chown ${lib.escapeShellArg "${secret.owner}:${secret.group}"} ${target}.tmp"}
          mv -f ${target}.tmp ${target}
        ''
        + lib.optionalString (secret.path != "${secretsDir}/${secret.name}") ''
          mkdir -p "$(dirname "${secret.path}")"
          ln -sfT "${secretsDir}/"${lib.escapeShellArg secret.name} "${secret.path}"
        '';
    in
    pkgs.writeShellScript "bixfuse-install-secrets" ''
      set -euo pipefail
      export PATH=${
        lib.makeBinPath [
          pkgs.coreutils
          pkgs.findutils
          pkgs.gnugrep
          pkgs.util-linux
        ]
      }
      mkdir -p "${secretsMountPoint}"
      chmod 0751 "${secretsMountPoint}"
      ${lib.optionalString mountRamfs ''
        grep -q " ${secretsMountPoint} ramfs " /proc/mounts ||
          mount -t ramfs none "${secretsMountPoint}" -o nodev,nosuid,mode=0751
      ''}
      number="$(basename "$(readlink "${secretsDir}" 2>/dev/null || echo 0)")"
      number=$((number + 1))
      generation="${secretsMountPoint}/$number"
      rm -rf "$generation"
      mkdir -p "$generation"
      chmod 0751 "$generation"
      ${lib.optionalString chown ''chown :keys "${secretsMountPoint}" "$generation"''}
      ${lib.concatMapStrings install secrets}
      ln -sfT "$generation" "${secretsDir}"
      find "${secretsMountPoint}" -mindepth 1 -maxdepth 1 ! -name "$number" -exec rm -rf {} +
    '';
}
