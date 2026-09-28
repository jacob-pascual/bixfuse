# The home-manager module of bixfuse: the secrets, SSH key, and git identity
# of a user, derived from the mnemonic of the user (SPEC.md section 10.4).
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.bixfuse;
  shared = import ./secrets.nix { inherit lib; };
  cat = lib.escapeShellArgs (
    [
      (lib.getExe cfg.package)
      "cat"
      "--mnemonic-file"
      cfg.mnemonicFile
    ]
    ++ lib.optionals (cfg.user.name != null) [
      "--gpg-name"
      cfg.user.name
    ]
    ++ lib.optionals (cfg.user.email != null) [
      "--gpg-email"
      cfg.user.email
    ]
  );

  installSecrets = shared.installScript {
    inherit pkgs cat;
    inherit (cfg) secretsDir secretsMountPoint;
    secrets = lib.attrValues cfg.secrets;
  };

  writeSshKey = pkgs.writeShellScript "bixfuse-write-ssh-key" ''
    set -euo pipefail
    export PATH=${lib.makeBinPath [ pkgs.coreutils pkgs.diffutils ]}
    ${shared.writeKeyFunction cat}
    mkdir -p "$HOME/.ssh"
    chmod 0700 "$HOME/.ssh"
    bixfuse_write_key .ssh/id_ed25519 "$HOME/.ssh/id_ed25519" 0600
    bixfuse_write_key .ssh/id_ed25519.pub "$HOME/.ssh/id_ed25519.pub" 0644
  '';
in
{
  options.bixfuse = {
    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "bixfuse.packages.\${system}.default";
      description = "The bixfuse package.";
    };
    mnemonicFile = mkOption {
      type = types.str;
      default = "${config.xdg.configHome}/bixfuse/mnemonic";
      defaultText = lib.literalExpression ''"''${config.xdg.configHome}/bixfuse/mnemonic"'';
      description = "The file with the BIP-39 mnemonic of the user. It must not be in the Nix store.";
    };
    user = {
      name = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "The name of the user: the git user.name and the name in the OpenPGP user ID.";
      };
      email = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "The email of the user: the git user.email and the email in the OpenPGP user ID.";
      };
    };
    secretsDir = mkOption {
      type = types.str;
      default = "\${XDG_RUNTIME_DIR}/bixfuse";
      description = "The directory of the secrets: a symlink to the current generation. Shell variables are expanded.";
    };
    secretsMountPoint = mkOption {
      type = types.str;
      default = "\${XDG_RUNTIME_DIR}/bixfuse.d";
      description = "The directory with the generations of the secrets. Shell variables are expanded.";
    };
    programs = {
      enable = lib.mkEnableOption "all program integrations of bixfuse";
      ssh.enable = mkOption {
        type = types.bool;
        default = cfg.programs.enable;
        defaultText = lib.literalExpression "config.bixfuse.programs.enable";
        description = "Write ~/.ssh/id_ed25519 and ~/.ssh/id_ed25519.pub from the mnemonic.";
      };
      git.enable = mkOption {
        type = types.bool;
        default = cfg.programs.enable;
        defaultText = lib.literalExpression "config.bixfuse.programs.enable";
        description = "Set programs.git.settings.user.name and .email from bixfuse.user.";
      };
    };
    secrets = mkOption {
      type = types.attrsOf (shared.secretType { inherit (cfg) secretsDir; });
      default = { };
      description = "The secrets of the user, in the style of sops-nix and agenix.";
    };
  };

  config = lib.mkMerge [
    { assertions = shared.assertions "bixfuse" cfg; }

    (lib.mkIf (cfg.secrets != { }) {
      assertions = [
        {
          assertion = pkgs.stdenv.hostPlatform.isLinux;
          message = "bixfuse.secrets needs a systemd user service, so it works on Linux only.";
        }
      ];
      systemd.user.services.bixfuse-secrets = {
        Unit.Description = "Install the bixfuse secrets";
        Service = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${installSecrets}";
        };
        Install.WantedBy = [ "default.target" ];
      };
    })

    (lib.mkIf cfg.programs.ssh.enable {
      home.activation.bixfuseSshKey = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
        run ${writeSshKey}
      '';
    })

    (lib.mkIf cfg.programs.git.enable {
      assertions = [
        {
          assertion = cfg.user.name != null && cfg.user.email != null;
          message = "bixfuse.programs.git needs bixfuse.user.name and bixfuse.user.email.";
        }
      ];
      programs.git.settings.user = {
        inherit (cfg.user) name email;
      };
    })
  ];
}
