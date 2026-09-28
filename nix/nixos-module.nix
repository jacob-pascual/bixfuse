# The NixOS module of bixfuse: the secrets and SSH host keys of a host,
# derived from the mnemonic of the host (SPEC.md section 10.3).
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
  cat = "${lib.getExe cfg.package} cat --mnemonic-file ${lib.escapeShellArg cfg.mnemonicFile}";

  installSecrets = shared.installScript {
    inherit pkgs cat;
    inherit (cfg) secretsDir secretsMountPoint;
    secrets = lib.attrValues cfg.secrets;
    mountRamfs = true;
    chown = true;
  };

  index = toString cfg.programs.sshd.index;
  writeHostKeys = pkgs.writeShellScript "bixfuse-write-host-keys" ''
    set -euo pipefail
    export PATH=${lib.makeBinPath [ pkgs.coreutils pkgs.diffutils ]}
    ${shared.writeKeyFunction cat}
    bixfuse_write_key .ssh/ed25519/${index}/id_ed25519 /etc/ssh/ssh_host_ed25519_key 0600
    bixfuse_write_key .ssh/ed25519/${index}/id_ed25519.pub /etc/ssh/ssh_host_ed25519_key.pub 0644
    bixfuse_write_key .ssh/rsa/4096/${index}/id_rsa /etc/ssh/ssh_host_rsa_key 0600
    bixfuse_write_key .ssh/rsa/4096/${index}/id_rsa.pub /etc/ssh/ssh_host_rsa_key.pub 0644
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
      default = "/etc/mnemonic";
      description = "The file with the BIP-39 mnemonic of the host. It must not be in the Nix store.";
    };
    secretsDir = mkOption {
      type = types.str;
      default = "/run/bixfuse";
      description = "The directory of the secrets: a symlink to the current generation.";
    };
    secretsMountPoint = mkOption {
      type = types.str;
      default = "/run/bixfuse.d";
      description = "The ramfs with the generations of the secrets.";
    };
    programs = {
      enable = lib.mkEnableOption "all program integrations of bixfuse";
      sshd = {
        enable = mkOption {
          type = types.bool;
          default = cfg.programs.enable;
          defaultText = lib.literalExpression "config.bixfuse.programs.enable";
          description = "Write the SSH host keys in /etc/ssh from the mnemonic.";
        };
        index = mkOption {
          type = types.ints.between 0 2147483647;
          default = 0;
          description = "The index of the host keys: .ssh/ed25519/{index} and .ssh/rsa/4096/{index}.";
        };
      };
    };
    secrets = mkOption {
      type = types.attrsOf (
        shared.secretType {
          inherit (cfg) secretsDir;
          extraOptions = {
            owner = mkOption {
              type = types.str;
              default = "root";
              description = "The owner of the secret.";
            };
            group = mkOption {
              type = types.str;
              default = "root";
              description = "The group of the secret.";
            };
          };
        }
      );
      default = { };
      description = "The secrets of the host, in the style of sops-nix and agenix.";
    };
  };

  config = lib.mkMerge [
    { assertions = shared.assertions "bixfuse" cfg; }

    (lib.mkIf (cfg.secrets != { }) {
      # After /etc, users, and groups: the secrets need the mnemonic file and
      # their owners.
      system.activationScripts.bixfuseSecrets = {
        deps = [ "etc" ];
        text = "${installSecrets}";
      };
    })

    (lib.mkIf cfg.programs.sshd.enable {
      assertions = [
        {
          assertion = !config.services.openssh.generateHostKeys;
          message = "bixfuse.programs.sshd writes the SSH host keys, so services.openssh.generateHostKeys must be false.";
        }
      ];
      services.openssh.generateHostKeys = lib.mkDefault false;
      system.activationScripts.bixfuseHostKeys = {
        deps = [ "etc" ];
        text = "${writeHostKeys}";
      };
    })
  ];
}
