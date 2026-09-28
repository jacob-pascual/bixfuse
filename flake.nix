{
  description = "bixfuse: a read-only FUSE filesystem of BIP-85 derived secrets";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Only for the test of the home-manager module.
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      home-manager,
    }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.callPackage ./package.nix { };
      });

      nixosModules.default = import ./nix/nixos-module.nix self;
      homeManagerModules.default = import ./nix/home-manager-module.nix self;
      homeModules.default = self.homeManagerModules.default;

      checks = forAllSystems (
        pkgs:
        let
          bixfuse = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        in
        {
          package = bixfuse;
        }
        // nixpkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          vm-test = import ./nix/vm-test.nix { inherit pkgs bixfuse; };
          module-test = import ./nix/module-test.nix { inherit pkgs self home-manager; };
        }
      );

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.stdenv.hostPlatform.system}.default ];
          packages = [
            pkgs.clippy
            pkgs.rustfmt
            pkgs.age
            pkgs.gnupg
            pkgs.openssh
            pkgs.wireguard-tools
          ];
        };
      });
    };
}
