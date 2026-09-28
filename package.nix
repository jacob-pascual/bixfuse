{
  lib,
  stdenv,
  rustPlatform,
  pkg-config,
  macfuse-stubs,
  age,
  gnupg,
  openssh,
}:

rustPlatform.buildRustPackage {
  pname = "bixfuse";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
      ./tests
    ];
  };

  cargoLock.lockFile = ./Cargo.lock;

  # fuser links libfuse only on macOS. On Linux it mounts through fusermount.
  nativeBuildInputs = lib.optionals stdenv.hostPlatform.isDarwin [ pkg-config ];
  buildInputs = lib.optionals stdenv.hostPlatform.isDarwin [ macfuse-stubs ];

  # The integration tests check the key files with the reference tools.
  nativeCheckInputs = [
    age
    gnupg
    openssh
  ];

  meta = {
    description = "Read-only FUSE filesystem of BIP-85 derived secrets";
    mainProgram = "bixfuse";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
