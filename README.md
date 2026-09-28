# bixfuse

bixfuse mounts a read-only FUSE filesystem of
[BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)
secrets. Each file holds one secret. The path of the file is the BIP-85
derivation path of the secret. [SPEC.md](SPEC.md) is the full specification.

```console
$ bixfuse mnemonic.txt /mnt/bixfuse &
$ cat /mnt/bixfuse/bip39/english/12/0
prosper short ramp prepare exchange stove life snack client enough purpose fold
$ cat /mnt/bixfuse/hex/32/0
e477d4694160a384b28ee2f72b54edcf0822fd6e1ee1780447455cdbed8f8c45
```

`mnemonic.txt` holds the BIP-39 mnemonic
`abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`.

## Layout

| Path | Content |
|---|---|
| `bip39/{language}/{words}/{index}` | BIP-39 mnemonic |
| `wif/{index}` | HD-Seed WIF |
| `xprv/{index}` | XPRV |
| `hex/{num_bytes}/{index}` | HEX |
| `base64/{pwd_len}/{index}` | PWD BASE64 password |
| `base85/{pwd_len}/{index}` | PWD BASE85 password |
| `dice/{sides}/{rolls}/{index}` | DICE rolls |
| `nostr/{identity}/{account_index}` | Nostr `nsec` |
| `rsa/{key_bits}/{key_index}/openssh-key-v1` | RSA private key, OpenSSH format |
| `rsa/{key_bits}/{key_index}/openssh-key-v1.pub` | RSA public key, `ssh-rsa` line |
| `rsa/{key_bits}/{key_index}/openpgp-secret.asc` | RSA GPG secret key (needs `--gpg-user-id`) |
| `rsa/{key_bits}/{key_index}/openpgp-public.asc` | RSA GPG public key (needs `--gpg-user-id`) |
| `rsa/{key_bits}/{key_index}/{0,1,2}/openssh-key-v1[.pub]` | RSA GPG sub keys (encrypt, authenticate, sign) |
| `age/x25519/{index}/private.age` | age identity (`AGE-SECRET-KEY-1...`) |
| `age/x25519/{index}/public.age` | age recipient (`age1...`) |

`ls` does not show index directories, but every valid index opens.
RSA keys are computed on first access: 4096-bit keys take 1 to 6 seconds.

## Usage

```
bixfuse [--gpg-user-id <USER_ID>] <MNEMONIC_FILE> <MOUNTPOINT>
```

bixfuse runs in the foreground. Press Ctrl-C, or send `SIGTERM`, to unmount.

## Install

```console
$ nix build github:jacob-pascual/bixfuse
```

### Linux

A normal user needs a setuid `fusermount3` on `PATH`. On NixOS, set
`programs.fuse.enable = true;`.

### macOS

Install [macFUSE](https://macfuse.github.io/) 5 or later. bixfuse uses the
default macFUSE backend, the kernel extension. On Apple Silicon, the kernel
extension needs Reduced Security in Recovery mode, an approval in System
Settings, and a restart. Until then, a mount fails with
`Operation not permitted`.

## Development

```console
$ nix develop -c cargo test   # unit tests and checks with age-keygen, ssh-keygen, gpg
$ nix flake check             # the package on every system, and a NixOS VM mount test on Linux
```
