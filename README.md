# bixfuse

bixfuse mounts a read-only FUSE filesystem of
[BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)
secrets. The visible directories hold the BIP-85 applications: the path of
a file is the BIP-85 derivation path of the secret. The hidden directories
(`.ssh`, `.age`, `.gnupg`) hold the same secrets in the formats of other
tools. [SPEC.md](SPEC.md) is the full specification.

```console
$ bixfuse mnemonic.txt /mnt/bixfuse &
$ cat /mnt/bixfuse/bip39/english/12/0
prosper short ramp prepare exchange stove life snack client enough purpose fold
$ cat /mnt/bixfuse/hex/32/0
e477d4694160a384b28ee2f72b54edcf0822fd6e1ee1780447455cdbed8f8c45
$ cat /mnt/bixfuse/.ssh/id_ed25519.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBLNnAEuWd15WSVVNTQRA/UUz7wRqzkKU26yArVE7HVd
```

`mnemonic.txt` holds the BIP-39 mnemonic
`abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`.

## Layout

### BIP-85 applications

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
| `rsa/{key_bits}/{key_index}/private.pem` | RSA key, PKCS#1 PEM |
| `rsa/{key_bits}/{key_index}/{0,1,2}/private.pem` | RSA GPG sub keys (encrypt, authenticate, sign) |

### Encodings

| Path | Content |
|---|---|
| `.ssh/id_ed25519`, `.ssh/id_ed25519.pub` | OpenSSH Ed25519 key, seed `hex/32/0` |
| `.ssh/id_rsa`, `.ssh/id_rsa.pub` | OpenSSH RSA key of `rsa/4096/0` |
| `.ssh/ed25519/{index}/id_ed25519[.pub]` | OpenSSH Ed25519 key, seed `hex/32/{index}` |
| `.ssh/rsa/{key_bits}/{key_index}[/{0,1,2}]/id_rsa[.pub]` | OpenSSH RSA key |
| `.age/private.age`, `.age/public.age` | age identity and recipient of `hex/32/0` |
| `.age/x25519/{index}/private.age`, `public.age` | age identity and recipient of `hex/32/{index}` |
| `.gnupg/secret.asc`, `.gnupg/public.asc` | OpenPGP key of `rsa/4096/0` and its sub keys (needs `--gpg-user-id`) |
| `.gnupg/rsa/{key_bits}/{key_index}/secret.asc`, `public.asc` | OpenPGP key (needs `--gpg-user-id`) |

**Caution:** an Ed25519 key and an age key with the same index come from the
same 32 bytes (`hex/32/{index}`). The defaults `.ssh/id_ed25519` and
`.age/private.age` are both index 0, so they are one secret. To keep an SSH
key and an age key independent, use different indexes.

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
