# bixfuse specification

Status: In Progress (2026-09-28)

## 1. Summary

bixfuse is a read-only FUSE (Filesystem in Userspace) program for Linux and
macOS. It reads a BIP-39 mnemonic from a file and mounts a filesystem of
BIP-85 (Deterministic Entropy From BIP32 Keychains) outputs.

The filesystem root `/` is the BIP-85 root `m/83696968'`. It has two parts:

1. **Visible directories** hold strict BIP-85 applications. The path of a
   file gives the BIP-85 derivation path, and the file holds the output as
   BIP-85 defines it.
2. **Hidden directories** (`/.<app>`) hold application-specific encodings of
   BIP-85 outputs: OpenSSH keys in `/.ssh`, age keys in `/.age`, OpenPGP keys
   in `/.gnupg`, WireGuard keys in `/.wireguard`.

## 2. Goals

1. Support every application in BIP-85 v2.1.0 (2026-08-02): BIP39, HD-Seed WIF,
   XPRV, HEX, PWD BASE64, PWD BASE85, RSA, RSA GPG, DICE, Nostr.
2. Support key types that BIP-85 does not define: OpenSSH Ed25519 keys,
   age X25519 identities, age post-quantum (ML-KEM-768 + X25519)
   identities, and WireGuard keys. Each key type has its own application number (section 5.3), so
   no two key types share a seed.
3. Produce outputs identical to the reference implementations:
   - [bipsea](https://github.com/akarve/bipsea) for all applications that bipsea supports.
   - [ethankosakovsky/bip85](https://github.com/ethankosakovsky/bip85)
     (pycryptodome `RSA.generate`) for RSA.
4. Build with Nix on `aarch64-darwin`, `x86_64-darwin`, `aarch64-linux`, and `x86_64-linux`.

## 3. Non-goals

1. Write access. The filesystem is read-only.
2. Testnet output (TPRV). The input is a mnemonic, so the root key is always mainnet.

## 4. Command-line interface

```
bixfuse [OPTIONS] <MOUNTPOINT>
bixfuse [OPTIONS] cat <PATH>...

OPTIONS: [--mnemonic-file <PATH>] [--passphrase-file <PATH>]
         [--gpg-name <NAME>] [--gpg-email <EMAIL>]
```

1. The mnemonic is one BIP-39 mnemonic (12, 15, 18, 21, or 24 words)
   followed by a newline. bixfuse detects the wordlist language. bixfuse
   rejects a mnemonic with a bad checksum.
2. `--mnemonic-file <PATH>` gives the file of the mnemonic. The path `-`
   means standard input. bixfuse reads standard input only for `-`.
3. Without `--mnemonic-file`, bixfuse uses the first of these files that
   exists: `/etc/mnemonic`, `$XDG_CONFIG_HOME/bixfuse/mnemonic`,
   `./mnemonic`, `./mnemonic.txt`. If `$XDG_CONFIG_HOME` is not set or is not
   absolute, it is `$HOME/.config` (XDG Base Directory Specification). If
   that file cannot be read or holds no valid mnemonic, bixfuse stops with an
   error; it does not try the next file. If no file exists, the error lists
   the files that bixfuse tried.
4. `--passphrase-file <PATH>` gives the file of the BIP-39 passphrase
   (`-` means standard input). bixfuse removes one trailing line ending (`\n`
   or `\r\n`); all other characters are part of the passphrase. BIP-39
   normalizes the passphrase to NFKD. Without this option, the passphrase is
   empty. The passphrase changes every derived key.
5. If both `--mnemonic-file` and `--passphrase-file` are `-`, bixfuse stops
   with an error.
6. The OpenPGP user ID of the `/.gnupg` keys is `<NAME> <<EMAIL>>`:
   - `NAME`: `--gpg-name`, else the full name of the current user in the
     user database (the GECOS field up to the first comma, from
     `getpwuid`: `/etc/passwd` on Linux, Directory Services on macOS), else
     the user name.
   - `EMAIL`: `--gpg-email`, else `<user name>@<fully qualified host name>`.
     The fully qualified host name is the canonical name of the host name
     from `getaddrinfo`, as for `hostname -f`; else the host name.
   The key fingerprints do not depend on the user ID, but the signatures in
   the files do. So the `/.gnupg` files differ between users and hosts.
7. `MOUNTPOINT` is an existing empty directory.
8. bixfuse runs in the foreground. It unmounts on `SIGINT` or `SIGTERM`.
9. `cat <PATH>...` does not mount. It writes the contents of each file to
   standard output, in order. `PATH` is a path of section 5, with or without
   a leading `/`. For a path that is not a file, bixfuse stops with an error
   and a non-zero exit status. The Nix modules (section 10) use `cat`.

## 5. Filesystem layout

In the tables, `{name}` is a directory or file named by a decimal number.
"Listed" tells if `ls` shows the entries of that level. `ls` hides the
hidden directories, as for every name that starts with `.`; `ls -a` shows them.

### 5.1 Visible directories: BIP-85 applications

| Path | BIP-85 derivation path | Listed |
|---|---|---|
| `/bip39/{language}/{words}/{index}` | `m/83696968'/39'/{lang_code}'/{words}'/{index}'` | language, words: yes; index: no |
| `/wif/{index}` | `m/83696968'/2'/{index}'` | no |
| `/xprv/{index}` | `m/83696968'/32'/{index}'` | no |
| `/hex/{num_bytes}/{index}` | `m/83696968'/128169'/{num_bytes}'/{index}'` | num_bytes: yes; index: no |
| `/base64/{pwd_len}/{index}` | `m/83696968'/707764'/{pwd_len}'/{index}'` | pwd_len: yes; index: no |
| `/base85/{pwd_len}/{index}` | `m/83696968'/707785'/{pwd_len}'/{index}'` | pwd_len: yes; index: no |
| `/dice/{sides}/{rolls}/{index}` | `m/83696968'/89101'/{sides}'/{rolls}'/{index}'` | no |
| `/nostr/{identity}/{account_index}` | `m/83696968'/128002'/{identity}'/{account_index}'` | no |
| `/rsa/{key_bits}/{key_index}/private.pem` | `m/83696968'/828365'/{key_bits}'/{key_index}'` | key_bits: 2048, 3072, 4096 only; key_index: no |
| `/rsa/{key_bits}/{key_index}/{sub_key}/private.pem` | `m/83696968'/828365'/{key_bits}'/{key_index}'/{sub_key}'` (RSA GPG sub keys) | sub_key: yes |

### 5.2 Hidden directories: application-specific encodings

Each hidden directory has flat default names at its top level and indexed
subdirectories for every other key.

| Path | Source | Listed |
|---|---|---|
| `/.ssh/id_ed25519`, `/.ssh/id_ed25519.pub` | Ed25519, index 0 | yes |
| `/.ssh/id_rsa`, `/.ssh/id_rsa.pub` | `rsa/4096/0` | yes |
| `/.ssh/ed25519/{index}/id_ed25519`, `.../id_ed25519.pub` | Ed25519 | index: no |
| `/.ssh/rsa/{key_bits}/{key_index}/id_rsa`, `.../id_rsa.pub` | `rsa/{key_bits}/{key_index}` | key_bits: 2048, 3072, 4096 only; key_index: no |
| `/.ssh/rsa/{key_bits}/{key_index}/{sub_key}/id_rsa`, `.../id_rsa.pub` | `rsa/{key_bits}/{key_index}/{sub_key}` | sub_key: yes |
| `/.age/private.age`, `/.age/public.age` | age X25519, index 0 | yes |
| `/.age/x25519/{index}/private.age`, `.../public.age` | age X25519 | index: no |
| `/.age/private-pq.age`, `/.age/public-pq.age` | age post-quantum, index 0 | yes |
| `/.age/mlkem768x25519/{index}/private.age`, `.../public.age` | age post-quantum | index: no |
| `/.gnupg/secret.asc`, `/.gnupg/public.asc` | `rsa/4096/0` and its sub keys 0, 1, 2 | yes |
| `/.gnupg/rsa/{key_bits}/{key_index}/secret.asc`, `.../public.asc` | `rsa/{key_bits}/{key_index}` and its sub keys 0, 1, 2 | key_bits: 2048, 3072, 4096 only; key_index: no |
| `/.wireguard/privatekey`, `/.wireguard/publickey` | WireGuard, index 0 | yes |
| `/.wireguard/x25519/{index}/privatekey`, `.../publickey` | WireGuard | index: no |

### 5.3 Application numbers of bixfuse

BIP-85 v2.1.0 does not define these key types. bixfuse gives each one its
own application number, as BIP-85 recommends: "Application numbers should be
semantic in some way, such as a BIP number or ASCII character code sequence."
As for RSA (`828365'` = ASCII `R` 82, `S` 83, `A` 65), the application number
is the decimal ASCII codes of the application name. The next level names the
key type, as the `{key_bits}'` level does for RSA.

| Key type | Derivation path | Meaning of the numbers |
|---|---|---|
| OpenSSH Ed25519 | `m/83696968'/838372'/25519'/{index}'` | `SSH` = 83 83 72; curve 25519 |
| age X25519 | `m/83696968'/657169'/25519'/{index}'` | `AGE` = 65 71 69; curve 25519 |
| age post-quantum | `m/83696968'/657169'/768'/{index}'` | `AGE`; ML-KEM-768 (with X25519) |
| WireGuard | `m/83696968'/8771'/25519'/{index}'` | `WG` = 87 71; curve 25519 |

The seed of each key is the first 32 bytes of the 64 bytes of entropy.
These paths are a bixfuse convention: other BIP-85 tools do not derive them.

If BIP-85 adopts [bitcoin/bips#2174](https://github.com/bitcoin/bips/pull/2174)
as it is (age keys from `hex/32/{index}`), bixfuse will change to the BIP-85
paths. Then the age keys will share seeds with `hex/32/{index}`, and the
documentation MUST tell careful users to use only one key per mnemonic.

### 5.4 Valid values

| Segment | Valid values |
|---|---|
| `language` | `english` (0), `japanese` (1), `korean` (2), `spanish` (3), `chinese_simplified` (4), `chinese_traditional` (5), `french` (6), `italian` (7), `czech` (8), `portuguese` (9) |
| `words` | 12, 15, 18, 21, 24 |
| `num_bytes` | 16 to 64 |
| `pwd_len` (base64) | 20 to 86 |
| `pwd_len` (base85) | 10 to 80 |
| `key_bits` | 1024 to 8192 (see 9.2) |
| `sub_key` | 0 (encryption), 1 (authentication), 2 (signature) |
| `sides` | 2 to 2^31 - 1 (see 9.2) |
| `rolls` | 1 to 10000 (see 9.2) |
| `identity`, `account_index` | 1 to 2^31 - 1 (0 is reserved by BIP-85) |
| every `index`, `key_index` | 0 to 2^31 - 1 |

A number segment MUST be in canonical decimal form: `0`, or a digit 1-9
followed by digits. `007` and `+7` do not exist. This rule gives each output
exactly one path in its directory tree.

## 6. BIP-85 core

1. Seed: BIP-39 seed of the mnemonic and the passphrase (section 4).
2. Root: BIP-32 master key from the seed.
3. Derive the child key `k` at the hardened path.
4. Entropy: `HMAC-SHA512(key = "bip-entropy-from-k", msg = k)`, 64 bytes.
5. DRNG (BIP85-DRNG-SHAKE256): a SHAKE256 stream seeded with the 64 bytes of entropy.

## 7. File contents

Every file ends with one newline (`\n`).

### 7.1 Visible directories

| Application | Content |
|---|---|
| bip39 | Mnemonic of the first `words * 4 / 3` bytes of entropy (128 bits for 12 words). Words in Unicode NFC, separated by an ASCII space, for every language (same as bipsea). |
| wif | Compressed mainnet WIF of the first 32 bytes. |
| xprv | Mainnet xprv. Chain code = bytes 0-31, private key = bytes 32-63. Depth, parent fingerprint, and child number are 0. |
| hex | Lowercase hex of the first `num_bytes` bytes. |
| base64 | RFC 4648 Base64 of all 64 bytes, first `pwd_len` characters. |
| base85 | Base85 (RFC 1924 alphabet, same as Python `base64.b85encode`) of all 64 bytes, first `pwd_len` characters. |
| dice | Rolls from the DRNG as BIP-85 specifies. `bits_per_roll` is computed exactly, as the bit length of `sides - 1`. Rolls are joined by `,`. Each roll is zero-padded to the width of `sides - 1` (same as bipsea). |
| nostr | Bech32 `nsec` of the first 32 bytes (NIP-19). |
| rsa `private.pem` | The RSA key (section 7.2) as PKCS#1 PEM (`-----BEGIN RSA PRIVATE KEY-----`, 64-character Base64 lines). This is pycryptodome `export_key(format='PEM', pkcs=1)`, the encoding of the BIP-85 reference RSA test vectors. |

A key that is 0 or not less than the secp256k1 curve order is invalid
(wif, xprv, nostr). BIP-85 requires a hard fail. A read of such a file
returns `EIO`.

### 7.2 RSA key generation

1. Seed the DRNG with the entropy of the RSA path.
2. Generate the key with the algorithm of pycryptodome 3.x
   `RSA.generate(bits, randfunc=drng.read, e=65537)`. The port MUST consume
   the DRNG bytes in the same order as pycryptodome. Specifically:
   - `Integer.random(exact_bits)`: read 1 byte for the most significant byte, then `bytes_needed - 1` bytes.
   - `generate_probable_prime`: candidate `| 1`, prime filter, then `test_probable_prime`.
   - `test_probable_prime`: no trial division. pycryptodome calls `map()` lazily, so its sieve has no effect. Then Miller-Rabin with the pycryptodome iteration table, then the Lucas test.
   - Miller-Rabin bases come from `Integer.random_range(2, n - 2)`.
   - `p` must be greater than `sqrt(2^(2*size_p - 1))`, and `gcd(p - 1, e) = 1`.
   - `q` has the same rules, and `|p - q| > 2^(bits/2 - 100)`.
   - Swap `p` and `q` if `p > q`.

### 7.3 `/.ssh`: OpenSSH keys

1. `id_rsa`, `id_ed25519`: unencrypted `openssh-key-v1` private keys
   (`ciphername none`). The check integers are 0, so the output is
   deterministic. The comment is empty. Base64 lines are 70 characters, as
   `ssh-keygen` writes them.
2. `id_rsa.pub`: `ssh-rsa <base64 blob>`. `id_ed25519.pub`: `ssh-ed25519 <base64 blob>`.
3. The Ed25519 seed (RFC 8032 private key) is the seed of section 5.3.

### 7.4 `/.age`: age keys

The seed is the seed of section 5.3. The formats are those of the
[age specification](https://github.com/C2SP/C2SP/blob/main/age.md).

| File | Content |
|---|---|
| X25519 `private.age` | Uppercase Bech32 with HRP `AGE-SECRET-KEY-` of the seed. |
| X25519 `public.age` | Bech32 with HRP `age` of `X25519(seed, basepoint)`. |
| post-quantum `private.age`, `private-pq.age` | Uppercase Bech32 with HRP `AGE-SECRET-KEY-PQ-` of the seed. |
| post-quantum `public.age`, `public-pq.age` | Bech32 with HRP `age1pq` of the 1216-byte X-Wing encapsulation key of the seed (draft-connolly-cfrg-xwing-kem-06; MLKEM768-X25519 of filippo.io/hpke-pq). The string has 1959 characters. As the age specification requires, Bech32 has no length limit here. |

### 7.5 `/.gnupg`: OpenPGP keys (RSA GPG)

The user ID is the user ID of section 4, item 6.

1. Keys: RFC 4880 version 4 RSA keys. Creation time is 1231006505 for all keys.
   - Primary key: `m/83696968'/828365'/{key_bits}'/{key_index}'`, flag Certify.
   - Sub key 0: flags Encrypt communications + Encrypt storage.
   - Sub key 1: flag Authenticate.
   - Sub key 2: flag Sign. The binding signature contains an embedded primary key binding signature (0x19).
2. Signatures: version 4, SHA-256, RSA PKCS#1 v1.5, creation time 1231006505.
   RSA PKCS#1 v1.5 signatures are deterministic, so the files are deterministic.
3. `secret.asc`: armored transferable secret key, not encrypted.
4. `public.asc`: armored transferable public key.

The primary key fingerprint depends only on the RSA key and the creation time.
Another BIP-85 tool that uses the same RSA algorithm gets the same fingerprint.
The signatures can differ between tools.

### 7.6 `/.wireguard`: WireGuard keys

The seed is the seed of section 5.3. The formats are those of `wg genkey`
and `wg pubkey` (wireguard-tools).

| File | Content |
|---|---|
| `privatekey` | RFC 4648 Base64 (44 characters) of the seed, clamped as `wg genkey` clamps a new key: clear the 3 lowest bits of byte 0, clear bit 7 of byte 31, set bit 6 of byte 31. |
| `publickey` | Base64 of `X25519(private key, basepoint)`, the output of `wg pubkey`. |

The clamping makes `privatekey` a key that `wg genkey` can write. WireGuard
clamps every private key before use, so the public key does not change.

## 8. Filesystem behavior

1. Mount options: read-only, filesystem name `bixfuse`, `default_permissions`.
   On Linux, a normal user needs a setuid `fusermount3` on `PATH`
   (NixOS: `programs.fuse.enable = true`). On macOS, bixfuse uses the
   default macFUSE backend (the kernel extension).
2. File mode `0400`, directory mode `0500`, owner = the user that mounts.
3. `ls` shows only the "Listed" entries of section 5. A lookup of any valid
   unlisted name succeeds. A lookup of an invalid name returns `ENOENT`.
4. Contents are computed on the first `lookup`, `getattr`, or `read` and kept
   in memory until unmount. File size is exact.
5. The filesystem is single-threaded. RSA generation blocks other requests
   until it completes. Measured on Apple Silicon (release build, 2026-09-27):
   2048-bit 0.4 s, 3072-bit 0.9 s, 4096-bit 1.1 s to 5.9 s, 8192-bit 94 s.
   The OpenPGP files need 4 keys. `ls -l /.ssh` generates the 4096-bit
   default key, and `ls -l /.gnupg` generates 4 of them.

## 9. Decisions and deviations

### 9.1 Decisions confirmed by the user

2026-09-27:

1. Language: Rust.
2. hex path: `hex/{num_bytes}/{index}`. The `base64` segment in the first
   request (`hex/base64/32/0`) is not part of the derivation path.
3. RSA GPG: full OpenPGP export, user ID from a command-line option.

2026-09-28, first set (supersedes the 2026-09-27 age path `age/x25519/{index}/`):

4. Application-specific encodings are in hidden directories `/.<app>`. The
   visible directories hold only strict BIP-85 applications.
5. Hidden directories have flat default names (index 0; RSA 4096-bit,
   key_index 0) and indexed subdirectories.
6. (Superseded by 9.) The Ed25519 SSH seed is `hex/32/{index}`, as for age.
7. (Superseded by 9.) The shared secret of `/.ssh/id_ed25519` and
   `/.age/private.age` (both `hex/32/0`) is accepted.
8. The visible RSA encoding is PKCS#1 PEM, in `private.pem`.

2026-09-28, second set:

9. Key types that BIP-85 does not define do not use `hex/32`. Each one has
   its own application number (section 5.3), with a key-type level.
10. Support age post-quantum identities, with flat defaults
    `private-pq.age` and `public-pq.age`.
11. If BIP-85 adopts bitcoin/bips#2174 as it is, bixfuse matches BIP-85, and
    the documentation tells careful users to use one key per mnemonic.

2026-09-28, third set (supersedes the positional `MNEMONIC_FILE` argument):

12. (Superseded by 14.) The mnemonic comes from standard input,
    `--mnemonic-file`, or a fixed list of default files, in that order.
13. (Superseded by 14.) A mnemonic on standard input together with
    `--mnemonic-file` is an error.

2026-09-28, fourth set:

14. bixfuse reads standard input only for `--mnemonic-file -` (and
    `--passphrase-file -`). Without `--mnemonic-file`, the default files of
    section 4 are used.
15. `--passphrase-file` gives the BIP-39 passphrase. (This removes the
    non-goal "BIP-39 passphrases".)
16. `--gpg-name` and `--gpg-email` replace `--gpg-user-id`. Their defaults
    come from the user database and the host name, so `/.gnupg` always
    exists.

2026-09-28, fifth set:

17. A NixOS module and a home-manager module (section 10) install secrets
    in the style of sops-nix and agenix. A secret is `type.<kind>` or
    `derivation`, and `derivation` is a path of section 5.
18. `bixfuse cat` prints files without a mount; the modules use it.
19. home-manager: `bixfuse.user.name` and `bixfuse.user.email` set the git
    identity and the OpenPGP user ID.
20. `programs.sshd` writes Ed25519 and RSA-4096 host keys of
    `bixfuse.programs.sshd.index` (default 0).
21. The modules never replace a key file with different contents.
22. Option names use `enable` (NixOS convention), not `enabled`.

2026-09-28, sixth set:

23. WireGuard keys in `/.wireguard`, with their own application number
    `8771'` (`WG`) and the key type level `25519'` (section 5.3). The first
    user is pascuals-infra: each host derives its WireGuard key from the
    host mnemonic.
24. The file names are `privatekey` and `publickey`, as in the WireGuard
    quick start (`wg genkey | tee privatekey | wg pubkey > publickey`).

### 9.2 Limits that are narrower than BIP-85

1. `rolls` is at most 10000, as in bipsea. BIP-85 allows 2^32 - 1. A larger
   file does not fit in memory with the design of section 8.
2. `key_bits` is at most 8192. BIP-85 sets no maximum. The limit prevents a
   single `ls` or `cat` from blocking the filesystem for a long time.
3. `sides` is at most 2^31 - 1. BIP-85 allows 2^32 - 1, but `sides` is a
   hardened BIP-32 index, and a hardened index must be less than 2^31.
   bipsea 4.0.0 fails with an `AssertionError` for `sides` >= 2^31.

### 9.3 Differences from bipsea 4.0.0

1. Dice with `sides` = 2^29 or 2^31: bipsea computes `bits_per_roll` with
   floating-point `math.log` and gets 30 and 32. The exact value, as BIP-85
   defines it, is 29 and 31. bixfuse uses the exact value, so its rolls for
   these two values of `sides` differ from bipsea. All other values of
   `sides` give the same result (checked for every `sides` < 2^17 and every
   power of two up to 2^32).

## 10. Nix modules

### 10.1 Purpose

One mnemonic is one identity: a host has one mnemonic (`/etc/mnemonic`), and
a user has one mnemonic (`~/.config/bixfuse/mnemonic`). Every key and
secret of that host or user derives from its mnemonic. The NixOS module
installs the secrets of a host; the home-manager module installs the
secrets of a user. Neither module mounts the FUSE filesystem: both call
`bixfuse cat` (section 4). The design follows sops-nix and agenix.

The flake exports `nixosModules.default` and `homeManagerModules.default`.
The mnemonic file MUST NOT be in the Nix store, so `mnemonicFile` is a
string, and a path in the Nix store is an evaluation error.

### 10.2 Secrets (both modules)

`bixfuse.secrets.<name>` has these options:

| Option | Default | Meaning |
|---|---|---|
| `type.<kind>` | none | The secret as a typed value (table below). |
| `derivation` | none | The secret as a path of section 5, for example `"bip39/english/12/0"`. |
| `path` | `<secretsDir>/<name>` | The path to use in other options. If it is not in `secretsDir`, it is a symlink to `<secretsDir>/<name>`. |
| `mode` | `"0400"` | The file mode. |
| `owner`, `group` (NixOS only) | `"root"`, `"root"` | The owner of the file. |

Exactly one of `type.<kind>` and `derivation` MUST be set. `type.<kind>`
only builds a path of section 5:

| `type.<kind>` | Attributes (defaults) | Path |
|---|---|---|
| `bip39` | `language` ("english"), `words` (12), `index` (0) | `bip39/{language}/{words}/{index}` |
| `wif`, `xprv` | `index` (0) | `wif/{index}`, `xprv/{index}` |
| `hex` | `bytes` (32), `index` (0) | `hex/{bytes}/{index}` |
| `base64`, `base85` | `length` (required), `index` (0) | `base64/{length}/{index}`, `base85/{length}/{index}` |
| `dice` | `sides` (6), `rolls` (required), `index` (0) | `dice/{sides}/{rolls}/{index}` |
| `nostr` | `identity` (1), `account` (1) | `nostr/{identity}/{account}` |
| `rsa` | `bits` (4096), `index` (0), `subKey` (null) | `rsa/{bits}/{index}[/{subKey}]/private.pem` |
| `sshEd25519` | `index` (0), `public` (false) | `.ssh/ed25519/{index}/id_ed25519[.pub]` |
| `sshRsa` | `bits` (4096), `index` (0), `subKey` (null), `public` (false) | `.ssh/rsa/{bits}/{index}[/{subKey}]/id_rsa[.pub]` |
| `age` | `index` (0), `public` (false) | `.age/x25519/{index}/{private,public}.age` |
| `agePq` | `index` (0), `public` (false) | `.age/mlkem768x25519/{index}/{private,public}.age` |
| `gpg` | `bits` (4096), `index` (0), `public` (false) | `.gnupg/rsa/{bits}/{index}/{secret,public}.asc` |
| `wireguard` | `index` (0), `public` (false) | `.wireguard/x25519/{index}/{private,public}key` |

Secrets are written to a new generation directory
`<secretsMountPoint>/<generation>`, and then `secretsDir` becomes a symlink
to it; the previous generation is removed. If `bixfuse cat` fails for a
secret, installation stops with an error.

### 10.3 NixOS module

| Option | Default |
|---|---|
| `bixfuse.package` | the bixfuse package of the flake |
| `bixfuse.mnemonicFile` | `"/etc/mnemonic"` |
| `bixfuse.secretsDir` | `"/run/bixfuse"` |
| `bixfuse.secretsMountPoint` | `"/run/bixfuse.d"` (a `ramfs`, mode 0751) |
| `bixfuse.programs.enable` | `false` |
| `bixfuse.programs.sshd.enable` | `bixfuse.programs.enable` |
| `bixfuse.programs.sshd.index` | `0` |

1. An activation script installs the secrets after `/etc` is set up. A
   second activation script sets owner and group after users and groups
   exist.
2. `programs.sshd` writes these host keys at activation:

   | File | Path of section 5 | Mode |
   |---|---|---|
   | `/etc/ssh/ssh_host_ed25519_key` | `.ssh/ed25519/{index}/id_ed25519` | 0600 |
   | `/etc/ssh/ssh_host_ed25519_key.pub` | `.ssh/ed25519/{index}/id_ed25519.pub` | 0644 |
   | `/etc/ssh/ssh_host_rsa_key` | `.ssh/rsa/4096/{index}/id_rsa` | 0600 |
   | `/etc/ssh/ssh_host_rsa_key.pub` | `.ssh/rsa/4096/{index}/id_rsa.pub` | 0644 |

3. `programs.sshd` sets `services.openssh.generateHostKeys` to false with
   `mkDefault`. If it is true anyway, evaluation fails with an assertion.
4. If a host key file exists with different contents, activation stops with
   an error that names the file. bixfuse never replaces a different key.

### 10.4 home-manager module

| Option | Default |
|---|---|
| `bixfuse.package` | the bixfuse package of the flake |
| `bixfuse.mnemonicFile` | `"${config.xdg.configHome}/bixfuse/mnemonic"` |
| `bixfuse.user.name`, `bixfuse.user.email` | `null` |
| `bixfuse.secretsDir` | `"${XDG_RUNTIME_DIR}/bixfuse"` |
| `bixfuse.secretsMountPoint` | `"${XDG_RUNTIME_DIR}/bixfuse.d"` |
| `bixfuse.programs.enable` | `false` |
| `bixfuse.programs.ssh.enable` | `bixfuse.programs.enable` |
| `bixfuse.programs.git.enable` | `bixfuse.programs.enable` |

1. The systemd user service `bixfuse-secrets.service` installs the secrets
   at login and at each activation. It needs systemd, so secrets are
   available on Linux only; on macOS a secret is an evaluation error.
2. `bixfuse.user.name` and `bixfuse.user.email`, if set, are passed to
   `bixfuse cat` as `--gpg-name` and `--gpg-email`.
3. `programs.ssh` writes `~/.ssh/id_ed25519` (0600) and
   `~/.ssh/id_ed25519.pub` (0644) from `.ssh/id_ed25519` and
   `.ssh/id_ed25519.pub` at activation. If a file exists with different
   contents, activation stops with an error that names the file.
4. `programs.git` sets `programs.git.settings.user.name` and
   `programs.git.settings.user.email` to `bixfuse.user.name` and
   `bixfuse.user.email`. Both MUST be set (assertion).

## 11. Test plan

1. BIP-85 test vectors (all applications), from the BIP text and bipsea.
2. The BIP-39 passphrase vector ("TREZOR") of trezor/python-mnemonic, and
   `hex/32/0` with that passphrase from bipsea.
3. The user's examples for the mnemonic `abandon ... about`:
   - `bip39/english/12/0` = `prosper short ramp prepare exchange stove life snack client enough purpose fold`
   - `hex/32/0` = `e477d4694160a384b28ee2f72b54edcf0822fd6e1ee1780447455cdbed8f8c45`
4. age X25519 and post-quantum vectors from bitcoin/bips#2174, for the
   encoding functions. For the bixfuse paths of section 5.3: vectors from
   independent tools (entropy from bipsea, Ed25519 from Python
   `cryptography`, age recipients from `age-keygen` 1.3.2, WireGuard private
   keys from Python `hashlib` and `bip32` 5.0.0, WireGuard public keys from
   `wg pubkey` 1.0.20260223).
5. RSA: SHA-256 of `private.pem` without its trailing newline matches the
   reference vectors of ethankosakovsky/bip85 (2048-bit and 4096-bit).
6. OpenSSH: `ssh-keygen -y` of `id_rsa`, `id_ed25519`, and `private.pem`
   equals the `.pub` line, and a `ssh-keygen -Y sign` signature verifies.
7. age: `age-keygen -y` of each identity equals its recipient, and a file
   encrypted to each recipient decrypts with its identity.
8. OpenPGP: `gpg --import` succeeds, capabilities are C/E/A/S, signatures
   check, and the primary fingerprint equals an independent computation.
9. WireGuard: `wg pubkey` of each `privatekey` equals its `publickey`, and
   each `privatekey` is clamped.
10. Mount test on Linux: `nix/vm-test.nix` (flake check `vm-test`). A normal
    user mounts, reads every application, runs age-keygen, ssh-keygen, gpg, and wg
    on the mounted files, and unmounts with `SIGTERM`. It also checks
    `--mnemonic-file -`, the default mnemonic files, `--passphrase-file`, the
    input errors, the default OpenPGP user ID, and `--gpg-name`/`--gpg-email`.
11. Module test: `nix/module-test.nix` (flake check `module-test`). A host
    with its own mnemonic installs typed and `derivation` secrets with owner,
    group, mode, and a custom path, and a `type.wireguard` secret that
    `wg pubkey` reads; writes SSH host keys that sshd serves;
    refuses to replace a changed host key. A user with another mnemonic gets
    `~/.ssh/id_ed25519`, the git identity, and a secret from the systemd user
    service. Passed on `aarch64-linux` (2026-09-28).
12. Mount test on macOS with macFUSE: pending. On 2026-09-27 the macFUSE
   kernel extension was not enabled, and mounts failed with
   `Operation not permitted`.
