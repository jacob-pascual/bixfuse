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
   in `/.gnupg`.

## 2. Goals

1. Support every application in BIP-85 v2.1.0 (2026-08-02): BIP39, HD-Seed WIF,
   XPRV, HEX, PWD BASE64, PWD BASE85, RSA, RSA GPG, DICE, Nostr.
2. Support age X25519 identities as defined by the open BIP-85 pull request
   [bitcoin/bips#2174](https://github.com/bitcoin/bips/pull/2174).
3. Support OpenSSH Ed25519 keys with the seed from the HEX application
   (`hex/32/{index}`), the same way as age.
4. Produce outputs identical to the reference implementations:
   - [bipsea](https://github.com/akarve/bipsea) for all applications that bipsea supports.
   - [ethankosakovsky/bip85](https://github.com/ethankosakovsky/bip85)
     (pycryptodome `RSA.generate`) for RSA.
5. Build with Nix on `aarch64-darwin`, `x86_64-darwin`, `aarch64-linux`, and `x86_64-linux`.

## 3. Non-goals

1. BIP-39 passphrases. The seed always uses the empty passphrase.
2. Write access. The filesystem is read-only.
3. Testnet output (TPRV). The input is a mnemonic, so the root key is always mainnet.
4. The age post-quantum (X-Wing) identity flavor.

## 4. Command-line interface

```
bixfuse [--gpg-user-id <USER_ID>] <MNEMONIC_FILE> <MOUNTPOINT>
```

1. `MNEMONIC_FILE` holds one BIP-39 mnemonic (12, 15, 18, 21, or 24 words)
   followed by a newline. bixfuse detects the wordlist language. bixfuse
   rejects a mnemonic with a bad checksum.
2. `MOUNTPOINT` is an existing empty directory.
3. `--gpg-user-id` sets the OpenPGP user ID, for example `"Alice <alice@example.org>"`.
   When this option is absent, `/.gnupg` does not exist.
4. bixfuse runs in the foreground. It unmounts on `SIGINT` or `SIGTERM`.

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
| `/.ssh/id_ed25519`, `/.ssh/id_ed25519.pub` | seed `hex/32/0` | yes |
| `/.ssh/id_rsa`, `/.ssh/id_rsa.pub` | `rsa/4096/0` | yes |
| `/.ssh/ed25519/{index}/id_ed25519`, `.../id_ed25519.pub` | seed `hex/32/{index}` | index: no |
| `/.ssh/rsa/{key_bits}/{key_index}/id_rsa`, `.../id_rsa.pub` | `rsa/{key_bits}/{key_index}` | key_bits: 2048, 3072, 4096 only; key_index: no |
| `/.ssh/rsa/{key_bits}/{key_index}/{sub_key}/id_rsa`, `.../id_rsa.pub` | `rsa/{key_bits}/{key_index}/{sub_key}` | sub_key: yes |
| `/.age/private.age`, `/.age/public.age` | `hex/32/0` | yes |
| `/.age/x25519/{index}/private.age`, `.../public.age` | `hex/32/{index}` | index: no |
| `/.gnupg/secret.asc`, `/.gnupg/public.asc` | `rsa/4096/0` and its sub keys 0, 1, 2 | yes, if `--gpg-user-id` |
| `/.gnupg/rsa/{key_bits}/{key_index}/secret.asc`, `.../public.asc` | `rsa/{key_bits}/{key_index}` and its sub keys 0, 1, 2 | key_bits: 2048, 3072, 4096 only; key_index: no |

**Caution:** `/.ssh/ed25519/{index}` and `/.age/x25519/{index}` use the same
32 bytes, `hex/32/{index}`. The defaults `/.ssh/id_ed25519` and
`/.age/private.age` are both index 0, so they are one secret: the OpenSSH
Ed25519 file contains the seed, and the seed is the age identity. The user
accepted this on 2026-09-28 (section 9.1). To keep SSH and age keys
independent, use a different index for each.

### 5.3 Valid values

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

1. Seed: BIP-39 seed of the mnemonic with the empty passphrase.
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
3. The Ed25519 seed (RFC 8032 private key) is the 32 bytes of `hex/32/{index}`.

### 7.4 `/.age`: age keys

| File | Content |
|---|---|
| `private.age` | Uppercase Bech32 with HRP `AGE-SECRET-KEY-` of the 32 bytes of `hex/32/{index}`. |
| `public.age` | Bech32 with HRP `age` of `X25519(those 32 bytes, basepoint)`. |

### 7.5 `/.gnupg`: OpenPGP keys (RSA GPG)

The directory exists only if `--gpg-user-id` is set.

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

2026-09-28 (supersedes the 2026-09-27 age path `age/x25519/{index}/`):

4. Application-specific encodings are in hidden directories `/.<app>`. The
   visible directories hold only strict BIP-85 applications.
5. Hidden directories have flat default names (index 0; RSA 4096-bit,
   key_index 0) and indexed subdirectories.
6. The Ed25519 SSH seed is `hex/32/{index}`, as for age.
7. The shared secret of `/.ssh/id_ed25519` and `/.age/private.age` (both
   `hex/32/0`) is accepted.
8. The visible RSA encoding is PKCS#1 PEM, in `private.pem`.

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

## 10. Test plan

1. BIP-85 test vectors (all applications), from the BIP text and bipsea.
2. The user's examples for the mnemonic `abandon ... about`:
   - `bip39/english/12/0` = `prosper short ramp prepare exchange stove life snack client enough purpose fold`
   - `hex/32/0` = `e477d4694160a384b28ee2f72b54edcf0822fd6e1ee1780447455cdbed8f8c45`
3. age vector from bitcoin/bips#2174.
4. RSA: SHA-256 of `private.pem` without its trailing newline matches the
   reference vectors of ethankosakovsky/bip85 (2048-bit and 4096-bit).
5. OpenSSH: `ssh-keygen -y` of `id_rsa`, `id_ed25519`, and `private.pem`
   equals the `.pub` line, and a `ssh-keygen -Y sign` signature verifies.
   The Ed25519 public key equals an independent computation (Python
   `cryptography`).
6. OpenPGP: `gpg --import` succeeds, capabilities are C/E/A/S, signatures
   check, and the primary fingerprint equals an independent computation.
7. Mount test on Linux: `nix/vm-test.nix` (flake check `vm-test`). A normal
   user mounts, reads every application, runs age-keygen, ssh-keygen, and gpg
   on the mounted files, and unmounts with `SIGTERM`.
8. Mount test on macOS with macFUSE: pending. On 2026-09-27 the macFUSE
   kernel extension was not enabled, and mounts failed with
   `Operation not permitted`.
