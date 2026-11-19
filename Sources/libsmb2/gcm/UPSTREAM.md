# AES-GCM for libsmb2, without OpenSSL

libsmb2 seals SMB 3.1.1 traffic with AES-128-GCM and AES-256-GCM only when it is built with OpenSSL (`HAVE_OPENSSL`).
This directory provides GCM without OpenSSL, taking third-party code only for what libsmb2 itself lacks:

- the GCM mode (GHASH, counter, tag): BearSSL's `src/aead/gcm.c` with the constant-time `src/hash/ghash_ctmul64.c`;
- AES-256: libsmb2's AES (`lib/aes.c`, `lib/aes_reference.c`) is AES-128 only, so AES-256-GCM uses BearSSL's
  constant-time `aes_ct64` (`src/symcipher/aes_ct64.c`, `aes_ct64_enc.c`, `aes_ct64_ctr.c`), plus the two
  little-endian codec helpers it calls (`src/codec/enc32le.c`, `dec32le.c`).

AES-128-GCM runs on libsmb2's own `AES128_ECB_encrypt()`: upstream's reference AES, or `../patches/aes.c` on Apple
platforms. `evp_gcm.c` wraps it in a BearSSL counter-mode class for `br_gcm`.

BearSSL is under the MIT license (`bearssl/LICENSE.txt`), which is compatible with libsmb2's LGPL-2.1-or-later. The
files of ours here are under the LGPL-2.1-or-later, like libsmb2.

## How it plugs into libsmb2

- `../patches/smb3-seal.c` and `../patches/smb2-cmd-negotiate.c` define `HAVE_OPENSSL` for those two upstream files
  only. The first seals through `<openssl/evp.h>`, the second offers and accepts the GCM ciphers. The rest of
  libsmb2 (AES-CCM, signing) is built as before.
- `include/openssl/evp.h` and `evp_gcm.c` implement the part of OpenSSL's EVP API that `smb3_aesgcm()` calls, over
  `br_gcm`. No OpenSSL code is involved.
- On Apple platforms SwiftSMB installs CryptoKit's `AES.GCM` through `swiftsmb_set_gcm_seal()`
  (`../include/swiftsmb-gcm.h`, `Sources/SwiftSMB/Bridge/Bridge-GCM.swift`), and the BearSSL code here is not used.
  Everywhere else, and in a process that has not created a SwiftSMB context, `evp_gcm.c` seals with it.
- `bearssl/` holds BearSSL's files unmodified, and `Package.swift` excludes the directory. Each `bearssl_*.c` here
  includes `include/swiftsmb_bearssl.h`, which gives every BearSSL function and table a `swiftsmb_` prefix, then one
  BearSSL source file. The prefix keeps them from colliding with, or binding to, another BearSSL in the same process.
- `gcm/include`, `gcm/bearssl/inc` and `gcm/bearssl/src` are on the target's header search path, after `include`,
  so libsmb2's `"config.h"` still wins over BearSSL's `src/config.h` (which `inner.h` finds next to itself).

## Copied files

From BearSSL `v0.6` (commit `8ef7680081c61b486622f2d983c0d3d21e83caad`, https://www.bearssl.org/git/BearSSL),
unmodified. The five algorithm files are identical on BearSSL's `master` as of April 2026.

| File | SHA-256 |
|---|---|
| `LICENSE.txt` | `771bf18c8633ea69ec9b07d2e604c4b99b7bef41b0f5ce6385d24df4448f61ca` |
| `src/inner.h` | `05a4c5b30599a00deda2648fbb842c07eb783bc5a62589ba90c3fada36ad732a` |
| `src/config.h` | `785d0cea25a7bbcb2b6d32e096072ac00b12f4d0b4819aa95ca28816a0e484d0` |
| `src/aead/gcm.c` | `1bea4df57ed57cdcd3dc2a44e7dbbe5866ccf045e0722fb68a2801dffa2f640f` |
| `src/hash/ghash_ctmul64.c` | `a5a5986e621de05735fdfd257fd39f313400ff53631d575232c230d3184bc4b9` |
| `src/symcipher/aes_ct64.c` | `755144aacacfb0eb9434876661655d16b91caa4f54fa46351dc626a56d9048f1` |
| `src/symcipher/aes_ct64_enc.c` | `3e2b380ddbc0f5d9bd3f8622d552e052a6361948ecc4077486a17273fa0148c4` |
| `src/symcipher/aes_ct64_ctr.c` | `713a6e5afafa06f9bd608d5552abba5d38f5790a7d58f2c397c9257904a2943f` |
| `src/codec/enc32le.c` | `7faa71643fc74570fd4c550974a075ec05485a0b3805cbdc826d662cb347e79b` |
| `src/codec/dec32le.c` | `fb45ce9e370d72c495dfbb08267e2fd32dcf5215c28df5d2db24f842b2d2d43a` |
| `inc/bearssl.h` | `5e73cb64005a5efd5082932bb9b7a3301a748969841c45d7f61123006e9ca5fe` |
| `inc/bearssl_aead.h` | `9d90afbc65535335517c028817ac0704af6b58971f2c262a65eb26e0b4099201` |
| `inc/bearssl_block.h` | `a00b4a48c42c824f2ec4ee775672df9cec86ad455b08cb8ae7eb8c89e63d082a` |
| `inc/bearssl_ec.h` | `3ee566b317361828cce70a96ce22d34d865b8dea73e65de55a6f511076bab766` |
| `inc/bearssl_hash.h` | `adfe3039fe48962c7fd74a1031f6d9dde951fb12a6acdae65a39f4d8537d2ef9` |
| `inc/bearssl_hmac.h` | `a40c14a7a71d5b4fa21f8485d7ad3975d3a37b9cd8b9f72cd0fa032af8105614` |
| `inc/bearssl_kdf.h` | `dee68113a97743febd0fee22d545c9548d81a6448e5b28311fa8ce384ee48bd8` |
| `inc/bearssl_pem.h` | `ef36260e8568e5927178e92c2aab849be71bc07414c01baeb1d12a3a51a82c3e` |
| `inc/bearssl_prf.h` | `0162e674d6c49425bfa0e8e9c79b3d850530e7928288930284fb7ac940a12b17` |
| `inc/bearssl_rand.h` | `968335e8a2957e5bf64cb0b6b1f916e53bc330e8c66d5f2d2f658f415a56dd44` |
| `inc/bearssl_rsa.h` | `1d9538cb78269cd02ca9ec118f67930ba88730eece4427f973fda2cb7122f9ff` |
| `inc/bearssl_ssl.h` | `52ea66d52eac903661865d99a05b5621e743a4acb227d7faf154bb5ce1ea48f3` |
| `inc/bearssl_x509.h` | `92a1674630209ee2a35d078990f7d8a1bf98753b4ec97db9aa9c288f7c294ab1` |

`inner.h` declares much of BearSSL and includes `bearssl.h`, which includes every public header, so all of `inc/`
is needed even though only the files above are compiled.

## Speed

Without the CryptoKit hook, 8 MiB, release build:

| | Apple M4 | Linux arm64 (same M4, Docker) |
|---|---|---|
| AES-128-GCM (libsmb2's AES) | ~590 MB/s (`patches/aes.c`, CommonCrypto) | ~47 MB/s (reference AES, key expanded per block) |
| AES-256-GCM (BearSSL `aes_ct64`) | ~165 MB/s | ~138 MB/s |

## Updating

1. Check out the new BearSSL release tag in a separate clone.
2. Copy the files above over these, and update the tag, commit, and hashes in this file.
3. Build. If a copied file calls a BearSSL function that is not compiled here, add its source file and a
   `bearssl_*.c` wrapper. If it defines a new global symbol, add its `swiftsmb_` name to
   `include/swiftsmb_bearssl.h`: `nm -g` on the `bearssl_*.o` objects must show no `br_` symbol.
4. Check the result against the GCM test vectors (McGrew–Viega test cases 2–4 and 14–16) and a full OpenSSL build,
   and against a Samba server with `server smb3 encryption algorithms` set to `AES-128-GCM` and to `AES-256-GCM`,
   with the CryptoKit hook and with `swiftsmb_set_gcm_seal(nil)`.
