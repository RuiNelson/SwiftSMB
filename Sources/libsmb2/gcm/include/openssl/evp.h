/*
 * SwiftSMB: the part of OpenSSL's EVP cipher API that libsmb2's smb3-seal.c
 * uses for AES-128-GCM and AES-256-GCM sealing, and nothing else. No OpenSSL
 * code is involved.
 *
 * libsmb2 only builds GCM with OpenSSL (HAVE_OPENSSL). Sources/libsmb2/patches
 * defines HAVE_OPENSSL for smb3-seal.c and smb2-cmd-negotiate.c alone, and
 * this header answers their #include <openssl/evp.h>. ../evp_gcm.c implements
 * it with BearSSL's GCM (Sources/libsmb2/gcm/bearssl).
 *
 * This file is distributed under the same license as libsmb2, the GNU
 * Lesser General Public License, version 2.1 or later.
 *
 * Only what smb3_aesgcm() does is supported: one EVP_CipherInit_ex() with
 * the cipher, key and 12-byte IV, the AAD through EVP_CipherUpdate() with a
 * NULL output, the data in one or more EVP_CipherUpdate() calls, then
 * EVP_CipherFinal_ex() and the tag through EVP_CIPHER_CTX_ctrl().
 */
#ifndef OPENSSL_EVP_H
#define OPENSSL_EVP_H

#ifdef __cplusplus
extern "C" {
#endif

#define EVP_CipherInit_ex swiftsmb_EVP_CipherInit_ex
#define EVP_CipherUpdate swiftsmb_EVP_CipherUpdate
#define EVP_CipherFinal_ex swiftsmb_EVP_CipherFinal_ex
#define EVP_CIPHER_CTX_new swiftsmb_EVP_CIPHER_CTX_new
#define EVP_CIPHER_CTX_free swiftsmb_EVP_CIPHER_CTX_free
#define EVP_CIPHER_CTX_ctrl swiftsmb_EVP_CIPHER_CTX_ctrl
#define EVP_aes_128_gcm swiftsmb_EVP_aes_128_gcm
#define EVP_aes_256_gcm swiftsmb_EVP_aes_256_gcm

/* The values OpenSSL uses. */
#define EVP_CTRL_AEAD_SET_IVLEN 0x9
#define EVP_CTRL_AEAD_GET_TAG 0x10
#define EVP_CTRL_AEAD_SET_TAG 0x11

typedef struct swiftsmb_evp_cipher_st EVP_CIPHER;
typedef struct swiftsmb_evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct swiftsmb_engine_st ENGINE;

const EVP_CIPHER *EVP_aes_128_gcm(void);
const EVP_CIPHER *EVP_aes_256_gcm(void);

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);

/* Returns 1 on success and 0 on failure, like OpenSSL. */
int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
                      const unsigned char *key, const unsigned char *iv, int enc);
int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl);
int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

#ifdef __cplusplus
}
#endif

#endif
