/*
 * SwiftSMB: a hook that hands libsmb2's AES-GCM sealing to another
 * implementation. SwiftSMB installs CryptoKit's AES.GCM on Apple platforms.
 * With no hook installed, the portable code in Sources/libsmb2/gcm (BearSSL's
 * GCM over libsmb2's AES-128, or BearSSL's AES-256) seals instead.
 */
#ifndef SWIFTSMB_GCM_H
#define SWIFTSMB_GCM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Seals or opens one SMB3 message with AES-GCM, in place.
 *
 * key is 16 bytes (AES-128-GCM) or 32 bytes (AES-256-GCM), and iv is 12
 * bytes. data holds data_len bytes of plaintext to encrypt, or of ciphertext
 * to decrypt; either is replaced in place. tag is 16 bytes: written when
 * encrypting, and the expected tag when decrypting.
 *
 * Returns 0 on success. Returns -1 on failure, which for decryption includes
 * a tag that does not match; data is then undefined.
 */
typedef int (*swiftsmb_gcm_seal_fn)(int encrypt,
                                    const unsigned char *key, size_t key_len,
                                    const unsigned char *iv,
                                    const unsigned char *aad, size_t aad_len,
                                    unsigned char *data, size_t data_len,
                                    unsigned char *tag);

/* Installs fn, or with NULL goes back to the portable code. */
void swiftsmb_set_gcm_seal(swiftsmb_gcm_seal_fn fn);

#ifdef __cplusplus
}
#endif

#endif
