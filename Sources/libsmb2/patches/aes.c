/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   SwiftSMB replacement for upstream lib/aes.c (single-block AES-128 encryption).

   Copyright (C) 2025 by Ronnie Sahlberg <ronniesahlberg@gmail.com>
   Copyright (C) 2026 SwiftSMB contributors

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 * AES128_ECB_encrypt() encrypts one 16-byte block, and its callers (AES-CMAC
 * signing in smb2-signing.c) call it once per block of the message with the
 * same key. Upstream's CommonCrypto version creates and releases a CCCryptor
 * on every call, which costs far more than the block itself. Here each thread
 * keeps the cryptor for the last key it used, and only creates a new one when
 * the key changes. Without CommonCrypto this file is upstream's, unchanged.
 *
 * See https://github.com/sahlberg/libsmb2/issues/541
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(__APPLE__) && defined(HAVE_COMMONCRYPTO_COMMONCRYPTOR_H)

#include "aes.h"
#include "aes_reference.h"

#include <CommonCrypto/CommonCryptor.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define AES128_KEY_LEN 16
#define AES128_BLOCK_SIZE 16

struct swiftsmb_aes_cache {
        CCCryptorRef cryptor;
        uint8_t key[AES128_KEY_LEN];
};

static pthread_key_t swiftsmb_aes_cache_key;
static pthread_once_t swiftsmb_aes_cache_once = PTHREAD_ONCE_INIT;
static int swiftsmb_aes_cache_ready;

static void swiftsmb_aes_cache_free(void *value)
{
        struct swiftsmb_aes_cache *cache = value;

        if (cache->cryptor != NULL) {
                CCCryptorRelease(cache->cryptor);
        }
        memset_s(cache, sizeof(*cache), 0, sizeof(*cache));
        free(cache);
}

static void swiftsmb_aes_cache_init(void)
{
        swiftsmb_aes_cache_ready =
                pthread_key_create(&swiftsmb_aes_cache_key, swiftsmb_aes_cache_free) == 0;
}

/* Constant time: the comparison must not reveal how much of the key matched. */
static int swiftsmb_same_key(const uint8_t a[AES128_KEY_LEN], const uint8_t b[AES128_KEY_LEN])
{
        uint8_t diff = 0;
        int i;

        for (i = 0; i < AES128_KEY_LEN; i++) {
                diff |= a[i] ^ b[i];
        }
        return diff == 0;
}

static CCCryptorRef swiftsmb_cryptor_for_key(const uint8_t *key)
{
        struct swiftsmb_aes_cache *cache;

        pthread_once(&swiftsmb_aes_cache_once, swiftsmb_aes_cache_init);
        if (!swiftsmb_aes_cache_ready) {
                return NULL;
        }
        cache = pthread_getspecific(swiftsmb_aes_cache_key);
        if (cache == NULL) {
                cache = calloc(1, sizeof(*cache));
                if (cache == NULL) {
                        return NULL;
                }
                if (pthread_setspecific(swiftsmb_aes_cache_key, cache) != 0) {
                        free(cache);
                        return NULL;
                }
        }
        if (cache->cryptor != NULL && swiftsmb_same_key(cache->key, key)) {
                return cache->cryptor;
        }
        if (cache->cryptor != NULL) {
                CCCryptorRelease(cache->cryptor);
                cache->cryptor = NULL;
        }
        if (CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode,
                            key, AES128_KEY_LEN, NULL, &cache->cryptor) != kCCSuccess) {
                cache->cryptor = NULL;
                return NULL;
        }
        memcpy(cache->key, key, AES128_KEY_LEN);
        return cache->cryptor;
}

void AES128_ECB_encrypt(uint8_t *input, const uint8_t *key, uint8_t *output)
{
        CCCryptorRef cryptor = swiftsmb_cryptor_for_key(key);
        uint8_t block[AES128_BLOCK_SIZE];
        size_t moved = 0;

        if (cryptor != NULL) {
                /* ECB cannot run in place in CommonCrypto, and callers pass the
                 * same buffer for input and output. */
                memcpy(block, input, AES128_BLOCK_SIZE);
                if (CCCryptorUpdate(cryptor, block, AES128_BLOCK_SIZE, output,
                                    AES128_BLOCK_SIZE, &moved) == kCCSuccess &&
                    moved == AES128_BLOCK_SIZE) {
                        return;
                }
        }
        AES128_ECB_encrypt_reference(input, key, output);
}

#else

#include "../upstream/lib/aes.c"

#endif
