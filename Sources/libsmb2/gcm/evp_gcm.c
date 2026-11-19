/*
   SwiftSMB: AES-GCM behind the EVP subset in include/openssl/evp.h.

   Two implementations:
   - A hook installed with swiftsmb_set_gcm_seal() (SwiftSMB installs
     CryptoKit's AES.GCM on Apple platforms). It seals a whole message at
     once, so the context collects the AAD and the data, and calls it from
     EVP_CipherFinal_ex().
   - Without a hook, BearSSL's GCM (br_gcm_*, with the constant-time
     br_ghash_ctmul64), message by message as the calls arrive. Its block
     cipher is libsmb2's own AES128_ECB_encrypt() (aes.c) for AES-128-GCM.
     libsmb2 has no AES-256, so AES-256-GCM uses BearSSL's constant-time
     br_aes_ct64 in counter mode.

   This file is distributed under the same license as libsmb2, the GNU
   Lesser General Public License, version 2.1 or later.
*/
#include "swiftsmb_bearssl.h"
#include "bearssl_aead.h"
#include "bearssl_block.h"
#include "bearssl_hash.h"

#include <openssl/evp.h>
#include "swiftsmb-gcm.h"
/* libsmb2's AES-128: upstream lib/aes.c, or patches/aes.c on Apple platforms. */
#include "aes.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define GCM_BLOCK 16
#define GCM_IV 12
#define GCM_MAX_KEY 32

static swiftsmb_gcm_seal_fn swiftsmb_gcm_hook;

void swiftsmb_set_gcm_seal(swiftsmb_gcm_seal_fn fn)
{
        __atomic_store_n(&swiftsmb_gcm_hook, fn, __ATOMIC_RELEASE);
}

static void cleanse(void *ptr, size_t len)
{
        volatile unsigned char *p = ptr;

        while (len--) {
                *p++ = 0;
        }
}

/*
 * A BearSSL CTR class over libsmb2's AES-128, which takes the raw key on
 * every block. The counter block is the 12-byte IV and a 32-bit big-endian
 * counter, as br_block_ctr_class defines it.
 */
typedef struct {
        const br_block_ctr_class *vtable;
        unsigned char key[16];
} libsmb2_aes128_ctr_keys;

static void libsmb2_aes128_ctr_init(const br_block_ctr_class **ctx, const void *key, size_t len)
{
        libsmb2_aes128_ctr_keys *keys = (libsmb2_aes128_ctr_keys *)(void *)ctx;

        (void)len;
        memcpy(keys->key, key, sizeof(keys->key));
}

static uint32_t libsmb2_aes128_ctr_run(const br_block_ctr_class *const *ctx, const void *iv,
                                       uint32_t cc, void *data, size_t len)
{
        const libsmb2_aes128_ctr_keys *keys = (const libsmb2_aes128_ctr_keys *)(const void *)ctx;
        unsigned char *buf = data;
        unsigned char counter[GCM_BLOCK], stream[GCM_BLOCK];
        size_t n, i;

        memcpy(counter, iv, GCM_IV);
        while (len > 0) {
                counter[12] = (unsigned char)(cc >> 24);
                counter[13] = (unsigned char)(cc >> 16);
                counter[14] = (unsigned char)(cc >> 8);
                counter[15] = (unsigned char)cc;
                cc++;
                AES128_ECB_encrypt(counter, keys->key, stream);
                n = len < GCM_BLOCK ? len : GCM_BLOCK;
                for (i = 0; i < n; i++) {
                        buf[i] ^= stream[i];
                }
                buf += n;
                len -= n;
        }
        cleanse(stream, sizeof(stream));
        return cc;
}

static const br_block_ctr_class libsmb2_aes128_ctr_vtable = {
        sizeof(libsmb2_aes128_ctr_keys),
        16,
        4,
        libsmb2_aes128_ctr_init,
        libsmb2_aes128_ctr_run
};

struct swiftsmb_evp_cipher_st {
        int key_bits;
};

static const EVP_CIPHER swiftsmb_aes_128_gcm = { 128 };
static const EVP_CIPHER swiftsmb_aes_256_gcm = { 256 };

struct swiftsmb_evp_cipher_ctx_st {
        const EVP_CIPHER *cipher;
        int enc;
        int key_set;
        int iv_known;
        int iv_pending;
        int iv_set;
        int flipped;
        int finished;
        unsigned char iv[GCM_BLOCK];
        size_t iv_len;
        unsigned char tag[GCM_BLOCK];
        size_t tag_len;
        unsigned char key_bytes[GCM_MAX_KEY];

        /* With a hook: the message, sealed at once in EVP_CipherFinal_ex(). */
        swiftsmb_gcm_seal_fn hook;
        unsigned char *aad;
        size_t aad_len;
        size_t aad_cap;
        unsigned char *data;
        size_t data_len;
        int data_seen;

        /* Without a hook. br_gcm_context points at the counter-mode context,
         * so neither may move. */
        union {
                const br_block_ctr_class *vtable;
                libsmb2_aes128_ctr_keys aes128;
                br_aes_ct64_ctr_keys aes256;
        } ctr;
        br_gcm_context gcm;
};

const EVP_CIPHER *EVP_aes_128_gcm(void)
{
        return &swiftsmb_aes_128_gcm;
}

const EVP_CIPHER *EVP_aes_256_gcm(void)
{
        return &swiftsmb_aes_256_gcm;
}

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void)
{
        EVP_CIPHER_CTX *ctx = calloc(1, sizeof(*ctx));

        if (ctx != NULL) {
                ctx->iv_len = GCM_IV;
        }
        return ctx;
}

static void reset_message(EVP_CIPHER_CTX *ctx)
{
        if (ctx->aad != NULL) {
                cleanse(ctx->aad, ctx->aad_cap);
        }
        ctx->aad_len = 0;
        ctx->data = NULL;
        ctx->data_len = 0;
        ctx->data_seen = 0;
        ctx->flipped = 0;
        ctx->finished = 0;
        ctx->tag_len = 0;
}

void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
{
        if (ctx == NULL) {
                return;
        }
        if (ctx->aad != NULL) {
                cleanse(ctx->aad, ctx->aad_cap);
                free(ctx->aad);
        }
        cleanse(ctx, sizeof(*ctx));
        free(ctx);
}

static void apply_iv(EVP_CIPHER_CTX *ctx)
{
        if (ctx->key_set && ctx->iv_pending) {
                if (ctx->hook == NULL) {
                        br_gcm_reset(&ctx->gcm, ctx->iv, ctx->iv_len);
                }
                ctx->iv_pending = 0;
                ctx->iv_set = 1;
                reset_message(ctx);
        }
}

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
                      const unsigned char *key, const unsigned char *iv, int enc)
{
        (void)impl;
        if (ctx == NULL) {
                return 0;
        }
        if (cipher != NULL) {
                ctx->cipher = cipher;
                ctx->key_set = 0;
                ctx->iv_set = 0;
        }
        if (ctx->cipher == NULL) {
                return 0;
        }
        if (enc != -1) {
                ctx->enc = enc ? 1 : 0;
        }
        if (key != NULL) {
                size_t key_len = (size_t)ctx->cipher->key_bits / 8;

                ctx->hook = __atomic_load_n(&swiftsmb_gcm_hook, __ATOMIC_ACQUIRE);
                /* The hook takes the message in one piece, which needs a 12-byte IV. */
                if (ctx->iv_len != GCM_IV) {
                        ctx->hook = NULL;
                }
                memcpy(ctx->key_bytes, key, key_len);
                if (ctx->hook == NULL) {
                        if (ctx->cipher->key_bits == 128) {
                                ctx->ctr.vtable = &libsmb2_aes128_ctr_vtable;
                        } else {
                                ctx->ctr.vtable = &br_aes_ct64_ctr_vtable;
                        }
                        ctx->ctr.vtable->init(&ctx->ctr.vtable, key, key_len);
                        br_gcm_init(&ctx->gcm, &ctx->ctr.vtable, br_ghash_ctmul64);
                }
                ctx->key_set = 1;
                ctx->iv_set = 0;
                /* A key without a new IV reuses the last one, as OpenSSL does. */
                if (iv == NULL && ctx->iv_known) {
                        ctx->iv_pending = 1;
                }
        }
        if (iv != NULL) {
                memcpy(ctx->iv, iv, ctx->iv_len);
                ctx->iv_known = 1;
                ctx->iv_pending = 1;
        }
        apply_iv(ctx);
        return 1;
}

static int collect_aad(EVP_CIPHER_CTX *ctx, const unsigned char *in, size_t len)
{
        if (ctx->aad_len + len > ctx->aad_cap) {
                size_t cap = ctx->aad_len + len;
                unsigned char *aad = malloc(cap);

                if (aad == NULL) {
                        return 0;
                }
                if (ctx->aad != NULL) {
                        memcpy(aad, ctx->aad, ctx->aad_len);
                        cleanse(ctx->aad, ctx->aad_cap);
                        free(ctx->aad);
                }
                ctx->aad = aad;
                ctx->aad_cap = cap;
        }
        memcpy(ctx->aad + ctx->aad_len, in, len);
        ctx->aad_len += len;
        return 1;
}

int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl)
{
        if (ctx == NULL || outl == NULL || inl < 0 || !ctx->iv_set || ctx->finished) {
                return 0;
        }
        *outl = 0;
        if (inl == 0) {
                return 1;
        }
        if (in == NULL) {
                return 0;
        }
        if (out == NULL) {
                /* AAD. It must come before any data. */
                if (ctx->data_seen || ctx->flipped) {
                        return 0;
                }
                if (ctx->hook != NULL) {
                        if (!collect_aad(ctx, in, (size_t)inl)) {
                                return 0;
                        }
                } else {
                        br_gcm_aad_inject(&ctx->gcm, in, (size_t)inl);
                }
                *outl = inl;
                return 1;
        }
        /* Both implementations encrypt in place. */
        if (out != in) {
                memmove(out, in, (size_t)inl);
        }
        if (ctx->hook != NULL) {
                /* One piece of data only: the hook seals the message at once,
                 * in out, from EVP_CipherFinal_ex(). */
                if (ctx->data_seen) {
                        return 0;
                }
                ctx->data = out;
                ctx->data_len = (size_t)inl;
                ctx->data_seen = 1;
        } else {
                if (!ctx->flipped) {
                        br_gcm_flip(&ctx->gcm);
                        ctx->flipped = 1;
                }
                br_gcm_run(&ctx->gcm, ctx->enc, out, (size_t)inl);
        }
        *outl = inl;
        return 1;
}

int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
        (void)out;
        if (ctx == NULL || outl == NULL || !ctx->iv_set || ctx->finished) {
                return 0;
        }
        *outl = 0;
        ctx->finished = 1;
        if (!ctx->enc && ctx->tag_len == 0) {
                return 0;
        }
        if (ctx->hook != NULL) {
                unsigned char tag[GCM_BLOCK];

                /* The hook checks a full 16-byte tag. */
                if (!ctx->enc && ctx->tag_len != GCM_BLOCK) {
                        return 0;
                }
                if (!ctx->enc) {
                        memcpy(tag, ctx->tag, GCM_BLOCK);
                }
                if (ctx->hook(ctx->enc, ctx->key_bytes, (size_t)ctx->cipher->key_bits / 8,
                              ctx->iv, ctx->aad, ctx->aad_len,
                              ctx->data, ctx->data_len, tag) != 0) {
                        return 0;
                }
                if (ctx->enc) {
                        memcpy(ctx->tag, tag, GCM_BLOCK);
                        ctx->tag_len = GCM_BLOCK;
                }
                return 1;
        }
        if (!ctx->flipped) {
                br_gcm_flip(&ctx->gcm);
                ctx->flipped = 1;
        }
        if (ctx->enc) {
                br_gcm_get_tag(&ctx->gcm, ctx->tag);
                ctx->tag_len = GCM_BLOCK;
                return 1;
        }
        /* Constant time; 1 when the tag matches. */
        return (int)br_gcm_check_tag_trunc(&ctx->gcm, ctx->tag, ctx->tag_len);
}

int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
        if (ctx == NULL) {
                return 0;
        }
        switch (type) {
        case EVP_CTRL_AEAD_SET_IVLEN:
                if (arg <= 0 || arg > GCM_BLOCK || ctx->iv_set) {
                        return 0;
                }
                ctx->iv_len = (size_t)arg;
                return 1;
        case EVP_CTRL_AEAD_SET_TAG:
                if (ctx->enc || ptr == NULL || arg <= 0 || arg > GCM_BLOCK || ctx->finished) {
                        return 0;
                }
                memcpy(ctx->tag, ptr, (size_t)arg);
                ctx->tag_len = (size_t)arg;
                return 1;
        case EVP_CTRL_AEAD_GET_TAG:
                if (!ctx->enc || !ctx->finished || ptr == NULL || arg <= 0 ||
                    (size_t)arg > ctx->tag_len) {
                        return 0;
                }
                memcpy(ptr, ctx->tag, (size_t)arg);
                return 1;
        }
        return 0;
}
