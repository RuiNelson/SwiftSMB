/*
   SwiftSMB: symbol names for the BearSSL code in Sources/libsmb2/gcm/bearssl.

   Every BearSSL function and table compiled into libsmb2 gets a swiftsmb_
   prefix, so it never collides with, or binds to, another BearSSL in the same
   process. The bearssl_*.c wrappers and evp_gcm.c include this header before
   any BearSSL header. When a BearSSL update adds a global symbol to these
   files, add it here: nm on the objects must show no br_ symbol.

   This file is distributed under the same license as libsmb2, the GNU
   Lesser General Public License, version 2.1 or later.
*/
#ifndef SWIFTSMB_BEARSSL_H
#define SWIFTSMB_BEARSSL_H

/* src/aead/gcm.c */
#define br_gcm_init swiftsmb_br_gcm_init
#define br_gcm_reset swiftsmb_br_gcm_reset
#define br_gcm_aad_inject swiftsmb_br_gcm_aad_inject
#define br_gcm_flip swiftsmb_br_gcm_flip
#define br_gcm_run swiftsmb_br_gcm_run
#define br_gcm_get_tag swiftsmb_br_gcm_get_tag
#define br_gcm_get_tag_trunc swiftsmb_br_gcm_get_tag_trunc
#define br_gcm_check_tag swiftsmb_br_gcm_check_tag
#define br_gcm_check_tag_trunc swiftsmb_br_gcm_check_tag_trunc
#define br_gcm_vtable swiftsmb_br_gcm_vtable

/* src/hash/ghash_ctmul64.c */
#define br_ghash_ctmul64 swiftsmb_br_ghash_ctmul64

/* src/symcipher/aes_ct64.c, aes_ct64_enc.c, aes_ct64_ctr.c */
#define br_aes_ct64_bitslice_Sbox swiftsmb_br_aes_ct64_bitslice_Sbox
#define br_aes_ct64_bitslice_encrypt swiftsmb_br_aes_ct64_bitslice_encrypt
#define br_aes_ct64_ortho swiftsmb_br_aes_ct64_ortho
#define br_aes_ct64_interleave_in swiftsmb_br_aes_ct64_interleave_in
#define br_aes_ct64_interleave_out swiftsmb_br_aes_ct64_interleave_out
#define br_aes_ct64_keysched swiftsmb_br_aes_ct64_keysched
#define br_aes_ct64_skey_expand swiftsmb_br_aes_ct64_skey_expand
#define br_aes_ct64_ctr_init swiftsmb_br_aes_ct64_ctr_init
#define br_aes_ct64_ctr_run swiftsmb_br_aes_ct64_ctr_run
#define br_aes_ct64_ctr_vtable swiftsmb_br_aes_ct64_ctr_vtable

/* src/codec/enc32le.c, dec32le.c */
#define br_range_enc32le swiftsmb_br_range_enc32le
#define br_range_dec32le swiftsmb_br_range_dec32le

#endif
