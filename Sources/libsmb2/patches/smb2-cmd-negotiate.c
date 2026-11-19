/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   SwiftSMB wrapper for upstream lib/smb2-cmd-negotiate.c: AES-GCM without OpenSSL.

   libsmb2 builds AES-128-GCM and AES-256-GCM only when HAVE_OPENSSL is
   defined. Defining it for the whole target would also move AES-CCM and the
   signing code onto OpenSSL, so it is defined for this file alone, and
   smb3-seal.c and smb2-cmd-negotiate.c are the two files that need it: the
   first seals with GCM through <openssl/evp.h>, the second offers and
   accepts the GCM ciphers. Sources/libsmb2/gcm answers <openssl/evp.h> with
   a small EVP shim of ours over BearSSL's GCM; no OpenSSL code is involved.

   This file is distributed under the same license as libsmb2, the GNU
   Lesser General Public License, version 2.1 or later.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_OPENSSL
#define HAVE_OPENSSL 1
#endif

#include "../upstream/lib/smb2-cmd-negotiate.c"
