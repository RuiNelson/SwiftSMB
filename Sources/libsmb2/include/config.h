/* Platform-specific libsmb2 configuration for Swift Package Manager builds. */

#if defined(__linux__)
#include "linux/config.h"
#elif defined(__APPLE__)
#include "../upstream/include/apple/config.h"
/* Upstream's apple/config.h leaves this out, so aes.c would fall back to the
 * table-based reference AES, which is not constant-time. CommonCrypto uses
 * the hardware AES instructions. It serves SMB3 encryption (AES-128-CCM)
 * and signing (AES-128-CMAC). */
#if __has_include(<CommonCrypto/CommonCryptor.h>)
#define HAVE_COMMONCRYPTO_COMMONCRYPTOR_H 1
#endif
#else
#error Unsupported platform
#endif
