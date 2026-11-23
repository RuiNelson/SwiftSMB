/* Windows support for libsmb2 builds that use SwiftSMB's windows-config.h (it declares arc4random_buf). Empty elsewhere. */

#if defined(_WIN32)

#include <stdlib.h>
#include <stddef.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <windows.h>
#include <bcrypt.h>

#ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#endif

/* The system's preferred random number generator, as arc4random_buf() is on the platforms that have it: it does not
 * report a failure, so one ends the process rather than letting a predictable value reach a nonce or a challenge. */
void arc4random_buf(void *buf, size_t len)
{
        unsigned char *p = (unsigned char *)buf;

        while (len > 0) {
                ULONG chunk = len > 0x40000000u ? 0x40000000u : (ULONG)len;

                if (BCryptGenRandom(NULL, p, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
                        abort();
                }
                p += chunk;
                len -= chunk;
        }
}

#else

/* ISO C forbids an empty translation unit. */
typedef int swiftsmb_windows_compat_unused;

#endif
