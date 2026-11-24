/* config.h for Windows builds without a configure step, such as Swift Package Manager builds.
 *
 * Same role as the fork's include/linux/config.h and include/apple/config.h (Vendored/libsmb2-SwiftSMB/MODS.md M5),
 * but kept in SwiftSMB's own glue until it can move into the fork with a MODS.md entry. The Swift compiler's C importer
 * reads this file too (it is the first header of the SMB2 module), so what libsmb2's headers key on must be defined
 * here and not only on the command line. */

/* libsmb2's own Windows switch (lib/compat.h, include/smb2/libsmb2.h). The Swift toolchain's clang defines _WIN32
 * only, and libsmb2 keys on _WINDOWS, which MSVC project files define. */
#ifndef _WINDOWS
#define _WINDOWS 1
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS 1
#endif

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#endif

/* The CRT has no O_SYNC or O_DIRECTORY. libsmb2 tests for both (lib/libsmb2.c), and SwiftSMB passes them to smb2_open
 * (Bridge.OpenFlagValues), so both sides read these. The values avoid every flag of the CRT's <fcntl.h>
 * (0x0 to 0x40000). Without O_DIRECTORY, smb2_notify_change_async would open its directory as a file. */
#ifndef O_SYNC
#define O_SYNC 0x100000
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0x200000
#endif

/* Whether or not TCP sockets should be allowed to linger after closure */
#define CONFIGURE_OPTION_TCP_LINGER 1
#define HAVE_LINGER 1

#define HAVE_ERRNO_H 1
#define HAVE_FCNTL_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_SOCKADDR_STORAGE 1
#define HAVE_STDINT_H 1
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_TIME_H 1

/* Cryptographically strong source for smb2_random_bytes(), which provides the NTLMv2 client challenge, the SMB 3.1.1
 * preauth salt, the client GUID and the nonce of every sealed PDU. Without one it falls back to random(), which
 * libsmb2 maps to rand() here: predictable. lib/init.c uses arc4random_buf() when this is defined, and
 * windows_compat.c provides it over BCryptGenRandom. */
#include <stddef.h>
void arc4random_buf(void *buf, size_t len);
#define HAVE_ARC4RANDOM_BUF 1

#define PACKAGE "libsmb2"
#define PACKAGE_BUGREPORT "ronniesahlberg@gmail.com"
#define PACKAGE_NAME "libsmb2"
#define PACKAGE_STRING "libsmb2 4.0.0"
#define PACKAGE_TARNAME "libsmb2"
#define PACKAGE_URL ""
#define PACKAGE_VERSION "4.0.0"
#define STDC_HEADERS 1
#define VERSION "4.0.0"
