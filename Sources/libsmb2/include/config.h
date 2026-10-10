/* Platform-specific libsmb2 configuration for Swift Package Manager builds. */

#if defined(__linux__)
#include "linux/config.h"
#elif defined(__APPLE__)
#include "../upstream/include/apple/config.h"
#else
#error Unsupported platform
#endif

/* Missing prototype: libdcerpc/dcerpc-srvsvc.c calls dcerpc_pdu_direction (renamed by
 * libsmb2-dcerpc-prefix.h) without declaring it. Every libsmb2 .c file includes config.h first. */
struct dcerpc_pdu;
int libsmb2_dcerpc_pdu_direction(struct dcerpc_pdu *pdu);
