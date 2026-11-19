/* libsmb2 configuration for Swift Package Manager builds: the fork's own
 * configuration for the platform (Vendored/libsmb2-SwiftSMB/MODS.md M1, M5). */

#if defined(__linux__)
#include "../../../Vendored/libsmb2-SwiftSMB/include/linux/config.h"
#elif defined(__APPLE__)
#include "../../../Vendored/libsmb2-SwiftSMB/include/apple/config.h"
#else
#error Unsupported platform
#endif
