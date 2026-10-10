/* Platform-specific libsmb2 configuration for Swift Package Manager builds. */

#if defined(__linux__)
#include "linux/config.h"
#elif defined(__APPLE__)
#include "../upstream/include/apple/config.h"
#else
#error Unsupported platform
#endif
