#!/bin/zsh

# Runs the test suite under AddressSanitizer (macOS).
#
# SwiftPM does not link the ASan runtime into the dynamic `libsmb2` product, so pass it to the linker explicitly.
# Extra arguments are forwarded to `swift test`, for example `zsh asan.sh --filter SMBNotify`.

set -e

runtime=$(xcrun clang -print-file-name=libclang_rt.asan_osx_dynamic.dylib)
swift test --sanitize=address -Xlinker "$runtime" -Xlinker -rpath -Xlinker "${runtime:h}" "$@"
