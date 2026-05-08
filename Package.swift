// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftSMB",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .macCatalyst(.v13),
        .tvOS(.v13),
        .visionOS(.v1),
        .watchOS(.v6),
    ],
    products: [
        .library(
            name: "SwiftSMB",
            targets: ["SwiftSMB"],
        ),
        .library(
            name: "libsmb2",
            type: .dynamic,
            targets: ["libsmb2"],
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/RuiNelson/PathWorks.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-collections.git", from: "1.1.0"),
    ],
    targets: [
        .target(
            name: "libsmb2",
            path: "libsmb2",
            exclude: [
                "lib/CMakeLists.txt",
                "lib/libsmb2.syms",
                "lib/Makefile.am",
                "lib/Makefile.AMIGA",
                "lib/Makefile.AMIGA_AROS",
                "lib/Makefile.AMIGA_OS3",
                "lib/Makefile.PS3_PPU",
                "lib/dreamcast",
                "lib/ps2",
            ],
            sources: [
                "lib",
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include"),
                .headerSearchPath("include/apple"),
                .headerSearchPath("include/smb2"),
                .headerSearchPath("lib"),
                .define("_U_", to: "__attribute__((unused))"),
                .define("HAVE_CONFIG_H", to: "1"),
            ],
        ),
        .target(
            name: "SwiftSMB",
            dependencies: [
                "libsmb2",
                .product(name: "PathWorks", package: "PathWorks"),
                .product(name: "Collections", package: "swift-collections"),
            ],
        ),
        .testTarget(
            name: "SwiftSMBTests",
            dependencies: ["SwiftSMB"],
        ),
    ],
)
