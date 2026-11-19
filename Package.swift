// swift-tools-version: 6.4
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let includeIntegrationTests = Context.environment["SWIFTSMB_SKIP_INTEGRATION_TESTS"] == nil

var testTargets: [Target] = [
    .testTarget(
        name: "SwiftSMBUnitTests",
        dependencies: ["SwiftSMB"],
        path: "Tests/SwiftSMBUnitTests",
    ),
]

if includeIntegrationTests {
    testTargets.append(
        .testTarget(
            name: "SwiftSMBTests",
            dependencies: ["SwiftSMB", "SwiftSMBAVFoundation", "SwiftSMBEXIFKit"],
            path: "Tests/SwiftSMBTests",
        )
    )
}

// Opt-in trait for the EXIFKit integration. While it is disabled, SwiftPM neither resolves nor fetches EXIFKit, and
// the SwiftSMBEXIFKit module is empty.
let exifKitTrait = "EXIFKit"

let package = Package(
    name: "SwiftSMB",
    platforms: [
        .macOS(.v11),
        .iOS(.v14),
        .visionOS(.v1),
        .watchOS(.v7),
        .tvOS(.v14),
        .macCatalyst(.v14),
        .custom("android", versionString: "28"),
    ],
    products: [
        .library(
            name: "SwiftSMB",
            targets: ["SwiftSMB"],
        ),
        .library(
            name: "SwiftSMBAVFoundation",
            targets: ["SwiftSMBAVFoundation"],
        ),
        .library(
            name: "SwiftSMBEXIFKit",
            targets: ["SwiftSMBEXIFKit"],
        ),
        .library(
            name: "libsmb2",
            type: .dynamic,
            targets: ["libsmb2"],
        ),
    ],
    traits: [
        .trait(
            name: exifKitTrait,
            description: "Adds EXIF metadata access over SMB to the SwiftSMBEXIFKit product, through EXIFKit.",
        ),
        // Disabled by default, so consumers of the core products never resolve EXIFKit.
        .default(enabledTraits: []),
    ],
    dependencies: [
        .package(url: "https://github.com/RuiNelson/PathWorks.git", .upToNextMajor(from: "2.0.1")),
        .package(url: "https://github.com/RuiNelson/EXIFKit.git", .upToNextMajor(from: "0.4.0")),
    ],
    targets: [
        .target(
            name: "libsmb2",
            // libsmb2 is our fork, RuiNelson/libsmb2-SwiftSMB, in Vendored/libsmb2-SwiftSMB (its MODS.md lists what
            // it changes). The SwiftPM glue (configuration selector, module map, header forwarders) lives in
            // Sources/libsmb2, so the target spans the package root, as SwiftSFTP's libssh2 target does.
            path: ".",
            exclude: [
                "Vendored/libsmb2-SwiftSMB/lib/CMakeLists.txt",
                "Vendored/libsmb2-SwiftSMB/lib/libsmb2.syms",
                "Vendored/libsmb2-SwiftSMB/lib/Makefile.am",
                "Vendored/libsmb2-SwiftSMB/lib/Makefile.AMIGA",
                "Vendored/libsmb2-SwiftSMB/lib/Makefile.AMIGA_AROS",
                "Vendored/libsmb2-SwiftSMB/lib/Makefile.AMIGA_OS3",
                "Vendored/libsmb2-SwiftSMB/lib/Makefile.PS3_PPU",
                "Vendored/libsmb2-SwiftSMB/lib/dreamcast",
                "Vendored/libsmb2-SwiftSMB/lib/ps2",
                // BearSSL's own files, which lib/bearssl/bearssl_*.c compile with renamed symbols.
                "Vendored/libsmb2-SwiftSMB/lib/bearssl/upstream",
                "Vendored/libsmb2-SwiftSMB/lib/bearssl/UPSTREAM.md",
            ],
            sources: [
                "Vendored/libsmb2-SwiftSMB/lib",
                "Sources/libsmb2/xcode_compat.c",
            ],
            publicHeadersPath: "Sources/libsmb2/include",
            cSettings: [
                // Sources/libsmb2/include comes first, so its config.h, the configuration selector, is the one
                // libsmb2's "config.h" finds. BearSSL's inner.h finds its own config.h next to itself.
                .headerSearchPath("Sources/libsmb2/include"),
                .headerSearchPath("Vendored/libsmb2-SwiftSMB/include/smb2"),
                .headerSearchPath("Vendored/libsmb2-SwiftSMB/lib"),
                .headerSearchPath("Vendored/libsmb2-SwiftSMB/lib/bearssl/upstream/inc"),
                .headerSearchPath("Vendored/libsmb2-SwiftSMB/lib/bearssl/upstream/src"),
                .define("_U_", to: "__attribute__((unused))"),
                .define("HAVE_CONFIG_H", to: "1"),
                // AES-128-GCM and AES-256-GCM without OpenSSL (the fork's MODS.md M4). On the command line rather than
                // in config.h, because the BearSSL wrappers must not include config.h.
                .define("HAVE_BUILTIN_AES_GCM", to: "1"),
                .disableWarning("conversion")
            ],
        ),
        .target(
            name: "SwiftSMB",
            dependencies: [
                "libsmb2",
                .product(name: "PathWorks", package: "PathWorks"),
            ],
        ),
        .target(
            name: "SwiftSMBAVFoundation",
            dependencies: [
                "SwiftSMB",
                .product(name: "PathWorks", package: "PathWorks"),
            ],
        ),
        .target(
            name: "SwiftSMBEXIFKit",
            dependencies: [
                "SwiftSMB",
                .product(name: "EXIFKit", package: "EXIFKit", condition: .when(traits: [exifKitTrait])),
                .product(name: "PathWorks", package: "PathWorks"),
            ],
        ),
    ] + testTargets,
)
