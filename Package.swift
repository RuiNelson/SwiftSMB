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
            path: "Sources/libsmb2",
            exclude: [
                // Replaced by the files of the same name in patches/, which include them.
                "upstream/lib/aes.c",
                "upstream/lib/aes128ccm.c",
                "upstream/lib/smb2-cmd-negotiate.c",
                "upstream/lib/smb3-seal.c",
                // BearSSL's files are compiled through the gcm/bearssl_*.c wrappers, which rename their symbols.
                "gcm/bearssl",
                "gcm/UPSTREAM.md",
                "upstream/lib/CMakeLists.txt",
                "upstream/lib/libsmb2.syms",
                "upstream/lib/Makefile.am",
                "upstream/lib/Makefile.AMIGA",
                "upstream/lib/Makefile.AMIGA_AROS",
                "upstream/lib/Makefile.AMIGA_OS3",
                "upstream/lib/Makefile.PS3_PPU",
                "upstream/lib/dreamcast",
                "upstream/lib/ps2",
            ],
            sources: [
                "upstream/lib",
                "patches",
                "gcm",
                "xcode_compat.c",
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include"),
                .headerSearchPath("upstream/include/smb2"),
                .headerSearchPath("upstream/lib"),
                // AES-GCM (see gcm/UPSTREAM.md): <openssl/evp.h> for patches/smb3-seal.c, then BearSSL's headers. Keep
                // these after "include", so libsmb2's "config.h" wins over BearSSL's src/config.h.
                .headerSearchPath("gcm/include"),
                .headerSearchPath("gcm/bearssl/inc"),
                .headerSearchPath("gcm/bearssl/src"),
                .define("_U_", to: "__attribute__((unused))"),
                .define("HAVE_CONFIG_H", to: "1"),
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
