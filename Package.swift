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
            dependencies: ["SwiftSMB"],
            path: "Tests/SwiftSMBTests",
        )
    )
}

let package = Package(
    name: "SwiftSMB",
    platforms: [
        .macOS("10.15.4"),
        .iOS("13.4"),
        .macCatalyst("13.4"),
        .tvOS("13.4"),
        .visionOS(.v1),
        .watchOS("6.2"),
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
        .package(url: "https://github.com/RuiNelson/PathWorks.git", from: "2.0.1"),
    ],
    targets: [
        .target(
            name: "libsmb2",
            path: "Sources/libsmb2",
            exclude: [
                "upstream/lib/CMakeLists.txt",
                "upstream/lib/libsmb2-dcerpc-full.syms",
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
                "xcode_compat.c",
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include"),
                .headerSearchPath("upstream/include/smb2"),
                .headerSearchPath("upstream/lib"),
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
    ] + testTargets,
)
