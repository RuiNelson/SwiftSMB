//
// Part of SwiftSMB
// LibraryVersion.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

public extension SMB {
    /// A semantic version of the libsmb2 C library that SwiftSMB is built on.
    struct LibraryVersion: Comparable, Hashable, CustomStringConvertible, CustomDebugStringConvertible, Sendable {
        /// The major version.
        public let major: Int

        /// The minor version.
        public let minor: Int

        /// The patch version.
        public let patch: Int

        /// Creates a version from its components.
        public init(major: Int, minor: Int, patch: Int) {
            self.major = major
            self.minor = minor
            self.patch = patch
        }

        init(_ bridgeValue: Bridge.LibraryVersion) {
            self.init(major: Int(bridgeValue.major), minor: Int(bridgeValue.minor), patch: Int(bridgeValue.patch))
        }

        public static func < (lhs: LibraryVersion, rhs: LibraryVersion) -> Bool {
            (lhs.major, lhs.minor, lhs.patch) < (rhs.major, rhs.minor, rhs.patch)
        }

        /// The version as `major.minor.patch`.
        public var description: String {
            "\(major).\(minor).\(patch)"
        }

        public var debugDescription: String {
            "SMB.LibraryVersion(\(description))"
        }
    }

    /// The version of the libsmb2 library linked into this process, for diagnostics and bug reports.
    static let libsmb2Version = LibraryVersion(Bridge.libraryVersion())
}
