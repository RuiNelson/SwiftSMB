//
// Part of SwiftSMB
// CacheFileID.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

public extension SMB {
    /// Identifies one file whose bytes a cache keeps in a ``SMB/CacheStorage``.
    ///
    /// A cache makes a new identifier for every file it starts tracking, and another one when it tracks the file at the
    /// same path again later. Identifiers are unique within the process, so caches can share one storage. They are not
    /// stable across launches: a storage that persists bytes cannot use them to find those bytes again in a later run.
    struct CacheFileID: Hashable, CustomStringConvertible, CustomDebugStringConvertible, Sendable {
        private let value: UInt64

        /// Creates an identifier that no other identifier created in this process shares.
        public init() {
            value = Self.counter.next()
        }

        public var description: String {
            "CacheFileID(\(value))"
        }

        public var debugDescription: String {
            "SMB.CacheFileID(\(value))"
        }

        private static let counter = ProcessUniqueCounter(label: "com.ruinelson.SwiftSMB.SMB.CacheFileID.counter")
    }
}
