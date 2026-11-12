//
// Part of SwiftSMB
// CacheRequestID.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

public extension SMB {
    /// Identifies one request an ``SMB/Connection`` makes of its ``SMB/BlockLevelReadCache``: a lookup, the store that
    /// may follow it, and the ``SMB/BlockLevelReadCache/requestEnded(_:)`` that closes it.
    ///
    /// The connection makes a new identifier for every request. A cache uses it only to tell requests apart.
    struct CacheRequestID: Hashable, CustomDebugStringConvertible, Sendable {
        private let value: UInt64

        /// Creates an identifier that no other identifier created in this process shares.
        public init() {
            value = Self.counter.next()
        }

        public var debugDescription: String {
            "SMB.CacheRequestID(\(value))"
        }

        private static let counter = ProcessUniqueCounter(label: "com.ruinelson.SwiftSMB.SMB.CacheRequestID.counter")
    }
}
