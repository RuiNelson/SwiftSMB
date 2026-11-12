//
// Part of SwiftSMB
// CacheBlockSource.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

public extension SMB {
    /// Where bytes handed to an ``SMB/BlockLevelReadCache`` came from, so the cache can decide whether and how to keep
    /// them.
    enum CacheBlockSource: Hashable, CustomDebugStringConvertible, Sendable {
        /// Downloaded from the server.
        case download

        /// Uploaded to the server and acknowledged by it.
        case upload

        public var debugDescription: String {
            switch self {
            case .download: "SMB.CacheBlockSource.download"
            case .upload: "SMB.CacheBlockSource.upload"
            }
        }
    }
}
