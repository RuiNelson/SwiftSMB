//
// Part of SwiftSMB
// CachedStat.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

public extension SMB {
    /// A stat answered by an ``SMB/BlockLevelReadCache``.
    enum CachedStat: Equatable, CustomDebugStringConvertible, Sendable {
        /// An entry exists at the path, with this metadata.
        case exists(Stat)

        /// Nothing exists at the path.
        case doesNotExist

        public var debugDescription: String {
            switch self {
            case let .exists(stat): "SMB.CachedStat.exists(\(stat.debugDescription))"
            case .doesNotExist: "SMB.CachedStat.doesNotExist"
            }
        }
    }
}
