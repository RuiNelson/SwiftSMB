//
// Part of SwiftSMB
// SMBValues.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation

public extension SMB {
    /// A share advertised by an SMB server.
    struct Share: Equatable, Hashable, CustomDebugStringConvertible, Sendable {
        /// The resource kind behind a share.
        public enum Kind: Equatable, Hashable, CustomDebugStringConvertible, Sendable {
            /// A disk-backed file share.
            case diskTree

            /// A print queue share.
            case printQueue

            /// A device share.
            case device

            /// An IPC share.
            case ipc

            /// An unrecognized share kind.
            case unknown(UInt32)

            /// Creates a public share kind from a bridge value.
            init(_ bridgeValue: SMB2ShareKind) {
                switch bridgeValue {
                case .diskTree:
                    self = .diskTree
                case .printQueue:
                    self = .printQueue
                case .device:
                    self = .device
                case .ipc:
                    self = .ipc
                case let .unknown(rawValue):
                    self = .unknown(rawValue)
                }
            }

            public var debugDescription: String {
                switch self {
                case .diskTree: "SMB.Share.Kind.diskTree"
                case .printQueue: "SMB.Share.Kind.printQueue"
                case .device: "SMB.Share.Kind.device"
                case .ipc: "SMB.Share.Kind.ipc"
                case let .unknown(rawValue): "SMB.Share.Kind.unknown(\(hex(rawValue)))"
                }
            }
        }

        /// Attributes attached to a share.
        public struct Attributes: OptionSet, Equatable, Hashable, CustomDebugStringConvertible, Sendable {
            /// The raw share attributes bitfield.
            public let rawValue: UInt32

            /// The share is temporary.
            public static let temporary = Attributes(rawValue: SMB2ShareAttributes.temporary.rawValue)

            /// The share is hidden.
            public static let hidden = Attributes(rawValue: SMB2ShareAttributes.hidden.rawValue)

            /// Creates share attributes from a raw bitfield.
            public init(rawValue: UInt32) {
                self.rawValue = rawValue
            }

            public var debugDescription: String {
                describeFlags([
                    (.temporary, "temporary"),
                    (.hidden, "hidden"),
                ], typeName: "SMB.Share.Attributes")
            }
        }

        /// The share name.
        public let name: String

        /// The share kind, when detailed enumeration returned one.
        public let kind: Kind?

        /// The share attributes.
        public let attributes: Attributes

        /// A server-provided share description.
        public let remark: String?

        /// A Boolean value indicating whether the share is hidden.
        public var isHidden: Bool {
            attributes.contains(.hidden)
        }

        /// A Boolean value indicating whether the share is temporary.
        public var isTemporary: Bool {
            attributes.contains(.temporary)
        }

        /// Creates a share value.
        ///
        /// - Parameters:
        ///   - name: The share name.
        ///   - kind: The share kind.
        ///   - attributes: Share attributes.
        ///   - remark: A server-provided share description.
        public init(name: String, kind: Kind?, attributes: Attributes = [], remark: String? = nil) {
            self.name = name
            self.kind = kind
            self.attributes = attributes
            self.remark = remark
        }

        /// Creates a public share value from a bridge value.
        init(_ bridgeValue: SMB2Share) {
            name = bridgeValue.name
            kind = bridgeValue.kind.map(Kind.init)
            attributes = Attributes(rawValue: bridgeValue.attributes.rawValue)
            remark = bridgeValue.remark
        }

        public var debugDescription: String {
            "SMB.Share(name: \(name), kind: \(String(describing: kind)), attributes: \(attributes.debugDescription), remark: \(String(describing: remark)))"
        }
    }

    /// The kind of filesystem node represented by a path or directory entry.
    enum NodeType: Equatable, CustomDebugStringConvertible, Sendable {
        /// A regular file.
        case file

        /// A directory.
        case directory

        /// A symbolic link.
        case link

        /// An unrecognized node type.
        case unknown(UInt32)

        /// Creates a public node type from a bridge value.
        init(_ bridgeValue: SMB2NodeType) {
            switch bridgeValue {
            case .file:
                self = .file
            case .directory:
                self = .directory
            case .link:
                self = .link
            case let .unknown(rawValue):
                self = .unknown(rawValue)
            }
        }

        public var debugDescription: String {
            switch self {
            case .file: "SMB.NodeType.file"
            case .directory: "SMB.NodeType.directory"
            case .link: "SMB.NodeType.link"
            case let .unknown(rawValue): "SMB.NodeType.unknown(\(hex(rawValue)))"
            }
        }
    }

    /// Metadata for a file, directory, or link.
    struct Stat: Equatable, CustomDebugStringConvertible, Sendable {
        /// The node type.
        public let type: NodeType

        /// The number of hard links.
        public let linkCount: UInt32

        /// The server-provided inode value.
        public let inode: UInt64

        /// The node size, in bytes.
        public let size: UInt64

        /// The access time, in seconds since the Unix epoch.
        public let accessTimeSeconds: UInt64

        /// Nanoseconds component for ``accessTime``.
        public let accessTimeNanoseconds: UInt64

        /// The modification time, in seconds since the Unix epoch.
        public let modificationTimeSeconds: UInt64

        /// Nanoseconds component for ``modificationTime``.
        public let modificationTimeNanoseconds: UInt64

        /// The metadata change time, in seconds since the Unix epoch.
        public let changeTimeSeconds: UInt64

        /// Nanoseconds component for ``changeTime``.
        public let changeTimeNanoseconds: UInt64

        /// The creation time, in seconds since the Unix epoch.
        public let birthTimeSeconds: UInt64

        /// Nanoseconds component for ``birthTime``.
        public let birthTimeNanoseconds: UInt64
        
        /// The time the file was last accessed.
        public var accessTime: Date {
            Date(seconds: accessTimeSeconds, nanoseconds: accessTimeNanoseconds)
        }

        /// The time the file was last modified.
        public var modificationTime: Date {
            Date(seconds: modificationTimeSeconds, nanoseconds: modificationTimeNanoseconds)
        }

        /// The time the file's metadata was last changed.
        public var changeTime: Date {
            Date(seconds: changeTimeSeconds, nanoseconds: changeTimeNanoseconds)
        }

        /// The time the file was created.
        public var birthTime: Date {
            Date(seconds: birthTimeSeconds, nanoseconds: birthTimeNanoseconds)
        }

        /// Creates a public stat value from a bridge value.
        init(_ bridgeValue: SMB2Stat) {
            type = NodeType(bridgeValue.type)
            linkCount = bridgeValue.linkCount
            inode = bridgeValue.inode
            size = bridgeValue.size
            accessTimeSeconds = bridgeValue.accessTime
            accessTimeNanoseconds = bridgeValue.accessTimeNanoseconds
            modificationTimeSeconds = bridgeValue.modificationTime
            modificationTimeNanoseconds = bridgeValue.modificationTimeNanoseconds
            changeTimeSeconds = bridgeValue.changeTime
            changeTimeNanoseconds = bridgeValue.changeTimeNanoseconds
            birthTimeSeconds = bridgeValue.birthTime
            birthTimeNanoseconds = bridgeValue.birthTimeNanoseconds
        }

        public var debugDescription: String {
            "SMB.Stat(type: \(type.debugDescription), size: \(size), inode: \(inode), linkCount: \(linkCount))"
        }
    }

    /// Filesystem statistics for a share path.
    struct FilesystemStat: Equatable, CustomDebugStringConvertible, Sendable {
        /// The preferred block size for filesystem operations.
        public let blockSize: UInt32

        /// The fundamental filesystem fragment size.
        public let fragmentSize: UInt32

        /// The total number of blocks.
        public let blocks: UInt64

        /// The number of free blocks.
        public let freeBlocks: UInt64

        /// The number of blocks available to the current user.
        public let availableBlocks: UInt64

        /// The total file node count.
        public let fileCount: UInt32

        /// The number of free file nodes.
        public let freeFileCount: UInt32

        /// The number of file nodes available to the current user.
        public let availableFileCount: UInt32

        /// The filesystem identifier.
        public let filesystemID: UInt32

        /// Filesystem flags returned by the server.
        public let flags: UInt32

        /// The maximum supported file name length.
        public let maximumNameLength: UInt32

        /// Creates a public filesystem stat value from a bridge value.
        init(_ bridgeValue: SMB2StatVFS) {
            blockSize = bridgeValue.blockSize
            fragmentSize = bridgeValue.fragmentSize
            blocks = bridgeValue.blocks
            freeBlocks = bridgeValue.freeBlocks
            availableBlocks = bridgeValue.availableBlocks
            fileCount = bridgeValue.fileCount
            freeFileCount = bridgeValue.freeFileCount
            availableFileCount = bridgeValue.availableFileCount
            filesystemID = bridgeValue.filesystemID
            flags = bridgeValue.flags
            maximumNameLength = bridgeValue.maximumNameLength
        }

        public var debugDescription: String {
            "SMB.FilesystemStat(blockSize: \(blockSize), fragmentSize: \(fragmentSize), blocks: \(blocks), freeBlocks: \(freeBlocks), availableBlocks: \(availableBlocks), fileCount: \(fileCount), freeFileCount: \(freeFileCount), availableFileCount: \(availableFileCount), filesystemID: \(filesystemID), flags: \(flags), maximumNameLength: \(maximumNameLength))"
        }
    }

    /// An entry returned while reading an SMB directory.
    struct DirectoryEntry: Equatable, CustomDebugStringConvertible, Sendable {
        /// The entry name.
        public let name: String

        /// Metadata for the entry.
        public let stat: Stat

        /// Creates a public directory entry from a bridge value.
        init(_ bridgeValue: SMB2DirectoryEntry) {
            name = bridgeValue.name
            stat = Stat(bridgeValue.stat)
        }

        public var debugDescription: String {
            "SMB.DirectoryEntry(name: \(name), stat: \(stat.debugDescription))"
        }
    }

    /// Components parsed from an SMB URL.
    struct ParsedURL: Equatable, CustomDebugStringConvertible, Sendable {
        /// The domain component, if present.
        public let domain: String?

        /// The user component, if present.
        public let user: String?

        /// The server component.
        public let server: String

        /// The share component.
        public let share: String

        /// The path component, relative to the share root.
        public let path: String?

        /// Creates a public parsed URL value from a bridge value.
        init(_ bridgeValue: SMB2URL) {
            domain = bridgeValue.domain
            user = bridgeValue.user
            server = bridgeValue.server
            share = bridgeValue.share
            path = bridgeValue.path
        }

        public var debugDescription: String {
            "SMB.ParsedURL(domain: \(String(describing: domain)), user: \(String(describing: user)), server: \(server), share: \(share), path: \(String(describing: path)))"
        }
    }
}
