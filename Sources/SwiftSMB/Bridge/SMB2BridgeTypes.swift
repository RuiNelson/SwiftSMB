//
// Part of SwiftSMB
// SMB2BridgeTypes.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SMB2

extension Bridge {
    struct Context {
        let raw: UnsafeMutablePointer<smb2_context>
    }

    struct FileHandle {
        let raw: OpaquePointer
    }

    enum AuthenticationMethod: Equatable {
        case automatic
        case ntlmssp
        case kerberos

        var rawValue: Int32 {
            switch self {
            case .automatic:
                Int32(SMB2_SEC_UNDEFINED.rawValue)
            case .ntlmssp:
                Int32(SMB2_SEC_NTLMSSP.rawValue)
            case .kerberos:
                Int32(SMB2_SEC_KRB5.rawValue)
            }
        }
    }

    struct SecurityMode: OptionSet, Equatable {
        let rawValue: UInt16

        static let signingEnabled = SecurityMode(rawValue: UInt16(SMB2_NEGOTIATE_SIGNING_ENABLED))
        static let signingRequired = SecurityMode(rawValue: UInt16(SMB2_NEGOTIATE_SIGNING_REQUIRED))
    }

    enum OpenAccessMode: Equatable {
        case readOnly
        case writeOnly
        case readWrite

        var rawValue: Int32 {
            switch self {
            case .readOnly:
                O_RDONLY
            case .writeOnly:
                O_WRONLY
            case .readWrite:
                O_RDWR
            }
        }
    }

    struct OpenOptions: OptionSet, Equatable {
        let rawValue: Int32

        static let synchronous = OpenOptions(rawValue: O_SYNC)
        static let create = OpenOptions(rawValue: O_CREAT)
        static let exclusive = OpenOptions(rawValue: O_EXCL)
        static let truncate = OpenOptions(rawValue: O_TRUNC)
        static let append = OpenOptions(rawValue: O_APPEND)
        static let directory = OpenOptions(rawValue: O_DIRECTORY)
    }

    struct OpenFlags: Equatable {
        let accessMode: OpenAccessMode
        let options: OpenOptions

        init(
            _ accessMode: OpenAccessMode = .readOnly,
            options: OpenOptions = [],
        ) {
            self.accessMode = accessMode
            self.options = options
        }

        var rawValue: Int32 {
            accessMode.rawValue | options.rawValue
        }
    }

    struct DirectoryHandle {
        let raw: UnsafeMutablePointer<smb2dir>
    }

    enum ShareEnumerationLevel: Equatable {
        case namesOnly
        case detailed

        var rawValue: SHARE_INFO_enum {
            switch self {
            case .namesOnly:
                SHARE_INFO_0
            case .detailed:
                SHARE_INFO_1
            }
        }
    }

    enum ShareKind: Equatable, Hashable {
        case diskTree
        case printQueue
        case device
        case ipc
        case unknown(UInt32)

        init(rawValue: UInt32) {
            switch rawValue & 0x0000_0003 {
            case UInt32(SHARE_TYPE_DISKTREE):
                self = .diskTree
            case UInt32(SHARE_TYPE_PRINTQ):
                self = .printQueue
            case UInt32(SHARE_TYPE_DEVICE):
                self = .device
            case UInt32(SHARE_TYPE_IPC):
                self = .ipc
            default:
                self = .unknown(rawValue & 0x0000_0003)
            }
        }
    }

    struct ShareAttributes: OptionSet, Equatable, Hashable {
        let rawValue: UInt32

        static let temporary = ShareAttributes(rawValue: UInt32(SHARE_TYPE_TEMPORARY))
        static let hidden = ShareAttributes(rawValue: UInt32(SHARE_TYPE_HIDDEN))

        init(rawValue: UInt32) {
            self.rawValue = rawValue
        }

        init(rawShareType: UInt32) {
            rawValue = rawShareType & (Self.temporary.rawValue | Self.hidden.rawValue)
        }
    }

    struct Share: Equatable, Hashable {
        let name: String
        let kind: ShareKind?
        let attributes: ShareAttributes
        let remark: String?

        var isHidden: Bool {
            attributes.contains(.hidden)
        }

        var isTemporary: Bool {
            attributes.contains(.temporary)
        }
    }

    enum NodeType: Equatable {
        case file
        case directory
        case link
        case unknown(UInt32)

        init(rawValue: UInt32) {
            switch rawValue {
            case UInt32(SMB2_TYPE_FILE):
                self = .file
            case UInt32(SMB2_TYPE_DIRECTORY):
                self = .directory
            case UInt32(SMB2_TYPE_LINK):
                self = .link
            default:
                self = .unknown(rawValue)
            }
        }
    }

    struct Stat: Equatable {
        let type: NodeType
        let linkCount: UInt32
        let inode: UInt64
        let size: UInt64
        let accessTime: UInt64
        let accessTimeNanoseconds: UInt64
        let modificationTime: UInt64
        let modificationTimeNanoseconds: UInt64
        let changeTime: UInt64
        let changeTimeNanoseconds: UInt64
        let birthTime: UInt64
        let birthTimeNanoseconds: UInt64

        init(_ stat: smb2_stat_64) {
            type = NodeType(rawValue: stat.smb2_type)
            linkCount = stat.smb2_nlink
            inode = stat.smb2_ino
            size = stat.smb2_size
            accessTime = stat.smb2_atime
            accessTimeNanoseconds = stat.smb2_atime_nsec
            modificationTime = stat.smb2_mtime
            modificationTimeNanoseconds = stat.smb2_mtime_nsec
            changeTime = stat.smb2_ctime
            changeTimeNanoseconds = stat.smb2_ctime_nsec
            birthTime = stat.smb2_btime
            birthTimeNanoseconds = stat.smb2_btime_nsec
        }
    }

    struct VFSStat: Equatable {
        let blockSize: UInt32
        let fragmentSize: UInt32
        let blocks: UInt64
        let freeBlocks: UInt64
        let availableBlocks: UInt64
        let fileCount: UInt32
        let freeFileCount: UInt32
        let availableFileCount: UInt32
        let filesystemID: UInt32
        let flags: UInt32
        let maximumNameLength: UInt32

        init(_ statvfs: smb2_statvfs) {
            blockSize = statvfs.f_bsize
            fragmentSize = statvfs.f_frsize
            blocks = statvfs.f_blocks
            freeBlocks = statvfs.f_bfree
            availableBlocks = statvfs.f_bavail
            fileCount = statvfs.f_files
            freeFileCount = statvfs.f_ffree
            availableFileCount = statvfs.f_favail
            filesystemID = statvfs.f_fsid
            flags = statvfs.f_flag
            maximumNameLength = statvfs.f_namemax
        }
    }

    struct DirectoryEntry: Equatable {
        let name: String
        let stat: Stat

        init(_ entry: smb2dirent) {
            name = entry.name.map(String.init(cString:)) ?? ""
            stat = Stat(entry.st)
        }
    }

    struct NotifyChangeFlags: OptionSet, Equatable {
        let rawValue: UInt16

        static let watchTree = NotifyChangeFlags(rawValue: UInt16(SMB2_CHANGE_NOTIFY_WATCH_TREE))
    }

    struct NotifyChangeFilter: OptionSet, Equatable {
        let rawValue: UInt32

        static let fileName = NotifyChangeFilter(rawValue: UInt32(SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME))
        static let directoryName =
            NotifyChangeFilter(rawValue: UInt32(SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_DIR_NAME))
        static let attributes =
            NotifyChangeFilter(rawValue: UInt32(SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_ATTRIBUTES))
        static let size = NotifyChangeFilter(rawValue: UInt32(SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_SIZE))
        static let lastWrite =
            NotifyChangeFilter(rawValue: UInt32(SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_LAST_WRITE))
        static let lastAccess =
            NotifyChangeFilter(rawValue: UInt32(SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_LAST_ACCESS))
        static let creation = NotifyChangeFilter(rawValue: UInt32(SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_CREATION))
        static let extendedAttributes =
            NotifyChangeFilter(rawValue: UInt32(SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_EA))
        static let security = NotifyChangeFilter(rawValue: UInt32(SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_SECURITY))
        static let streamName =
            NotifyChangeFilter(rawValue: UInt32(SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_STREAM_NAME))
        static let streamSize =
            NotifyChangeFilter(rawValue: UInt32(SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_STREAM_SIZE))
        static let streamWrite =
            NotifyChangeFilter(rawValue: UInt32(SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_STREAM_WRITE))

        static let all: NotifyChangeFilter = [
            .fileName,
            .directoryName,
            .attributes,
            .size,
            .lastWrite,
            .lastAccess,
            .creation,
            .extendedAttributes,
            .security,
            .streamName,
            .streamSize,
            .streamWrite,
        ]
    }

    enum NotifyChangeAction: Equatable {
        case added
        case removed
        case modified
        case renamedOldName
        case renamedNewName
        case addedStream
        case removedStream
        case modifiedStream
        case unknown(UInt32)

        init(rawValue: UInt32) {
            switch rawValue {
            case UInt32(SMB2_NOTIFY_CHANGE_FILE_ACTION_ADDED):
                self = .added
            case UInt32(SMB2_NOTIFY_CHANGE_FILE_ACTION_REMOVED):
                self = .removed
            case UInt32(SMB2_NOTIFY_CHANGE_FILE_ACTION_MODIFIED):
                self = .modified
            case UInt32(SMB2_NOTIFY_CHANGE_FILE_ACTION_RENAMED_OLD_NAME):
                self = .renamedOldName
            case UInt32(SMB2_NOTIFY_CHANGE_FILE_ACTION_RENAMED_NEW_NAME):
                self = .renamedNewName
            case UInt32(SMB2_NOTIFY_CHANGE_FILE_ACTION_ADDED_STREAM):
                self = .addedStream
            case UInt32(SMB2_NOTIFY_CHANGE_FILE_ACTION_REMOVED_STREAM):
                self = .removedStream
            case UInt32(SMB2_NOTIFY_CHANGE_FILE_ACTION_MODIFIED_STREAM):
                self = .modifiedStream
            default:
                self = .unknown(rawValue)
            }
        }
    }

    struct NotifyChange: Equatable {
        let action: NotifyChangeAction
        let name: String

        init(action: NotifyChangeAction, name: String) {
            self.action = action
            self.name = name
        }

        init(_ change: smb2_file_notify_change_information) {
            action = NotifyChangeAction(rawValue: change.action)
            name = change.name.map(String.init(cString:)) ?? ""
        }

        static func changes(from firstChange: UnsafeMutablePointer<smb2_file_notify_change_information>)
        -> [NotifyChange] {
            var changes: [NotifyChange] = []
            var change: UnsafeMutablePointer<smb2_file_notify_change_information>? = firstChange

            while let currentChange = change {
                changes.append(NotifyChange(currentChange.pointee))
                change = currentChange.pointee.next
            }

            return changes
        }
    }

    typealias NotifyChangeHandler = @Sendable (Result<[NotifyChange], SMB.Error>) -> Void

    struct SMB2URL: Equatable {
        let domain: String?
        let user: String?
        let server: String
        let share: String
        let path: String?

        init(_ url: smb2_url) {
            domain = url.domain.map(String.init(cString:))
            user = url.user.map(String.init(cString:))
            server = url.server.map(String.init(cString:)) ?? ""
            share = url.share.map(String.init(cString:)) ?? ""
            path = url.path.map(String.init(cString:))
        }
    }

    struct PendingRequest {
        let state: PendingRequestState
    }

    final class PendingRequestState: @unchecked Sendable {
        let operation: String
        let handler: NotifyChangeHandler

        private let lock = NSLock()
        private var raw: UnsafeMutablePointer<smb2_pdu>?
        private var callbackData: UnsafeMutableRawPointer?
        private var isFinished = false

        init(
            operation: String,
            handler: @escaping NotifyChangeHandler,
        ) {
            self.operation = operation
            self.handler = handler
        }

        func didCreateRequest(
            raw: UnsafeMutablePointer<smb2_pdu>,
            callbackData: UnsafeMutableRawPointer,
        ) {
            lock.lock()
            defer { lock.unlock() }

            self.raw = raw
            self.callbackData = callbackData
        }

        func cancel() -> (raw: UnsafeMutablePointer<smb2_pdu>, callbackData: UnsafeMutableRawPointer)? {
            lock.lock()
            defer { lock.unlock() }

            guard !isFinished, let raw, let callbackData else {
                return nil
            }

            isFinished = true
            self.raw = nil
            self.callbackData = nil

            return (raw, callbackData)
        }

        func complete() -> NotifyChangeHandler? {
            lock.lock()
            defer { lock.unlock() }

            guard !isFinished else {
                return nil
            }

            isFinished = true
            raw = nil
            callbackData = nil

            return handler
        }
    }
}
