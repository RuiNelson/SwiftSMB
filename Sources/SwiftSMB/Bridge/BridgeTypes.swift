//
// Part of SwiftSMB
// BridgeTypes.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(Android)
    import Android
#endif
import Foundation
import SMB2

extension Bridge {
    /// A libsmb2 context and the serial queue that owns it.
    ///
    /// libsmb2 contexts are not safe to service concurrently, so once a context is shared every call that touches `raw`
    /// runs on `queue` (see ``Bridge/perform(on:_:)``). Different contexts run in parallel.
    final class Context: @unchecked Sendable {
        let raw: UnsafeMutablePointer<smb2_context>

        /// The serial queue that owns `raw`.
        let queue = DispatchQueue(label: "com.ruinelson.SwiftSMB.bridge.context")

        /// Whether `raw` has not been destroyed yet. Mutated on `queue`, and safe to observe from public handles.
        private let protectedLiveness = Protected(true, label: "com.ruinelson.SwiftSMB.bridge.context.liveness")
        var isAlive: Bool {
            get { protectedLiveness.current }
            set { protectedLiveness.current = newValue }
        }

        /// Whether the context is being shut down. Set before the shutdown is enqueued, so that a request waiting on
        /// the server, such as a blocking lock, is withdrawn instead of holding the shutdown back. Never cleared.
        private let protectedIsClosing = Protected(false, label: "com.ruinelson.SwiftSMB.bridge.context.closing")
        var isClosing: Bool {
            protectedIsClosing.current
        }

        /// Marks the context as being shut down.
        func markClosing() {
            protectedIsClosing.current = true
        }

        /// Open local C allocations owned by this context. Confined to `queue`.
        var fileHandles: [ObjectIdentifier: FileHandle] = [:]
        var directoryHandles: [ObjectIdentifier: DirectoryHandle] = [:]

        /// Receives the oplock and lease breaks the server sends. Confined to `queue`.
        var opLockBreakHandler: OpLockBreakHandler?

        init(raw: UnsafeMutablePointer<smb2_context>) {
            self.raw = raw
        }

        // The `smb2_context` fields libsmb2 has no accessor for. Like `raw`, they are confined to `queue`.

        /// The command timeout, in seconds; `0` means none.
        var commandTimeoutSeconds: Int32 {
            raw.pointee.timeout
        }

        /// The signing negotiation flags configured with `smb2_set_security_mode`.
        var configuredSecurityMode: SecurityMode {
            SecurityMode(rawValue: raw.pointee.security_mode)
        }

        /// Clears the last error string, so a later failure is not reported with it.
        func clearErrorString() {
            withUnsafeMutableBytes(of: &raw.pointee.error_string) { $0[0] = 0 }
        }

        /// Clears the last error string and NT status, which libsmb2 keeps until another failure overwrites them.
        func clearError() {
            raw.pointee.nterror = 0
            clearErrorString()
        }
    }

    /// A file handle whose liveness is confined to its context queue.
    final class FileHandle: @unchecked Sendable {
        private var raw: OpaquePointer?
        let appendsWrites: Bool

        init(raw: OpaquePointer, appendsWrites: Bool = false) {
            self.raw = raw
            self.appendsWrites = appendsWrites
        }

        func requireRaw(operation: SMB.Error.InvalidArgumentOperation) throws -> OpaquePointer {
            guard let raw else {
                throw SMB.Error.invalidArgument(cause: .fileAlreadyClosed, onOperation: operation)
            }
            return raw
        }

        /// Marks the handle closed before its C storage can be freed. Must run on the context queue.
        func takeRaw() -> OpaquePointer? {
            defer { raw = nil }
            return raw
        }
    }

    struct FileID: Hashable, Sendable {
        var raw: smb2_file_id

        static let allOnes = FileID((
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF
        ))

        init(_ raw: smb2_file_id) {
            self.raw = raw
        }

        static func == (lhs: FileID, rhs: FileID) -> Bool {
            withUnsafeBytes(of: lhs.raw) { lhsBytes in
                withUnsafeBytes(of: rhs.raw) { rhsBytes in
                    lhsBytes.elementsEqual(rhsBytes)
                }
            }
        }

        func hash(into hasher: inout Hasher) {
            withUnsafeBytes(of: raw) { hasher.combine(bytes: $0) }
        }
    }

    enum AuthenticationMethod: Equatable, Sendable {
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

    struct SecurityMode: OptionSet, Equatable, Sendable {
        let rawValue: UInt16

        static let signingEnabled = SecurityMode(rawValue: UInt16(SMB2_NEGOTIATE_SIGNING_ENABLED))
        static let signingRequired = SecurityMode(rawValue: UInt16(SMB2_NEGOTIATE_SIGNING_REQUIRED))
    }

    enum OpenAccessMode: Equatable, Sendable {
        case readOnly
        case writeOnly
        case readWrite

        var rawValue: Int32 {
            switch self {
            case .readOnly:
                OpenFlagValues.readOnly
            case .writeOnly:
                OpenFlagValues.writeOnly
            case .readWrite:
                OpenFlagValues.readWrite
            }
        }
    }

    struct OpenOptions: OptionSet, Equatable, Sendable {
        let rawValue: Int32

        static let synchronous = OpenOptions(rawValue: OpenFlagValues.synchronous)
        static let create = OpenOptions(rawValue: OpenFlagValues.create)
        static let exclusive = OpenOptions(rawValue: OpenFlagValues.exclusive)
        static let truncate = OpenOptions(rawValue: OpenFlagValues.truncate)
        static let append = OpenOptions(rawValue: OpenFlagValues.append)
        static let directory = OpenOptions(rawValue: OpenFlagValues.directory)
    }

    struct OpenFlags: Equatable, Sendable {
        let accessMode: OpenAccessMode
        let options: OpenOptions

        init(
            _ accessMode: OpenAccessMode = .readOnly,
            options: OpenOptions = []
        ) {
            self.accessMode = accessMode
            self.options = options
        }

        var rawValue: Int32 {
            accessMode.rawValue | options.rawValue
        }
    }

    /// How a server-side copy opens its destination.
    enum CopyDestination: Equatable, Sendable {
        /// Creates the destination and fails with `STATUS_OBJECT_NAME_COLLISION` if it exists (`FILE_CREATE`). The copy
        /// owns the file, so giving it up removes it.
        case createNew
        /// Truncates an existing destination and fails with `STATUS_OBJECT_NAME_NOT_FOUND` if there is none
        /// (`FILE_OVERWRITE`), so it never creates a file it would not own.
        case replaceExisting

        var openOptions: OpenOptions {
            switch self {
            case .createNew: [.create, .exclusive]
            case .replaceExisting: [.truncate]
            }
        }
    }

    /// The dialects a context offers when it negotiates (`smb2_negotiate_version`).
    enum DialectPreference: Equatable, Sendable {
        case any
        case anySMB2
        case anySMB3
        case smb2_02
        case smb2_10
        case smb3_00
        case smb3_02
        case smb3_11

        var rawValue: smb2_negotiate_version {
            switch self {
            case .any: SMB2_VERSION_ANY
            case .anySMB2: SMB2_VERSION_ANY2
            case .anySMB3: SMB2_VERSION_ANY3
            case .smb2_02: SMB2_VERSION_0202
            case .smb2_10: SMB2_VERSION_0210
            case .smb3_00: SMB2_VERSION_0300
            case .smb3_02: SMB2_VERSION_0302
            case .smb3_11: SMB2_VERSION_0311
            }
        }
    }

    /// The dialect revision a context negotiated (MS-SMB2 2.2.4 `DialectRevision`), `0` before it connects.
    struct DialectRevision: RawRepresentable, Hashable, Sendable {
        let rawValue: UInt16

        static let smb2_02 = DialectRevision(rawValue: UInt16(SMB2_VERSION_0202.rawValue))
        static let smb2_10 = DialectRevision(rawValue: UInt16(SMB2_VERSION_0210.rawValue))
        static let smb3_00 = DialectRevision(rawValue: UInt16(SMB2_VERSION_0300.rawValue))
        static let smb3_02 = DialectRevision(rawValue: UInt16(SMB2_VERSION_0302.rawValue))
        static let smb3_11 = DialectRevision(rawValue: UInt16(SMB2_VERSION_0311.rawValue))

        /// Whether this is an SMB 3 dialect.
        var isSMB3: Bool {
            rawValue >= Self.smb3_00.rawValue
        }
    }

    /// Windows file attributes (MS-FSCC 2.6), as the server reports them.
    struct FileAttributes: OptionSet, Hashable, Sendable {
        let rawValue: UInt32

        static let readOnly = FileAttributes(rawValue: 0x0000_0001)
        static let hidden = FileAttributes(rawValue: 0x0000_0002)
        static let system = FileAttributes(rawValue: 0x0000_0004)
        static let directory = FileAttributes(rawValue: 0x0000_0010)
        static let archive = FileAttributes(rawValue: 0x0000_0020)
        static let normal = FileAttributes(rawValue: 0x0000_0080)
        static let reparsePoint = FileAttributes(rawValue: 0x0000_0400)
    }

    /// A timestamp for `smb2_set_basic_info`, in the `smb2_timeval` form libsmb2 takes.
    struct BasicInfoTime: Sendable {
        /// The timestamp as libsmb2 takes it.
        let timeval: smb2_timeval

        /// Leaves the timestamp unchanged.
        ///
        /// libsmb2 treats `tv_sec == 0xffffffff && tv_usec == 0xffffffff` as "leave unchanged". C converts both sides
        /// to the wider type, so the fields must hold 4294967295 when they are 64-bit and -1 (the same bits) when they
        /// are 32-bit, as on arm64_32.
        static let unchanged = BasicInfoTime(timeval: smb2_timeval(
            tv_sec: time_t(truncatingIfNeeded: UInt32.max),
            tv_usec: CLong(truncatingIfNeeded: UInt32.max)
        ))

        private init(timeval: smb2_timeval) {
            self.timeval = timeval
        }

        /// Converts a date without trapping; `nil` leaves the timestamp unchanged.
        ///
        /// - Throws: ``SMB/Error/posix(code:operation:message:)`` with `EINVAL` if the date is not finite or is outside
        /// what an SMB file time can hold.
        init(date: Date?) throws {
            guard let date else {
                self = .unchanged
                return
            }
            let interval = date.timeIntervalSince1970
            let maximumInterval = Double(UInt64.max) / 10_000_000 - 11_644_473_600
            guard interval.isFinite,
                  interval > -11_644_473_600,
                  interval < maximumInterval,
                  let seconds = time_t(exactly: interval.rounded(.down)) else {
                throw SMB.Error.posix(
                    code: POSIXErrorCode.EINVAL.rawValue,
                    operation: "smb2_set_basic_info",
                    message: "Timestamp cannot be represented as an SMB file time"
                )
            }
            let microseconds = CLong((interval - Double(seconds)) * 1_000_000)
            if seconds == 0, microseconds == 0 {
                // libsmb2 interprets an all-zero timeval as "leave unchanged". An equivalent nonzero representation
                // allows an explicit Unix epoch timestamp to be written instead of silently skipping it.
                timeval = smb2_timeval(tv_sec: -1, tv_usec: 1_000_000)
                return
            }
            timeval = smb2_timeval(tv_sec: seconds, tv_usec: microseconds)
        }
    }

    enum OpLockLevel: UInt8, Equatable, Sendable {
        case none = 0x00
        case levelII = 0x01
        case exclusive = 0x08
        case batch = 0x09
        case lease = 0xFF
    }

    struct LeaseState: OptionSet, Equatable, Sendable {
        let rawValue: UInt32

        static let readCaching = LeaseState(rawValue: 0x01)
        static let handleCaching = LeaseState(rawValue: 0x02)
        static let writeCaching = LeaseState(rawValue: 0x04)
    }

    /// A directory handle whose liveness is confined to its context queue.
    final class DirectoryHandle: @unchecked Sendable {
        private var raw: UnsafeMutablePointer<smb2dir>?

        init(raw: UnsafeMutablePointer<smb2dir>) {
            self.raw = raw
        }

        func requireRaw(operation: SMB.Error.InvalidArgumentOperation) throws -> UnsafeMutablePointer<smb2dir> {
            guard let raw else {
                throw SMB.Error.invalidArgument(cause: .directoryAlreadyClosed, onOperation: operation)
            }
            return raw
        }

        /// Marks the handle closed before its C storage can be freed. Must run on the context queue.
        func takeRaw() -> UnsafeMutablePointer<smb2dir>? {
            defer { raw = nil }
            return raw
        }
    }

    enum ShareEnumerationLevel: Equatable, Sendable {
        case namesOnly
        case detailed
        case full

        var rawValue: smb2_share_info_level {
            switch self {
            case .namesOnly:
                SMB2_SHARE_INFO_0
            case .detailed:
                SMB2_SHARE_INFO_1
            case .full:
                SMB2_SHARE_INFO_2
            }
        }
    }

    enum ShareKind: Equatable, Hashable, Sendable {
        case diskTree
        case printQueue
        case device
        case ipc
        case unknown(UInt32)

        init(rawValue: UInt32) {
            switch rawValue & 0x0000_0003 {
            case UInt32(SMB2_SHARE_TYPE_DISKTREE):
                self = .diskTree
            case UInt32(SMB2_SHARE_TYPE_PRINTQ):
                self = .printQueue
            case UInt32(SMB2_SHARE_TYPE_DEVICE):
                self = .device
            case UInt32(SMB2_SHARE_TYPE_IPC):
                self = .ipc
            default:
                self = .unknown(rawValue & 0x0000_0003)
            }
        }
    }

    struct ShareAttributes: OptionSet, Equatable, Hashable, Sendable {
        let rawValue: UInt32

        static let temporary = ShareAttributes(rawValue: UInt32(SMB2_SHARE_TYPE_TEMPORARY))
        static let hidden = ShareAttributes(rawValue: UInt32(SMB2_SHARE_TYPE_HIDDEN))

        init(rawValue: UInt32) {
            self.rawValue = rawValue
        }

        init(rawShareType: UInt32) {
            rawValue = rawShareType & (Self.temporary.rawValue | Self.hidden.rawValue)
        }
    }

    struct Share: Equatable, Hashable, Sendable {
        let name: String
        let kind: ShareKind?
        let attributes: ShareAttributes
        let remark: String?

        /// The share's path on the server. Only reported by `.full` enumeration.
        let path: String?

        /// The raw `shi2_permissions` bitfield. Only reported by `.full` enumeration.
        let permissions: UInt32?

        /// The limit on concurrent users, `nil` when the share has none. Only reported by `.full` enumeration.
        let maximumUsers: UInt32?

        /// The number of current users. Only reported by `.full` enumeration.
        let currentUsers: UInt32?

        init(
            name: String,
            kind: ShareKind?,
            attributes: ShareAttributes,
            remark: String?,
            path: String? = nil,
            permissions: UInt32? = nil,
            maximumUsers: UInt32? = nil,
            currentUsers: UInt32? = nil
        ) {
            self.name = name
            self.kind = kind
            self.attributes = attributes
            self.remark = remark
            self.path = path
            self.permissions = permissions
            self.maximumUsers = maximumUsers
            self.currentUsers = currentUsers
        }

        var isHidden: Bool {
            attributes.contains(.hidden)
        }

        var isTemporary: Bool {
            attributes.contains(.temporary)
        }
    }

    struct SecurityIdentifier: Equatable, Sendable {
        let revision: UInt8
        let identifierAuthority: UInt64
        let subauthorities: [UInt32]
    }

    struct AccessControlEntry: Equatable, Sendable {
        let kind: UInt8
        let flags: UInt8
        let accessMask: UInt32
        let trustee: SecurityIdentifier
    }

    struct AccessControlList: Equatable, Sendable {
        let revision: UInt8
        let entries: [AccessControlEntry]
    }

    struct SecurityDescriptor: Equatable, Sendable {
        let owner: SecurityIdentifier?
        let group: SecurityIdentifier?
        let discretionaryAccessControlList: AccessControlList?
    }

    enum NodeType: Equatable, Sendable {
        case file
        case directory
        case link
        case fifo
        case characterDevice
        case blockDevice
        case socket
        case unknown(UInt32)

        init(rawValue: UInt32) {
            switch rawValue {
            case UInt32(SMB2_TYPE_FILE):
                self = .file
            case UInt32(SMB2_TYPE_DIRECTORY):
                self = .directory
            case UInt32(SMB2_TYPE_LINK):
                self = .link
            case UInt32(SMB2_TYPE_FIFO):
                self = .fifo
            case UInt32(SMB2_TYPE_CHARDEV):
                self = .characterDevice
            case UInt32(SMB2_TYPE_BLOCKDEV):
                self = .blockDevice
            case UInt32(SMB2_TYPE_SOCKET):
                self = .socket
            default:
                self = .unknown(rawValue)
            }
        }
    }

    /// The version of the libsmb2 library linked into the process, from `smb2_get_libsmb2Version`.
    struct LibraryVersion: Equatable, Sendable {
        let major: UInt8
        let minor: UInt8
        let patch: UInt8

        init(_ version: smb2_libversion) {
            major = version.major_version
            minor = version.minor_version
            patch = version.patch_version
        }
    }

    /// A `smb2_stat_64`. Since libsmb2 7.0.0 the seconds fields hold a signed `time_t` (negative before 1970) in their
    /// `uint64_t` storage, so they are read back as `Int64` bit patterns.
    struct Stat: Equatable, Sendable {
        let type: NodeType
        let linkCount: UInt32
        let inode: UInt64
        let size: UInt64
        let accessTime: Int64
        let accessTimeNanoseconds: UInt64
        let modificationTime: Int64
        let modificationTimeNanoseconds: UInt64
        let changeTime: Int64
        let changeTimeNanoseconds: UInt64
        let birthTime: Int64
        let birthTimeNanoseconds: UInt64
        let attributes: FileAttributes
        let reparseTag: UInt32

        init(_ stat: smb2_stat_64) {
            type = NodeType(rawValue: stat.smb2_type)
            linkCount = stat.smb2_nlink
            inode = stat.smb2_ino
            size = stat.smb2_size
            accessTime = Int64(bitPattern: stat.smb2_atime)
            accessTimeNanoseconds = stat.smb2_atime_nsec
            modificationTime = Int64(bitPattern: stat.smb2_mtime)
            modificationTimeNanoseconds = stat.smb2_mtime_nsec
            changeTime = Int64(bitPattern: stat.smb2_ctime)
            changeTimeNanoseconds = stat.smb2_ctime_nsec
            birthTime = Int64(bitPattern: stat.smb2_btime)
            birthTimeNanoseconds = stat.smb2_btime_nsec
            attributes = FileAttributes(rawValue: stat.smb2_attributes)
            reparseTag = stat.smb2_reparse_tag
        }
    }

    struct VFSStat: Equatable, Sendable {
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

    struct DirectoryEntry: Equatable, Sendable {
        let name: String
        let stat: Stat

        init(_ entry: smb2dirent) {
            name = entry.name.map(String.init(cString:)) ?? ""
            stat = Stat(entry.st)
        }
    }

    struct NotifyChangeFlags: OptionSet, Equatable, Sendable {
        let rawValue: UInt16

        static let watchTree = NotifyChangeFlags(rawValue: UInt16(SMB2_CHANGE_NOTIFY_WATCH_TREE))
    }

    struct NotifyChangeFilter: OptionSet, Equatable, Sendable {
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

    enum NotifyChangeAction: Equatable, Sendable {
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

    struct NotifyChange: Equatable, Sendable {
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
    }

    typealias NotifyChangeHandler = @Sendable (Result<[NotifyChange], SMB.Error>) -> Void

    struct SMB2URL: Equatable, Sendable {
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

    struct PendingRequest: Sendable {
        let state: PendingRequestState

        /// The request's MessageId, used to withdraw it with an SMB2 CANCEL.
        let messageID: UInt64
    }

    final class PendingRequestState: @unchecked Sendable {
        let operation: String
        let handler: NotifyChangeHandler

        private let lock = NSLock()
        private var isFinished = false

        init(
            operation: String,
            handler: @escaping NotifyChangeHandler
        ) {
            self.operation = operation
            self.handler = handler
        }

        /// Marks the request cancelled, so that its eventual completion does not call `handler`.
        ///
        /// - Returns: Whether the request had not completed yet.
        @discardableResult
        func cancel() -> Bool {
            lock.lock()
            defer { lock.unlock() }

            let wasPending = !isFinished
            isFinished = true
            return wasPending
        }

        /// Marks the request completed and returns `handler`, or `nil` if it was already cancelled or completed.
        func complete() -> NotifyChangeHandler? {
            lock.lock()
            defer { lock.unlock() }

            guard !isFinished else {
                return nil
            }

            isFinished = true
            return handler
        }
    }
}
