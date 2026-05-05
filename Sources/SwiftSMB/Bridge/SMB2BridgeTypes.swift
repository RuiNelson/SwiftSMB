//
//  SMB2BridgeTypes.swift
//
//  Part of SwiftSMB.
//   Licensed under LGPL v2.1
//

import Darwin
import SMB2

struct SMB2Context {
    let raw: UnsafeMutablePointer<smb2_context>
}

struct SMB2FileHandle {
    let raw: OpaquePointer
}

enum SMB2AuthenticationMethod: Equatable {
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

struct SMB2SecurityMode: OptionSet, Equatable {
    let rawValue: UInt16

    static let signingEnabled = SMB2SecurityMode(rawValue: UInt16(SMB2_NEGOTIATE_SIGNING_ENABLED))
    static let signingRequired = SMB2SecurityMode(rawValue: UInt16(SMB2_NEGOTIATE_SIGNING_REQUIRED))
}

enum SMB2OpenAccessMode: Equatable {
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

struct SMB2OpenOptions: OptionSet, Equatable {
    let rawValue: Int32

    static let synchronous = SMB2OpenOptions(rawValue: O_SYNC)
    static let create = SMB2OpenOptions(rawValue: O_CREAT)
    static let exclusive = SMB2OpenOptions(rawValue: O_EXCL)
}

struct SMB2OpenFlags: Equatable {
    let accessMode: SMB2OpenAccessMode
    let options: SMB2OpenOptions

    init(
        _ accessMode: SMB2OpenAccessMode = .readOnly,
        options: SMB2OpenOptions = [],
    ) {
        self.accessMode = accessMode
        self.options = options
    }

    var rawValue: Int32 {
        accessMode.rawValue | options.rawValue
    }
}

struct SMB2DirectoryHandle {
    let raw: UnsafeMutablePointer<smb2dir>
}

enum SMB2ShareEnumerationLevel: Equatable {
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

enum SMB2ShareKind: Equatable, Hashable {
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

struct SMB2ShareAttributes: OptionSet, Equatable, Hashable {
    let rawValue: UInt32

    static let temporary = SMB2ShareAttributes(rawValue: UInt32(SHARE_TYPE_TEMPORARY))
    static let hidden = SMB2ShareAttributes(rawValue: UInt32(SHARE_TYPE_HIDDEN))

    init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    init(rawShareType: UInt32) {
        rawValue = rawShareType & (Self.temporary.rawValue | Self.hidden.rawValue)
    }
}

struct SMB2Share: Equatable, Hashable {
    let name: String
    let kind: SMB2ShareKind?
    let attributes: SMB2ShareAttributes
    let remark: String?

    var isHidden: Bool {
        attributes.contains(.hidden)
    }

    var isTemporary: Bool {
        attributes.contains(.temporary)
    }
}

enum SMB2NodeType: Equatable {
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

struct SMB2Stat: Equatable {
    let type: SMB2NodeType
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
        type = SMB2NodeType(rawValue: stat.smb2_type)
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

struct SMB2StatVFS: Equatable {
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

struct SMB2DirectoryEntry: Equatable {
    let name: String
    let stat: SMB2Stat

    init(_ entry: smb2dirent) {
        name = entry.name.map(String.init(cString:)) ?? ""
        stat = SMB2Stat(entry.st)
    }
}

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
