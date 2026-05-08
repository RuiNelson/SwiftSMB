//
// Part of SwiftSMB
// SMBError-InvalidArgument.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation

public extension SMB.Error {
    /// The operation that encountered an invalid argument.
    enum InvalidArgumentOperation: Equatable, Sendable {
        case smb2ConnectShare
        case smb2ParseURL
        case smb2SetTimeout
        case smb2Read
        case smb2Pread
        case smb2Write
        case smb2Pwrite
        case smb2Lseek
        case smb2Fsync
        case smb2Ftruncate
        case smb2Fstat
        case smb2Close
        case smb2Closedir
        case smb2Open
        case smb2Opendir
        case smb2Mkdir
        case smb2Rmdir
        case smb2Unlink
        case smb2Rename
        case smb2Truncate
        case smb2Readlink
        case smb2Readdir
        case smb2Rewinddir
        case smb2Telldir
        case smb2Seekdir
        case smb2Stat
        case smb2Statvfs
        case smb2GetDialect
        case smb2GetSessionID
        case smb2GetMaxReadSize
        case smb2GetMaxWriteSize
        case smb2Echo
        case smb2CmdChangeNotifyAsync
        case smb2DecodeFileNotifyChangeInformation
        case smb2GetFileID
        case smb2ShareEnumSync
        case smbConnectionWriteFromPipeToFile
        case smbConnectionReadFromFileToPipe
        case smbConnectionDownloadFile
        case smbConnectionUploadFile
        case smbConnectionPipeBlockSize
        case smbConnectionRemoveItem
        case smbConnectionListDirectory
        case smbConnectionReadFile
        case smbConnectionWriteFile
        case smbConnectionMakeDirectory

        var description: String {
            switch self {
            case .smb2ConnectShare: "smb2_connect_share"
            case .smb2ParseURL: "smb2_parse_url"
            case .smb2SetTimeout: "smb2_set_timeout"
            case .smb2Read: "smb2_read"
            case .smb2Pread: "smb2_pread"
            case .smb2Write: "smb2_write"
            case .smb2Pwrite: "smb2_pwrite"
            case .smb2Lseek: "smb2_lseek"
            case .smb2Fsync: "smb2_fsync"
            case .smb2Ftruncate: "smb2_ftruncate"
            case .smb2Fstat: "smb2_fstat"
            case .smb2Close: "smb2_close"
            case .smb2Closedir: "smb2_closedir"
            case .smb2Open: "smb2_open"
            case .smb2Opendir: "smb2_opendir"
            case .smb2Mkdir: "smb2_mkdir"
            case .smb2Rmdir: "smb2_rmdir"
            case .smb2Unlink: "smb2_unlink"
            case .smb2Rename: "smb2_rename"
            case .smb2Truncate: "smb2_truncate"
            case .smb2Readlink: "smb2_readlink"
            case .smb2Readdir: "smb2_readdir"
            case .smb2Rewinddir: "smb2_rewinddir"
            case .smb2Telldir: "smb2_telldir"
            case .smb2Seekdir: "smb2_seekdir"
            case .smb2Stat: "smb2_stat"
            case .smb2Statvfs: "smb2_statvfs"
            case .smb2GetDialect: "smb2_get_dialect"
            case .smb2GetSessionID: "smb2_get_session_id"
            case .smb2GetMaxReadSize: "smb2_get_max_read_size"
            case .smb2GetMaxWriteSize: "smb2_get_max_write_size"
            case .smb2Echo: "smb2_echo"
            case .smb2CmdChangeNotifyAsync: "smb2_cmd_change_notify_async"
            case .smb2DecodeFileNotifyChangeInformation: "smb2_decode_filenotifychangeinformation"
            case .smb2GetFileID: "smb2_get_file_id"
            case .smb2ShareEnumSync: "smb2_share_enum_sync"
            case .smbConnectionWriteFromPipeToFile: "SMB.Connection.write(fromPipe:toFile:)"
            case .smbConnectionReadFromFileToPipe: "SMB.Connection.read(fromFile:toPipe:)"
            case .smbConnectionDownloadFile: "SMB.Connection.downloadFile"
            case .smbConnectionUploadFile: "SMB.Connection.uploadFile"
            case .smbConnectionPipeBlockSize: "SMB.Connection.pipeBlockSize"
            case .smbConnectionRemoveItem: "SMB.Connection.removeItem"
            case .smbConnectionListDirectory: "SMB.Connection.listDirectory"
            case .smbConnectionReadFile: "SMB.Connection.readFile"
            case .smbConnectionWriteFile: "SMB.Connection.writeFile"
            case .smbConnectionMakeDirectory: "SMB.Connection.makeDirectory"
            }
        }
    }

    /// The reason an invalid argument was encountered.
    enum InvalidArgumentException: Equatable, Sendable {
        case invalidShareName(String)
        case shareNameMustBeSingleComponent
        case pathMustNotBeEmpty
        case pathMustContainAtLeastOneComponent
        case invalidPathComponent(String)
        case timeoutMustFitInInt32Seconds
        case byteCountMustBeNonNegative
        case fileAlreadyClosed
        case connectionAlreadyClosed
        case directoryAlreadyClosed
        case bufferSizeMustBeGreaterThanZero
        case blockSizeMustBeGreaterThanZero
        case serverMaximumBlockSizeMustBeGreaterThanZero
        case blockSizeMustBePositiveAndFitInInt
        case remotePathIsNotAFile
        case remoteFileShorterThanResumeOffset
        case remoteParentDirectoryDoesNotExist
        case remoteParentPathIsNotADirectory
        case remoteDestinationIsNotAFile
        case pipeDataMustBeginWithStartPackage
        case localFileShorterThanResumeOffset
        case offsetBeyondEndOfLocalFile
        case unableToDetermineLocalFileSize
        case byteCountCannotBeRepresentedAsUInt32(Int)
        case directoryFileHandleMissingFileID
        case failedToAllocateFileNotifyChangeInformation
        case unsupportedShareEnumerationLevel(UInt32)

        var description: String {
            switch self {
            case let .invalidShareName(share): "Invalid share name '\(share)'"
            case .shareNameMustBeSingleComponent: "Share name must be a single component"
            case .pathMustNotBeEmpty: "Path must not be empty"
            case .pathMustContainAtLeastOneComponent: "Path must contain at least one component"
            case let .invalidPathComponent(component): "Invalid path component '\(component)'"
            case .timeoutMustFitInInt32Seconds: "Timeout must fit in Int32 seconds"
            case .byteCountMustBeNonNegative: "Byte count must be greater than or equal to zero"
            case .fileAlreadyClosed: "File is already closed"
            case .connectionAlreadyClosed: "Connection is already closed"
            case .directoryAlreadyClosed: "Directory is already closed"
            case .bufferSizeMustBeGreaterThanZero: "Buffer size must be greater than zero"
            case .blockSizeMustBeGreaterThanZero: "Block size must be greater than zero"
            case .serverMaximumBlockSizeMustBeGreaterThanZero: "Server maximum block size must be greater than zero"
            case .blockSizeMustBePositiveAndFitInInt: "Block size must be greater than zero and fit in Int"
            case .remotePathIsNotAFile: "Remote path is not a file"
            case .remoteFileShorterThanResumeOffset: "Remote file is shorter than the requested resume offset"
            case .remoteParentDirectoryDoesNotExist: "Remote parent directory does not exist"
            case .remoteParentPathIsNotADirectory: "Remote parent path exists and is not a directory"
            case .remoteDestinationIsNotAFile: "Remote destination is not a file"
            case .pipeDataMustBeginWithStartPackage: "Pipe data must begin with a start package"
            case .localFileShorterThanResumeOffset: "Local file is shorter than the requested resume offset"
            case .offsetBeyondEndOfLocalFile: "Offset is beyond the end of the local file"
            case .unableToDetermineLocalFileSize: "Unable to determine local file size"
            case let .byteCountCannotBeRepresentedAsUInt32(count): "Byte count \(count) cannot be represented as UInt32"
            case .directoryFileHandleMissingFileID: "Directory file handle does not have a file id"
            case .failedToAllocateFileNotifyChangeInformation: "Failed to allocate file notify change information"
            case let .unsupportedShareEnumerationLevel(level): "Unsupported share enumeration level \(level)"
            }
        }
    }
}
