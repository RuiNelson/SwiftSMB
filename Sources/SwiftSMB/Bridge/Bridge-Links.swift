//
// Part of SwiftSMB
// Bridge-Links.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(Android)
    import Android
#endif
import Foundation
import SMB2
import SMB2.Raw

extension Bridge {
    // MARK: - Symbolic Links

    private final class ReadLinkState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished = false
        var destination: String?
    }

    private static let readLinkCallback: smb2_command_cb = { _, status, commandData, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<ReadLinkState>.fromOpaque(callbackData).takeUnretainedValue()
        if status == 0, let commandData {
            state.destination = String(cString: commandData.assumingMemoryBound(to: CChar.self))
        }
        state.finish(status)
    }

    private static func _readLink(
        context: Context,
        path: String,
        bufferSize: Int = 4096
    ) throws -> String {
        guard bufferSize > 0 else {
            throw SMB.Error.invalidArgument(
                cause: .bufferSizeMustBeGreaterThanZero,
                onOperation: .smb2Readlink
            )
        }

        _ = try bufferSize.asUInt32(operation: .smb2Readlink)
        let state = ReadLinkState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { releaseWhenFinished(state, callbackData) }
        let status = path.withCString { smb2_readlink_async(context.raw, $0, readLinkCallback, callbackData) }
        guard status == 0 else {
            state.finish(status)
            throw SMB.Error.fromBridge(context, operation: "smb2_readlink", status: status)
        }
        try serviceUntilFinished(context: context, state: state)
        try check(state.status, context: context, operation: "smb2_readlink")
        guard let destination = state.destination else {
            throw SMB.Error.unknown(operation: "smb2_readlink", message: "Server returned no link destination")
        }
        return String(decoding: destination.utf8.prefix(bufferSize), as: UTF8.self)
    }

    /// Reads the destination path of a symbolic link.
    static func readLink(
        context: Context,
        path: String,
        bufferSize: Int = 16384
    ) async throws -> String {
        try await perform(on: context) {
            try _readLink(context: context, path: path, bufferSize: bufferSize)
        }
    }

    private final class MakeLinkState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished = false
    }

    private static let makeLinkCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<MakeLinkState>.fromOpaque(callbackData).takeUnretainedValue()
        state.finish(status)
    }

    private static func _makeLink(
        context: Context,
        path: String,
        destination: String,
        isDirectory: Bool,
        isAbsolute: Bool
    ) throws {
        // The reparse data length is a 16-bit field holding 12 fixed bytes plus the substitute and print names, both
        // UTF-16. libsmb2 prefixes an absolute substitute name with `\??\` (4 more code units).
        let nameBytes = destination.utf16.count * 2
        guard 12 + 2 * nameBytes + 8 <= Int(UInt16.max) else {
            throw SMB.Error.posix(
                code: POSIXErrorCode.ENAMETOOLONG.rawValue,
                operation: "smb2_symlink",
                message: "Link destination is too long"
            )
        }

        var flags: UInt32 = 0
        if isDirectory {
            flags |= UInt32(SMB2_SYMLINK_DIRECTORY)
        }
        if isAbsolute {
            flags |= UInt32(SMB2_SYMLINK_ABSOLUTE)
        }

        let state = MakeLinkState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { releaseWhenFinished(state, callbackData) }
        let status = destination.withCString { targetPointer in
            path.withCString { linkPointer in
                smb2_symlink_async(context.raw, targetPointer, linkPointer, flags, makeLinkCallback, callbackData)
            }
        }
        guard status == 0 else {
            state.finish(status)
            throw SMB.Error.fromBridge(context, operation: "smb2_symlink", status: status)
        }
        try serviceUntilFinished(context: context, state: state)
        try check(state.status, context: context, operation: "smb2_symlink")
    }

    /// Creates a symbolic link at `path` pointing to `destination`.
    ///
    /// Windows symbolic links are typed: pass `isDirectory` when `destination` is a directory. A destination that
    /// starts with a drive letter or a path separator is taken as absolute, and `isAbsolute` forces it for any other.
    static func makeLink(
        context: Context,
        path: String,
        destination: String,
        isDirectory: Bool = false,
        isAbsolute: Bool = false
    ) async throws {
        try await perform(on: context) {
            try _makeLink(
                context: context,
                path: path,
                destination: destination,
                isDirectory: isDirectory,
                isAbsolute: isAbsolute
            )
        }
    }

    private static func _makeHardLink(
        context: Context,
        existingPath: String,
        newPath: String
    ) throws {
        let status = existingPath.withCString { existingPathPointer in
            newPath.withCString { newPathPointer in
                smb2_link(context.raw, existingPathPointer, newPathPointer)
            }
        }
        try check(status, context: context, operation: "smb2_link")
    }

    /// Creates a hard link at `newPath` pointing to `existingPath`.
    static func makeHardLink(
        context: Context,
        existingPath: String,
        newPath: String
    ) async throws {
        try await perform(on: context) {
            try _makeHardLink(context: context, existingPath: existingPath, newPath: newPath)
        }
    }
}
