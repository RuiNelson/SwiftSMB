//
// Part of SwiftSMB
// Bridge-Notifications.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SMB2
import SMB2.Raw

extension Bridge {
    // MARK: - Notify Operations

    private static let defaultNotifyOutputBufferLength: UInt32 = 0xFFFF
    private static let defaultNotifyServiceTimeoutMilliseconds: Int32 = 50
    private static let notifyChangeEntryHeaderLength = 12
    private static let maximumNotifyChangeEntryCount = 4096

    private static func _notifyChange(
        context: Context,
        directory: FileHandle,
        flags: NotifyChangeFlags = [],
        filter: NotifyChangeFilter = .all,
        handler: @escaping NotifyChangeHandler,
    ) throws -> PendingRequest {
        guard let fileID = smb2_get_file_id(directory.raw) else {
            throw SMB.Error.invalidArgument(
                cause: .directoryFileHandleMissingFileID,
                onOperation: .smb2GetFileID,
            )
        }

        var request = smb2_change_notify_request()
        request.flags = flags.rawValue
        request.output_buffer_length = defaultNotifyOutputBufferLength
        request.file_id = fileID.pointee
        request.completion_filter = filter.rawValue

        let state = PendingRequestState(
            operation: "smb2_cmd_change_notify_async",
            handler: handler,
        )
        let callbackData = Unmanaged.passRetained(state).toOpaque()

        guard let rawPDU = smb2_cmd_change_notify_async(
            context.raw,
            &request,
            notifyChangeCallback,
            callbackData,
        ) else {
            Unmanaged<PendingRequestState>.fromOpaque(callbackData).release()
            throw SMB.Error.fromBridge(context, operation: "smb2_cmd_change_notify_async")
        }

        state.didCreateRequest(raw: rawPDU, callbackData: callbackData)
        smb2_queue_pdu(context.raw, rawPDU)

        return PendingRequest(state: state)
    }

    /// Starts a one-shot cancellable change notification request for an open directory file handle.
    static func notifyChange(
        context: Context,
        directory: FileHandle,
        flags: NotifyChangeFlags = [],
        filter: NotifyChangeFilter = .all,
        handler: @escaping NotifyChangeHandler,
    ) throws -> PendingRequest {
        try Bridge.sync {
            try _notifyChange(context: context, directory: directory, flags: flags, filter: filter, handler: handler)
        }
    }

    private static func _cancel(context: Context, request: PendingRequest) {
        guard let cancellation = request.state.cancel() else {
            return
        }

        smb2_free_pdu(context.raw, cancellation.raw)
        Unmanaged<PendingRequestState>.fromOpaque(cancellation.callbackData).release()
    }

    /// Cancels a pending raw SMB2 request if it has not completed yet.
    static func cancel(context: Context, request: PendingRequest) {
        Bridge.sync {
            _cancel(context: context, request: request)
        }
    }

    private static func _serviceNotifyEvents(
        context: Context,
        timeoutMilliseconds: Int32 = defaultNotifyServiceTimeoutMilliseconds,
    ) throws {
        var pfd = pollfd()
        pfd.fd = smb2_get_fd(context.raw)
        pfd.events = Int16(smb2_which_events(context.raw))

        var rc: Int32 = 0
        repeat {
            rc = withUnsafeMutablePointer(to: &pfd) { poll($0, 1, timeoutMilliseconds) }
        }
        while rc < 0 && errno == EINTR

        if rc < 0 {
            throw SMB.Error.posix(
                code: errno,
                operation: "poll",
                message: "poll failed while waiting for SMB2 notification",
            )
        }

        if smb2_service(context.raw, Int32(pfd.revents)) < 0 {
            throw SMB.Error.fromBridge(context, operation: "smb2_service")
        }
    }

    /// Services pending SMB2 events for a notification watcher.
    static func serviceNotifyEvents(
        context: Context,
        timeoutMilliseconds: Int32 = defaultNotifyServiceTimeoutMilliseconds,
    ) throws {
        try Bridge.sync {
            try _serviceNotifyEvents(context: context, timeoutMilliseconds: timeoutMilliseconds)
        }
    }

    // MARK: - Notify Helpers

    private static let notifyChangeCallback: smb2_command_cb = { rawContext, status, commandData, callbackData in
        guard let callbackData else {
            return
        }

        let state = Unmanaged<PendingRequestState>
            .fromOpaque(callbackData)
            .takeRetainedValue()

        guard let handler = state.complete() else {
            return
        }

        guard let rawContext else {
            handler(.failure(.unknown(
                operation: state.operation,
                message: "Missing SMB2 context in callback",
            )))
            return
        }

        let context = Context(raw: rawContext)

        guard status == 0 else {
            handler(.failure(notifyChangeError(context: context, status: status, operation: state.operation)))
            return
        }

        guard let commandData else {
            handler(.success([]))
            return
        }

        handler(decodeNotifyChanges(context: context, commandData: commandData))
    }

    private static func decodeNotifyChanges(
        context: Context,
        commandData: UnsafeMutableRawPointer,
    ) -> Result<[NotifyChange], SMB.Error> {
        let reply = commandData.assumingMemoryBound(to: smb2_change_notify_reply.self).pointee

        guard reply.output_buffer_length > 0, let output = reply.output else {
            return .success([])
        }

        let buffer = UnsafeRawBufferPointer(
            start: output,
            count: Int(reply.output_buffer_length),
        )
        return decodeNotifyChanges(buffer)
    }

    private static func decodeNotifyChanges(_ buffer: UnsafeRawBufferPointer) -> Result<[NotifyChange], SMB.Error> {
        var changes: [NotifyChange] = []
        var offset = 0

        for _ in 0 ..< maximumNotifyChangeEntryCount {
            guard offset + notifyChangeEntryHeaderLength <= buffer.count else {
                return .failure(malformedNotifyChangeResponse("Entry header exceeds output buffer length"))
            }

            let nextEntryOffset = readLittleEndianUInt32(from: buffer, at: offset)
            let action = readLittleEndianUInt32(from: buffer, at: offset + 4)
            let nameLength = Int(readLittleEndianUInt32(from: buffer, at: offset + 8))
            let nameOffset = offset + notifyChangeEntryHeaderLength

            guard nameLength % 2 == 0,
                  nameLength <= buffer.count - nameOffset else {
                return .failure(malformedNotifyChangeResponse("Entry name exceeds output buffer length"))
            }

            changes.append(NotifyChange(
                action: NotifyChangeAction(rawValue: action),
                name: decodeNotifyChangeName(from: buffer, offset: nameOffset, byteCount: nameLength),
            ))

            guard nextEntryOffset != 0 else {
                return .success(changes)
            }

            let nextOffsetDelta = Int(nextEntryOffset)
            guard nextOffsetDelta >= notifyChangeEntryHeaderLength,
                  nextOffsetDelta <= buffer.count - offset else {
                return .failure(malformedNotifyChangeResponse("Entry offset is not monotonic within output buffer"))
            }

            offset += nextOffsetDelta
        }

        return .failure(malformedNotifyChangeResponse("Entry count exceeded defensive limit"))
    }

    private static func readLittleEndianUInt32(from buffer: UnsafeRawBufferPointer, at offset: Int) -> UInt32 {
        UInt32(buffer[offset])
            | (UInt32(buffer[offset + 1]) << 8)
            | (UInt32(buffer[offset + 2]) << 16)
            | (UInt32(buffer[offset + 3]) << 24)
    }

    private static func decodeNotifyChangeName(
        from buffer: UnsafeRawBufferPointer,
        offset: Int,
        byteCount: Int,
    ) -> String {
        var codeUnits: [UInt16] = []
        codeUnits.reserveCapacity(byteCount / 2)

        var index = offset
        let end = offset + byteCount
        while index < end {
            codeUnits.append(UInt16(buffer[index]) | (UInt16(buffer[index + 1]) << 8))
            index += 2
        }

        return String(decoding: codeUnits, as: UTF16.self)
    }

    private static func malformedNotifyChangeResponse(_ message: String) -> SMB.Error {
        .unknown(
            operation: "smb2_decode_filenotifychangeinformation",
            message: message,
        )
    }

    private static func notifyChangeError(
        context: Context,
        status: Int32,
        operation: String,
    ) -> SMB.Error {
        let rawStatus = UInt32(bitPattern: status)
        let message = smb2_get_error(context.raw).map(String.init(cString:)) ?? ""

        if let knownStatus = SMB.SMBStatus(rawValue: rawStatus) {
            return .ntStatus(knownStatus, posixCode: nil, operation: operation, message: message)
        }

        return .unknownNTStatus(rawValue: rawStatus, posixCode: nil, operation: operation, message: message)
    }
}
