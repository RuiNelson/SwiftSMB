//
// Part of SwiftSMB
// SMB2Bridge-Notify.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Darwin
import Foundation
import SMB2
import SMB2.Raw

private let defaultNotifyOutputBufferLength: UInt32 = 0xFFFF
private let defaultNotifyServiceTimeoutMilliseconds: Int32 = 50
private let notifyChangeEntryHeaderLength = 12
private let maximumNotifyChangeEntryCount = 4096

// Notes for the next layer:
//
// Why this file exists
// --------------------
// Change notifications are not a great fit for the synchronous POSIX-like
// bridge in SMB2Bridge.swift. A notification request is long-lived, completes
// only when the server reports a change (or an error), and must be cancellable
// when the user stops watching a directory or tears down the SMB context.
//
// This bridge intentionally uses the raw PDU API:
//
//     smb2_cmd_change_notify_async
//
// instead of the higher-level helpers:
//
//     smb2_notify_change_async
//     smb2_notify_change_filehandle_async
//
// The high-level helpers allocate their own internal callback state and decode
// the response before calling the application callback. During context
// destruction, libsmb2 aborts pending PDUs by invoking callbacks with a failure
// status and a NULL payload. The high-level notify helper currently assumes a
// reply payload exists before the application callback gets control, which makes
// "destroy context before first notification" an unsafe lifecycle edge.
//
// Ownership model
// ---------------
// notifyChange(context:directory:flags:filter:handler:) returns an
// SMB2PendingRequest. The request token owns the retained Swift callback state
// until exactly one of these happens:
//
// - libsmb2 completes the PDU and invokes notifyChangeCallback
// - the public layer calls cancel(context:request:)
//
// The public layer must retain the returned SMB2PendingRequest for as long as
// the request may be cancelled. Dropping the Swift value does not cancel the
// underlying PDU; it only loses the handle needed to cancel it.
//
// Directory handle lifetime
// -------------------------
// The directory argument is an SMB2FileHandle, not a path. This is deliberate:
// a path-based helper would need to hide an open directory handle, and then the
// next layer would have no clear place to coordinate cancellation, close, and
// context destruction.
//
// The public layer must keep the directory file handle open until the request
// completes or is cancelled. Do not close the file handle while a notification
// request created from it is still pending.
//
// One-shot vs continuous watching
// -------------------------------
// This bridge is one-shot. A successful callback means one notify request
// completed; it does not remain subscribed. A continuous directory watcher
// should re-arm by issuing a new notifyChange request after a successful result,
// normally only if the user's watcher is still active.
//
// Cancellation and shutdown
// -------------------------
// cancel(context:request:) removes the PDU from libsmb2's queues by calling
// smb2_free_pdu. Cancelling does not call the handler.
//
// Before closing a directory handle or destroying an SMB2 context, the public
// layer should cancel all pending notify requests it owns. If a request is not
// cancelled before context destruction, libsmb2 may still invoke our callback
// with a shutdown status. This bridge handles that status safely, but the public
// layer should still treat pending work during destruction as a lifecycle bug.
//
// Event-loop requirement
// ----------------------
// Starting a notify request only queues the PDU. The callback will not run
// unless the next layer keeps servicing the libsmb2 context, typically via
// smb2_get_fd/smb2_which_events/smb2_service or the fd callback mechanism.

/// Starts a one-shot cancellable change notification request for an open directory file handle.
func notifyChange(
    context: SMB2Context,
    directory: SMB2FileHandle,
    flags: SMB2NotifyChangeFlags = [],
    filter: SMB2NotifyChangeFilter = .all,
    handler: @escaping SMB2NotifyChangeHandler,
) throws -> SMB2PendingRequest {
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

    let state = SMB2PendingRequestState(
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
        Unmanaged<SMB2PendingRequestState>.fromOpaque(callbackData).release()
        throw SMB.Error.fromBridge(context, operation: "smb2_cmd_change_notify_async")
    }

    state.didCreateRequest(raw: rawPDU, callbackData: callbackData)
    smb2_queue_pdu(context.raw, rawPDU)

    return SMB2PendingRequest(state: state)
}

/// Cancels a pending raw SMB2 request if it has not completed yet.
func cancel(context: SMB2Context, request: SMB2PendingRequest) {
    guard let cancellation = request.state.cancel() else {
        return
    }

    smb2_free_pdu(context.raw, cancellation.raw)
    Unmanaged<SMB2PendingRequestState>.fromOpaque(cancellation.callbackData).release()
}

/// Services pending SMB2 events for a notification watcher.
func serviceNotifyEvents(
    context: SMB2Context,
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

struct SMB2PendingRequest {
    fileprivate let state: SMB2PendingRequestState
}

private final class SMB2PendingRequestState: @unchecked Sendable {
    let operation: String
    let handler: SMB2NotifyChangeHandler

    private let lock = NSLock()
    private var raw: UnsafeMutablePointer<smb2_pdu>?
    private var callbackData: UnsafeMutableRawPointer?
    private var isFinished = false

    init(
        operation: String,
        handler: @escaping SMB2NotifyChangeHandler,
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

    func complete() -> SMB2NotifyChangeHandler? {
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

private let notifyChangeCallback: smb2_command_cb = { rawContext, status, commandData, callbackData in
    guard let callbackData else {
        return
    }

    let state = Unmanaged<SMB2PendingRequestState>
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

    let context = SMB2Context(raw: rawContext)

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

private func decodeNotifyChanges(
    context: SMB2Context,
    commandData: UnsafeMutableRawPointer,
) -> Result<[SMB2NotifyChange], SMB.Error> {
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

private func decodeNotifyChanges(_ buffer: UnsafeRawBufferPointer) -> Result<[SMB2NotifyChange], SMB.Error> {
    var changes: [SMB2NotifyChange] = []
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

        changes.append(SMB2NotifyChange(
            action: SMB2NotifyChangeAction(rawValue: action),
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

private func readLittleEndianUInt32(from buffer: UnsafeRawBufferPointer, at offset: Int) -> UInt32 {
    UInt32(buffer[offset])
        | (UInt32(buffer[offset + 1]) << 8)
        | (UInt32(buffer[offset + 2]) << 16)
        | (UInt32(buffer[offset + 3]) << 24)
}

private func decodeNotifyChangeName(
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

private func malformedNotifyChangeResponse(_ message: String) -> SMB.Error {
    .unknown(
        operation: "smb2_decode_filenotifychangeinformation",
        message: message,
    )
}

private func notifyChangeError(
    context: SMB2Context,
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
