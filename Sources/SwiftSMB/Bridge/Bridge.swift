//
// Part of SwiftSMB
// Bridge.swift
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

/// Central bridge class for all libsmb2 operations.
class Bridge {
    // MARK: - Synchronization

    // ⚠️
    //
    // `libsmb2` contexts are not thread-safe. Every call that touches a shared context runs on that context's serial
    // queue through `perform(on:_:)`, so operations on one context are serialized while different contexts run in
    // parallel. Creating and destroying contexts additionally takes `lifecycleLock`, because `smb2_init_context` and
    // `smb2_destroy_context` mutate process-wide libsmb2 state (the active-context list and the `srandom` seed).
    //
    // Blocking libsmb2 calls never run on the Swift concurrency cooperative pool: callers suspend while the work runs
    // on
    // the context queue.

    /// Serializes libsmb2 calls that mutate process-wide state.
    private static let lifecycleLock = Protected((), label: "com.ruinelson.SwiftSMB.bridge.lifecycle")

    /// Runs `body` on the context's serial queue and returns its result.
    ///
    /// Throws ``SMB/Error/operationRequestedAfterConnectionClosed`` without running `body` if the context has already
    /// been destroyed. Task cancellation is not checked, so cleanup operations still run in cancelled tasks.
    @discardableResult
    static func perform<T: Sendable>(
        on context: Context,
        _ body: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            context.queue.async {
                guard context.isAlive else {
                    continuation.resume(throwing: SMB.Error.operationRequestedAfterConnectionClosed)
                    return
                }
                clearError(on: context)
                continuation.resume(with: Result { try body() })
            }
        }
    }

    /// Clears the context's last error string and NT status. Must run on the context queue.
    ///
    /// libsmb2 keeps both until another failure overwrites them, and ``SMB/Error/fromBridge(_:operation:status:)``
    /// prefers the NT status over the status an operation reports. Clearing them before each operation keeps a failure
    /// from being reported with the status and message of an earlier, unrelated one.
    private static func clearError(on context: Context) {
        context.raw.pointee.nterror = 0
        withUnsafeMutableBytes(of: &context.raw.pointee.error_string) { $0[0] = 0 }
    }

    /// Enqueues `body` on the context's serial queue without waiting for it. Used from `deinit`, which cannot await.
    ///
    /// `body` is skipped if the context has been destroyed by the time it runs.
    static func performInBackground(on context: Context, _ body: @escaping @Sendable () -> Void) {
        context.queue.async {
            guard context.isAlive else {
                return
            }
            body()
        }
    }

    /// Waits until every operation already enqueued on the context has finished.
    static func waitForPendingOperations(on context: Context) async {
        await withCheckedContinuation { continuation in
            context.queue.async {
                continuation.resume()
            }
        }
    }

    // MARK: - Context Management

    /// Creates a new libsmb2 context.
    ///
    /// The new context is not shared yet, so this runs on the caller's thread.
    static func createContext() throws -> Context {
        guard let raw = lifecycleLock.withLock({ _ in smb2_init_context() }) else {
            throw SMB.Error.contextCreationFailed
        }

        return Context(raw: raw)
    }

    /// Closes the active connection for a context without destroying the context.
    static func closeContext(_ context: Context) async {
        try? await perform(on: context) {
            closeOwnedHandles(on: context)
            guard context.isAlive else { return }
            smb2_close_context(context.raw)
        }
    }

    /// Destroys a context and marks it dead. Must run on the context queue, or on a context that was never shared.
    static func _destroyContext(_ context: Context) {
        guard context.isAlive else { return }
        context.isAlive = false
        for directory in Array(context.directoryHandles.values) {
            _closeDir(context: context, directory: directory)
        }
        let rawFiles = context.fileHandles.values.compactMap { $0.takeRaw() }
        context.fileHandles.removeAll()
        lifecycleLock.withLock { _ in
            smb2_destroy_context(context.raw)
        }
        // Contrary to its header documentation, libsmb2 does not track open file allocations. Pending callbacks must
        // run during destroy before these allocations are reclaimed; otherwise they may still reference a handle.
        for raw in rawFiles {
            free(UnsafeMutableRawPointer(raw))
        }
    }

    /// Destroys a libsmb2 context and any resources it owns.
    ///
    /// Destroying an already destroyed context does nothing. Operations enqueued afterwards throw
    /// ``SMB/Error/operationRequestedAfterConnectionClosed``.
    static func destroyContext(_ context: Context) async {
        try? await perform(on: context) {
            _destroyContext(context)
        }
    }

    /// Disconnects from the share, then closes and destroys the context, as one queue operation.
    ///
    /// Doing all three in one step means no other operation can run on a disconnected or closed context in between;
    /// operations enqueued afterwards throw ``SMB/Error/operationRequestedAfterConnectionClosed``. The context is
    /// destroyed even if the disconnect fails, and the disconnect error is rethrown.
    static func shutdown(_ context: Context) async throws {
        try await perform(on: context) {
            try _shutdown(context)
        }
    }

    /// Disconnects, closes, and destroys a context without waiting. Used from `deinit`, which cannot await.
    static func teardownInBackground(_ context: Context) {
        performInBackground(on: context) {
            _ = try? _shutdown(context)
        }
    }

    private static func _shutdown(_ context: Context) throws {
        defer {
            if context.isAlive {
                smb2_close_context(context.raw)
                _destroyContext(context)
            }
        }
        closeOwnedHandles(on: context)
        guard context.isAlive else {
            throw SMB.Error.operationRequestedAfterConnectionClosed
        }
        try _disconnectShare(context: context)
    }

    /// Closes all registered handles while their context is still connected. Must run on the context queue.
    private static func closeOwnedHandles(on context: Context) {
        for directory in Array(context.directoryHandles.values) {
            _closeDir(context: context, directory: directory)
        }
        for file in Array(context.fileHandles.values) {
            guard context.isAlive else { return }
            try? _close(context: context, file: file)
        }
    }

    // MARK: - Configuration

    /// Sets the command timeout in seconds for a context.
    static func setTimeout(_ seconds: Int32, on context: Context) async throws {
        try await perform(on: context) {
            smb2_set_timeout(context.raw, seconds)
        }
    }

    /// Returns the command timeout in seconds for a context.
    static func getTimeout(on context: Context) async throws -> Int32 {
        try await perform(on: context) {
            context.raw.pointee.timeout
        }
    }

    /// Sets the SMB dialect negotiation preference for a context.
    static func setVersion(_ version: smb2_negotiate_version, on context: Context) async throws {
        try await perform(on: context) {
            smb2_set_version(context.raw, version)
        }
    }

    private static func _getDialect(on context: Context) -> UInt16 {
        smb2_get_dialect(context.raw)
    }

    /// Returns the currently negotiated SMB dialect for a context.
    static func getDialect(on context: Context) async throws -> UInt16 {
        try await perform(on: context) {
            _getDialect(on: context)
        }
    }

    static func _setSecurityMode(_ securityMode: SecurityMode, on context: Context) {
        smb2_set_security_mode(context.raw, securityMode.rawValue)
    }

    /// Sets SMB signing-related negotiation flags for a context.
    static func setSecurityMode(_ securityMode: SecurityMode, on context: Context) async throws {
        try await perform(on: context) {
            _setSecurityMode(securityMode, on: context)
        }
    }

    /// Explicitly requires or disables SMB3 encryption for a context.
    ///
    /// Not calling this function leaves libsmb2's automatic encryption negotiation in effect.
    static func setSeal(_ enabled: Bool, on context: Context) async throws {
        try await perform(on: context) {
            smb2_set_seal(context.raw, enabled ? 1 : 0)
        }
    }

    /// Returns the server GUID negotiated for a connected context as a native Swift UUID.
    static func getServerGUID(on context: Context) async throws -> UUID {
        try await perform(on: context) {
            guard let rawGUID = smb2_get_server_guid(context.raw) else {
                return UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
            }

            var bytes = Array(UnsafeRawBufferPointer(start: rawGUID, count: 16))
            // SMB transmits the first three GUID fields in little-endian order. Foundation.UUID expects canonical byte
            // order, so normalize those fields before constructing the value.
            bytes.swapAt(0, 3)
            bytes.swapAt(1, 2)
            bytes.swapAt(4, 5)
            bytes.swapAt(6, 7)
            return UUID(uuid: (
                bytes[0],
                bytes[1],
                bytes[2],
                bytes[3],
                bytes[4],
                bytes[5],
                bytes[6],
                bytes[7],
                bytes[8],
                bytes[9],
                bytes[10],
                bytes[11],
                bytes[12],
                bytes[13],
                bytes[14],
                bytes[15]
            ))
        }
    }

    /// Enables or disables required SMB signing for a context.
    static func setSign(_ required: Bool, on context: Context) async throws {
        try await perform(on: context) {
            smb2_set_sign(context.raw, required ? 1 : 0)
        }
    }

    /// Sets the authentication mechanism for a context.
    static func setAuthentication(_ authentication: AuthenticationMethod, on context: Context) async throws {
        try await perform(on: context) {
            smb2_set_authentication(context.raw, authentication.rawValue)
        }
    }

    /// Sets the username used for authentication.
    static func setUser(_ user: String, on context: Context) async throws {
        try await perform(on: context) {
            user.withCString { smb2_set_user(context.raw, $0) }
        }
    }

    /// Returns the username currently configured on a context.
    static func getUser(on context: Context) async throws -> String? {
        try await perform(on: context) {
            smb2_get_user(context.raw).map(String.init(cString:))
        }
    }

    /// Sets the password used for authentication.
    static func setPassword(_ password: String, on context: Context) async throws {
        try await perform(on: context) {
            password.withCString { smb2_set_password(context.raw, $0) }
        }
    }

    /// Loads the password from the NTLM_USER_FILE credential file if available.
    static func setPasswordFromFile(on context: Context) async throws {
        try await perform(on: context) {
            smb2_set_password_from_file(context.raw)
        }
    }

    /// Sets the authentication domain for a context.
    static func setDomain(_ domain: String, on context: Context) async throws {
        try await perform(on: context) {
            domain.withCString { smb2_set_domain(context.raw, $0) }
        }
    }

    /// Returns the authentication domain currently configured on a context.
    static func getDomain(on context: Context) async throws -> String? {
        try await perform(on: context) {
            smb2_get_domain(context.raw).map(String.init(cString:))
        }
    }

    /// Sets the workstation name used for authentication.
    static func setWorkstation(_ workstation: String, on context: Context) async throws {
        try await perform(on: context) {
            workstation.withCString { smb2_set_workstation(context.raw, $0) }
        }
    }

    /// Returns the workstation name currently configured on a context.
    static func getWorkstation(on context: Context) async throws -> String? {
        try await perform(on: context) {
            smb2_get_workstation(context.raw).map(String.init(cString:))
        }
    }

    // MARK: - Connection

    /// The connection deadline, in seconds, used while connecting a context whose command timeout is `0`.
    ///
    /// `smb2_connect_share` gives up once `time(NULL)` has advanced past the command timeout while the TCP connection
    /// is
    /// still pending, and it checks that before handling the event that completes the connection. With a timeout of `0`
    /// it therefore fails any connect that crosses a wall-clock second boundary, which becomes likely when many
    /// connections are opened concurrently.
    static let defaultConnectTimeoutSeconds: Int32 = 30

    static func _connectShare(
        context: Context,
        server: String,
        share: String,
        user: String? = nil
    ) throws {
        // A command timeout of 0 means "no command timeout", but libsmb2 would also treat it as a connection window
        // that ends at the next wall-clock second. Connect with a real deadline, then restore the configured value.
        let commandTimeout = context.raw.pointee.timeout
        if commandTimeout == 0 {
            smb2_set_timeout(context.raw, defaultConnectTimeoutSeconds)
        }
        defer {
            if commandTimeout == 0 {
                smb2_set_timeout(context.raw, 0)
            }
        }

        let status = server.withCString { serverPointer in
            share.withCString { sharePointer in
                user.withOptionalCString { userPointer in
                    smb2_connect_share(context.raw, serverPointer, sharePointer, userPointer)
                }
            }
        }

        try check(status, context: context, operation: "smb2_connect_share")
    }

    /// Connects a context to a share on a server.
    static func connectShare(
        context: Context,
        server: String,
        share: String,
        user: String? = nil
    ) async throws {
        try await perform(on: context) {
            try _connectShare(context: context, server: server, share: share, user: user)
        }
    }

    static func _disconnectShare(context: Context) throws {
        try check(smb2_disconnect_share(context.raw), context: context, operation: "smb2_disconnect_share")
    }

    /// Disconnects a context from its current share.
    static func disconnectShare(context: Context) async throws {
        try await perform(on: context) {
            try _disconnectShare(context: context)
        }
    }

    /// Selects a previously connected tree ID for subsequent requests.
    static func selectTreeID(_ treeID: UInt32, context: Context) async throws {
        try await perform(on: context) {
            try check(smb2_select_tree_id(context.raw, treeID), context: context, operation: "smb2_select_tree_id")
        }
    }

    private static func _getSessionID(context: Context) throws -> UInt64 {
        var sessionID: UInt64 = 0
        try check(smb2_get_session_id(context.raw, &sessionID), context: context, operation: "smb2_get_session_id")
        return sessionID
    }

    /// Returns the SMB session ID for a context.
    static func getSessionID(context: Context) async throws -> UInt64 {
        try await perform(on: context) {
            try _getSessionID(context: context)
        }
    }

    // MARK: - File Operations

    private static func _open(
        context: Context,
        path: String,
        flags: OpenFlags = OpenFlags()
    ) throws -> FileHandle {
        try _open(context: context, path: path, flags: flags, opLockLevel: .none, leaseState: [], leaseKey: nil)
    }

    /// Opens or creates a file and returns a file handle.
    static func open(
        context: Context,
        path: String,
        flags: OpenFlags = OpenFlags()
    ) async throws -> FileHandle {
        try await perform(on: context) {
            try _open(context: context, path: path, flags: flags)
        }
    }

    // MARK: - Open with OpLock/Lease

    private final class OpenState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished: Bool = false
        var fileHandle: FileHandle?
        let context: Context
        let appendsWrites: Bool

        init(context: Context, appendsWrites: Bool) {
            self.context = context
            self.appendsWrites = appendsWrites
        }
    }

    private static let openCallback: smb2_command_cb = { _, status, commandData, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<OpenState>.fromOpaque(callbackData).takeUnretainedValue()
        if status == 0, let commandData {
            let file = FileHandle(raw: OpaquePointer(commandData), appendsWrites: state.appendsWrites)
            state.context.fileHandles[ObjectIdentifier(file)] = file
            state.fileHandle = file
        }
        state.finish(status)
    }

    private static func _open(
        context: Context,
        path: String,
        flags: OpenFlags = OpenFlags(),
        opLockLevel: OpLockLevel = .none,
        leaseState: LeaseState = [],
        leaseKey: Data? = nil
    ) throws -> FileHandle {
        if opLockLevel == .lease, let leaseKey, leaseKey.count != 16 {
            throw SMB.Error.posix(
                code: POSIXErrorCode.EINVAL.rawValue,
                operation: "smb2_open_async_with_oplock_or_lease",
                message: "Lease key must contain exactly 16 bytes"
            )
        }
        let state = OpenState(context: context, appendsWrites: flags.options.contains(.append))
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { releaseWhenFinished(state, callbackData) }

        let status: Int32
        if opLockLevel == .lease, let leaseKey, !leaseState.isEmpty {
            var mutableKey = leaseKey
            status = mutableKey.withUnsafeMutableBytes { keyBuffer in
                path.withCString { pathPointer in
                    smb2_open_async_with_oplock_or_lease(
                        context.raw,
                        pathPointer,
                        flags.rawValue,
                        opLockLevel.rawValue,
                        leaseState.rawValue,
                        keyBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        openCallback,
                        callbackData
                    )
                }
            }
        }
        else {
            status = path.withCString { pathPointer in
                smb2_open_async_with_oplock_or_lease(
                    context.raw,
                    pathPointer,
                    flags.rawValue,
                    opLockLevel.rawValue,
                    0,
                    nil,
                    openCallback,
                    callbackData
                )
            }
        }

        guard status == 0 else {
            state.finish(status)
            throw SMB.Error.fromBridge(context, operation: "smb2_open_async_with_oplock_or_lease", status: status)
        }

        try serviceUntilFinished(context: context, state: state)

        if state.status != 0 {
            throw SMB.Error.fromBridge(
                context,
                operation: "smb2_open_async_with_oplock_or_lease",
                status: state.status
            )
        }

        guard let handle = state.fileHandle else {
            throw SMB.Error.unknown(
                operation: "smb2_open_async_with_oplock_or_lease",
                message: "File handle was nil after successful open"
            )
        }

        return handle
    }

    /// Opens or creates a file with an oplock or lease request.
    static func open(
        context: Context,
        path: String,
        flags: OpenFlags = OpenFlags(),
        opLockLevel: OpLockLevel = .none,
        leaseState: LeaseState = [],
        leaseKey: Data? = nil
    ) async throws -> FileHandle {
        try await perform(on: context) {
            try _open(
                context: context,
                path: path,
                flags: flags,
                opLockLevel: opLockLevel,
                leaseState: leaseState,
                leaseKey: leaseKey
            )
        }
    }

    private final class CloseState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished = false
    }

    private static let closeCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        Unmanaged<CloseState>.fromOpaque(callbackData).takeUnretainedValue().finish(status)
    }

    private static func _close(context: Context, file: FileHandle) throws {
        guard context.isAlive else { return }
        guard let raw = file.takeRaw() else { return }
        context.fileHandles.removeValue(forKey: ObjectIdentifier(file))
        let state = CloseState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { releaseWhenFinished(state, callbackData) }
        let status = smb2_close_async(context.raw, raw, closeCallback, callbackData)
        guard status == 0 else {
            state.finish(status)
            free(UnsafeMutableRawPointer(raw))
            throw SMB.Error.fromBridge(context, operation: "smb2_close", status: status)
        }
        try serviceUntilFinished(context: context, state: state)
        try check(state.status, context: context, operation: "smb2_close")
    }

    /// Closes an open file handle.
    static func close(context: Context, file: FileHandle) async throws {
        try await perform(on: context) {
            try _close(context: context, file: file)
        }
    }

    /// Closes an open file handle without waiting. Used from `deinit`, which cannot await.
    static func closeInBackground(context: Context, file: FileHandle) {
        performInBackground(on: context) {
            _ = try? _close(context: context, file: file)
        }
    }

    private static func _sync(context: Context, file: FileHandle) throws {
        let raw = try file.requireRaw(operation: .smb2Fsync)
        try performStatus(context: context, operation: "smb2_fsync") {
            smb2_fsync_async(context.raw, raw, $0, $1)
        }
    }

    /// Flushes pending writes for an open file handle.
    static func sync(context: Context, file: FileHandle) async throws {
        try await perform(on: context) {
            try _sync(context: context, file: file)
        }
    }

    private static func _getMaxReadSize(context: Context) -> UInt32 {
        smb2_get_max_read_size(context.raw)
    }

    /// Returns the maximum read size supported by the connected server.
    static func getMaxReadSize(context: Context) async throws -> UInt32 {
        try await perform(on: context) {
            _getMaxReadSize(context: context)
        }
    }

    private static func _getMaxWriteSize(context: Context) -> UInt32 {
        smb2_get_max_write_size(context.raw)
    }

    /// Returns the maximum write size supported by the connected server.
    static func getMaxWriteSize(context: Context) async throws -> UInt32 {
        try await perform(on: context) {
            _getMaxWriteSize(context: context)
        }
    }

    private final class FileIOState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished = false
        let buffer: UnsafeMutablePointer<UInt8>

        init(count: Int) {
            buffer = .allocate(capacity: count)
        }

        deinit {
            buffer.deallocate()
        }
    }

    private static let fileIOCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        Unmanaged<FileIOState>.fromOpaque(callbackData).takeUnretainedValue().finish(status)
    }

    /// Owns the read buffer until its callback finishes, including when servicing fails before the reply arrives.
    private static func readData(
        count: Int,
        context: Context,
        operation: String,
        _ body: (UnsafeMutablePointer<UInt8>, smb2_command_cb, UnsafeMutableRawPointer) -> Int32
    ) throws -> Data {
        let state = FileIOState(count: count)
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { releaseWhenFinished(state, callbackData) }
        let status = body(state.buffer, fileIOCallback, callbackData)
        guard status == 0 else {
            state.finish(status)
            throw SMB.Error.fromBridge(context, operation: operation, status: status)
        }
        try serviceUntilFinished(context: context, state: state)
        let bytesRead = try Int(check(state.status, context: context, operation: operation))
        guard bytesRead <= count else {
            throw SMB.Error.unknown(operation: operation, message: "Server returned more bytes than requested")
        }
        return Data(bytes: state.buffer, count: bytesRead)
    }

    /// Owns the write buffer until its callback finishes, including when servicing fails before the reply arrives.
    private static func writeData(
        _ data: Data,
        context: Context,
        operation: String,
        _ body: (UnsafeMutablePointer<UInt8>, smb2_command_cb, UnsafeMutableRawPointer) -> Int32
    ) throws -> Int {
        let state = FileIOState(count: data.count)
        data.copyBytes(to: state.buffer, count: data.count)
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { releaseWhenFinished(state, callbackData) }
        let status = body(state.buffer, fileIOCallback, callbackData)
        guard status == 0 else {
            state.finish(status)
            throw SMB.Error.fromBridge(context, operation: operation, status: status)
        }
        try serviceUntilFinished(context: context, state: state)
        let bytesWritten = try Int(check(state.status, context: context, operation: operation))
        guard bytesWritten <= data.count else {
            throw SMB.Error.unknown(operation: operation, message: "Server accepted more bytes than provided")
        }
        return bytesWritten
    }

    /// Reads up to `count` bytes from a file at an explicit offset.
    ///
    /// - Returns: The bytes read. An empty value indicates end of file.
    static func read(context: Context, file: FileHandle, count: Int, offset: UInt64) async throws -> Data {
        let byteCount = try count.asUInt32(operation: .smb2Pread)
        return try await perform(on: context) {
            let raw = try file.requireRaw(operation: .smb2Pread)
            guard byteCount > 0 else { return Data() }
            let previousOffset = try _seek(context: context, file: file, offset: 0, whence: SEEK_CUR)
            defer {
                if context.isAlive {
                    _ = smb2_lseek(context.raw, raw, Int64(previousOffset), SEEK_SET, nil)
                }
            }
            return try readData(count: count, context: context, operation: "smb2_pread") {
                smb2_pread_async(context.raw, raw, $0, byteCount, offset, $1, $2)
            }
        }
    }

    /// Writes bytes to a file at an explicit offset.
    ///
    /// - Returns: The number of bytes the server accepted, which may be fewer than `data.count`.
    static func write(context: Context, file: FileHandle, data: Data, offset: UInt64) async throws -> Int {
        let byteCount = try data.count.asUInt32(operation: .smb2Pwrite)
        return try await perform(on: context) {
            let raw = try file.requireRaw(operation: .smb2Pwrite)
            guard byteCount > 0 else { return 0 }
            let previousOffset = try _seek(context: context, file: file, offset: 0, whence: SEEK_CUR)
            defer {
                if context.isAlive {
                    _ = smb2_lseek(context.raw, raw, Int64(previousOffset), SEEK_SET, nil)
                }
            }
            return try writeData(data, context: context, operation: "smb2_pwrite") {
                smb2_pwrite_async(context.raw, raw, $0, byteCount, offset, $1, $2)
            }
        }
    }

    /// Reads up to `count` bytes from the current file offset.
    ///
    /// - Returns: The bytes read. An empty value indicates end of file.
    static func read(context: Context, file: FileHandle, count: Int) async throws -> Data {
        let byteCount = try count.asUInt32(operation: .smb2Read)
        return try await perform(on: context) {
            let raw = try file.requireRaw(operation: .smb2Read)
            guard byteCount > 0 else { return Data() }
            return try readData(count: count, context: context, operation: "smb2_read") {
                smb2_read_async(context.raw, raw, $0, byteCount, $1, $2)
            }
        }
    }

    /// Writes bytes at the current file offset.
    ///
    /// - Returns: The number of bytes the server accepted, which may be fewer than `data.count`.
    static func write(context: Context, file: FileHandle, data: Data) async throws -> Int {
        let byteCount = try data.count.asUInt32(operation: .smb2Write)
        return try await perform(on: context) {
            let raw = try file.requireRaw(operation: .smb2Write)
            guard byteCount > 0 else { return 0 }
            if file.appendsWrites {
                // libsmb2 ignores O_APPEND. Refresh the end on every write so reopening or seeking an append handle
                // never overwrites the existing contents.
                let size = try _getFileSize(context: context, file: file)
                let destination = try seekDestination(from: size, offset: 0)
                _ = smb2_lseek(context.raw, raw, Int64(destination), SEEK_SET, nil)
            }
            return try writeData(data, context: context, operation: "smb2_write") {
                smb2_write_async(context.raw, raw, $0, byteCount, $1, $2)
            }
        }
    }

    private static func _seek(
        context: Context,
        file: FileHandle,
        offset: Int64,
        whence: Int32
    ) throws -> UInt64 {
        let raw = try file.requireRaw(operation: .smb2Lseek)
        let base: UInt64
        switch whence {
        case SEEK_SET:
            base = 0
        case SEEK_CUR:
            var previousOffset: UInt64 = 0
            let status = smb2_lseek(context.raw, raw, 0, SEEK_CUR, &previousOffset)
            guard status >= 0 else {
                throw SMB.Error.fromBridge(context, operation: "smb2_lseek", status: Int32(clamping: status))
            }
            base = previousOffset
        case SEEK_END:
            base = try _getFileSize(context: context, file: file)
        default:
            throw SMB.Error.posix(
                code: POSIXErrorCode.EINVAL.rawValue,
                operation: "smb2_lseek",
                message: "Invalid seek origin"
            )
        }
        // libsmb2 performs unchecked signed addition and changes the position before validating SEEK_END. Calculate
        // the destination first, and use an absolute seek so a failure never corrupts the current position.
        let destination = try seekDestination(from: base, offset: offset)
        var currentOffset: UInt64 = 0
        let status = smb2_lseek(context.raw, raw, Int64(destination), SEEK_SET, &currentOffset)
        guard status >= 0 else {
            throw SMB.Error.fromBridge(context, operation: "smb2_lseek", status: Int32(clamping: status))
        }

        return currentOffset
    }

    static func seekDestination(from base: UInt64, offset: Int64) throws -> UInt64 {
        let destination: UInt64
        if offset < 0 {
            guard base >= offset.magnitude else {
                throw SMB.Error.posix(
                    code: POSIXErrorCode.EINVAL.rawValue,
                    operation: "smb2_lseek",
                    message: "Seek offset would become negative"
                )
            }
            destination = base - offset.magnitude
        }
        else {
            let (sum, overflow) = base.addingReportingOverflow(UInt64(offset))
            guard !overflow else {
                throw SMB.Error.posix(
                    code: POSIXErrorCode.EOVERFLOW.rawValue,
                    operation: "smb2_lseek",
                    message: "Seek offset cannot be represented as Int64"
                )
            }
            destination = sum
        }
        guard destination <= UInt64(Int64.max) else {
            throw SMB.Error.posix(
                code: POSIXErrorCode.EOVERFLOW.rawValue,
                operation: "smb2_lseek",
                message: "Seek offset cannot be represented as Int64"
            )
        }
        return destination
    }

    /// Moves the current file offset and returns the resulting offset.
    static func seek(
        context: Context,
        file: FileHandle,
        offset: Int64,
        whence: Int32
    ) async throws -> UInt64 {
        try await perform(on: context) {
            try _seek(context: context, file: file, offset: offset, whence: whence)
        }
    }

    private static func _unlink(context: Context, path: String) throws {
        try check(path.withCString { smb2_unlink(context.raw, $0) }, context: context, operation: "smb2_unlink")
    }

    /// Removes a file or link at a path.
    static func unlink(context: Context, path: String) async throws {
        try await perform(on: context) {
            try _unlink(context: context, path: path)
        }
    }

    // MARK: - Directory Operations

    private static func _removeDir(context: Context, path: String) throws {
        try check(path.withCString { smb2_rmdir(context.raw, $0) }, context: context, operation: "smb2_rmdir")
    }

    /// Removes an empty directory at a path.
    static func removeDir(context: Context, path: String) async throws {
        try await perform(on: context) {
            try _removeDir(context: context, path: path)
        }
    }

    private static func _makeDir(context: Context, path: String) throws {
        try check(path.withCString { smb2_mkdir(context.raw, $0) }, context: context, operation: "smb2_mkdir")
    }

    /// Creates a directory at a path.
    static func makeDir(context: Context, path: String) async throws {
        try await perform(on: context) {
            try _makeDir(context: context, path: path)
        }
    }

    private final class OpenDirectoryState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished = false
        var directory: DirectoryHandle?
        let context: Context

        init(context: Context) {
            self.context = context
        }
    }

    private static let openDirectoryCallback: smb2_command_cb = { _, status, commandData, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<OpenDirectoryState>.fromOpaque(callbackData).takeUnretainedValue()
        if status == 0, let commandData {
            let directory = DirectoryHandle(raw: commandData.assumingMemoryBound(to: smb2dir.self))
            state.context.directoryHandles[ObjectIdentifier(directory)] = directory
            state.directory = directory
        }
        state.finish(status)
    }

    private static func _openDir(context: Context, path: String) throws -> DirectoryHandle {
        let state = OpenDirectoryState(context: context)
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { releaseWhenFinished(state, callbackData) }
        let status = path.withCString { smb2_opendir_async(context.raw, $0, openDirectoryCallback, callbackData) }
        guard status == 0 else {
            state.finish(status)
            throw SMB.Error.fromBridge(context, operation: "smb2_opendir", status: status)
        }
        try serviceUntilFinished(context: context, state: state)
        try check(state.status, context: context, operation: "smb2_opendir")
        guard let directory = state.directory else {
            throw SMB.Error.unknown(operation: "smb2_opendir", message: "Server returned no directory handle")
        }
        return directory
    }

    /// Opens a directory and returns a directory handle.
    static func openDir(context: Context, path: String) async throws -> DirectoryHandle {
        try await perform(on: context) {
            try _openDir(context: context, path: path)
        }
    }

    private static func _closeDir(context: Context, directory: DirectoryHandle) {
        guard let raw = directory.takeRaw() else { return }
        context.directoryHandles.removeValue(forKey: ObjectIdentifier(directory))
        smb2_closedir(context.raw, raw)
    }

    /// Closes an open directory handle.
    static func closeDir(context: Context, directory: DirectoryHandle) async throws {
        try await perform(on: context) {
            _closeDir(context: context, directory: directory)
        }
    }

    /// Closes an open directory handle without waiting. Used from `deinit`, which cannot await.
    static func closeDirInBackground(context: Context, directory: DirectoryHandle) {
        performInBackground(on: context) {
            _closeDir(context: context, directory: directory)
        }
    }

    private static func _readDir(context: Context, directory: DirectoryHandle) throws -> DirectoryEntry? {
        try smb2_readdir(context.raw, directory.requireRaw(operation: .smb2Readdir)).map { DirectoryEntry($0.pointee) }
    }

    /// Reads the next directory entry from a directory handle.
    static func readDir(context: Context, directory: DirectoryHandle) async throws -> DirectoryEntry? {
        try await perform(on: context) {
            try _readDir(context: context, directory: directory)
        }
    }

    private static func _rewindDir(context: Context, directory: DirectoryHandle) throws {
        try smb2_rewinddir(context.raw, directory.requireRaw(operation: .smb2Rewinddir))
    }

    /// Rewinds a directory handle to the first entry.
    static func rewindDir(context: Context, directory: DirectoryHandle) async throws {
        try await perform(on: context) {
            try _rewindDir(context: context, directory: directory)
        }
    }

    private static func _tellDir(context: Context, directory: DirectoryHandle) throws -> Int {
        try Int(smb2_telldir(context.raw, directory.requireRaw(operation: .smb2Telldir)))
    }

    /// Returns the current directory stream location.
    static func tellDir(context: Context, directory: DirectoryHandle) async throws -> Int {
        try await perform(on: context) {
            try _tellDir(context: context, directory: directory)
        }
    }

    private static func _seekDir(context: Context, directory: DirectoryHandle, location: Int) throws {
        let raw = try directory.requireRaw(operation: .smb2Seekdir)
        guard location >= 0, let position = CLong(exactly: location) else {
            throw SMB.Error.posix(
                code: POSIXErrorCode.EINVAL.rawValue,
                operation: "smb2_seekdir",
                message: "Directory position must be nonnegative and fit in C long"
            )
        }
        smb2_seekdir(context.raw, raw, position)
    }

    /// Moves a directory handle to a previously returned stream location.
    static func seekDir(context: Context, directory: DirectoryHandle, location: Int) async throws {
        try await perform(on: context) {
            try _seekDir(context: context, directory: directory, location: location)
        }
    }

    // MARK: - File Statistics

    private final class QueryFileSizeState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished = false
        var size: UInt64?
    }

    private static let queryFileSizeCallback: smb2_command_cb = { rawContext, status, commandData, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<QueryFileSizeState>.fromOpaque(callbackData).takeUnretainedValue()
        if status == SMB2_STATUS_SUCCESS, let rawContext, let commandData {
            let reply = commandData.assumingMemoryBound(to: smb2_query_info_reply.self).pointee
            if let buffer = reply.output_buffer {
                defer { smb2_free_data(rawContext, buffer) }
                if reply.output_buffer_length >= 24 {
                    state.size = buffer.withMemoryRebound(to: smb2_file_standard_info.self, capacity: 1) {
                        $0.pointee.end_of_file
                    }
                }
            }
        }
        state.finish(status)
    }

    /// Queries the original handle's current size without requiring read-data or read-attributes access.
    private static func _getFileSize(context: Context, file: FileHandle) throws -> UInt64 {
        let operation = "smb2_query_info(FILE_STANDARD_INFORMATION)"
        let raw = try file.requireRaw(operation: .smb2Fstat)
        guard let fileID = smb2_get_file_id(raw) else {
            throw SMB.Error.fromBridge(context, operation: "smb2_get_file_id")
        }
        clearError(on: context)
        let state = QueryFileSizeState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { releaseWhenFinished(state, callbackData) }
        var request = smb2_query_info_request()
        request.info_type = UInt8(SMB2_0_INFO_FILE)
        request.file_info_class = UInt8(SMB2_FILE_STANDARD_INFORMATION)
        request.output_buffer_length = 24
        request.file_id = fileID.pointee
        guard let pdu = smb2_cmd_query_info_async(context.raw, &request, queryFileSizeCallback, callbackData) else {
            state.isFinished = true
            throw SMB.Error.fromBridge(context, operation: operation)
        }
        smb2_queue_pdu(context.raw, pdu)
        try serviceUntilFinished(context: context, state: state)
        if state.status != SMB2_STATUS_SUCCESS {
            throw SMB.Error.fromBridge(context, operation: operation, status: state.status)
        }
        guard let size = state.size else {
            throw SMB.Error.ntStatus(
                .invalidNetworkResponse,
                posixCode: nil,
                operation: operation,
                message: "Server returned no complete file standard information"
            )
        }
        return size
    }

    private class StatusState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished = false
    }

    private final class OutputState<Value>: StatusState {
        let pointer: UnsafeMutablePointer<Value>

        init(_ value: Value) {
            pointer = .allocate(capacity: 1)
            pointer.initialize(to: value)
        }

        deinit {
            pointer.deinitialize(count: 1)
            pointer.deallocate()
        }
    }

    private static let statusCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        Unmanaged<StatusState>.fromOpaque(callbackData).takeUnretainedValue().finish(status)
    }

    private static func performStatus(
        context: Context,
        operation: String,
        _ body: (smb2_command_cb, UnsafeMutableRawPointer) -> Int32
    ) throws {
        let state = StatusState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { releaseWhenFinished(state, callbackData) }
        let status = body(statusCallback, callbackData)
        guard status == 0 else {
            state.finish(status)
            throw SMB.Error.fromBridge(context, operation: operation, status: status)
        }
        try serviceUntilFinished(context: context, state: state)
        try check(state.status, context: context, operation: operation)
    }

    private static func performOutput<Value>(
        _ value: Value,
        context: Context,
        operation: String,
        _ body: (UnsafeMutablePointer<Value>, smb2_command_cb, UnsafeMutableRawPointer) -> Int32
    ) throws -> Value {
        let state = OutputState(value)
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { releaseWhenFinished(state, callbackData) }
        let status = body(state.pointer, statusCallback, callbackData)
        guard status == 0 else {
            state.finish(status)
            throw SMB.Error.fromBridge(context, operation: operation, status: status)
        }
        try serviceUntilFinished(context: context, state: state)
        try check(state.status, context: context, operation: operation)
        return state.pointer.pointee
    }

    private static func _statVFS(context: Context, path: String) throws -> VFSStat {
        let statvfs = try performOutput(
            smb2_statvfs(),
            context: context,
            operation: "smb2_statvfs"
        ) { pointer, callback, data in
            path.withCString { smb2_statvfs_async(context.raw, $0, pointer, callback, data) }
        }
        return VFSStat(statvfs)
    }

    /// Returns filesystem statistics for a path.
    static func statVFS(context: Context, path: String) async throws -> VFSStat {
        try await perform(on: context) {
            try _statVFS(context: context, path: path)
        }
    }

    private static func _fileStatistics(context: Context, file: FileHandle) throws -> Stat {
        let raw = try file.requireRaw(operation: .smb2Fstat)
        let stat = try performOutput(smb2_stat_64(), context: context, operation: "smb2_fstat") {
            smb2_fstat_async(context.raw, raw, $0, $1, $2)
        }
        return Stat(stat)
    }

    /// Returns file statistics for an open file handle.
    static func fileStatistics(context: Context, file: FileHandle) async throws -> Stat {
        try await perform(on: context) {
            try _fileStatistics(context: context, file: file)
        }
    }

    private static func _fileStatistics(context: Context, path: String) throws -> Stat {
        let stat = try performOutput(
            smb2_stat_64(),
            context: context,
            operation: "smb2_stat"
        ) { pointer, callback, data in
            path.withCString { smb2_stat_async(context.raw, $0, pointer, callback, data) }
        }
        return Stat(stat)
    }

    /// Returns file statistics for a path.
    static func fileStatistics(context: Context, path: String) async throws -> Stat {
        try await perform(on: context) {
            try _fileStatistics(context: context, path: path)
        }
    }

    private static func _rename(context: Context, oldPath: String, newPath: String) throws {
        let status = oldPath.withCString { oldPathPointer in
            newPath.withCString { newPathPointer in
                smb2_rename(context.raw, oldPathPointer, newPathPointer)
            }
        }

        try check(status, context: context, operation: "smb2_rename")
    }

    /// Renames or moves an entry from one path to another.
    static func rename(context: Context, oldPath: String, newPath: String) async throws {
        try await perform(on: context) {
            try _rename(context: context, oldPath: oldPath, newPath: newPath)
        }
    }

    private static func _truncate(context: Context, path: String, length: UInt64) throws {
        try check(
            path.withCString { smb2_truncate(context.raw, $0, length) },
            context: context,
            operation: "smb2_truncate"
        )
    }

    /// Truncates a file at a path to a length in bytes.
    static func truncate(context: Context, path: String, length: UInt64) async throws {
        try await perform(on: context) {
            try _truncate(context: context, path: path, length: length)
        }
    }

    private static func _truncate(context: Context, file: FileHandle, length: UInt64) throws {
        let raw = try file.requireRaw(operation: .smb2Ftruncate)
        try performStatus(context: context, operation: "smb2_ftruncate") {
            smb2_ftruncate_async(context.raw, raw, length, $0, $1)
        }
    }

    /// Truncates an open file handle to a length in bytes.
    static func truncate(context: Context, file: FileHandle, length: UInt64) async throws {
        try await perform(on: context) {
            try _truncate(context: context, file: file, length: length)
        }
    }

    private static func _echo(context: Context) throws {
        try check(smb2_echo(context.raw), context: context, operation: "smb2_echo")
    }

    /// Sends an SMB echo request to verify the connection is responsive.
    static func echo(context: Context) async throws {
        try await perform(on: context) {
            try _echo(context: context)
        }
    }

    // MARK: - Private Helpers

    /// Checks an SMB status code and throws if it indicates an error.
    @discardableResult static func check(
        _ status: Int32,
        context: Context,
        operation: String
    ) throws -> Int32 {
        guard status >= 0 else {
            throw SMB.Error.fromBridge(context, operation: operation, status: status)
        }
        return status
    }

    // MARK: - File Stats Helpers

    private static let fileBasicInformationWireLength = 40

    protocol PendingOperationState: AnyObject {
        var status: Int32 { get set }
        var isFinished: Bool { get set }
    }

    private final class SetStatsState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished: Bool = false
    }

    private final class QueryAttributesState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished: Bool = false
        var fileAttributes: UInt32 = 0
        var hasAttributes = false
    }

    private static let setStatsCreateCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<SetStatsState>.fromOpaque(callbackData).takeUnretainedValue()
        state.recordStatus(status)
    }

    private static let setStatsSetCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<SetStatsState>.fromOpaque(callbackData).takeUnretainedValue()
        state.recordStatus(status)
    }

    private static let setStatsCloseCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<SetStatsState>.fromOpaque(callbackData).takeUnretainedValue()
        state.finish(status)
    }

    private static let queryAttributesCreateCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<QueryAttributesState>.fromOpaque(callbackData).takeUnretainedValue()
        state.recordStatus(status)
    }

    private static let queryAttributesQueryCallback: smb2_command_cb =
        { rawContext, status, commandData, callbackData in
            guard let callbackData else { return }
            let state = Unmanaged<QueryAttributesState>.fromOpaque(callbackData).takeUnretainedValue()
            state.recordStatus(status)
            if status == SMB2_STATUS_SUCCESS, let commandData {
                let reply = commandData.bindMemory(to: smb2_query_info_reply.self, capacity: 1)
                if let rawContext, let buffer = reply.pointee.output_buffer {
                    defer { smb2_free_data(rawContext, buffer) }
                    guard reply.pointee.output_buffer_length >= fileBasicInformationWireLength else {
                        return
                    }
                    let info = buffer.withMemoryRebound(to: smb2_file_basic_info.self, capacity: 1) { $0.pointee }
                    state.fileAttributes = info.file_attributes
                    state.hasAttributes = true
                }
            }
        }

    private static let queryAttributesCloseCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<QueryAttributesState>.fromOpaque(callbackData).takeUnretainedValue()
        state.finish(status)
    }

    /// Converts a date to libsmb2's basic-information timestamp representation without trapping.
    static func basicInfoTimeval(from date: Date?) throws -> smb2_timeval {
        guard let date else {
            return smb2_timeval(tv_sec: 0xFFFF_FFFF, tv_usec: CLong(truncatingIfNeeded: UInt32.max))
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
            return smb2_timeval(tv_sec: -1, tv_usec: 1_000_000)
        }
        return smb2_timeval(tv_sec: seconds, tv_usec: microseconds)
    }

    static func serviceUntilFinished(context: Context, state: some PendingOperationState) throws {
        do {
            var pfd = pollfd()
            while !state.isFinished {
                // Without a connection, poll() ignores the descriptor and this loop would never finish. libsmb2's own
                // synchronous wait loop fails in this case too.
                pfd.fd = smb2_get_fd(context.raw)
                guard pfd.fd >= 0 else {
                    throw noConnectionError(operation: "smb2_service")
                }
                pfd.events = Int16(smb2_which_events(context.raw))
                var rc: Int32 = 0
                repeat {
                    rc = withUnsafeMutablePointer(to: &pfd) { poll($0, 1, 1000) }
                }
                while rc < 0 && errno == EINTR
                if rc < 0 {
                    throw SMB.Error.posix(
                        code: errno,
                        operation: "poll",
                        message: "poll failed while waiting for SMB2 operation"
                    )
                }
                if smb2_service(context.raw, Int32(pfd.revents)) < 0 {
                    throw SMB.Error.fromBridge(context, operation: "smb2_service")
                }
            }
        }
        catch {
            // An unfinished C command can still hold its handle and buffers. Abort all callbacks before another
            // operation can close that handle or overwrite callback data that libsmb2 stores directly on it.
            _destroyContext(context)
            throw error
        }
    }

    /// The error thrown when a context has no connection to service.
    static func noConnectionError(operation: String) -> SMB.Error {
        .posix(code: POSIXErrorCode.ENOTCONN.rawValue, operation: operation, message: "No connection exists")
    }

    /// Balances `Unmanaged.passRetained(state)` for a queued command once no callback can reference `state` any more.
    ///
    /// A queued PDU keeps its callback data until its last callback runs, which can happen after the caller stopped
    /// waiting — for example with `SMB2_STATUS_SHUTDOWN` when the context is destroyed after a network error. If the
    /// operation did not finish, `state` is deliberately leaked so that such a late callback never touches freed
    /// memory.
    static func releaseWhenFinished<State: PendingOperationState>(
        _ state: State,
        _ callbackData: UnsafeMutableRawPointer
    ) {
        guard state.isFinished else {
            return
        }
        Unmanaged<State>.fromOpaque(callbackData).release()
    }

    private static func _setStats(
        context: Context,
        path: String,
        creationTime: Date? = nil,
        lastAccessTime: Date? = nil,
        lastWriteTime: Date? = nil,
        changeTime: Date? = nil,
        fileAttributes: UInt32? = nil
    ) throws {
        var info = try smb2_file_basic_info(
            creation_time: basicInfoTimeval(from: creationTime),
            last_access_time: basicInfoTimeval(from: lastAccessTime),
            last_write_time: basicInfoTimeval(from: lastWriteTime),
            change_time: basicInfoTimeval(from: changeTime),
            file_attributes: fileAttributes ?? 0
        )

        let state = SetStatsState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        var isQueued = false
        defer {
            if !isQueued {
                state.isFinished = true
            }
            releaseWhenFinished(state, callbackData)
        }

        try path.withCString { pathPointer in
            try withUnsafeMutablePointer(to: &info) { infoPointer in
                var cr_req = smb2_create_request(
                    security_flags: 0,
                    requested_oplock_level: 0,
                    impersonation_level: UInt32(SMB2_IMPERSONATION_IMPERSONATION),
                    smb_create_flags: 0,
                    desired_access: UInt32(SMB2_FILE_WRITE_ATTRIBUTES),
                    file_attributes: 0,
                    share_access: UInt32(SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE),
                    create_disposition: UInt32(SMB2_FILE_OPEN),
                    create_options: 0,
                    name_offset: 0,
                    name_length: 0,
                    name: pathPointer,
                    create_context_offset: 0,
                    create_context_length: 0,
                    create_context: nil
                )

                guard let pdu = smb2_cmd_create_async(context.raw, &cr_req, setStatsCreateCallback, callbackData) else {
                    throw SMB.Error.fromBridge(context, operation: "smb2_cmd_create_async")
                }

                var si_req = smb2_set_info_request(
                    info_type: 1,
                    file_info_class: 4,
                    buffer_length: 0,
                    buffer_offset: 0,
                    additional_information: 0,
                    file_id: FileID.allOnes.raw,
                    input_data: infoPointer
                )

                guard let next_pdu = smb2_cmd_set_info_async(context.raw, &si_req, setStatsSetCallback, callbackData) else {
                    smb2_free_pdu(context.raw, pdu)
                    throw SMB.Error.fromBridge(context, operation: "smb2_cmd_set_info_async")
                }
                smb2_add_compound_pdu(context.raw, pdu, next_pdu)

                var cl_req = smb2_close_request(
                    flags: 0,
                    file_id: FileID.allOnes.raw
                )

                guard let close_pdu = smb2_cmd_close_async(context.raw, &cl_req, setStatsCloseCallback, callbackData) else {
                    smb2_free_pdu(context.raw, pdu)
                    throw SMB.Error.fromBridge(context, operation: "smb2_cmd_close_async")
                }
                smb2_add_compound_pdu(context.raw, pdu, close_pdu)

                smb2_queue_pdu(context.raw, pdu)
                isQueued = true

                try serviceUntilFinished(context: context, state: state)

                if state.status != SMB2_STATUS_SUCCESS {
                    throw SMB.Error.fromBridge(context, operation: "setStats", status: state.status)
                }
            }
        }
    }

    /// Sets basic file information (timestamps and attributes) for a path.
    static func setStats(
        context: Context,
        path: String,
        creationTime: Date? = nil,
        lastAccessTime: Date? = nil,
        lastWriteTime: Date? = nil,
        changeTime: Date? = nil,
        fileAttributes: UInt32? = nil
    ) async throws {
        try await perform(on: context) {
            try _setStats(
                context: context,
                path: path,
                creationTime: creationTime,
                lastAccessTime: lastAccessTime,
                lastWriteTime: lastWriteTime,
                changeTime: changeTime,
                fileAttributes: fileAttributes
            )
        }
    }

    private static func _getFileAttributes(context: Context, path: String) throws -> UInt32 {
        let state = QueryAttributesState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        var isQueued = false
        defer {
            if !isQueued {
                state.isFinished = true
            }
            releaseWhenFinished(state, callbackData)
        }

        return try path.withCString { pathPointer in
            var cr_req = smb2_create_request(
                security_flags: 0,
                requested_oplock_level: 0,
                impersonation_level: UInt32(SMB2_IMPERSONATION_IMPERSONATION),
                smb_create_flags: 0,
                desired_access: UInt32(SMB2_FILE_READ_ATTRIBUTES),
                file_attributes: 0,
                share_access: UInt32(SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE),
                create_disposition: UInt32(SMB2_FILE_OPEN),
                create_options: 0,
                name_offset: 0,
                name_length: 0,
                name: pathPointer,
                create_context_offset: 0,
                create_context_length: 0,
                create_context: nil
            )

            guard let pdu = smb2_cmd_create_async(context.raw, &cr_req, queryAttributesCreateCallback, callbackData) else {
                throw SMB.Error.fromBridge(context, operation: "smb2_cmd_create_async")
            }

            var qi_req = smb2_query_info_request(
                info_type: 1,
                file_info_class: 4,
                output_buffer_length: 4096,
                input_buffer_offset: 0,
                input_buffer_length: 0,
                input_buffer: nil,
                additional_information: 0,
                flags: 0,
                file_id: FileID.allOnes.raw,
                input: nil
            )

            guard let next_pdu = smb2_cmd_query_info_async(
                context.raw,
                &qi_req,
                queryAttributesQueryCallback,
                callbackData
            ) else {
                smb2_free_pdu(context.raw, pdu)
                throw SMB.Error.fromBridge(context, operation: "smb2_cmd_query_info_async")
            }
            smb2_add_compound_pdu(context.raw, pdu, next_pdu)

            var cl_req = smb2_close_request(
                flags: 0,
                file_id: FileID.allOnes.raw
            )

            guard let close_pdu = smb2_cmd_close_async(
                context.raw,
                &cl_req,
                queryAttributesCloseCallback,
                callbackData
            ) else {
                smb2_free_pdu(context.raw, pdu)
                throw SMB.Error.fromBridge(context, operation: "smb2_cmd_close_async")
            }
            smb2_add_compound_pdu(context.raw, pdu, close_pdu)

            smb2_queue_pdu(context.raw, pdu)
            isQueued = true

            try serviceUntilFinished(context: context, state: state)

            if state.status != SMB2_STATUS_SUCCESS {
                throw SMB.Error.fromBridge(context, operation: "getFileAttributes", status: state.status)
            }
            guard state.hasAttributes else {
                throw SMB.Error.ntStatus(
                    .invalidNetworkResponse,
                    posixCode: nil,
                    operation: "getFileAttributes",
                    message: "Server returned no complete file basic information"
                )
            }

            return state.fileAttributes
        }
    }

    /// Returns the file attributes for a path.
    static func getFileAttributes(context: Context, path: String) async throws -> UInt32 {
        try await perform(on: context) {
            try _getFileAttributes(context: context, path: path)
        }
    }

    // MARK: - Server-Side Copy Helpers

    /// Per-request limits for FSCTL_SRV_COPYCHUNK, as advertised by the server in a SRV_COPYCHUNK_RESPONSE (MS-SMB2
    /// 2.2.32.1).
    private struct CopyChunkLimits {
        let maxChunkCount: UInt32
        let maxChunkLength: UInt32
        let maxTotalLength: UInt32
    }

    /// A single chunk in a server-side copy request.
    private struct CopyChunk {
        let sourceOffset: UInt64
        let targetOffset: UInt64
        let length: UInt32
    }

    private final class ResumeKeyState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished = false
        var resumeKey: smb2_srv_copychunk_resume_key?
    }

    private static let resumeKeyCallback: smb2_command_cb = { rawContext, status, commandData, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<ResumeKeyState>.fromOpaque(callbackData).takeUnretainedValue()
        if let rawContext, let commandData {
            if status == 0 {
                state.resumeKey = commandData.assumingMemoryBound(to: smb2_srv_copychunk_resume_key.self).pointee
            }
            smb2_free_data(rawContext, commandData)
        }
        state.finish(status)
    }

    private final class CopyChunkState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished = false
        var reply: smb2_srv_copychunk_reply?
    }

    private static let copyChunkCallback: smb2_command_cb = { rawContext, status, commandData, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<CopyChunkState>.fromOpaque(callbackData).takeUnretainedValue()
        if let rawContext, let commandData {
            state.reply = commandData.assumingMemoryBound(to: smb2_srv_copychunk_reply.self).pointee
            smb2_free_data(rawContext, commandData)
        }
        state.finish(status)
    }

    private static func _requestResumeKey(
        context: Context,
        sourceHandle: OpaquePointer
    ) throws -> smb2_srv_copychunk_resume_key {
        let state = ResumeKeyState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { releaseWhenFinished(state, callbackData) }
        let status = smb2_request_resume_key_async(context.raw, sourceHandle, resumeKeyCallback, callbackData)
        guard status == 0 else {
            state.finish(status)
            throw SMB.Error.fromBridge(context, operation: "smb2_request_resume_key", status: status)
        }
        try serviceUntilFinished(context: context, state: state)
        try check(state.status, context: context, operation: "smb2_request_resume_key")
        guard let resumeKey = state.resumeKey else {
            throw SMB.Error.unknown(operation: "smb2_request_resume_key", message: "Server returned no resume key")
        }
        return resumeKey
    }

    /// Sends one FSCTL_SRV_COPYCHUNK request containing `chunks`.
    ///
    /// - Returns: `nil` on success, or the server's advertised limits when it rejected the request with
    /// `STATUS_INVALID_PARAMETER` (MS-SMB2 3.3.5.15.6.1).
    private static func _copyChunks(
        context: Context,
        destinationHandle: OpaquePointer,
        resumeKey: smb2_srv_copychunk_resume_key,
        chunks: [CopyChunk]
    ) throws -> CopyChunkLimits? {
        clearError(on: context)
        var resumeKey = resumeKey
        var rawChunks = chunks.map {
            smb2_srv_copychunk(
                source_offset: $0.sourceOffset,
                target_offset: $0.targetOffset,
                length: $0.length,
                reserved: 0
            )
        }
        let state = CopyChunkState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { releaseWhenFinished(state, callbackData) }
        let status = rawChunks.withUnsafeMutableBufferPointer { buffer in
            smb2_copychunk_async(
                context.raw,
                UInt32(SMB2_FSCTL_SRV_COPYCHUNK),
                &resumeKey,
                destinationHandle,
                buffer.baseAddress,
                UInt32(buffer.count),
                copyChunkCallback,
                callbackData
            )
        }

        guard status == 0 else {
            state.finish(status)
            throw SMB.Error.fromBridge(context, operation: "smb2_copychunk", status: status)
        }
        try serviceUntilFinished(context: context, state: state)
        let reply = state.reply ?? smb2_srv_copychunk_reply()

        if state.status < 0,
           UInt32(bitPattern: smb2_get_nterror(context.raw)) == SMB.SMBStatus.invalidParameter.rawValue,
           reply.chunks_written > 0,
           reply.chunk_bytes_written > 0,
           reply.total_bytes_written > 0 {
            return CopyChunkLimits(
                maxChunkCount: reply.chunks_written,
                maxChunkLength: reply.chunk_bytes_written,
                maxTotalLength: reply.total_bytes_written
            )
        }

        try check(state.status, context: context, operation: "smb2_copychunk")
        let expectedLength = chunks.reduce(UInt64(0)) { $0 + UInt64($1.length) }
        guard UInt64(reply.total_bytes_written) == expectedLength,
              reply.chunks_written == UInt32(chunks.count) else {
            throw SMB.Error.unknown(
                operation: "smb2_copychunk",
                message: "Server returned an incomplete copy response"
            )
        }
        return nil
    }

    /// Splits the region starting at `offset` into as many chunks as one COPYCHUNK request allows under `limits`.
    private static func planCopyChunks(
        from offset: UInt64,
        fileSize: UInt64,
        limits: CopyChunkLimits
    ) -> [CopyChunk] {
        var chunks: [CopyChunk] = []
        var position = offset
        var budget = UInt64(limits.maxTotalLength)
        // The advertised count is a maximum, so a smaller client cap is valid and prevents an untrusted server from
        // making us allocate billions of tiny chunks.
        let maximumChunkCount = min(Int(limits.maxChunkCount), 256)
        while position < fileSize, chunks.count < maximumChunkCount, budget > 0 {
            let length = min(UInt64(limits.maxChunkLength), fileSize - position, budget)
            chunks.append(CopyChunk(sourceOffset: position, targetOffset: position, length: UInt32(length)))
            position += length
            budget -= length
        }
        return chunks
    }

    private static func _serverSideCopy(
        context: Context,
        sourcePath: String,
        destinationPath: String,
        chunkSize: UInt32,
        exclusiveDestination: Bool
    ) throws {
        let stat = try _fileStatistics(context: context, path: sourcePath)
        // A directory reports size 0, which the empty-file shortcut below would silently "copy" to an empty file.
        guard stat.type != .directory else {
            throw SMB.Error.invalidArgument(cause: .remotePathIsNotAFile, onOperation: .smbConnectionCopyFile)
        }
        let fileSize = stat.size
        let destinationOptions: OpenOptions = exclusiveDestination ? [.create, .exclusive] : [.create, .truncate]

        guard fileSize > 0 else {
            let destination = try _open(
                context: context,
                path: destinationPath,
                flags: .init(.writeOnly, options: destinationOptions)
            )
            do {
                try _close(context: context, file: destination)
            }
            catch {
                if exclusiveDestination, context.isAlive {
                    try? _unlink(context: context, path: destinationPath)
                }
                throw error
            }
            return
        }

        let source = try _open(context: context, path: sourcePath)
        defer { try? _close(context: context, file: source) }
        let resumeKey = try _requestResumeKey(context: context, sourceHandle: source.requireRaw(operation: .smb2Read))

        let destination = try _open(
            context: context,
            path: destinationPath,
            flags: .init(.readWrite, options: destinationOptions)
        )
        defer { try? _close(context: context, file: destination) }

        do {
            // Start with one chunk sized to the negotiated max write size. If the server rejects that with its
            // COPYCHUNK limits, adopt them once and retry the same region with batched chunks.
            var limits = CopyChunkLimits(maxChunkCount: 1, maxChunkLength: chunkSize, maxTotalLength: chunkSize)
            var didAdoptServerLimits = false
            var offset: UInt64 = 0
            while offset < fileSize {
                let chunks = planCopyChunks(from: offset, fileSize: fileSize, limits: limits)
                if let serverLimits = try _copyChunks(
                    context: context,
                    destinationHandle: destination.requireRaw(operation: .smb2Write),
                    resumeKey: resumeKey,
                    chunks: chunks
                ) {
                    guard !didAdoptServerLimits,
                          serverLimits.maxChunkCount > 0,
                          serverLimits.maxChunkLength > 0,
                          serverLimits.maxTotalLength > 0 else {
                        throw SMB.Error.unknown(
                            operation: "FSCTL_SRV_COPYCHUNK",
                            message: "Server rejected a copy request that honors its advertised limits"
                        )
                    }
                    didAdoptServerLimits = true
                    limits = serverLimits
                    continue
                }
                offset += chunks.reduce(0) { $0 + UInt64($1.length) }
            }
            try _close(context: context, file: destination)
            try _close(context: context, file: source)
        }
        catch {
            try? _close(context: context, file: destination)
            // An exclusive creator owns its partial destination; an overwrite caller may have supplied an existing
            // destination, which must remain the caller's responsibility on failure.
            if exclusiveDestination, context.isAlive {
                try? _unlink(context: context, path: destinationPath)
            }
            throw error
        }
    }

    /// Copies a file from source to destination using SMB2 server-side copy.
    static func serverSideCopy(
        context: Context,
        sourcePath: String,
        destinationPath: String,
        exclusiveDestination: Bool = false
    ) async throws {
        try await perform(on: context) {
            let chunkSize = max(smb2_get_max_write_size(context.raw), 1)
            try _serverSideCopy(
                context: context,
                sourcePath: sourcePath,
                destinationPath: destinationPath,
                chunkSize: chunkSize,
                exclusiveDestination: exclusiveDestination
            )
        }
    }
}

extension Bridge.PendingOperationState {
    /// Records a command's status, keeping the first non-success status seen.
    func recordStatus(_ status: Int32) {
        if self.status == SMB2_STATUS_SUCCESS {
            self.status = status
        }
    }

    /// Records a command's status and marks the operation as finished.
    func finish(_ status: Int32) {
        recordStatus(status)
        isFinished = true
    }
}

// MARK: - String Extensions
