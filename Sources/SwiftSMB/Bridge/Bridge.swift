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
                continuation.resume(with: Result { try body() })
            }
        }
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
            smb2_close_context(context.raw)
        }
    }

    /// Destroys a context and marks it dead. Must run on the context queue, or on a context that was never shared.
    static func _destroyContext(_ context: Context) {
        lifecycleLock.withLock { _ in
            smb2_destroy_context(context.raw)
        }
        context.isAlive = false
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

    /// Disconnects, closes, and destroys a context without waiting. Used from `deinit`, which cannot await.
    static func teardownInBackground(_ context: Context) {
        performInBackground(on: context) {
            _ = try? _disconnectShare(context: context)
            smb2_close_context(context.raw)
            _destroyContext(context)
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
        let rawHandle = path.withCString { smb2_open(context.raw, $0, flags.rawValue) }

        guard let rawHandle else {
            throw SMB.Error.fromBridge(context, operation: "smb2_open")
        }

        return FileHandle(raw: rawHandle)
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
        var fileHandle: OpaquePointer?
    }

    private static let openCallback: smb2_command_cb = { _, status, commandData, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<OpenState>.fromOpaque(callbackData).takeUnretainedValue()
        if status == 0, let commandData {
            state.fileHandle = OpaquePointer(commandData)
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
        let state = OpenState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { Unmanaged<OpenState>.fromOpaque(callbackData).release() }

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
            throw SMB.Error.fromBridge(context, operation: "smb2_open_async_with_oplock_or_lease")
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

        return FileHandle(raw: handle)
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

    private static func _close(context: Context, file: FileHandle) throws {
        try check(smb2_close(context.raw, file.raw), context: context, operation: "smb2_close")
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
        try check(smb2_fsync(context.raw, file.raw), context: context, operation: "smb2_fsync")
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

    /// Allocates `count` bytes, lets `body` fill them, and returns the prefix `body` reports as read.
    private static func readData(
        count: Int,
        context: Context,
        operation: String,
        _ body: (UnsafeMutablePointer<UInt8>?) -> Int32
    ) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { bytes in
            body(bytes.baseAddress?.assumingMemoryBound(to: UInt8.self))
        }
        data.count = try Int(check(status, context: context, operation: operation))
        return data
    }

    /// Calls `body` with a pointer to `data`'s bytes and returns the number of bytes `body` reports as written.
    private static func writeData(
        _ data: Data,
        context: Context,
        operation: String,
        _ body: (UnsafePointer<UInt8>?) -> Int32
    ) throws -> Int {
        let status = data.withUnsafeBytes { bytes in
            body(bytes.baseAddress?.assumingMemoryBound(to: UInt8.self))
        }
        return try Int(check(status, context: context, operation: operation))
    }

    /// Reads up to `count` bytes from a file at an explicit offset.
    ///
    /// - Returns: The bytes read. An empty value indicates end of file.
    static func read(context: Context, file: FileHandle, count: Int, offset: UInt64) async throws -> Data {
        let byteCount = try count.asUInt32(operation: .smb2Pread)
        return try await perform(on: context) {
            try readData(count: count, context: context, operation: "smb2_pread") {
                smb2_pread(context.raw, file.raw, $0, byteCount, offset)
            }
        }
    }

    /// Writes bytes to a file at an explicit offset.
    ///
    /// - Returns: The number of bytes the server accepted, which may be fewer than `data.count`.
    static func write(context: Context, file: FileHandle, data: Data, offset: UInt64) async throws -> Int {
        let byteCount = try data.count.asUInt32(operation: .smb2Pwrite)
        return try await perform(on: context) {
            try writeData(data, context: context, operation: "smb2_pwrite") {
                smb2_pwrite(context.raw, file.raw, $0, byteCount, offset)
            }
        }
    }

    /// Reads up to `count` bytes from the current file offset.
    ///
    /// - Returns: The bytes read. An empty value indicates end of file.
    static func read(context: Context, file: FileHandle, count: Int) async throws -> Data {
        let byteCount = try count.asUInt32(operation: .smb2Read)
        return try await perform(on: context) {
            try readData(count: count, context: context, operation: "smb2_read") {
                smb2_read(context.raw, file.raw, $0, byteCount)
            }
        }
    }

    /// Writes bytes at the current file offset.
    ///
    /// - Returns: The number of bytes the server accepted, which may be fewer than `data.count`.
    static func write(context: Context, file: FileHandle, data: Data) async throws -> Int {
        let byteCount = try data.count.asUInt32(operation: .smb2Write)
        return try await perform(on: context) {
            try writeData(data, context: context, operation: "smb2_write") {
                smb2_write(context.raw, file.raw, $0, byteCount)
            }
        }
    }

    private static func _seek(
        context: Context,
        file: FileHandle,
        offset: Int64,
        whence: Int32
    ) throws -> UInt64 {
        var currentOffset: UInt64 = 0
        let status = smb2_lseek(context.raw, file.raw, offset, whence, &currentOffset)
        guard status >= 0 else {
            throw SMB.Error.fromBridge(context, operation: "smb2_lseek", status: Int32(clamping: status))
        }

        return currentOffset
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

    private static func _openDir(context: Context, path: String) throws -> DirectoryHandle {
        let rawDirectory = path.withCString { smb2_opendir(context.raw, $0) }

        guard let rawDirectory else {
            throw SMB.Error.fromBridge(context, operation: "smb2_opendir")
        }

        return DirectoryHandle(raw: rawDirectory)
    }

    /// Opens a directory and returns a directory handle.
    static func openDir(context: Context, path: String) async throws -> DirectoryHandle {
        try await perform(on: context) {
            try _openDir(context: context, path: path)
        }
    }

    private static func _closeDir(context: Context, directory: DirectoryHandle) {
        smb2_closedir(context.raw, directory.raw)
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

    private static func _readDir(context: Context, directory: DirectoryHandle) -> DirectoryEntry? {
        smb2_readdir(context.raw, directory.raw).map { DirectoryEntry($0.pointee) }
    }

    /// Reads the next directory entry from a directory handle.
    static func readDir(context: Context, directory: DirectoryHandle) async throws -> DirectoryEntry? {
        try await perform(on: context) {
            _readDir(context: context, directory: directory)
        }
    }

    private static func _rewindDir(context: Context, directory: DirectoryHandle) {
        smb2_rewinddir(context.raw, directory.raw)
    }

    /// Rewinds a directory handle to the first entry.
    static func rewindDir(context: Context, directory: DirectoryHandle) async throws {
        try await perform(on: context) {
            _rewindDir(context: context, directory: directory)
        }
    }

    private static func _tellDir(context: Context, directory: DirectoryHandle) -> Int {
        Int(smb2_telldir(context.raw, directory.raw))
    }

    /// Returns the current directory stream location.
    static func tellDir(context: Context, directory: DirectoryHandle) async throws -> Int {
        try await perform(on: context) {
            _tellDir(context: context, directory: directory)
        }
    }

    private static func _seekDir(context: Context, directory: DirectoryHandle, location: Int) {
        smb2_seekdir(context.raw, directory.raw, numericCast(location))
    }

    /// Moves a directory handle to a previously returned stream location.
    static func seekDir(context: Context, directory: DirectoryHandle, location: Int) async throws {
        try await perform(on: context) {
            _seekDir(context: context, directory: directory, location: location)
        }
    }

    // MARK: - File Statistics

    private static func _statVFS(context: Context, path: String) throws -> VFSStat {
        var statvfs = smb2_statvfs()
        try check(
            path.withCString { smb2_statvfs(context.raw, $0, &statvfs) },
            context: context,
            operation: "smb2_statvfs"
        )
        return VFSStat(statvfs)
    }

    /// Returns filesystem statistics for a path.
    static func statVFS(context: Context, path: String) async throws -> VFSStat {
        try await perform(on: context) {
            try _statVFS(context: context, path: path)
        }
    }

    private static func _fileStatistics(context: Context, file: FileHandle) throws -> Stat {
        var stat = smb2_stat_64()
        try check(smb2_fstat(context.raw, file.raw, &stat), context: context, operation: "smb2_fstat")
        return Stat(stat)
    }

    /// Returns file statistics for an open file handle.
    static func fileStatistics(context: Context, file: FileHandle) async throws -> Stat {
        try await perform(on: context) {
            try _fileStatistics(context: context, file: file)
        }
    }

    private static func _fileStatistics(context: Context, path: String) throws -> Stat {
        var stat = smb2_stat_64()
        try check(
            path.withCString { smb2_stat(context.raw, $0, &stat) },
            context: context,
            operation: "smb2_stat"
        )
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
        try check(smb2_ftruncate(context.raw, file.raw, length), context: context, operation: "smb2_ftruncate")
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
                }
            }
        }

    private static let queryAttributesCloseCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<QueryAttributesState>.fromOpaque(callbackData).takeUnretainedValue()
        state.finish(status)
    }

    static func serviceUntilFinished(context: Context, state: some PendingOperationState) throws {
        var pfd = pollfd()
        pfd.fd = smb2_get_fd(context.raw)

        while !state.isFinished {
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

    private static func _setStats(
        context: Context,
        path: String,
        creationTime: Date? = nil,
        lastAccessTime: Date? = nil,
        lastWriteTime: Date? = nil,
        changeTime: Date? = nil,
        fileAttributes: UInt32? = nil
    ) throws {
        let dontChangeTime = smb2_timeval(tv_sec: 0xFFFF_FFFF, tv_usec: 0xFFFF_FFFF)

        func smb2Timeval(from date: Date?) -> smb2_timeval {
            guard let date else {
                return dontChangeTime
            }
            let interval = date.timeIntervalSince1970
            let sec = time_t(interval)
            let usec = CLong((interval - Double(sec)) * 1_000_000)
            return smb2_timeval(tv_sec: sec, tv_usec: usec)
        }

        var info = smb2_file_basic_info(
            creation_time: smb2Timeval(from: creationTime),
            last_access_time: smb2Timeval(from: lastAccessTime),
            last_write_time: smb2Timeval(from: lastWriteTime),
            change_time: smb2Timeval(from: changeTime),
            file_attributes: fileAttributes ?? 0
        )

        let state = SetStatsState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { Unmanaged<SetStatsState>.fromOpaque(callbackData).release() }

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

        defer { Unmanaged<QueryAttributesState>.fromOpaque(callbackData).release() }

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

            try serviceUntilFinished(context: context, state: state)

            if state.status != SMB2_STATUS_SUCCESS {
                throw SMB.Error.fromBridge(context, operation: "getFileAttributes", status: state.status)
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

    private static func _requestResumeKey(
        context: Context,
        sourceHandle: OpaquePointer
    ) throws -> smb2_srv_copychunk_resume_key {
        var resumeKey = smb2_srv_copychunk_resume_key()
        try check(
            smb2_request_resume_key(context.raw, sourceHandle, &resumeKey),
            context: context,
            operation: "smb2_request_resume_key"
        )
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
        var resumeKey = resumeKey
        var rawChunks = chunks.map {
            smb2_srv_copychunk(
                source_offset: $0.sourceOffset,
                target_offset: $0.targetOffset,
                length: $0.length,
                reserved: 0
            )
        }
        var reply = smb2_srv_copychunk_reply()
        let status = rawChunks.withUnsafeMutableBufferPointer { buffer in
            smb2_copychunk(
                context.raw,
                UInt32(SMB2_FSCTL_SRV_COPYCHUNK),
                &resumeKey,
                destinationHandle,
                buffer.baseAddress,
                UInt32(buffer.count),
                &reply
            )
        }

        if status < 0,
           reply.chunks_written > 0,
           reply.chunk_bytes_written > 0,
           reply.total_bytes_written > 0 {
            return CopyChunkLimits(
                maxChunkCount: reply.chunks_written,
                maxChunkLength: reply.chunk_bytes_written,
                maxTotalLength: reply.total_bytes_written
            )
        }

        try check(status, context: context, operation: "smb2_copychunk")
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
        while position < fileSize, chunks.count < Int(limits.maxChunkCount), budget > 0 {
            let length = min(UInt64(limits.maxChunkLength), fileSize - position, budget)
            chunks.append(CopyChunk(sourceOffset: position, targetOffset: position, length: UInt32(length)))
            position += length
            budget -= length
        }
        return chunks
    }

    /// Closes a raw file handle, ignoring any error. Used to clean up handles on error paths.
    private static func closeQuietly(_ rawHandle: OpaquePointer, context: Context) {
        _ = try? check(smb2_close(context.raw, rawHandle), context: context, operation: "smb2_close")
    }

    private static func _serverSideCopy(
        context: Context,
        sourcePath: String,
        destinationPath: String,
        chunkSize: UInt32
    ) throws {
        var stat = smb2_stat_64()
        try check(
            sourcePath.withCString { smb2_stat(context.raw, $0, &stat) },
            context: context,
            operation: "smb2_stat"
        )
        let fileSize = stat.smb2_size

        guard fileSize > 0 else {
            let rawHandle = destinationPath.withCString {
                smb2_open(context.raw, $0, O_WRONLY | O_CREAT | O_TRUNC)
            }
            guard let rawHandle else {
                throw SMB.Error.fromBridge(context, operation: "smb2_open")
            }
            try check(smb2_close(context.raw, rawHandle), context: context, operation: "smb2_close")
            return
        }

        let rawSourceHandle = sourcePath.withCString {
            smb2_open(context.raw, $0, O_RDONLY)
        }
        guard let rawSourceHandle else {
            throw SMB.Error.fromBridge(context, operation: "smb2_open")
        }

        let resumeKey: smb2_srv_copychunk_resume_key
        do {
            resumeKey = try _requestResumeKey(context: context, sourceHandle: rawSourceHandle)
        }
        catch {
            closeQuietly(rawSourceHandle, context: context)
            throw error
        }

        let rawDestHandle = destinationPath.withCString {
            smb2_open(context.raw, $0, O_RDWR | O_CREAT | O_TRUNC)
        }
        guard let rawDestHandle else {
            closeQuietly(rawSourceHandle, context: context)
            throw SMB.Error.fromBridge(context, operation: "smb2_open")
        }

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
                    destinationHandle: rawDestHandle,
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
        }
        catch {
            closeQuietly(rawDestHandle, context: context)
            closeQuietly(rawSourceHandle, context: context)
            throw error
        }

        try check(smb2_close(context.raw, rawDestHandle), context: context, operation: "smb2_close")
        try check(smb2_close(context.raw, rawSourceHandle), context: context, operation: "smb2_close")
    }

    /// Copies a file from source to destination using SMB2 server-side copy.
    static func serverSideCopy(
        context: Context,
        sourcePath: String,
        destinationPath: String
    ) async throws {
        try await perform(on: context) {
            let chunkSize = max(smb2_get_max_write_size(context.raw), 1)
            try _serverSideCopy(
                context: context,
                sourcePath: sourcePath,
                destinationPath: destinationPath,
                chunkSize: chunkSize
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
