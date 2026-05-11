//
// Part of SwiftSMB
// Bridge.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SMB2
import SMB2.Raw

/// Central bridge class for all libsmb2 operations.
class Bridge {
    // MARK: - Synchronization
    
    //                               ⚠️
    // The underlying library, `libsmb2` is not thread-safe for the most part.
    // Use this synchronization apparatus to avoid MP problems.
    //

    private static let bridgeQueue = DispatchQueue(label: "com.ruinelson.swiftsmb.bridge")

    /// Executes a bridge operation on the bridge queue.
    private static func sync<T>(_ body: () throws -> T) rethrows -> T {
        try bridgeQueue.sync {
            try body()
        }
    }

    // MARK: - Context Management

    private static func _createContext() throws -> Context {
        guard let raw = smb2_init_context() else {
            throw SMB.Error.contextCreationFailed
        }

        return Context(raw: raw)
    }

    /// Creates a new libsmb2 context.
    static func createContext() throws -> Context {
        try sync {
            try _createContext()
        }
    }

    /// Closes the active connection for a context without destroying the context.
    static func closeContext(_ context: Context) {
        smb2_close_context(context.raw)
    }

    private static func _destroyContext(_ context: Context) {
        smb2_destroy_context(context.raw)
    }

    /// Destroys a libsmb2 context and any resources it owns.
    static func destroyContext(_ context: Context) {
        sync {
            _destroyContext(context)
        }
    }

    // MARK: - Configuration

    /// Sets the command timeout in seconds for a context.
    static func setTimeout(_ seconds: Int32, on context: Context) {
        smb2_set_timeout(context.raw, seconds)
    }

    /// Sets the SMB dialect negotiation preference for a context.
    static func setVersion(_ version: smb2_negotiate_version, on context: Context) {
        smb2_set_version(context.raw, version)
    }

    private static func _getDialect(on context: Context) -> UInt16 {
        smb2_get_dialect(context.raw)
    }

    /// Returns the currently negotiated SMB dialect for a context.
    static func getDialect(on context: Context) -> UInt16 {
        sync {
            _getDialect(on: context)
        }
    }

    /// Sets SMB signing-related negotiation flags for a context.
    static func setSecurityMode(_ securityMode: SecurityMode, on context: Context) {
        smb2_set_security_mode(context.raw, securityMode.rawValue)
    }

    /// Enables or disables SMB3 encryption for a context.
    static func setSeal(_ enabled: Bool, on context: Context) {
        smb2_set_seal(context.raw, enabled ? 1 : 0)
    }

    /// Enables or disables required SMB signing for a context.
    static func setSign(_ required: Bool, on context: Context) {
        smb2_set_sign(context.raw, required ? 1 : 0)
    }

    /// Sets the authentication mechanism for a context.
    static func setAuthentication(_ authentication: AuthenticationMethod, on context: Context) {
        smb2_set_authentication(context.raw, authentication.rawValue)
    }

    /// Sets the username used for authentication.
    static func setUser(_ user: String, on context: Context) {
        user.withCString { smb2_set_user(context.raw, $0) }
    }

    /// Returns the username currently configured on a context.
    static func getUser(on context: Context) -> String? {
        smb2_get_user(context.raw).map(String.init(cString:))
    }

    /// Sets the password used for authentication.
    static func setPassword(_ password: String, on context: Context) {
        password.withCString { smb2_set_password(context.raw, $0) }
    }

    /// Loads the password from the NTLM_USER_FILE credential file if available.
    static func setPasswordFromFile(on context: Context) {
        smb2_set_password_from_file(context.raw)
    }

    /// Sets the authentication domain for a context.
    static func setDomain(_ domain: String, on context: Context) {
        domain.withCString { smb2_set_domain(context.raw, $0) }
    }

    /// Returns the authentication domain currently configured on a context.
    static func getDomain(on context: Context) -> String? {
        smb2_get_domain(context.raw).map(String.init(cString:))
    }

    /// Sets the workstation name used for authentication.
    static func setWorkstation(_ workstation: String, on context: Context) {
        workstation.withCString { smb2_set_workstation(context.raw, $0) }
    }

    /// Returns the workstation name currently configured on a context.
    static func getWorkstation(on context: Context) -> String? {
        smb2_get_workstation(context.raw).map(String.init(cString:))
    }

    // MARK: - Connection

    private static func _connectShare(
        context: Context,
        server: String,
        share: String,
        user: String? = nil,
    ) throws {
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
        user: String? = nil,
    ) throws {
        try sync {
            try _connectShare(context: context, server: server, share: share, user: user)
        }
    }

    private static func _disconnectShare(context: Context) throws {
        try check(smb2_disconnect_share(context.raw), context: context, operation: "smb2_disconnect_share")
    }

    /// Disconnects a context from its current share.
    static func disconnectShare(context: Context) throws {
        try sync {
            try _disconnectShare(context: context)
        }
    }

    /// Selects a previously connected tree ID for subsequent requests.
    static func selectTreeID(_ treeID: UInt32, context: Context) throws {
        try check(smb2_select_tree_id(context.raw, treeID), context: context, operation: "smb2_select_tree_id")
    }

    private static func _getSessionID(context: Context) throws -> UInt64 {
        var sessionID: UInt64 = 0
        try check(smb2_get_session_id(context.raw, &sessionID), context: context, operation: "smb2_get_session_id")
        return sessionID
    }

    /// Returns the SMB session ID for a context.
    static func getSessionID(context: Context) throws -> UInt64 {
        try sync {
            try _getSessionID(context: context)
        }
    }

    // MARK: - URL Parsing

    private static func _parseURL(_ url: String, context: Context) throws -> SMB2URL {
        let rawURL = url.withCString { smb2_parse_url(context.raw, $0) }

        guard let rawURL else {
            throw SMB.Error.fromBridge(context, operation: "smb2_parse_url")
        }

        defer { smb2_destroy_url(rawURL) }
        return SMB2URL(rawURL.pointee)
    }

    /// Parses an SMB URL into Swift-friendly URL components.
    static func parseURL(_ url: String, context: Context) throws -> SMB2URL {
        try sync {
            try _parseURL(url, context: context)
        }
    }

    // MARK: - File Operations

    private static func _open(
        context: Context,
        path: String,
        flags: OpenFlags = OpenFlags(),
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
        flags: OpenFlags = OpenFlags(),
    ) throws -> FileHandle {
        try sync {
            try _open(context: context, path: path, flags: flags)
        }
    }

    private static func _close(context: Context, file: FileHandle) throws {
        try check(smb2_close(context.raw, file.raw), context: context, operation: "smb2_close")
    }

    /// Closes an open file handle.
    static func close(context: Context, file: FileHandle) throws {
        try sync {
            try _close(context: context, file: file)
        }
    }

    private static func _sync(context: Context, file: FileHandle) throws {
        try check(smb2_fsync(context.raw, file.raw), context: context, operation: "smb2_fsync")
    }

    /// Flushes pending writes for an open file handle.
    static func sync(context: Context, file: FileHandle) throws {
        try sync {
            try _sync(context: context, file: file)
        }
    }

    private static func _getMaxReadSize(context: Context) -> UInt32 {
        smb2_get_max_read_size(context.raw)
    }

    /// Returns the maximum read size supported by the connected server.
    static func getMaxReadSize(context: Context) -> UInt32 {
        sync {
            _getMaxReadSize(context: context)
        }
    }

    private static func _getMaxWriteSize(context: Context) -> UInt32 {
        smb2_get_max_write_size(context.raw)
    }

    /// Returns the maximum write size supported by the connected server.
    static func getMaxWriteSize(context: Context) -> UInt32 {
        sync {
            _getMaxWriteSize(context: context)
        }
    }

    /// Reads bytes from a file at an explicit offset.
    static func read(
        context: Context,
        file: FileHandle,
        into buffer: consuming MutableRawSpan,
        offset: UInt64,
    ) throws -> Int {
        var buffer = buffer
        return try sync {
            let count = try buffer.byteCount.asUInt32(operation: .smb2Pread)
            let status = buffer.withUnsafeMutableBytes { bytes in
                bytes.bindMemory(to: UInt8.self).baseAddress.map {
                    smb2_pread(context.raw, file.raw, $0, count, offset)
                } ?? smb2_pread(context.raw, file.raw, nil, count, offset)
            }

            return try Int(check(status, context: context, operation: "smb2_pread"))
        }
    }

    private static func _write(
        context: Context,
        file: FileHandle,
        bytes: RawSpan,
        offset: UInt64,
    ) throws -> Int {
        let count = try bytes.byteCount.asUInt32(operation: .smb2Pwrite)
        let status = bytes.withUnsafeBytes { bytes in
            bytes.bindMemory(to: UInt8.self).baseAddress.map {
                smb2_pwrite(context.raw, file.raw, $0, count, offset)
            } ?? smb2_pwrite(context.raw, file.raw, nil, count, offset)
        }

        return try Int(check(status, context: context, operation: "smb2_pwrite"))
    }

    /// Writes bytes to a file at an explicit offset.
    static func write(
        context: Context,
        file: FileHandle,
        bytes: RawSpan,
        offset: UInt64,
    ) throws -> Int {
        try sync {
            try _write(context: context, file: file, bytes: bytes, offset: offset)
        }
    }

    /// Reads bytes from the current file offset.
    static func read(
        context: Context,
        file: FileHandle,
        into buffer: consuming MutableRawSpan,
    ) throws -> Int {
        var buffer = buffer
        return try sync {
            let count = try buffer.byteCount.asUInt32(operation: .smb2Read)
            let status = buffer.withUnsafeMutableBytes { bytes in
                bytes.bindMemory(to: UInt8.self).baseAddress.map {
                    smb2_read(context.raw, file.raw, $0, count)
                } ?? smb2_read(context.raw, file.raw, nil, count)
            }

            return try Int(check(status, context: context, operation: "smb2_read"))
        }
    }

    private static func _write(
        context: Context,
        file: FileHandle,
        bytes: RawSpan,
    ) throws -> Int {
        let count = try bytes.byteCount.asUInt32(operation: .smb2Write)
        let status = bytes.withUnsafeBytes { bytes in
            bytes.bindMemory(to: UInt8.self).baseAddress.map {
                smb2_write(context.raw, file.raw, $0, count)
            } ?? smb2_write(context.raw, file.raw, nil, count)
        }

        return try Int(check(status, context: context, operation: "smb2_write"))
    }

    /// Writes bytes at the current file offset.
    static func write(
        context: Context,
        file: FileHandle,
        bytes: RawSpan,
    ) throws -> Int {
        try sync {
            try _write(context: context, file: file, bytes: bytes)
        }
    }

    private static func _seek(
        context: Context,
        file: FileHandle,
        offset: Int64,
        whence: Int32,
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
        whence: Int32,
    ) throws -> UInt64 {
        try sync {
            try _seek(context: context, file: file, offset: offset, whence: whence)
        }
    }

    private static func _unlink(context: Context, path: String) throws {
        try check(path.withCString { smb2_unlink(context.raw, $0) }, context: context, operation: "smb2_unlink")
    }

    /// Removes a file or link at a path.
    static func unlink(context: Context, path: String) throws {
        try sync {
            try _unlink(context: context, path: path)
        }
    }

    // MARK: - Directory Operations

    private static func _removeDir(context: Context, path: String) throws {
        try check(path.withCString { smb2_rmdir(context.raw, $0) }, context: context, operation: "smb2_rmdir")
    }

    /// Removes an empty directory at a path.
    static func removeDir(context: Context, path: String) throws {
        try sync {
            try _removeDir(context: context, path: path)
        }
    }

    private static func _makeDir(context: Context, path: String) throws {
        try check(path.withCString { smb2_mkdir(context.raw, $0) }, context: context, operation: "smb2_mkdir")
    }

    /// Creates a directory at a path.
    static func makeDir(context: Context, path: String) throws {
        try sync {
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
    static func openDir(context: Context, path: String) throws -> DirectoryHandle {
        try sync {
            try _openDir(context: context, path: path)
        }
    }

    private static func _closeDir(context: Context, directory: DirectoryHandle) {
        smb2_closedir(context.raw, directory.raw)
    }

    /// Closes an open directory handle.
    static func closeDir(context: Context, directory: DirectoryHandle) {
        sync {
            _closeDir(context: context, directory: directory)
        }
    }

    private static func _readDir(context: Context, directory: DirectoryHandle) -> DirectoryEntry? {
        smb2_readdir(context.raw, directory.raw).map { DirectoryEntry($0.pointee) }
    }

    /// Reads the next directory entry from a directory handle.
    static func readDir(context: Context, directory: DirectoryHandle) -> DirectoryEntry? {
        sync {
            _readDir(context: context, directory: directory)
        }
    }

    private static func _rewindDir(context: Context, directory: DirectoryHandle) {
        smb2_rewinddir(context.raw, directory.raw)
    }

    /// Rewinds a directory handle to the first entry.
    static func rewindDir(context: Context, directory: DirectoryHandle) {
        sync {
            _rewindDir(context: context, directory: directory)
        }
    }

    private static func _tellDir(context: Context, directory: DirectoryHandle) -> Int {
        Int(smb2_telldir(context.raw, directory.raw))
    }

    /// Returns the current directory stream location.
    static func tellDir(context: Context, directory: DirectoryHandle) -> Int {
        sync {
            _tellDir(context: context, directory: directory)
        }
    }

    private static func _seekDir(context: Context, directory: DirectoryHandle, location: Int) {
        smb2_seekdir(context.raw, directory.raw, numericCast(location))
    }

    /// Moves a directory handle to a previously returned stream location.
    static func seekDir(context: Context, directory: DirectoryHandle, location: Int) {
        sync {
            _seekDir(context: context, directory: directory, location: location)
        }
    }

    // MARK: - File Statistics

    private static func _statVFS(context: Context, path: String) throws -> VFSStat {
        var statvfs = smb2_statvfs()
        try check(
            path.withCString { smb2_statvfs(context.raw, $0, &statvfs) },
            context: context,
            operation: "smb2_statvfs",
        )
        return VFSStat(statvfs)
    }

    /// Returns filesystem statistics for a path.
    static func statVFS(context: Context, path: String) throws -> VFSStat {
        try sync {
            try _statVFS(context: context, path: path)
        }
    }

    private static func _fileStatistics(context: Context, file: FileHandle) throws -> Stat {
        var stat = smb2_stat_64()
        try check(smb2_fstat(context.raw, file.raw, &stat), context: context, operation: "smb2_fstat")
        return Stat(stat)
    }

    /// Returns file statistics for an open file handle.
    static func fileStatistics(context: Context, file: FileHandle) throws -> Stat {
        try sync {
            try _fileStatistics(context: context, file: file)
        }
    }

    private static func _fileStatistics(context: Context, path: String) throws -> Stat {
        var stat = smb2_stat_64()
        try check(
            path.withCString { smb2_stat(context.raw, $0, &stat) },
            context: context,
            operation: "smb2_stat",
        )
        return Stat(stat)
    }

    /// Returns file statistics for a path.
    static func fileStatistics(context: Context, path: String) throws -> Stat {
        try sync {
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
    static func rename(context: Context, oldPath: String, newPath: String) throws {
        try sync {
            try _rename(context: context, oldPath: oldPath, newPath: newPath)
        }
    }

    private static func _truncate(context: Context, path: String, length: UInt64) throws {
        try check(
            path.withCString { smb2_truncate(context.raw, $0, length) },
            context: context,
            operation: "smb2_truncate",
        )
    }

    /// Truncates a file at a path to a length in bytes.
    static func truncate(context: Context, path: String, length: UInt64) throws {
        try sync {
            try _truncate(context: context, path: path, length: length)
        }
    }

    private static func _truncate(context: Context, file: FileHandle, length: UInt64) throws {
        try check(smb2_ftruncate(context.raw, file.raw, length), context: context, operation: "smb2_ftruncate")
    }

    /// Truncates an open file handle to a length in bytes.
    static func truncate(context: Context, file: FileHandle, length: UInt64) throws {
        try sync {
            try _truncate(context: context, file: file, length: length)
        }
    }

    private static func _readLink(
        context: Context,
        path: String,
        bufferSize: Int = 4096,
    ) throws -> String {
        guard bufferSize > 0 else {
            throw SMB.Error.invalidArgument(
                cause: .bufferSizeMustBeGreaterThanZero,
                onOperation: .smb2Readlink,
            )
        }

        let count = try bufferSize.asUInt32(operation: .smb2Readlink)
        var buffer = [CChar](repeating: 0, count: bufferSize)
        let status = path.withCString { smb2_readlink(context.raw, $0, &buffer, count) }
        try check(status, context: context, operation: "smb2_readlink")
        return buffer.withUnsafeBufferPointer { pointer in
            String(cString: pointer.baseAddress!)
        }
    }

    /// Reads the destination path of a symbolic link.
    static func readLink(
        context: Context,
        path: String,
        bufferSize: Int = 4096,
    ) throws -> String {
        try sync {
            try _readLink(context: context, path: path, bufferSize: bufferSize)
        }
    }
    
    private static func _echo(context: Context) throws {
        try check(smb2_echo(context.raw), context: context, operation: "smb2_echo")
    }

    /// Sends an SMB echo request to verify the connection is responsive.
    static func echo(context: Context) throws {
        try sync {
            try _echo(context: context)
        }
    }

    // MARK: - Share Listing

    private static func _listShares(
        context: Context,
        server: String,
        user: String? = nil,
        includeHidden: Bool = false,
    ) throws -> [Share] {
        setSecurityMode(.signingEnabled, on: context)
        try _connectShare(context: context, server: server, share: "IPC$", user: user)

        do {
            let shares = try filterForUserVisibleDiskShares(
                listSharesOnConnectedIPCShare(context: context),
                includeHidden: includeHidden,
            )
            try _disconnectShare(context: context)
            return shares
        }
        catch {
            try? _disconnectShare(context: context)
            throw error
        }
    }

    /// Connects to IPC$, enumerates user-visible disk shares, and disconnects.
    static func listShares(
        context: Context,
        server: String,
        user: String? = nil,
        includeHidden: Bool = false,
    ) throws -> [Share] {
        try sync {
            try _listShares(context: context, server: server, user: user, includeHidden: includeHidden)
        }
    }

    /// Enumerates shares using SRVSVC on a context that is already connected to IPC$.
    static func listSharesOnConnectedIPCShare(
        context: Context,
        level: ShareEnumerationLevel = .detailed,
    ) throws -> [Share] {
        guard let response = smb2_share_enum_sync(context.raw, level.rawValue) else {
            throw SMB.Error.fromBridge(context, operation: "smb2_share_enum_sync")
        }

        defer { smb2_free_data(context.raw, response) }

        switch response.pointee.ses.Level {
        case UInt32(SHARE_INFO_0.rawValue):
            return shares(from: response.pointee.ses.ShareInfo.Level0)
        case UInt32(SHARE_INFO_1.rawValue):
            return shares(from: response.pointee.ses.ShareInfo.Level1)
        default:
            throw SMB.Error.invalidArgument(
                cause: .unsupportedShareEnumerationLevel(response.pointee.ses.Level),
                onOperation: .smb2ShareEnumSync,
            )
        }
    }

    // MARK: - Notify Operations

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
        try sync {
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
        sync {
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
        try sync {
            try _serviceNotifyEvents(context: context, timeoutMilliseconds: timeoutMilliseconds)
        }
    }

    // MARK: - Private Helpers

    /// Checks an SMB status code and throws if it indicates an error.
    @discardableResult private static func check(
        _ status: Int32,
        context: Context,
        operation: String,
    ) throws -> Int32 {
        guard status >= 0 else {
            throw SMB.Error.fromBridge(context, operation: operation, status: status)
        }
        return status
    }

    // MARK: - Share Listing Helpers

    private static func shares(_ count: UInt32, _ body: (Int) -> Share) -> [Share] {
        (0 ..< Int(count)).map(body)
    }

    private static func shares(from container: srvsvc_SHARE_INFO_0_CONTAINER) -> [Share] {
        guard let buffer = container.Buffer?.pointee.share_info_0 else {
            return []
        }

        return shares(container.EntriesRead) { index in
            Share(
                name: string(from: buffer[index].netname),
                kind: nil,
                attributes: [],
                remark: nil,
            )
        }
    }

    private static func shares(from container: srvsvc_SHARE_INFO_1_CONTAINER) -> [Share] {
        guard let buffer = container.Buffer?.pointee.share_info_1 else {
            return []
        }

        return shares(container.EntriesRead) { index in
            let info = buffer[index]
            return Share(
                name: string(from: info.netname),
                kind: ShareKind(rawValue: info.type),
                attributes: ShareAttributes(rawShareType: info.type),
                remark: string(from: info.remark),
            )
        }
    }

    private static func string(from string: dcerpc_utf16) -> String {
        string.utf8.map(String.init(cString:)) ?? ""
    }

    private static func filterForUserVisibleDiskShares(_ shares: [Share], includeHidden: Bool) -> [Share] {
        shares.filter { share in
            share.kind == .diskTree && (includeHidden || !share.isHidden)
        }
    }

    // MARK: - File Stats Helpers

    private static let fileBasicInformationWireLength = 40

    private protocol PendingOperationState: AnyObject {
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
        if state.status == SMB2_STATUS_SUCCESS {
            state.status = status
        }
    }

    private static let setStatsSetCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<SetStatsState>.fromOpaque(callbackData).takeUnretainedValue()
        if state.status == SMB2_STATUS_SUCCESS {
            state.status = status
        }
    }

    private static let setStatsCloseCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<SetStatsState>.fromOpaque(callbackData).takeUnretainedValue()
        if state.status == SMB2_STATUS_SUCCESS {
            state.status = status
        }
        state.isFinished = true
    }

    private static let queryAttributesCreateCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<QueryAttributesState>.fromOpaque(callbackData).takeUnretainedValue()
        if state.status == SMB2_STATUS_SUCCESS {
            state.status = status
        }
    }

    private static let queryAttributesQueryCallback: smb2_command_cb =
        { rawContext, status, commandData, callbackData in
            guard let callbackData else { return }
            let state = Unmanaged<QueryAttributesState>.fromOpaque(callbackData).takeUnretainedValue()
            if state.status == SMB2_STATUS_SUCCESS {
                state.status = status
            }
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
        if state.status == SMB2_STATUS_SUCCESS {
            state.status = status
        }
        state.isFinished = true
    }

    private static func serviceUntilFinished(context: Context, state: some PendingOperationState) throws {
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
                    message: "poll failed while waiting for SMB2 operation",
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
        fileAttributes: UInt32? = nil,
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
            file_attributes: fileAttributes ?? 0xFFFF_FFFF,
        )

        let state = SetStatsState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { Unmanaged<SetStatsState>.fromOpaque(callbackData).release() }

        let fileIDAllOnes: (
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
        ) =
            (0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)

        try path.withCString { pathPointer in
            try withUnsafeMutablePointer(to: &info) { infoPointer in
                var cr_req = smb2_create_request(
                    security_flags: 0,
                    requested_oplock_level: 0,
                    impersonation_level: 2,
                    smb_create_flags: 0,
                    desired_access: 0x4000_0000,
                    file_attributes: 0,
                    share_access: 0x0000_0001 | 0x0000_0002,
                    create_disposition: 1,
                    create_options: 0,
                    name_offset: 0,
                    name_length: 0,
                    name: pathPointer,
                    create_context_offset: 0,
                    create_context_length: 0,
                    create_context: nil,
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
                    file_id: fileIDAllOnes,
                    input_data: infoPointer,
                )

                guard let next_pdu = smb2_cmd_set_info_async(context.raw, &si_req, setStatsSetCallback, callbackData) else {
                    smb2_free_pdu(context.raw, pdu)
                    throw SMB.Error.fromBridge(context, operation: "smb2_cmd_set_info_async")
                }
                smb2_add_compound_pdu(context.raw, pdu, next_pdu)

                var cl_req = smb2_close_request(
                    flags: 1,
                    file_id: fileIDAllOnes,
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
        fileAttributes: UInt32? = nil,
    ) throws {
        try sync {
            try _setStats(
                context: context,
                path: path,
                creationTime: creationTime,
                lastAccessTime: lastAccessTime,
                lastWriteTime: lastWriteTime,
                changeTime: changeTime,
                fileAttributes: fileAttributes,
            )
        }
    }

    private static func _getFileAttributes(context: Context, path: String) throws -> UInt32 {
        let state = QueryAttributesState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()

        defer { Unmanaged<QueryAttributesState>.fromOpaque(callbackData).release() }

        let fileIDAllOnes: (
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
            UInt8,
        ) =
            (0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)

        return try path.withCString { pathPointer in
            var cr_req = smb2_create_request(
                security_flags: 0,
                requested_oplock_level: 0,
                impersonation_level: 2,
                smb_create_flags: 0,
                desired_access: 0x0000_0080,
                file_attributes: 0,
                share_access: 0x0000_0001 | 0x0000_0002,
                create_disposition: 1,
                create_options: 0,
                name_offset: 0,
                name_length: 0,
                name: pathPointer,
                create_context_offset: 0,
                create_context_length: 0,
                create_context: nil,
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
                file_id: fileIDAllOnes,
                input: nil,
            )

            guard let next_pdu = smb2_cmd_query_info_async(
                context.raw,
                &qi_req,
                queryAttributesQueryCallback,
                callbackData,
            ) else {
                smb2_free_pdu(context.raw, pdu)
                throw SMB.Error.fromBridge(context, operation: "smb2_cmd_query_info_async")
            }
            smb2_add_compound_pdu(context.raw, pdu, next_pdu)

            var cl_req = smb2_close_request(
                flags: 0,
                file_id: fileIDAllOnes,
            )

            guard let close_pdu = smb2_cmd_close_async(
                context.raw,
                &cl_req,
                queryAttributesCloseCallback,
                callbackData,
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
    static func getFileAttributes(context: Context, path: String) throws -> UInt32 {
        try sync {
            try _getFileAttributes(context: context, path: path)
        }
    }

    // MARK: - Notify Helpers

    private static let defaultNotifyOutputBufferLength: UInt32 = 0xFFFF
    private static let defaultNotifyServiceTimeoutMilliseconds: Int32 = 50
    private static let notifyChangeEntryHeaderLength = 12
    private static let maximumNotifyChangeEntryCount = 4096

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

// MARK: - String Extensions

private extension String {
    func withOptionalCString<T>(_ body: (UnsafePointer<CChar>?) throws -> T) rethrows -> T {
        try withCString { try body($0) }
    }
}
