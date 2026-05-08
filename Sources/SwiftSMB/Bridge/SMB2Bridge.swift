//
// Part of SwiftSMB
// SMB2Bridge.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Darwin
import Foundation
import SMB2

/// Creates a new libsmb2 context.
func createContext() throws -> SMB2Context {
    guard let raw = smb2_init_context() else {
        throw SMB.Error.contextCreationFailed
    }

    return SMB2Context(raw: raw)
}

/// Closes the active connection for a context without destroying the context.
func closeContext(_ context: SMB2Context) {
    smb2_close_context(context.raw)
}

/// Destroys a libsmb2 context and any resources it owns.
func destroyContext(_ context: SMB2Context) {
    smb2_destroy_context(context.raw)
}

/// Sets the command timeout in seconds for a context.
func setTimeout(_ seconds: Int32, on context: SMB2Context) {
    smb2_set_timeout(context.raw, seconds)
}

/// Sets the SMB dialect negotiation preference for a context.
func setVersion(_ version: smb2_negotiate_version, on context: SMB2Context) {
    smb2_set_version(context.raw, version)
}

/// Returns the currently negotiated SMB dialect for a context.
func getDialect(on context: SMB2Context) -> UInt16 {
    smb2_get_dialect(context.raw)
}

/// Sets SMB signing-related negotiation flags for a context.
func setSecurityMode(_ securityMode: SMB2SecurityMode, on context: SMB2Context) {
    smb2_set_security_mode(context.raw, securityMode.rawValue)
}

/// Enables or disables SMB3 encryption for a context.
func setSeal(_ enabled: Bool, on context: SMB2Context) {
    smb2_set_seal(context.raw, enabled ? 1 : 0)
}

/// Enables or disables required SMB signing for a context.
func setSign(_ required: Bool, on context: SMB2Context) {
    smb2_set_sign(context.raw, required ? 1 : 0)
}

/// Sets the authentication mechanism for a context.
func setAuthentication(_ authentication: SMB2AuthenticationMethod, on context: SMB2Context) {
    smb2_set_authentication(context.raw, authentication.rawValue)
}

/// Sets the username used for authentication.
func setUser(_ user: String, on context: SMB2Context) {
    user.withCString { smb2_set_user(context.raw, $0) }
}

/// Returns the username currently configured on a context.
func getUser(on context: SMB2Context) -> String? {
    smb2_get_user(context.raw).map(String.init(cString:))
}

/// Sets the password used for authentication.
func setPassword(_ password: String, on context: SMB2Context) {
    password.withCString { smb2_set_password(context.raw, $0) }
}

/// Loads the password from the NTLM_USER_FILE credential file if available.
func setPasswordFromFile(on context: SMB2Context) {
    smb2_set_password_from_file(context.raw)
}

/// Sets the authentication domain for a context.
func setDomain(_ domain: String, on context: SMB2Context) {
    domain.withCString { smb2_set_domain(context.raw, $0) }
}

/// Returns the authentication domain currently configured on a context.
func getDomain(on context: SMB2Context) -> String? {
    smb2_get_domain(context.raw).map(String.init(cString:))
}

/// Sets the workstation name used for authentication.
func setWorkstation(_ workstation: String, on context: SMB2Context) {
    workstation.withCString { smb2_set_workstation(context.raw, $0) }
}

/// Returns the workstation name currently configured on a context.
func getWorkstation(on context: SMB2Context) -> String? {
    smb2_get_workstation(context.raw).map(String.init(cString:))
}

/// Connects a context to a share on a server.
func connectShare(
    context: SMB2Context,
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

/// Disconnects a context from its current share.
func disconnectShare(context: SMB2Context) throws {
    try check(smb2_disconnect_share(context.raw), context: context, operation: "smb2_disconnect_share")
}

/// Selects a previously connected tree ID for subsequent requests.
func selectTreeID(_ treeID: UInt32, context: SMB2Context) throws {
    try check(smb2_select_tree_id(context.raw, treeID), context: context, operation: "smb2_select_tree_id")
}

/// Returns the SMB session ID for a context.
func getSessionID(context: SMB2Context) throws -> UInt64 {
    var sessionID: UInt64 = 0
    try check(smb2_get_session_id(context.raw, &sessionID), context: context, operation: "smb2_get_session_id")
    return sessionID
}

/// Parses an SMB URL into Swift-friendly URL components.
func parseURL(_ url: String, context: SMB2Context) throws -> SMB2URL {
    let rawURL = url.withCString { smb2_parse_url(context.raw, $0) }

    guard let rawURL else {
        throw SMB.Error.fromBridge(context, operation: "smb2_parse_url")
    }

    defer { smb2_destroy_url(rawURL) }
    return SMB2URL(rawURL.pointee)
}

/// Opens or creates a file and returns a file handle.
func open(
    context: SMB2Context,
    path: String,
    flags: SMB2OpenFlags = SMB2OpenFlags(),
) throws -> SMB2FileHandle {
    let rawHandle = path.withCString { smb2_open(context.raw, $0, flags.rawValue) }

    guard let rawHandle else {
        throw SMB.Error.fromBridge(context, operation: "smb2_open")
    }

    return SMB2FileHandle(raw: rawHandle)
}

/// Closes an open file handle.
func close(context: SMB2Context, file: SMB2FileHandle) throws {
    try check(smb2_close(context.raw, file.raw), context: context, operation: "smb2_close")
}

/// Flushes pending writes for an open file handle.
func sync(context: SMB2Context, file: SMB2FileHandle) throws {
    try check(smb2_fsync(context.raw, file.raw), context: context, operation: "smb2_fsync")
}

/// Returns the maximum read size supported by the connected server.
func getMaxReadSize(context: SMB2Context) -> UInt32 {
    smb2_get_max_read_size(context.raw)
}

/// Returns the maximum write size supported by the connected server.
func getMaxWriteSize(context: SMB2Context) -> UInt32 {
    smb2_get_max_write_size(context.raw)
}

/// Reads bytes from a file at an explicit offset.
func read(
    context: SMB2Context,
    file: SMB2FileHandle,
    into buffer: consuming MutableRawSpan,
    offset: UInt64,
) throws -> Int {
    var buffer = buffer
    let count = try buffer.byteCount.asUInt32(operation: .smb2Pread)
    let status = buffer.withUnsafeMutableBytes { bytes in
        bytes.bindMemory(to: UInt8.self).baseAddress.map {
            smb2_pread(context.raw, file.raw, $0, count, offset)
        } ?? smb2_pread(context.raw, file.raw, nil, count, offset)
    }

    return try Int(check(status, context: context, operation: "smb2_pread"))
}

/// Writes bytes to a file at an explicit offset.
func write(
    context: SMB2Context,
    file: SMB2FileHandle,
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

/// Reads bytes from the current file offset.
func read(
    context: SMB2Context,
    file: SMB2FileHandle,
    into buffer: consuming MutableRawSpan,
) throws -> Int {
    var buffer = buffer
    let count = try buffer.byteCount.asUInt32(operation: .smb2Read)
    let status = buffer.withUnsafeMutableBytes { bytes in
        bytes.bindMemory(to: UInt8.self).baseAddress.map {
            smb2_read(context.raw, file.raw, $0, count)
        } ?? smb2_read(context.raw, file.raw, nil, count)
    }

    return try Int(check(status, context: context, operation: "smb2_read"))
}

/// Writes bytes at the current file offset.
func write(
    context: SMB2Context,
    file: SMB2FileHandle,
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

/// Moves the current file offset and returns the resulting offset.
func seek(
    context: SMB2Context,
    file: SMB2FileHandle,
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

/// Removes a file or link at a path.
func unlink(context: SMB2Context, path: String) throws {
    try check(path.withCString { smb2_unlink(context.raw, $0) }, context: context, operation: "smb2_unlink")
}

/// Removes an empty directory at a path.
func removeDir(context: SMB2Context, path: String) throws {
    try check(path.withCString { smb2_rmdir(context.raw, $0) }, context: context, operation: "smb2_rmdir")
}

/// Creates a directory at a path.
func makeDir(context: SMB2Context, path: String) throws {
    try check(path.withCString { smb2_mkdir(context.raw, $0) }, context: context, operation: "smb2_mkdir")
}

/// Returns filesystem statistics for a path.
func statVFS(context: SMB2Context, path: String) throws -> SMB2StatVFS {
    var statvfs = smb2_statvfs()
    try check(
        path.withCString { smb2_statvfs(context.raw, $0, &statvfs) },
        context: context,
        operation: "smb2_statvfs",
    )
    return SMB2StatVFS(statvfs)
}

/// Returns file statistics for an open file handle.
func fileStatistics(context: SMB2Context, file: SMB2FileHandle) throws -> SMB2Stat {
    var stat = smb2_stat_64()
    try check(smb2_fstat(context.raw, file.raw, &stat), context: context, operation: "smb2_fstat")
    return SMB2Stat(stat)
}

/// Returns file statistics for a path.
func fileStatistics(context: SMB2Context, path: String) throws -> SMB2Stat {
    var stat = smb2_stat_64()
    try check(
        path.withCString { smb2_stat(context.raw, $0, &stat) },
        context: context,
        operation: "smb2_stat",
    )
    return SMB2Stat(stat)
}

/// Renames or moves an entry from one path to another.
func rename(context: SMB2Context, oldPath: String, newPath: String) throws {
    let status = oldPath.withCString { oldPathPointer in
        newPath.withCString { newPathPointer in
            smb2_rename(context.raw, oldPathPointer, newPathPointer)
        }
    }

    try check(status, context: context, operation: "smb2_rename")
}

/// Truncates a file at a path to a length in bytes.
func truncate(context: SMB2Context, path: String, length: UInt64) throws {
    try check(
        path.withCString { smb2_truncate(context.raw, $0, length) },
        context: context,
        operation: "smb2_truncate",
    )
}

/// Truncates an open file handle to a length in bytes.
func truncate(context: SMB2Context, file: SMB2FileHandle, length: UInt64) throws {
    try check(smb2_ftruncate(context.raw, file.raw, length), context: context, operation: "smb2_ftruncate")
}

/// Reads the destination path of a symbolic link.
func readLink(
    context: SMB2Context,
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

/// Sends an SMB echo request to verify the connection is responsive.
func echo(context: SMB2Context) throws {
    try check(smb2_echo(context.raw), context: context, operation: "smb2_echo")
}

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

private let setStatsCreateCallback: smb2_command_cb = { _, status, _, callbackData in
    guard let callbackData else { return }
    let state = Unmanaged<SetStatsState>.fromOpaque(callbackData).takeUnretainedValue()
    if state.status == SMB2_STATUS_SUCCESS {
        state.status = status
    }
}

private let setStatsSetCallback: smb2_command_cb = { _, status, _, callbackData in
    guard let callbackData else { return }
    let state = Unmanaged<SetStatsState>.fromOpaque(callbackData).takeUnretainedValue()
    if state.status == SMB2_STATUS_SUCCESS {
        state.status = status
    }
}

private let setStatsCloseCallback: smb2_command_cb = { _, status, _, callbackData in
    guard let callbackData else { return }
    let state = Unmanaged<SetStatsState>.fromOpaque(callbackData).takeUnretainedValue()
    if state.status == SMB2_STATUS_SUCCESS {
        state.status = status
    }
    state.isFinished = true
}

private let queryAttributesCreateCallback: smb2_command_cb = { _, status, _, callbackData in
    guard let callbackData else { return }
    let state = Unmanaged<QueryAttributesState>.fromOpaque(callbackData).takeUnretainedValue()
    if state.status == SMB2_STATUS_SUCCESS {
        state.status = status
    }
}

private let queryAttributesQueryCallback: smb2_command_cb = { _, status, commandData, callbackData in
    guard let callbackData else { return }
    let state = Unmanaged<QueryAttributesState>.fromOpaque(callbackData).takeUnretainedValue()
    if state.status == SMB2_STATUS_SUCCESS {
        state.status = status
    }
    if status == SMB2_STATUS_SUCCESS, let commandData {
        let reply = commandData.bindMemory(to: smb2_query_info_reply.self, capacity: 1)
        if let buffer = reply.pointee.output_buffer,
           reply.pointee.output_buffer_length >= MemoryLayout<smb2_file_basic_info>.size {
            let info = buffer.withMemoryRebound(to: smb2_file_basic_info.self, capacity: 1) { $0.pointee }
            state.fileAttributes = info.file_attributes
        }
    }
}

private let queryAttributesCloseCallback: smb2_command_cb = { _, status, _, callbackData in
    guard let callbackData else { return }
    let state = Unmanaged<QueryAttributesState>.fromOpaque(callbackData).takeUnretainedValue()
    if state.status == SMB2_STATUS_SUCCESS {
        state.status = status
    }
    state.isFinished = true
}

private func serviceUntilFinished(context: SMB2Context, state: some PendingOperationState) throws {
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

/// Sets basic file information (timestamps and attributes) for a path.
func setStats(
    context: SMB2Context,
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

    Unmanaged<SetStatsState>.fromOpaque(callbackData).release()
}

/// Returns the file attributes for a path.
func getFileAttributes(context: SMB2Context, path: String) throws -> UInt32 {
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

        guard let close_pdu = smb2_cmd_close_async(context.raw, &cl_req, queryAttributesCloseCallback, callbackData) else {
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

/// Opens a directory and returns a directory handle.
func openDir(context: SMB2Context, path: String) throws -> SMB2DirectoryHandle {
    let rawDirectory = path.withCString { smb2_opendir(context.raw, $0) }

    guard let rawDirectory else {
        throw SMB.Error.fromBridge(context, operation: "smb2_opendir")
    }

    return SMB2DirectoryHandle(raw: rawDirectory)
}

/// Closes an open directory handle.
func closeDir(context: SMB2Context, directory: SMB2DirectoryHandle) {
    smb2_closedir(context.raw, directory.raw)
}

/// Reads the next directory entry from a directory handle.
func readDir(context: SMB2Context, directory: SMB2DirectoryHandle) -> SMB2DirectoryEntry? {
    smb2_readdir(context.raw, directory.raw).map { SMB2DirectoryEntry($0.pointee) }
}

/// Rewinds a directory handle to the first entry.
func rewindDir(context: SMB2Context, directory: SMB2DirectoryHandle) {
    smb2_rewinddir(context.raw, directory.raw)
}

/// Returns the current directory stream location.
func tellDir(context: SMB2Context, directory: SMB2DirectoryHandle) -> Int {
    Int(smb2_telldir(context.raw, directory.raw))
}

/// Moves a directory handle to a previously returned stream location.
func seekDir(context: SMB2Context, directory: SMB2DirectoryHandle, location: Int) {
    smb2_seekdir(context.raw, directory.raw, numericCast(location))
}
