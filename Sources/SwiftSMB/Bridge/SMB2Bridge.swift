//
// Part of SwiftSMB
// SMB2Bridge.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

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
    let count = try buffer.byteCount.asUInt32(operation: "smb2_pread")
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
    let count = try bytes.byteCount.asUInt32(operation: "smb2_pwrite")
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
    let count = try buffer.byteCount.asUInt32(operation: "smb2_read")
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
    let count = try bytes.byteCount.asUInt32(operation: "smb2_write")
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
            operation: "smb2_readlink",
            message: "Buffer size must be greater than zero",
        )
    }

    let count = try bufferSize.asUInt32(operation: "smb2_readlink")
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
