//
// Part of SwiftSMB
// Connection-CacheReports.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(Android)
    import Android
#endif
import Foundation

// MARK: Requests

extension SMB.Connection {
    /// Runs `body` as one request of `cache`, then ends the request however `body` ends.
    ///
    /// - Parameters:
    ///   - cache: The cache the request goes to.
    ///   - body: The lookup, the call to the server, and the store, given the request's identifier.
    /// - Returns: What `body` returns.
    /// - Throws: What `body` throws.
    nonisolated(nonsending) func withCacheRequest<R>(
        on cache: any SMB.BlockLevelReadCache,
        _ body: (SMB.CacheRequestID) async throws -> R
    ) async throws -> R {
        let request = SMB.CacheRequestID()
        let result: R
        do {
            result = try await body(request)
        }
        catch {
            await cache.requestEnded(request)
            throw error
        }

        await cache.requestEnded(request)
        return result
    }
}

// MARK: Change reports

extension SMB.Connection {
    /// Runs `change`, a call that changes `paths` on the server, then reports them to the cache in `attachment`, also
    /// when the call fails: a timeout, a cancellation, or a lost connection can come after the server applied it.
    /// `libsmb2` keeps no call past its timeout that could still finish later, so the report follows at once.
    ///
    /// - Parameters:
    ///   - removing: Whether the change may remove what is at `paths`, so that files open there stop reporting.
    ///   - removingIfFailed: Whether the change may remove what is at `paths` when it fails, as a server-side copy
    /// removes the destination it created.
    nonisolated(nonsending) func reportingChange<R>(
        at paths: [String],
        to attachment: SMBCacheAttachment?,
        removing: Bool,
        removingIfFailed: Bool? = nil,
        _ change: () async throws -> R
    ) async throws -> R {
        let ticket = attachment?.openFiles.beginChange()
        let result: R
        do {
            result = try await change()
        }
        catch {
            await reportChange(at: paths, to: attachment, removing: removingIfFailed ?? removing, since: ticket)
            throw error
        }

        await reportChange(at: paths, to: attachment, removing: removing, removed: removing, since: ticket)
        return result
    }

    /// Runs `rename`, a rename of `from` to `to` on the server, then reports it to the cache in `attachment`. A rename
    /// that fails may still have happened, so both paths are reported as changed then, and files open at either stop
    /// reporting, keeping the paths they may be at.
    nonisolated(nonsending) func reportingRename(
        from: String,
        to: String,
        attachment: SMBCacheAttachment?,
        _ rename: () async throws -> Void
    ) async throws {
        let ticket = attachment?.openFiles.beginChange()
        do {
            try await rename()
        }
        catch {
            await reportFailedRename(from: from, to: to, attachment: attachment, since: ticket)
            throw error
        }

        await reportRename(from: from, to: to, attachment: attachment, since: ticket)
    }

    /// Reports a change at `paths`, made or possibly made through this connection, to the cache in `attachment`.
    ///
    /// Files open at or under `paths` stop reporting when the change may have removed them. Otherwise the change counts
    /// against them, so that their reports it overlapped are invalidated; see ``OpenFileRegistry``.
    ///
    /// - Parameters:
    ///   - paths: The paths that changed, or may have.
    ///   - attachment: The cache attached when the change was made, or `nil`.
    ///   - removing: Whether the change may have removed what is at `paths`, so that files open there stop reporting.
    ///   - removed: Whether the server confirmed it removed what was at `paths`, so files open there have no path left.
    /// Otherwise a change through them goes on invalidating the path they had.
    ///   - change: What ``OpenFileRegistry/beginChange()`` returned before the server call, which this ends, or `nil`
    /// to start the change now.
    nonisolated(nonsending) func reportChange(
        at paths: [String],
        to attachment: SMBCacheAttachment?,
        removing: Bool,
        removed: Bool = false,
        since change: OpenFileRegistry.ChangeTicket? = nil
    ) async {
        guard let attachment else {
            return
        }

        let change = change ?? attachment.openFiles.beginChange()
        var stray: [String] = []
        if removing {
            stray = attachment.openFiles.stopReporting(atOrUnder: paths, change: change, removed: removed)
        }
        else {
            attachment.openFiles.noteChanges(atOrUnder: paths, change: change)
        }

        await attachment.invalidate(paths + stray)
        await attachment.invalidate(attachment.openFiles.endChange(change))
    }

    /// Reports a rename whose call failed, and may have renamed `from` to `to` or not, to the cache in `attachment`.
    ///
    /// Both paths are invalidated. Files open at or under either stop reporting, and keep the paths they may be at.
    nonisolated(nonsending) func reportFailedRename(
        from: String,
        to: String,
        attachment: SMBCacheAttachment?,
        since change: OpenFileRegistry.ChangeTicket? = nil
    ) async {
        guard let attachment else {
            return
        }

        let change = change ?? attachment.openFiles.beginChange()
        let stray = attachment.openFiles.stopReportingAfterFailedRename(from: from, to: to, change: change)
        await attachment.invalidate([from, to] + stray)
        await attachment.invalidate(attachment.openFiles.endChange(change))
    }

    /// Reports a rename the server confirmed to the cache in `attachment`, and moves the files open at or under `from`
    /// with it.
    ///
    /// Reports those files hand over while the cache hears of the rename may land on either side of it, so the paths
    /// they reached are invalidated once it is through.
    nonisolated(nonsending) func reportRename(
        from: String,
        to: String,
        attachment: SMBCacheAttachment?,
        since change: OpenFileRegistry.ChangeTicket? = nil
    ) async {
        guard let attachment else {
            return
        }

        let change = change ?? attachment.openFiles.beginChange()
        let rename = attachment.openFiles.beginRename(from: from, to: to, change: change)
        await attachment.cache.didRename(from: from, to: to)

        await attachment.invalidate(attachment.openFiles.finishRename(rename))
        await attachment.invalidate(attachment.openFiles.endChange(change))
    }
}

extension SMBCacheAttachment {
    /// Invalidates `paths` in the cache, each once.
    func invalidate(_ paths: [String]) async {
        for path in RegistryPath.unique(paths) {
            await cache.invalidate(path: path)
        }
    }
}

// MARK: Answers

extension SMB.Error {
    /// The error a stat throws when the cache answers that nothing exists at `path`, as the server reports it.
    static func cachedPathNotFound(_ path: String) -> SMB.Error {
        .ntStatus(
            .objectNameNotFound,
            posixCode: ENOENT,
            operation: "smb2_stat",
            message: "Nothing exists at \(path)"
        )
    }
}
