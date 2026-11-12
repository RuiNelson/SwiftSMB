//
// Part of SwiftSMB
// Connection-Cache.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

public extension SMB.Connection {
    /// Attaches `cache`, replacing any cache already attached.
    ///
    /// Files opened and connections forked from now on use `cache`: they consult it before reading, stating, or
    /// listing, and report what they read, write, and change to it. Files already open keep the cache they were opened
    /// with. Each attachment keeps track of the files opened with it: renames and deletes through this connection, and
    /// through the forks made from now on, reach those files, but not files opened under an earlier attachment, even of
    /// the same cache, nor those of connections that attached `cache` separately. See ``SMB/BlockLevelReadCache`` for
    /// what the connection reports.
    ///
    /// A cache that needs a connection of its own to the server should get a fork made before the cache is attached, so
    /// that connection does not use the cache:
    ///
    /// ```swift
    /// let connection = try await SMB.connect(server: server, credentials: credentials, share: "Photos")
    ///
    /// let control = try await connection.fork()
    /// connection.attachCache(MySMBCache(controlConnection: control))
    /// ```
    ///
    /// Disconnecting does not disconnect a connection the cache holds; whoever owns the cache disconnects it. Attaching
    /// a cache to a connection that is already disconnected does nothing.
    ///
    /// - Parameter cache: The cache to attach.
    func attachCache(_ cache: any SMB.BlockLevelReadCache) {
        let attachment = SMBCacheAttachment(cache: cache)
        protectedCacheAttachment.withLock { current in
            // `disconnect()` takes the context before it detaches, so a cache attached after that check would stay.
            guard isConnected else {
                return
            }
            current = attachment
        }
    }

    /// Detaches the attached cache, if any.
    ///
    /// Files opened from now on use no cache. Files already open keep calling the cache they were opened with until
    /// they close, while renames and deletes through this connection no longer reach them or the cache.
    /// ``disconnect()`` and ``disconnectGracefully()`` detach the cache.
    func detachCache() {
        protectedCacheAttachment.current = nil
    }

    /// Whether a cache is attached.
    ///
    /// - Returns: `true` when a cache attached with ``attachCache(_:)`` is still attached.
    func hasCacheAttached() -> Bool {
        protectedCacheAttachment.current != nil
    }
}

/// A cache attached to a connection, shared by the forks made from that connection while it was attached.
///
/// A new attachment is made every time a cache is attached, so the files opened under one attachment are told apart
/// from those opened under another, even of the same cache.
struct SMBCacheAttachment: Sendable {
    /// The attached cache.
    let cache: any SMB.BlockLevelReadCache
    /// The files open with this attachment, across the connection and the forks that inherited it.
    let openFiles: OpenFileRegistry

    init(cache: any SMB.BlockLevelReadCache, openFiles: OpenFileRegistry = OpenFileRegistry()) {
        self.cache = cache
        self.openFiles = openFiles
    }
}

extension SMB.Connection {
    /// The attached cache, or `nil`.
    var cache: any SMB.BlockLevelReadCache? {
        cacheAttachment?.cache
    }

    /// The attached cache and what travels with it, or `nil`.
    var cacheAttachment: SMBCacheAttachment? {
        protectedCacheAttachment.current
    }
}
