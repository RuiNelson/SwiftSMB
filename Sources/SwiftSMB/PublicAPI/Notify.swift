//
// Part of SwiftSMB
// Notify.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

public extension SMB {
    /// Options that control how a directory watcher is armed.
    struct NotifyOptions: OptionSet, Equatable, CustomDebugStringConvertible, Sendable {
        /// The raw option bitfield.
        public let rawValue: UInt16

        /// Watch the entire subtree rooted at the requested directory.
        public static let recursive = NotifyOptions(rawValue: Bridge.NotifyChangeFlags.watchTree.rawValue)

        /// Creates notification options from a raw bitfield.
        ///
        /// - Parameter rawValue: The raw option bitfield.
        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        /// The bridge representation for these options.
        var bridgeValue: Bridge.NotifyChangeFlags {
            var flags = Bridge.NotifyChangeFlags()
            if contains(.recursive) {
                flags.insert(.watchTree)
            }
            return flags
        }

        /// A debug description of the enabled notification options.
        public var debugDescription: String {
            describeFlags([
                (.recursive, "recursive"),
            ], typeName: "SMB.NotifyOptions")
        }
    }

    /// The kinds of directory changes a watcher should report.
    struct NotifyFilter: OptionSet, Equatable, CustomDebugStringConvertible, Sendable {
        /// The raw filter bitfield.
        public let rawValue: UInt32

        /// File name changes.
        public static let fileName = NotifyFilter(rawValue: Bridge.NotifyChangeFilter.fileName.rawValue)

        /// Directory name changes.
        public static let directoryName = NotifyFilter(rawValue: Bridge.NotifyChangeFilter.directoryName.rawValue)

        /// File or directory attribute changes.
        public static let attributes = NotifyFilter(rawValue: Bridge.NotifyChangeFilter.attributes.rawValue)

        /// File size changes.
        public static let size = NotifyFilter(rawValue: Bridge.NotifyChangeFilter.size.rawValue)

        /// Last-write timestamp changes.
        public static let lastWrite = NotifyFilter(rawValue: Bridge.NotifyChangeFilter.lastWrite.rawValue)

        /// Last-access timestamp changes.
        public static let lastAccess = NotifyFilter(rawValue: Bridge.NotifyChangeFilter.lastAccess.rawValue)

        /// Creation timestamp changes.
        public static let creation = NotifyFilter(rawValue: Bridge.NotifyChangeFilter.creation.rawValue)

        /// Extended attribute changes.
        public static let extendedAttributes = NotifyFilter(rawValue: Bridge.NotifyChangeFilter.extendedAttributes
            .rawValue)

        /// Security descriptor changes.
        public static let security = NotifyFilter(rawValue: Bridge.NotifyChangeFilter.security.rawValue)

        /// Alternate data stream name changes.
        public static let streamName = NotifyFilter(rawValue: Bridge.NotifyChangeFilter.streamName.rawValue)

        /// Alternate data stream size changes.
        public static let streamSize = NotifyFilter(rawValue: Bridge.NotifyChangeFilter.streamSize.rawValue)

        /// Alternate data stream write changes.
        public static let streamWrite = NotifyFilter(rawValue: Bridge.NotifyChangeFilter.streamWrite.rawValue)

        /// All change kinds supported by this library.
        public static let all = NotifyFilter(rawValue: Bridge.NotifyChangeFilter.all.rawValue)

        /// Creates a notification filter from a raw bitfield.
        ///
        /// - Parameter rawValue: The raw filter bitfield.
        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }

        /// The bridge representation for this filter.
        var bridgeValue: Bridge.NotifyChangeFilter {
            Bridge.NotifyChangeFilter(rawValue: rawValue)
        }

        /// A debug description of the enabled notification filters.
        public var debugDescription: String {
            describeFlags([
                (.fileName, "fileName"),
                (.directoryName, "directoryName"),
                (.attributes, "attributes"),
                (.size, "size"),
                (.lastWrite, "lastWrite"),
                (.lastAccess, "lastAccess"),
                (.creation, "creation"),
                (.extendedAttributes, "extendedAttributes"),
                (.security, "security"),
                (.streamName, "streamName"),
                (.streamSize, "streamSize"),
                (.streamWrite, "streamWrite"),
            ], typeName: "SMB.NotifyFilter")
        }
    }

    /// A single change reported by an SMB directory notification.
    struct NotifyChange: Equatable, CustomDebugStringConvertible, Sendable {
        /// The action reported for a changed path.
        public enum Action: Equatable, CustomDebugStringConvertible, Sendable {
            /// A file or directory was added.
            case added

            /// A file or directory was removed.
            case removed

            /// A file or directory was modified.
            case modified

            /// The previous name of a renamed file or directory.
            case renamedOldName

            /// The new name of a renamed file or directory.
            case renamedNewName

            /// An alternate data stream was added.
            case addedStream

            /// An alternate data stream was removed.
            case removedStream

            /// An alternate data stream was modified.
            case modifiedStream

            /// An action value not recognized by this version of SwiftSMB.
            case unknown(UInt32)

            /// Creates a public action from a bridge value.
            init(_ bridgeValue: Bridge.NotifyChangeAction) {
                switch bridgeValue {
                case .added:
                    self = .added
                case .removed:
                    self = .removed
                case .modified:
                    self = .modified
                case .renamedOldName:
                    self = .renamedOldName
                case .renamedNewName:
                    self = .renamedNewName
                case .addedStream:
                    self = .addedStream
                case .removedStream:
                    self = .removedStream
                case .modifiedStream:
                    self = .modifiedStream
                case let .unknown(rawValue):
                    self = .unknown(rawValue)
                }
            }

            /// A debug description of the action.
            public var debugDescription: String {
                switch self {
                case .added: "SMB.NotifyChange.Action.added"
                case .removed: "SMB.NotifyChange.Action.removed"
                case .modified: "SMB.NotifyChange.Action.modified"
                case .renamedOldName: "SMB.NotifyChange.Action.renamedOldName"
                case .renamedNewName: "SMB.NotifyChange.Action.renamedNewName"
                case .addedStream: "SMB.NotifyChange.Action.addedStream"
                case .removedStream: "SMB.NotifyChange.Action.removedStream"
                case .modifiedStream: "SMB.NotifyChange.Action.modifiedStream"
                case let .unknown(rawValue): "SMB.NotifyChange.Action.unknown(\(hex(rawValue)))"
                }
            }
        }

        /// The change action.
        public let action: Action

        /// The changed path, relative to the watched directory.
        public let name: String

        /// Creates a notification change.
        ///
        /// - Parameters:
        ///   - action: The change action.
        ///   - name: The changed path, relative to the watched directory.
        public init(action: Action, name: String) {
            self.action = action
            self.name = name
        }

        /// Creates a public change from a bridge value.
        init(_ bridgeValue: Bridge.NotifyChange) {
            action = Action(bridgeValue.action)
            name = bridgeValue.name
        }

        /// A debug description of the change.
        public var debugDescription: String {
            "SMB.NotifyChange(action: \(action.debugDescription), name: \(name))"
        }
    }

    /// An armed directory watcher that reports change batches as an asynchronous sequence.
    ///
    /// Create a watcher with ``SMB/Connection/watchDirectory(at:options:filter:)`` and iterate it with `for try await`.
    /// The watcher is already armed when `watchDirectory` returns, so changes made after that point are reported:
    ///
    /// ```swift
    /// let watcher = try await connection.watchDirectory(at: "Inbox")
    /// for try await changes in watcher {
    ///     for change in changes {
    ///         print(change.action, change.name)
    ///     }
    /// }
    /// ```
    ///
    /// Iteration ends normally when the watcher is cancelled with ``cancel()``, when the iterating task is cancelled,
    /// when the connection is disconnected, or when the watcher is deallocated. It ends by throwing when the server or
    /// the network reports an error.
    ///
    /// Iterate a watcher from one task at a time. Change batches that arrive while nobody is iterating are buffered
    /// until they are consumed.
    final class NotifyWatcher: AsyncSequence, CustomDebugStringConvertible, Sendable {
        /// A batch of changes reported by a single SMB change notification.
        public typealias Element = [NotifyChange]

        /// An iterator over a watcher's change batches.
        ///
        /// The iterator keeps its watcher alive, so a watcher is not cancelled by deallocation while it is iterated.
        public struct AsyncIterator: AsyncIteratorProtocol {
            private let watcher: NotifyWatcher
            private var base: AsyncThrowingStream<[NotifyChange], any Swift.Error>.Iterator

            init(watcher: NotifyWatcher, base: AsyncThrowingStream<[NotifyChange], any Swift.Error>.Iterator) {
                self.watcher = watcher
                self.base = base
            }

            /// Returns the next change batch, or `nil` once the watcher has stopped.
            ///
            /// - Throws: ``SMB/Error`` if the server or the network reports an error while watching.
            public mutating func next() async throws -> [NotifyChange]? {
                try await base.next()
            }
        }

        /// The path being watched, relative to the share root.
        public let path: String

        private let state: SMBNotifyWatcherState
        private let stream: AsyncThrowingStream<[NotifyChange], any Swift.Error>

        /// Creates a watcher around an already-armed notification state and the stream it feeds.
        init(path: String, state: SMBNotifyWatcherState, stream: AsyncThrowingStream<[NotifyChange], any Swift.Error>) {
            self.path = path
            self.state = state
            self.stream = stream
        }

        deinit {
            cancel()
        }

        /// Returns an iterator over the change batches reported by the server.
        public func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator(watcher: self, base: stream.makeAsyncIterator())
        }

        /// Cancels the watcher.
        ///
        /// Cancellation is idempotent and returns immediately. Iteration ends normally once any pending SMB notify
        /// request has been cancelled and the internal directory handle has been closed.
        public func cancel() {
            state.cancel()
        }

        /// A debug description of the watched path.
        public var debugDescription: String {
            "SMB.NotifyWatcher(path: \(path))"
        }
    }
}

public extension SMB.Connection {
    /// Watches a directory for SMB change notifications.
    ///
    /// The returned watcher is already armed: changes made after this method returns are reported. Iterate it with
    /// `for try await` to receive change batches. Call ``SMB/NotifyWatcher/cancel()``, cancel the iterating task, or
    /// release the watcher when you are done.
    ///
    /// - Parameters:
    ///   - path: The directory path, relative to the share root.
    ///   - options: Watcher options, such as recursive subtree watching.
    ///   - filter: The kinds of changes to report.
    /// - Returns: An armed directory watcher.
    /// - Throws: ``SMB/Error`` if the connection is closed, `path` is invalid, or the directory cannot be opened or
    /// armed
    /// for notifications.
    func watchDirectory(
        at path: String = "",
        options: SMB.NotifyOptions = [],
        filter: SMB.NotifyFilter = .all
    ) async throws -> SMB.NotifyWatcher {
        let path = try SMB.validatePath(path, operation: .smb2Open, allowRoot: true)
        let context = try requireContext()
        let directory = try await Bridge.open(
            context: context,
            path: path,
            flags: Bridge.OpenFlags(.readOnly, options: [.directory])
        )

        let (stream, continuation) = AsyncThrowingStream<[SMB.NotifyChange], any Swift.Error>.makeStream()
        let state = SMBNotifyWatcherState(
            context: context,
            directory: directory,
            options: options.bridgeValue,
            filter: filter.bridgeValue,
            continuation: continuation,
            onFinish: { [weak self] id in
                self?.unregisterNotifyWatcher(id: id)
            }
        )

        do {
            try await state.armRequest()
        }
        catch {
            try? await Bridge.close(context: context, file: directory)
            throw error
        }

        state.start()
        registerNotifyWatcher(state)
        return SMB.NotifyWatcher(path: path, state: state, stream: stream)
    }
}

extension SMB.Connection {
    /// Registers a watcher so it can be cancelled before context teardown.
    func registerNotifyWatcher(_ watcher: SMBNotifyWatcherState) {
        protectedNotifyWatchers.withLock { watchers in
            watchers[watcher.id] = watcher
        }
    }

    /// Removes a finished watcher from the active watcher registry.
    func unregisterNotifyWatcher(id: UUID) {
        protectedNotifyWatchers.withLock { watchers in
            _ = watchers.removeValue(forKey: id)
        }
    }

    /// Cancels all active watchers and waits until they have released their bridge resources.
    func cancelNotifyWatchers() async {
        let watchers = protectedNotifyWatchers.take(replacingWith: [:])
        for watcher in watchers.values {
            await watcher.cancelAndWait()
        }
    }

    /// Cancels all active watchers without waiting. Used from `deinit`, which cannot await.
    ///
    /// Their cleanup is enqueued on the context queue, so it runs before any teardown enqueued afterwards.
    func cancelNotifyWatchersInBackground() {
        let watchers = protectedNotifyWatchers.take(replacingWith: [:])
        for watcher in watchers.values {
            watcher.releaseResourcesInBackground()
        }
    }
}

/// Owns the notification loop, the pending notify request, and the directory handle for a watcher.
final class SMBNotifyWatcherState: Sendable {
    /// Mutable watcher state protected by `protectedState`.
    struct State {
        /// Whether cancellation has been requested.
        var isCancellationRequested = false

        /// The currently armed bridge request, if one is pending.
        var pendingRequest: Bridge.PendingRequest?

        /// The completed bridge result waiting to be handled by the loop.
        var completedResult: Result<[Bridge.NotifyChange], SMB.Error>?

        /// Whether the pending request and directory handle have been released.
        var didReleaseResources = false

        /// The task running the notification loop.
        var loop: Task<Void, Never>?
    }

    /// Stable identity used by the connection watcher registry.
    let id = UUID()

    /// The SMB context that owns the pending request.
    private let context: Bridge.Context

    /// The open directory handle used to arm notifications.
    private let directory: Bridge.FileHandle

    /// Bridge options used for each notification request.
    private let options: Bridge.NotifyChangeFlags

    /// Bridge filter used for each notification request.
    private let filter: Bridge.NotifyChangeFilter

    /// Feeds change batches to the public watcher's stream.
    private let continuation: AsyncThrowingStream<[SMB.NotifyChange], any Swift.Error>.Continuation

    /// Called after cleanup so the connection can unregister this watcher.
    private let onFinish: @Sendable (UUID) -> Void

    /// Protected mutable state.
    private let protectedState: Protected<State>

    /// Creates watcher state for an open directory handle.
    init(
        context: Bridge.Context,
        directory: Bridge.FileHandle,
        options: Bridge.NotifyChangeFlags,
        filter: Bridge.NotifyChangeFilter,
        continuation: AsyncThrowingStream<[SMB.NotifyChange], any Swift.Error>.Continuation,
        onFinish: @escaping @Sendable (UUID) -> Void
    ) {
        self.context = context
        self.directory = directory
        self.options = options
        self.filter = filter
        self.continuation = continuation
        self.onFinish = onFinish
        protectedState = Protected(State(), label: "com.ruinelson.SwiftSMB.SMB.NotifyWatcher.state.\(id)")

        // Ending the iteration early, for example by cancelling the iterating task, cancels the watcher.
        continuation.onTermination = { [weak self] _ in
            self?.cancel()
        }
    }

    /// Arms a one-shot notify request and records it as pending.
    func armRequest() async throws {
        let request = try await Bridge.notifyChange(
            context: context,
            directory: directory,
            flags: options,
            filter: filter
        ) { [weak self] result in
            self?.complete(result)
        }

        protectedState.withLock { state in
            state.pendingRequest = request
        }
    }

    /// Starts the notification loop. The loop keeps this state alive until it finishes.
    func start() {
        let loop = Task {
            await self.run()
        }
        protectedState.withLock { state in
            state.loop = loop
        }
    }

    /// Requests cancellation. The loop stops after its current bridge operation.
    func cancel() {
        protectedState.withLock { state in
            state.isCancellationRequested = true
        }
    }

    /// Requests cancellation and waits until the loop has released its bridge resources.
    func cancelAndWait() async {
        cancel()
        let loop = protectedState.withLock { state in
            state.loop
        }
        await loop?.value
    }

    /// Requests cancellation and enqueues the release of bridge resources without waiting.
    func releaseResourcesInBackground() {
        cancel()
        let claim = claimResources()
        guard claim.claimed else {
            return
        }

        if let request = claim.pendingRequest {
            Bridge.cancelInBackground(context: context, request: request)
        }
        Bridge.closeInBackground(context: context, file: directory)
    }

    /// Services the SMB context, delivering each completed notification and re-arming until cancelled.
    private func run() async {
        var failure: (any Swift.Error)?
        do {
            while !isCancellationRequested {
                if let result = takeCompletedResult() {
                    try deliver(result)
                    try await armRequest()
                }
                else {
                    try await Bridge.serviceNotifyEvents(context: context)
                }
            }
        }
        catch {
            if !isCancellationRequested {
                failure = error
            }
        }

        await releaseResources()
        if let failure {
            continuation.finish(throwing: failure)
        }
        else {
            continuation.finish()
        }
        onFinish(id)
    }

    /// Whether the loop should stop.
    private var isCancellationRequested: Bool {
        protectedState.withLock { state in
            state.isCancellationRequested
        }
    }

    /// Stores a completed bridge result for the loop to consume. Called on the context queue.
    private func complete(_ result: Result<[Bridge.NotifyChange], SMB.Error>) {
        protectedState.withLock { state in
            state.pendingRequest = nil
            state.completedResult = result
        }
    }

    /// Takes the completed bridge result, if one is available.
    private func takeCompletedResult() -> Result<[Bridge.NotifyChange], SMB.Error>? {
        protectedState.withLock { state in
            let result = state.completedResult
            state.completedResult = nil
            return result
        }
    }

    /// Yields a successful change batch to the stream, or throws the reported failure.
    private func deliver(_ result: Result<[Bridge.NotifyChange], SMB.Error>) throws {
        let changes = try result.get().map(SMB.NotifyChange.init)
        if !changes.isEmpty {
            continuation.yield(changes)
        }
    }

    /// Claims the right to release bridge resources, which happens exactly once.
    private func claimResources() -> (claimed: Bool, pendingRequest: Bridge.PendingRequest?) {
        protectedState.withLock { state in
            guard !state.didReleaseResources else {
                return (false, nil)
            }

            state.didReleaseResources = true
            let request = state.pendingRequest
            state.pendingRequest = nil
            return (true, request)
        }
    }

    /// Cancels the pending notify request and closes the directory handle.
    private func releaseResources() async {
        let claim = claimResources()
        guard claim.claimed else {
            return
        }

        if let request = claim.pendingRequest {
            try? await Bridge.cancel(context: context, request: request)
        }
        try? await Bridge.close(context: context, file: directory)
    }
}
