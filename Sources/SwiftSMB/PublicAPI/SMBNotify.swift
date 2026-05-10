//
// Part of SwiftSMB
// SMBNotify.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Dispatch
import Foundation

public extension SMB {
    /// Options that control how a directory watcher is armed.
    struct NotifyOptions: OptionSet, Equatable, CustomDebugStringConvertible, Sendable {
        /// The raw option bitfield.
        public let rawValue: UInt16

        /// Watch the entire subtree rooted at the requested directory.
        public static let recursive = NotifyOptions(rawValue: SMB2NotifyChangeFlags.watchTree.rawValue)

        /// Creates notification options from a raw bitfield.
        ///
        /// - Parameter rawValue: The raw option bitfield.
        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        /// The bridge representation for these options.
        var bridgeValue: SMB2NotifyChangeFlags {
            var flags = SMB2NotifyChangeFlags()
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
        public static let fileName = NotifyFilter(rawValue: SMB2NotifyChangeFilter.fileName.rawValue)

        /// Directory name changes.
        public static let directoryName = NotifyFilter(rawValue: SMB2NotifyChangeFilter.directoryName.rawValue)

        /// File or directory attribute changes.
        public static let attributes = NotifyFilter(rawValue: SMB2NotifyChangeFilter.attributes.rawValue)

        /// File size changes.
        public static let size = NotifyFilter(rawValue: SMB2NotifyChangeFilter.size.rawValue)

        /// Last-write timestamp changes.
        public static let lastWrite = NotifyFilter(rawValue: SMB2NotifyChangeFilter.lastWrite.rawValue)

        /// Last-access timestamp changes.
        public static let lastAccess = NotifyFilter(rawValue: SMB2NotifyChangeFilter.lastAccess.rawValue)

        /// Creation timestamp changes.
        public static let creation = NotifyFilter(rawValue: SMB2NotifyChangeFilter.creation.rawValue)

        /// Extended attribute changes.
        public static let extendedAttributes = NotifyFilter(rawValue: SMB2NotifyChangeFilter.extendedAttributes
            .rawValue)

        /// Security descriptor changes.
        public static let security = NotifyFilter(rawValue: SMB2NotifyChangeFilter.security.rawValue)

        /// Alternate data stream name changes.
        public static let streamName = NotifyFilter(rawValue: SMB2NotifyChangeFilter.streamName.rawValue)

        /// Alternate data stream size changes.
        public static let streamSize = NotifyFilter(rawValue: SMB2NotifyChangeFilter.streamSize.rawValue)

        /// Alternate data stream write changes.
        public static let streamWrite = NotifyFilter(rawValue: SMB2NotifyChangeFilter.streamWrite.rawValue)

        /// All change kinds supported by this library.
        public static let all = NotifyFilter(rawValue: SMB2NotifyChangeFilter.all.rawValue)

        /// Creates a notification filter from a raw bitfield.
        ///
        /// - Parameter rawValue: The raw filter bitfield.
        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }

        /// The bridge representation for this filter.
        var bridgeValue: SMB2NotifyChangeFilter {
            SMB2NotifyChangeFilter(rawValue: rawValue)
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
            init(_ bridgeValue: SMB2NotifyChangeAction) {
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
        init(_ bridgeValue: SMB2NotifyChange) {
            action = Action(bridgeValue.action)
            name = bridgeValue.name
        }

        /// A debug description of the change.
        public var debugDescription: String {
            "SMB.NotifyChange(action: \(action.debugDescription), name: \(name))"
        }
    }

    /// A delegate that receives SMB directory notification callbacks.
    protocol NotifyWatcherDelegate: AnyObject, Sendable {
        /// Called when the server reports a batch of changes.
        ///
        /// - Parameters:
        ///   - watcher: The watcher that received the changes.
        ///   - changes: The change batch reported by the server.
        func notifyWatcher(_ watcher: NotifyWatcher, didReceive changes: [NotifyChange])

        /// Called after the watcher has armed its first notification request.
        ///
        /// - Parameter watcher: The watcher that started listening for changes.
        func notifyWatcherDidStart(_ watcher: NotifyWatcher)

        /// Called when the watcher stops because of an error.
        ///
        /// - Parameters:
        ///   - watcher: The watcher that failed.
        ///   - error: The error that stopped the watcher.
        func notifyWatcher(_ watcher: NotifyWatcher, didFailWith error: Swift.Error)

        /// Called when the watcher is cancelled or otherwise finishes without an error.
        ///
        /// - Parameter watcher: The watcher that finished.
        func notifyWatcherDidCancel(_ watcher: NotifyWatcher)
    }

    /// A cancellable SMB directory notification watcher.
    final class NotifyWatcher: CustomDebugStringConvertible, @unchecked Sendable {
        /// The path being watched, relative to the share root.
        public let path: String

        private let state: SMBNotifyWatcherState
        private let callbackQueue: DispatchQueue
        private let protectedDelegate: Protected<SMBNotifyWatcherDelegateBox>

        /// The object that receives watcher callbacks.
        ///
        /// The watcher keeps a weak reference to its delegate. Assign a new
        /// delegate if ownership changes while the watcher is running.
        public var delegate: (any NotifyWatcherDelegate)? {
            get {
                protectedDelegate.current.delegate
            }
            set {
                protectedDelegate.current = SMBNotifyWatcherDelegateBox(newValue)
            }
        }

        /// Creates a watcher around an already-open notification state.
        init(
            path: String,
            state: SMBNotifyWatcherState,
            callbacks: SMBNotifyWatcherCallbacks,
            delegate: (any NotifyWatcherDelegate)?,
            callbackQueue: DispatchQueue,
        ) {
            self.path = path
            self.state = state
            self.callbackQueue = callbackQueue
            protectedDelegate = Protected(
                SMBNotifyWatcherDelegateBox(delegate),
                label: "SwiftSMB.SMB.NotifyWatcher.delegate.\(state.id)",
            )
            callbacks.watcher = self
            state.start()
        }

        deinit {
            cancel()
        }

        /// Cancels the watcher.
        ///
        /// Cancellation is idempotent. The watcher stops after any pending
        /// SMB notify request has been cancelled and the internal directory
        /// handle has been closed.
        public func cancel() {
            state.cancel()
        }

        /// Receives a change batch from the watcher state.
        func notifyReceived(_ changes: [NotifyChange]) {
            callbackQueue.async { [self] in
                guard let delegate else { return }
                delegate.notifyWatcher(self, didReceive: changes)
            }
        }

        /// Receives the first-armed event from the watcher state.
        func notifyStarted() {
            callbackQueue.async { [self] in
                guard let delegate else { return }
                delegate.notifyWatcherDidStart(self)
            }
        }

        /// Receives a terminal failure from the watcher state.
        func notifyFailed(with error: Swift.Error) {
            callbackQueue.async { [self] in
                guard let delegate else { return }
                delegate.notifyWatcher(self, didFailWith: error)
            }
        }

        /// Receives normal watcher cancellation from the watcher state.
        func notifyCancelled() {
            callbackQueue.async { [self] in
                guard let delegate else { return }
                delegate.notifyWatcherDidCancel(self)
            }
        }

        /// A debug description of the watched path.
        public var debugDescription: String {
            "SMB.NotifyWatcher(path: \(path))"
        }
    }
}

public extension SMB.NotifyWatcherDelegate {
    /// Default no-op implementation for watchers that only care about changes.
    func notifyWatcherDidStart(_: SMB.NotifyWatcher) {
    }

    /// Default no-op implementation for watchers that only care about changes.
    func notifyWatcher(_: SMB.NotifyWatcher, didFailWith _: Swift.Error) {
    }

    /// Default no-op implementation for watchers that only care about changes.
    func notifyWatcherDidCancel(_: SMB.NotifyWatcher) {
    }
}

public extension SMB.Connection {
    /// Watches a directory for SMB change notifications.
    ///
    /// Keep the returned watcher alive for as long as you want notifications
    /// and call ``SMB/NotifyWatcher/cancel()`` when you are done. Delegate
    /// callbacks are delivered on `callbackQueue`.
    ///
    /// - Parameters:
    ///   - path: The directory path, relative to the share root.
    ///   - options: Watcher options, such as recursive subtree watching.
    ///   - filter: The kinds of changes to report.
    ///   - delegate: The object that receives notification callbacks.
    ///   - callbackQueue: The queue used to deliver delegate callbacks.
    /// - Returns: A cancellable directory watcher.
    /// - Throws: ``SMB/Error`` if the connection is closed, `path` is invalid,
    ///   or the directory cannot be opened for notifications.
    func watchDirectory(
        at path: String = "",
        options: SMB.NotifyOptions = [],
        filter: SMB.NotifyFilter = .all,
        delegate: (any SMB.NotifyWatcherDelegate)? = nil,
        callbackQueue: DispatchQueue = .main,
    ) throws -> SMB.NotifyWatcher {
        let path = try SMB.validatePath(path, operation: .smb2Open, allowRoot: true)
        let context = try requireContext()
        let directory = try Bridge.bridgeExecution {
            try Bridge.open(
                context: context,
                path: path,
                flags: SMB2OpenFlags(.readOnly, options: [.directory]),
            )
        }
        let callbacks = SMBNotifyWatcherCallbacks()
        let state = SMBNotifyWatcherState(
            context: context,
            directory: directory,
            options: options.bridgeValue,
            filter: filter.bridgeValue,
            callbacks: callbacks,
            onFinish: { [weak self] id in
                self?.unregisterNotifyWatcher(id: id)
            },
        )

        registerNotifyWatcher(state)
        return SMB.NotifyWatcher(
            path: path,
            state: state,
            callbacks: callbacks,
            delegate: delegate,
            callbackQueue: callbackQueue,
        )
    }
}

extension SMB.Connection {
    /// Registers a watcher so it can be cancelled before context teardown.
    func registerNotifyWatcher(_ watcher: SMBNotifyWatcherState) {
        var watchers = protectedNotifyWatchers.current
        watchers[watcher.id] = watcher
        protectedNotifyWatchers.current = watchers
    }

    /// Removes a finished watcher from the active watcher registry.
    func unregisterNotifyWatcher(id: UUID) {
        protectedNotifyWatchers.current = protectedNotifyWatchers.current.filter { $0.key != id }
    }

    /// Cancels all active watchers before closing the underlying SMB context.
    func cancelNotifyWatchers() {
        let watchers = protectedNotifyWatchers.take(replacingWith: [:])
        for watcher in watchers.values {
            watcher.cancelAndWait()
        }
    }
}

/// Weakly boxes a notification delegate for storage in `Protected`.
final class SMBNotifyWatcherDelegateBox: @unchecked Sendable {
    /// The delegate receiving public watcher callbacks.
    weak var delegate: (any SMB.NotifyWatcherDelegate)?

    /// Creates a weak delegate box.
    init(_ delegate: (any SMB.NotifyWatcherDelegate)?) {
        self.delegate = delegate
    }
}

/// Routes watcher-state events back to the public watcher.
final class SMBNotifyWatcherCallbacks: @unchecked Sendable {
    /// The public watcher that should receive state events.
    weak var watcher: SMB.NotifyWatcher?

    /// Delivers a change batch to the public watcher.
    func received(_ changes: [SMB.NotifyChange]) {
        watcher?.notifyReceived(changes)
    }

    /// Delivers the first-armed event to the public watcher.
    func started() {
        watcher?.notifyStarted()
    }

    /// Delivers a terminal failure to the public watcher.
    func failed(with error: Swift.Error) {
        watcher?.notifyFailed(with: error)
    }

    /// Delivers normal cancellation to the public watcher.
    func cancelled() {
        watcher?.notifyCancelled()
    }
}

/// Owns the bridge notification loop and directory handle for a watcher.
final class SMBNotifyWatcherState: @unchecked Sendable {
    /// Mutable watcher state protected by `protectedState`.
    struct State {
        /// Whether cancellation has been requested.
        var isCancellationRequested = false

        /// The currently armed bridge request, if one is pending.
        var pendingRequest: SMB2PendingRequest?

        /// The completed bridge result waiting to be handled by the loop.
        var completedResult: Result<[SMB2NotifyChange], SMB.Error>?
    }

    /// Stable identity used by the connection watcher registry.
    let id = UUID()

    /// The SMB context that owns the pending request.
    private let context: SMB2Context

    /// The open directory handle used to arm notifications.
    private let directory: SMB2FileHandle

    /// Bridge options used for each notification request.
    private let options: SMB2NotifyChangeFlags

    /// Bridge filter used for each notification request.
    private let filter: SMB2NotifyChangeFilter

    /// Callback router for public watcher events.
    private let callbacks: SMBNotifyWatcherCallbacks

    /// Called after cleanup so the connection can unregister this watcher.
    private let onFinish: @Sendable (UUID) -> Void

    /// Serial queue that services the libsmb2 context for this watcher.
    private let queue: DispatchQueue

    /// Protected mutable request state.
    private let protectedState: Protected<State>

    /// Whether the watcher has already reported a failure.
    private let protectedDidFail: Protected<Bool>

    /// Whether the watcher has already sent its terminal callback.
    private let protectedDidFinish: Protected<Bool>

    /// Whether bridge resources have already been released.
    private let protectedDidCleanUp: Protected<Bool>

    /// Signals `cancelAndWait()` after cleanup completes.
    private let cleanupSemaphore = DispatchSemaphore(value: 0)

    /// Whether the first-armed delegate callback has been sent.
    private var didStart = false

    /// Creates watcher state for an open directory handle.
    init(
        context: SMB2Context,
        directory: SMB2FileHandle,
        options: SMB2NotifyChangeFlags,
        filter: SMB2NotifyChangeFilter,
        callbacks: SMBNotifyWatcherCallbacks,
        onFinish: @escaping @Sendable (UUID) -> Void,
    ) {
        self.context = context
        self.directory = directory
        self.options = options
        self.filter = filter
        self.callbacks = callbacks
        self.onFinish = onFinish
        queue = DispatchQueue(label: "SwiftSMB.SMB.NotifyWatcher.\(id)")
        protectedState = Protected(State(), label: "SwiftSMB.SMB.NotifyWatcher.state.\(id)")
        protectedDidFail = Protected(false, label: "SwiftSMB.SMB.NotifyWatcher.didFail.\(id)")
        protectedDidFinish = Protected(false, label: "SwiftSMB.SMB.NotifyWatcher.didFinish.\(id)")
        protectedDidCleanUp = Protected(false, label: "SwiftSMB.SMB.NotifyWatcher.didCleanUp.\(id)")
    }

    /// Starts the serial notification loop.
    func start() {
        queue.async { [self] in
            run()
        }
    }

    /// Requests asynchronous cancellation.
    func cancel() {
        var state = protectedState.current
        state.isCancellationRequested = true
        protectedState.current = state
    }

    /// Requests cancellation and waits until bridge resources are released.
    func cancelAndWait() {
        cancel()
        if protectedDidCleanUp.current {
            return
        }
        cleanupSemaphore.wait()
    }

    /// Arms one-shot notify requests and services the SMB context until cancelled.
    private func run() {
        defer {
            cleanUp()
        }

        while !isCancellationRequested {
            do {
                let request = try Bridge.bridgeExecution {
                    try Bridge.notifyChange(
                        context: context,
                        directory: directory,
                        flags: options,
                        filter: filter,
                    ) { [weak self] result in
                        self?.complete(result)
                    }
                }

                guard setPendingRequest(request) else {
                    try Bridge.bridgeExecution {
                        Bridge.cancel(context: context, request: request)
                    }
                    return
                }

                notifyStartedIfNeeded()

                while !isCancellationRequested {
                    if let result = takeCompletedResult() {
                        try handle(result)
                        break
                    }

                    try Bridge.bridgeExecution {
                        try Bridge.serviceNotifyEvents(context: context)
                    }
                }
            }
            catch {
                guard !isCancellationRequested else {
                    return
                }
                fail(with: error)
                return
            }
        }
    }

    /// Whether the run loop should stop.
    private var isCancellationRequested: Bool {
        protectedState.current.isCancellationRequested
    }

    /// Stores a newly armed request unless cancellation already won the race.
    private func setPendingRequest(_ request: SMB2PendingRequest) -> Bool {
        var state = protectedState.current
        guard !state.isCancellationRequested else {
            protectedState.current = state
            return false
        }

        state.pendingRequest = request
        protectedState.current = state
        return true
    }

    /// Sends the first-armed delegate callback once.
    private func notifyStartedIfNeeded() {
        guard !didStart else {
            return
        }

        didStart = true
        callbacks.started()
    }

    /// Stores a completed bridge result for the run loop to consume.
    private func complete(_ result: Result<[SMB2NotifyChange], SMB.Error>) {
        var state = protectedState.current
        state.pendingRequest = nil
        state.completedResult = result
        protectedState.current = state
    }

    /// Takes the completed bridge result, if one is available.
    private func takeCompletedResult() -> Result<[SMB2NotifyChange], SMB.Error>? {
        var state = protectedState.current
        let result = state.completedResult
        state.completedResult = nil
        protectedState.current = state
        return result
    }

    /// Takes the current pending request so it can be cancelled.
    private func takePendingRequest() -> SMB2PendingRequest? {
        var state = protectedState.current
        let request = state.pendingRequest
        state.pendingRequest = nil
        protectedState.current = state
        return request
    }

    /// Converts a bridge result into public delegate callbacks.
    private func handle(_ result: Result<[SMB2NotifyChange], SMB.Error>) throws {
        switch result {
        case let .success(changes):
            let publicChanges = changes.map(SMB.NotifyChange.init)
            if !publicChanges.isEmpty {
                callbacks.received(publicChanges)
            }
        case let .failure(error):
            throw error
        }
    }

    /// Cancels pending bridge work and closes the watcher directory handle.
    private func cleanUp() {
        if let request = takePendingRequest() {
            try? Bridge.bridgeExecution {
                Bridge.cancel(context: context, request: request)
            }
        }

        try? Bridge.bridgeExecution {
            try Bridge.close(context: context, file: directory)
        }
        finish()
        onFinish(id)
        protectedDidCleanUp.current = true
        cleanupSemaphore.signal()
    }

    /// Reports a terminal failure.
    private func fail(with error: Swift.Error) {
        protectedDidFail.current = true
        callbacks.failed(with: error)
        finish()
    }

    /// Sends the terminal cancellation callback once.
    private func finish() {
        let alreadyFinished = protectedDidFinish.take(replacingWith: true)
        guard !alreadyFinished else {
            return
        }

        if !protectedDidFail.current {
            callbacks.cancelled()
        }
    }
}
