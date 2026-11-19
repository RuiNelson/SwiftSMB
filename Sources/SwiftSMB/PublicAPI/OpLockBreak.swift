//
// Part of SwiftSMB
// OpLockBreak.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

public extension SMB.File {
    /// A break of the oplock or lease a file was opened with.
    ///
    /// The server breaks an oplock or a lease when another client opens the file in a way that conflicts with what this
    /// client may cache. Data cached under the old state must be written back (for write caching) or dropped (for read
    /// caching) before the client goes on under the new state.
    struct OpLockBreak: Equatable, Sendable, CustomDebugStringConvertible {
        /// What the break changes.
        public enum Change: Equatable, Sendable {
            /// The lease's caching state is lowered from `from` to `to`.
            case lease(from: LeaseState, to: LeaseState)

            /// The oplock is lowered to `to`, either ``File/OpLock/levelII`` or ``File/OpLock/none``.
            case opLock(to: OpLock)
        }

        /// What the break changes.
        public let change: Change

        /// Whether the server waits for ``File/acknowledgeOpLockBreak(keeping:)`` before it lets the conflicting open
        /// go on.
        ///
        /// Write back or drop the cached data first, then acknowledge. If the server does not get the acknowledgement
        /// in time (35 seconds by default), it lowers the lease to no caching by itself. Breaks of classic oplocks are
        /// always acknowledged by SwiftSMB, and so are breaks that arrive while nobody iterates
        /// ``File/opLockBreaks``.
        public let requiresAcknowledgement: Bool

        public var debugDescription: String {
            switch change {
            case let .lease(from, to):
                "SMB.File.OpLockBreak(lease: \(from.debugDescription) -> \(to.debugDescription), "
                    + "requiresAcknowledgement: \(requiresAcknowledgement))"
            case let .opLock(to):
                "SMB.File.OpLockBreak(opLock -> \(to))"
            }
        }
    }

    /// The oplock and lease breaks of one file, as an asynchronous sequence.
    ///
    /// ```swift
    /// let file = try await connection.openFile(
    ///     at: "report.docx",
    ///     accessMode: .readWrite,
    ///     opLock: .lease([.readCaching, .writeCaching, .handleCaching])
    /// )
    /// for try await opLockBreak in file.opLockBreaks {
    ///     try await flushLocalChanges(to: file)
    ///     if opLockBreak.requiresAcknowledgement {
    ///         try await file.acknowledgeOpLockBreak()
    ///     }
    /// }
    /// ```
    ///
    /// While the sequence is iterated, SwiftSMB services the connection in the background, so breaks are seen even when
    /// the connection is otherwise idle, and lease breaks that need an acknowledgement wait for
    /// ``File/acknowledgeOpLockBreak(keeping:)``. When iteration ends with a break still unacknowledged, SwiftSMB
    /// acknowledges it with the state the server asked for.
    ///
    /// Iteration ends normally when the file is closed or the connection is disconnected, and by throwing when the
    /// connection fails. A file opened with ``File/OpLock/none`` has no breaks: its sequence is empty. Iterate it from
    /// one task at a time.
    final class OpLockBreaks: AsyncSequence, Sendable {
        public typealias Element = OpLockBreak

        /// An iterator over a file's breaks. It keeps the file open while it exists.
        public struct AsyncIterator: AsyncIteratorProtocol {
            private let breaks: OpLockBreaks
            private let listener: SMBOpLockBreakListener?
            private var base: AsyncThrowingStream<OpLockBreak, any Swift.Error>.Iterator

            init(breaks: OpLockBreaks, listener: SMBOpLockBreakListener?) {
                self.breaks = breaks
                self.listener = listener
                base = breaks.stream.makeAsyncIterator()
            }

            /// Returns the next break, or `nil` once the file is closed or the connection disconnected.
            ///
            /// - Throws: ``SMB/Error`` if the connection fails.
            public mutating func next() async throws -> OpLockBreak? {
                try await base.next()
            }
        }

        private let file: SMB.File
        private let stream: AsyncThrowingStream<OpLockBreak, any Swift.Error>

        init(file: SMB.File, stream: AsyncThrowingStream<OpLockBreak, any Swift.Error>) {
            self.file = file
            self.stream = stream
        }

        /// Returns an iterator, and starts listening for breaks.
        public func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator(breaks: self, listener: file.opLockBreakState.map(SMBOpLockBreakListener.init))
        }
    }

    /// The oplock and lease breaks the server sends for this file.
    var opLockBreaks: OpLockBreaks {
        if let opLockBreakState {
            return OpLockBreaks(file: self, stream: opLockBreakState.stream)
        }
        return OpLockBreaks(file: self, stream: AsyncThrowingStream { $0.finish() })
    }

    /// Acknowledges the lease break that ``OpLockBreak/requiresAcknowledgement``.
    ///
    /// Call it once the data cached under the old state has been written back or dropped. Doing nothing when no break
    /// waits for an acknowledgement, it is safe to call more than once.
    ///
    /// - Parameter state: The caching state to keep, which must be the state the server lowered the lease to, or less.
    ///   `nil` keeps the state the server lowered it to.
    /// - Throws: ``SMB/Error`` if `state` has caching the break took away, the connection is closed, or the server
    /// refuses the acknowledgement, for example because its break timeout expired first.
    func acknowledgeOpLockBreak(keeping state: LeaseState? = nil) async throws {
        try await connection.withOperation {
            let context = try connection.requireContext()
            guard let opLockBreakState, let pending = opLockBreakState.takePendingAcknowledgement() else { return }
            let kept = state ?? pending.newState
            guard pending.newState.isSuperset(of: kept) else {
                opLockBreakState.restorePendingAcknowledgement(pending)
                throw SMB.Error.invalidArgument(
                    cause: .leaseAcknowledgementAddsCaching(kept.debugDescription),
                    onOperation: .smbFileAcknowledgeOpLockBreak
                )
            }
            try await Bridge.acknowledgeLeaseBreak(context: context, key: pending.key, state: kept.bridgeValue)
        }
    }
}

// MARK: - Routing

/// Which open a break names: a lease by its key, a classic oplock by the file ID of its open.
enum SMBOpLockBreakTarget: Hashable, Sendable {
    case lease(Bridge.LeaseKey)
    case opLock(Bridge.FileID)
}

/// A lease break waiting for ``SMB/File/acknowledgeOpLockBreak(keeping:)``.
struct SMBPendingLeaseAcknowledgement: Sendable {
    let key: Bridge.LeaseKey
    let newState: SMB.File.LeaseState
}

/// Keeps one iteration of ``SMB/File/OpLockBreaks`` listening. Ending the iteration, also with `break`, releases it.
final class SMBOpLockBreakListener: Sendable {
    private let state: SMBOpLockBreakState

    init(_ state: SMBOpLockBreakState) {
        self.state = state
        state.beginListening()
    }

    deinit {
        state.endListening()
    }
}

/// The breaks of one file: the stream that delivers them and the acknowledgement that may be pending.
final class SMBOpLockBreakState: Sendable {
    private struct State {
        var listenerCount = 0
        var pendingAcknowledgement: SMBPendingLeaseAcknowledgement?
        var isFinished = false
    }

    let target: SMBOpLockBreakTarget
    let stream: AsyncThrowingStream<SMB.File.OpLockBreak, any Swift.Error>
    private let continuation: AsyncThrowingStream<SMB.File.OpLockBreak, any Swift.Error>.Continuation
    private let context: Bridge.Context
    private let router: SMBOpLockBreakRouter
    private let protectedState = Protected(State(), label: "com.ruinelson.SwiftSMB.SMB.File.opLockBreaks")

    init(target: SMBOpLockBreakTarget, context: Bridge.Context, router: SMBOpLockBreakRouter) {
        self.target = target
        self.context = context
        self.router = router
        (stream, continuation) = AsyncThrowingStream.makeStream()
    }

    /// Delivers a break and decides whether it waits for an acknowledgement. Called on the context queue.
    func receive(_ opLockBreak: Bridge.OpLockBreak) -> Bridge.OpLockBreakDisposition {
        protectedState.withLock { state in
            guard !state.isFinished else { return .acknowledgeNow }
            switch opLockBreak {
            case let .lease(key, currentState, newState, _, requiresAcknowledgement):
                let newState = SMB.File.LeaseState(rawValue: newState.rawValue)
                let waits = requiresAcknowledgement && state.listenerCount > 0
                if waits {
                    state.pendingAcknowledgement = SMBPendingLeaseAcknowledgement(key: key, newState: newState)
                }
                continuation.yield(SMB.File.OpLockBreak(
                    change: .lease(from: SMB.File.LeaseState(rawValue: currentState.rawValue), to: newState),
                    requiresAcknowledgement: waits
                ))
                return waits ? .acknowledgeLater : .acknowledgeNow

            case let .opLock(_, newLevel):
                continuation.yield(SMB.File.OpLockBreak(
                    change: .opLock(to: newLevel == .levelII ? .levelII : .none),
                    requiresAcknowledgement: false
                ))
                return .acknowledgeNow
            }
        }
    }

    func takePendingAcknowledgement() -> SMBPendingLeaseAcknowledgement? {
        protectedState.withLock { state in
            defer { state.pendingAcknowledgement = nil }
            return state.pendingAcknowledgement
        }
    }

    func restorePendingAcknowledgement(_ pending: SMBPendingLeaseAcknowledgement) {
        protectedState.withLock { state in
            if !state.isFinished, state.pendingAcknowledgement == nil {
                state.pendingAcknowledgement = pending
            }
        }
    }

    func beginListening() {
        let isFirst = protectedState.withLock { state in
            state.listenerCount += 1
            return state.listenerCount == 1 && !state.isFinished
        }
        if isFirst {
            router.retainListener(context: context)
        }
    }

    /// Stops listening. A break still waiting for an acknowledgement is acknowledged with the state the server asked
    /// for, since nobody is left to do it.
    func endListening() {
        let (isLast, pending) = protectedState.withLock { state in
            state.listenerCount -= 1
            guard state.listenerCount == 0 else { return (false, SMBPendingLeaseAcknowledgement?.none) }
            defer { state.pendingAcknowledgement = nil }
            return (!state.isFinished, state.pendingAcknowledgement)
        }
        if let pending {
            Bridge.acknowledgeLeaseBreakInBackground(
                context: context,
                key: pending.key,
                state: pending.newState.bridgeValue
            )
        }
        if isLast {
            router.releaseListener()
        }
    }

    /// Ends the stream, when the file closes or the connection goes away. Unacknowledged breaks need nothing more:
    /// closing the open ends its lease or oplock.
    func finish(throwing error: any Swift.Error? = nil) {
        let wasListening = protectedState.withLock { state in
            guard !state.isFinished else { return false }
            state.isFinished = true
            state.pendingAcknowledgement = nil
            return state.listenerCount > 0
        }
        router.unregister(self)
        if wasListening {
            router.releaseListener()
        }
        if let error {
            continuation.finish(throwing: error)
        }
        else {
            continuation.finish()
        }
    }
}

/// Routes the breaks of a connection's context to the files they name, and services the context while any file's breaks
/// are iterated.
final class SMBOpLockBreakRouter: Sendable {
    private final class WeakState: Sendable {
        weak let value: SMBOpLockBreakState?

        init(_ value: SMBOpLockBreakState) {
            self.value = value
        }
    }

    private struct State {
        var routes: [SMBOpLockBreakTarget: WeakState] = [:]
        var installedContext: ObjectIdentifier?
        var listenerCount = 0
        var loop: Task<Void, Never>?
        var isShutDown = false
    }

    /// How long the loop waits, off the context queue, between polls for breaks.
    private static let serviceIntervalNanoseconds: UInt64 = 50_000_000

    private let protectedState = Protected(State(), label: "com.ruinelson.SwiftSMB.SMB.Connection.opLockBreaks")

    /// Makes `context` hand its breaks to this router. Does nothing after the first call for a context.
    func install(on context: Bridge.Context) async throws {
        let isInstalled = protectedState.withLock { state in
            state.installedContext == ObjectIdentifier(context)
        }
        guard !isInstalled else { return }
        try await Bridge.setOpLockBreakHandler(context: context) { [weak self] opLockBreak in
            self?.route(opLockBreak) ?? .acknowledgeNow
        }
        protectedState.withLock { state in
            state.installedContext = ObjectIdentifier(context)
        }
    }

    func register(_ breakState: SMBOpLockBreakState) {
        protectedState.withLock { state in
            state.routes[breakState.target] = WeakState(breakState)
        }
    }

    func unregister(_ breakState: SMBOpLockBreakState) {
        protectedState.withLock { state in
            if state.routes[breakState.target]?.value === breakState {
                state.routes[breakState.target] = nil
            }
        }
    }

    /// Hands a break to the file it names. Called on the context queue. Breaks of files that are not open (any more)
    /// are acknowledged right away.
    private func route(_ opLockBreak: Bridge.OpLockBreak) -> Bridge.OpLockBreakDisposition {
        let target: SMBOpLockBreakTarget = switch opLockBreak {
        case let .lease(key, _, _, _, _): .lease(key)
        case let .opLock(fileID, _): .opLock(fileID)
        }
        let breakState = protectedState.withLock { state in
            state.routes[target]?.value
        }
        return breakState?.receive(opLockBreak) ?? .acknowledgeNow
    }

    /// Starts servicing `context` in the background, unless it already is.
    func retainListener(context: Bridge.Context) {
        protectedState.withLock { state in
            state.listenerCount += 1
            guard !state.isShutDown, state.loop == nil else { return }
            state.loop = Task { [weak self] in
                await self?.run(context: context)
            }
        }
    }

    /// Stops servicing the context once no file's breaks are iterated any more.
    func releaseListener() {
        let loop = protectedState.withLock { state in
            state.listenerCount -= 1
            guard state.listenerCount == 0 else { return Task<Void, Never>?.none }
            defer { state.loop = nil }
            return state.loop
        }
        loop?.cancel()
    }

    /// Ends every file's breaks, when the connection is disconnected.
    func shutDown() {
        let (states, loop) = protectedState.withLock { state in
            state.isShutDown = true
            defer {
                state.routes.removeAll()
                state.loop = nil
            }
            return (state.routes.values.compactMap(\.value), state.loop)
        }
        loop?.cancel()
        for breakState in states {
            breakState.finish()
        }
    }

    /// Services the context so that breaks arriving on an otherwise idle connection are seen. Servicing does not wait
    /// on the context queue, so operations on the connection are not held up.
    private func run(context: Bridge.Context) async {
        while !Task.isCancelled {
            do {
                try await Bridge.serviceEvents(context: context)
            }
            catch {
                failAll(with: error)
                return
            }
            try? await Task.sleep(nanoseconds: Self.serviceIntervalNanoseconds)
        }
    }

    /// Ends every file's breaks when servicing failed. A connection that was closed ends them normally.
    private func failAll(with error: any Swift.Error) {
        let states = protectedState.withLock { state in
            defer { state.loop = nil }
            return state.routes.values.compactMap(\.value)
        }
        let isClosed = if case .operationRequestedAfterConnectionClosed? = error as? SMB.Error {
            true
        }
        else {
            false
        }
        for breakState in states {
            breakState.finish(throwing: isClosed ? nil : error)
        }
    }
}
