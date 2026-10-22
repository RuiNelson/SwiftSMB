//
// Part of SwiftSMB
// MediaResourceLoader.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(AVFoundation) && !os(watchOS)
    import AVFoundation
    import Foundation
    import SwiftSMB
    import UniformTypeIdentifiers

    /// Answers AVFoundation's byte-range requests for one SMB file.
    ///
    /// Each loading request is served by its own task. All tasks share a single read-only file handle and read with
    /// ``SMB/File/read(upTo:atOffset:transferChunkSize:)``, which never moves the handle's offset.
    @available(macOS 11, iOS 14, tvOS 14, macCatalyst 14, visionOS 1, *)
    final class MediaResourceLoader: NSObject, AVAssetResourceLoaderDelegate, @unchecked Sendable {
        /// The delegate queue. Loading requests are only touched on this queue.
        let queue = DispatchQueue(label: "com.ruinelson.SwiftSMB.MediaResourceLoader")

        /// The media type reported to AVFoundation.
        let contentType: UTType

        private let source: MediaSource
        private let lock = NSLock()
        private var tasks: [ObjectIdentifier: Task<Void, Never>] = [:]

        init(connection: SMB.Connection, path: String, contentType: UTType) {
            source = MediaSource(connection: connection, path: path)
            self.contentType = contentType
        }

        deinit {
            for task in tasks.values {
                task.cancel()
            }
        }

        func resourceLoader(
            _: AVAssetResourceLoader,
            shouldWaitForLoadingOfRequestedResource loadingRequest: AVAssetResourceLoadingRequest
        ) -> Bool {
            let request = LoadingRequest(loadingRequest)
            let range = loadingRequest.dataRequest.map(RequestedRange.init)
            let id = ObjectIdentifier(loadingRequest)
            // Holding the lock while creating the task guarantees it is registered before it can remove itself.
            lock.withLock {
                tasks[id] = Task { [weak self] in
                    await self?.serve(request, range: range)
                    self?.removeTask(id)
                }
            }
            return true
        }

        func resourceLoader(_: AVAssetResourceLoader, didCancel loadingRequest: AVAssetResourceLoadingRequest) {
            removeTask(ObjectIdentifier(loadingRequest))?.cancel()
        }

        @discardableResult
        private func removeTask(_ id: ObjectIdentifier) -> Task<Void, Never>? {
            lock.withLock { tasks.removeValue(forKey: id) }
        }

        private func serve(_ request: LoadingRequest, range: RequestedRange?) async {
            do {
                let file = try await source.prepared()
                let contentType = contentType
                onQueue(request) { loadingRequest in
                    if let info = loadingRequest.contentInformationRequest {
                        info.contentType = contentType.identifier
                        info.contentLength = Int64(clamping: file.size)
                        info.isByteRangeAccessSupported = true
                    }
                }

                if let range {
                    let size = Int64(clamping: file.size)
                    var offset = min(range.start, size)
                    let end = range.toEnd ? size : min(range.end, size)
                    while offset < end {
                        try Task.checkCancellation()
                        let data = try await file.handle.read(
                            upTo: min(Int64(file.blockSize), end - offset),
                            atOffset: UInt64(offset)
                        )
                        guard !data.isEmpty else { break }
                        onQueue(request) { $0.dataRequest?.respond(with: data) }
                        offset += Int64(data.count)
                    }
                }

                onQueue(request) { $0.finishLoading() }
            }
            catch is CancellationError {
                // AVFoundation cancelled the request, so it must not be finished.
            }
            catch {
                let failure = Self.loadingError(for: error)
                onQueue(request) { $0.finishLoading(with: failure) }
            }
        }

        /// Runs `body` on the delegate queue unless the request has already been cancelled or finished.
        private func onQueue(
            _ request: LoadingRequest,
            _ body: @escaping @Sendable (AVAssetResourceLoadingRequest) -> Void
        ) {
            queue.async {
                let loadingRequest = request.value
                guard !loadingRequest.isCancelled, !loadingRequest.isFinished else { return }
                body(loadingRequest)
            }
        }

        /// The error to finish a failed request with.
        ///
        /// AVFoundation keeps only the code of that error and reads it as a POSIX code, so an ``SMB/Error`` becomes the
        /// POSIX error that matches it.
        private static func loadingError(for error: any Error) -> any Error {
            guard let error = error as? SMB.Error else {
                return error
            }
            return NSError(domain: NSPOSIXErrorDomain, code: Int(error.posixCode ?? EIO))
        }
    }

    /// Opens the SMB file once and shares the handle between all loading requests.
    private actor MediaSource {
        struct Prepared: Sendable {
            let handle: SMB.File
            let size: UInt64
            let blockSize: Int
        }

        private let connection: SMB.Connection
        private let path: String
        private var opening: Task<Prepared, any Error>?

        init(connection: SMB.Connection, path: String) {
            self.connection = connection
            self.path = path
        }

        func prepared() async throws -> Prepared {
            let task = opening ?? Task { [connection, path] in
                let handle = try await connection.openFile(at: path)
                return try await Prepared(
                    handle: handle,
                    size: handle.stat().size,
                    blockSize: connection.acceptedReadBlockSize
                )
            }
            opening = task
            do {
                return try await task.value
            }
            catch {
                // Lets a later request retry, for example after a transient network error.
                if opening == task {
                    opening = nil
                }
                throw error
            }
        }
    }

    /// The part of a data request read on the delegate queue, so the serving task never touches it elsewhere.
    private struct RequestedRange: Sendable {
        let start: Int64
        let end: Int64
        let toEnd: Bool

        init(_ dataRequest: AVAssetResourceLoadingDataRequest) {
            start = dataRequest.currentOffset
            let (end, overflow) = dataRequest.requestedOffset
                .addingReportingOverflow(Int64(dataRequest.requestedLength))
            self.end = overflow ? .max : end
            toEnd = dataRequest.requestsAllDataToEndOfResource
        }
    }

    /// Carries a loading request to the serving task, which only hands it back to the delegate queue.
    private struct LoadingRequest: @unchecked Sendable {
        let value: AVAssetResourceLoadingRequest

        init(_ value: AVAssetResourceLoadingRequest) {
            self.value = value
        }
    }
#endif
