//
// Part of SwiftSMB
// SMBMediaAssetTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(AVFoundation) && !os(watchOS)
    @testable import SwiftSMBAVFoundation
    import AVFoundation
    import Foundation
    import SwiftSMB
    import Testing
    import UniformTypeIdentifiers

    @Suite(.tags(.integration))
    struct SMBMediaAssetTests {
        @available(macOS 13, iOS 16, tvOS 16, macCatalyst 16, visionOS 1, *)
        @Test("asset loads duration and tracks from an SMB file") func assetLoadsDurationAndTracks() async throws {
            try await withUploadedMovie { connection, path in
                let asset = connection.makeAsset(at: path)
                let duration = try await asset.load(.duration)
                #expect(abs(duration.seconds - Double(TestMovie.frameCount) / Double(TestMovie.framesPerSecond)) < 0.2)

                let tracks = try await asset.loadTracks(withMediaType: .video)
                #expect(tracks.count == 1)
            }
        }

        @available(macOS 13, iOS 16, tvOS 16, macCatalyst 16, visionOS 1, *)
        @Test("asset reader decodes every frame through byte-range requests") func assetReaderDecodesEveryFrame()
        async throws {
            try await withUploadedMovie { connection, path in
                let asset = connection.makeAsset(at: path)
                let track = try #require(try await asset.loadTracks(withMediaType: .video).first)
                let reader = try AVAssetReader(asset: asset)
                let output = AVAssetReaderTrackOutput(
                    track: track,
                    outputSettings: [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA]
                )
                reader.add(output)
                #expect(reader.startReading())

                var frames = 0
                while let sample = output.copyNextSampleBuffer() {
                    if CMSampleBufferGetImageBuffer(sample) != nil {
                        frames += 1
                    }
                }
                #expect(reader.status == .completed)
                #expect(frames == TestMovie.frameCount)
            }
        }

        @available(macOS 13, iOS 16, tvOS 16, macCatalyst 16, visionOS 1, *)
        @Test("player item becomes ready to play") func playerItemBecomesReadyToPlay() async throws {
            try await withUploadedMovie { connection, path in
                let item = connection.makePlayerItem(at: path)
                let player = AVPlayer(playerItem: item)
                defer { player.replaceCurrentItem(with: nil) }

                let deadline = Date().addingTimeInterval(15)
                while item.status == .unknown, Date() < deadline {
                    try await Task.sleep(nanoseconds: 20_000_000)
                }
                #expect(item.status == .readyToPlay, "\(String(describing: item.error))")
            }
        }

        @available(macOS 13, iOS 16, tvOS 16, macCatalyst 16, visionOS 1, *)
        @Test("explicit content type is used for files without an extension") func explicitContentType()
        async throws {
            try await withUploadedMovie(fileExtension: nil) { connection, path in
                let asset = connection.makeAsset(at: path, contentType: .mpeg4Movie)
                let tracks = try await asset.loadTracks(withMediaType: .video)
                #expect(tracks.count == 1)
            }
        }

        @available(macOS 13, iOS 16, tvOS 16, macCatalyst 16, visionOS 1, *)
        @Test("content type is inferred from registered extensions only") func contentTypeInference() async throws {
            let connection = try await mediaConnection()
            defer { try? await connection.disconnect() }

            #expect(try contentType(of: connection.makeAsset(at: "Videos/holiday.MP4")) == .mpeg4Movie)
            #expect(try contentType(of: connection.makeAsset(at: "Videos/holiday")) == .movie)
            // `UTType(filenameExtension:)` returns a dynamic type, not `nil`, for an extension it doesn't know.
            #expect(try contentType(of: connection.makeAsset(at: "Videos/holiday.mp4.part")) == .movie)
        }

        @available(macOS 13, iOS 16, tvOS 16, macCatalyst 16, visionOS 1, *)
        @Test("missing file fails with a file-not-found error") func missingFileFailsToLoad() async throws {
            let connection = try await mediaConnection()
            defer { try? await connection.disconnect() }

            let asset = connection.makeAsset(at: uniquePath("missing") + ".mp4")
            do {
                _ = try await asset.load(.duration)
                Issue.record("Expected loading a missing file to fail")
            }
            catch {
                #expect(posixCodes(in: error).contains(Int(ENOENT)), "\(error)")
            }
        }

        @available(macOS 13, iOS 16, tvOS 16, macCatalyst 16, visionOS 1, *)
        @Test("closed connection fails with a not-connected error") func closedConnectionFailsToLoad() async throws {
            let connection = try await mediaConnection()
            let asset = connection.makeAsset(at: uniquePath("closed") + ".mp4")
            try await connection.disconnect()

            do {
                _ = try await asset.load(.duration)
                Issue.record("Expected loading through a closed connection to fail")
            }
            catch {
                #expect(posixCodes(in: error).contains(Int(ENOTCONN)), "\(error)")
            }
        }

        /// Writes a small H.264 movie, uploads it, and runs `body` with its share-relative path.
        @available(macOS 13, iOS 16, tvOS 16, macCatalyst 16, visionOS 1, *)
        private func withUploadedMovie(
            fileExtension: String? = "mp4",
            _ body: (SMB.Connection, String) async throws -> Void
        ) async throws {
            let connection = try await mediaConnection()
            defer { try? await connection.disconnect() }

            let path = uniquePath("movie") + (fileExtension.map { "." + $0 } ?? "")
            try await TestMovie.upload(to: path, on: connection)
            defer { await removeWhenReleased(path, on: connection) }

            try await body(connection, path)
        }
    }

    /// Removes `path`, retrying while AVFoundation still holds the file open.
    ///
    /// The asset's loader keeps one read handle open until AVFoundation releases it, and the server refuses to delete a
    /// file that is open (`STATUS_SHARING_VIOLATION`).
    private func removeWhenReleased(_ path: String, on connection: SMB.Connection) async {
        for _ in 0 ..< 30 {
            if await (try? connection.removeFile(at: path)) != nil {
                return
            }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
    }

    /// A small transfer block size makes AVFoundation's requests span several positional reads.
    private func mediaConnection() async throws -> SMB.Connection {
        try await SMB.connect(
            server: SMB.Server(host: testServerHost),
            share: TestShare.public,
            configuration: SMB.Configuration(transferBlockSize: 16 * 1024)
        )
    }

    /// The media type the asset reports to AVFoundation.
    @available(macOS 11, iOS 14, tvOS 14, macCatalyst 14, visionOS 1, *)
    private func contentType(of asset: AVURLAsset) throws -> UTType {
        try #require(asset as? SMBMediaAsset).loader.contentType
    }

    /// The POSIX codes in `error` and its underlying errors.
    ///
    /// AVFoundation wraps a loading failure in its own error and keeps only its code, as a POSIX underlying error.
    private func posixCodes(in error: any Error) -> [Int] {
        var codes: [Int] = []
        var current: NSError? = error as NSError
        while let error = current {
            if error.domain == NSPOSIXErrorDomain {
                codes.append(error.code)
            }
            current = error.userInfo[NSUnderlyingErrorKey] as? NSError
        }
        return codes
    }
#endif
