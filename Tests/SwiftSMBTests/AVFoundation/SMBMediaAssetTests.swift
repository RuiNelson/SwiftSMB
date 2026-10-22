//
// Part of SwiftSMB
// SMBMediaAssetTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(AVFoundation) && !os(watchOS)
    import AVFoundation
    import Foundation
    import SwiftSMB
    import SwiftSMBAVFoundation
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
        @Test("missing file fails to load") func missingFileFailsToLoad() async throws {
            let connection = try await mediaConnection()
            defer { try? await connection.disconnect() }

            let asset = connection.makeAsset(at: uniquePath("missing") + ".mp4")
            await #expect(throws: (any Error).self) {
                _ = try await asset.load(.duration)
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
            defer { try? await connection.removeFile(at: path) }

            try await body(connection, path)
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
#endif
